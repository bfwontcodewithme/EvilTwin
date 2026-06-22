import subprocess
import sys
import threading
from collections import defaultdict
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Disas, RadioTap, sendp

"""
    let's scan the traffic around 2 levels:
        1. 
        beacons of ap and compare the ssid name and the bssid, if bssid is different there is an imposter!
            scan_networks
            filter networks

            (clever attacker will spoof the bssid)
            no obvious imposter - suggest level 2
            imposter - display and add the context off multi ap's network, choose if to check deeper
        2.
        checking for:
            - packets out of sequence from the same bssid
            - large amount of disas packets sent in general(?) or to one target
            scan traffic and filter disas  / disauth packets

"""
INTERFACE = "wlxc83a35c2fcb0"
SUSPECT_DELTA = 25
aps_dict = {}
stop_chopper = threading.Event()
TEST= True

def set_monitor_mode(interface_name):
    print("[*] Setting up hardware changes for monitor mode ..")
    try:

        subprocess.run(["sudo", "systemctl", "stop", "NetworkManager"], check=True)
        subprocess.run(["sudo", "systemctl", "stop", "wpa_supplicant"], check=True)
        print("[*] Cleared background network services to prevent conflicts..")
        
        subprocess.run(["sudo","ip","link","set", interface_name, "down"], check=True)
        subprocess.run(["sudo","iw", interface_name,"set", "type", "monitor"], check=True)
        subprocess.run(["sudo","ip","link","set", interface_name, "up"], check=True)
        print(f"[+] {interface_name} is awake, isolated and locked in Monitor Mode!")
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to set adapter due to {e}")
        sys.exit(1)
    
def channel_hopper(interface_name):
    current_channel = 1
    while not stop_chopper.is_set():
        try:
            subprocess.run(["sudo","iw", "dev", interface_name, "set", "channel", str(current_channel)],check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            current_channel = (current_channel % 11) + 1
            
            if stop_chopper.wait(0.5):
                break
        except subprocess.CalledProcessError as e:   # CHECK if more error may happen
            print(f"[!] Channel hop error to {current_channel}: {e}")

def filter_packets(packet):
    # check if beacon
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr3

        if packet.haslayer(RadioTap) and packet[RadioTap].dBm_AntSignal is not None:
            rssi = packet[RadioTap].dBm_AntSignal
        else:
            return
        
        if bssid not in aps_dict:
            ssid = "<Hidden SSID>"
            channel = "Unknown"


            if packet.haslayer(Dot11Elt):
    # Ignores error if AP is broadcasting differently to prevent crashing
                elt = packet[Dot11Elt]
                if elt.ID ==0:
                    if elt.len != 0 and not all(byte == 0 for byte in elt.info):
                        ssid=elt.info.decode('utf-8', errors='ignore')

                current_layer = packet[Dot11Elt]
                while isinstance(current_layer, Dot11Elt):
                    # ID 3 is DS parameter
                    if current_layer.ID == 3:
                        channel = int(current_layer.info[0])

                    current_layer = current_layer.payload

                aps_dict[bssid] = {
                    "bssid" : bssid,
                    "ssid" : ssid,
                    "channel" : channel,
                    "rssi_history" : [rssi]
                }
        else:
            aps_dict[bssid]["rssi_history"].append(rssi)

# change scan time later
def level_1_check(interface_name):
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface_name,), daemon=True)
    hopper_thread.start()
    sniff(iface=interface_name, prn=filter_packets, store=False, timeout =15)
    print("[*] Completed sniffing")
    stop_chopper.set()
    hopper_thread.join()

    # finding imposter ap
    print("[*] Checking for anomalies")
    ssid_groups = defaultdict(list)

    for bssid, info in aps_dict.items():
        ssid_groups[info["ssid"]].append({
            "bssid" : bssid,
            "channel" : info["channel"]
        })

    duplicate_ssids = {ssid: (bssids) for ssid, bssids in ssid_groups.items() if len(bssids) > 1}
    
    rssi_anomalies = {}
    for bssid, info in aps_dict.items():
        history = info.get("rssi_history", [])
        if len(history) >= 4:
            variance = max(history) - min(history)
            
            if variance > SUSPECT_DELTA:
                rssi_anomalies[bssid] = {
                    "ssid" : info["ssid"],
                    "channel" : info["channel"],
                    "variance" : variance,
                    "rssi_history" : history
                }
    
    if duplicate_ssids:
        print("\n [!] Found SSIDs broadcast by multiple BSSIDs:")
        print(duplicate_ssids)
        print ("Lazy attacker")
        suspect_ssid = list(duplicate_ssids.keys())[0]
        cloned_aps = duplicate_ssids[suspect_ssid] #list of [{'bssid':..., 'channel':...}]
        primary_target_bssid = cloned_aps[0]['bssid']
        target_data = {
            "ssid" : suspect_ssid,
            "channel" : cloned_aps[0]['channel'],
            "all_cloned_bssids" : [ap['bssid'] for ap in cloned_aps],
            "attack_type" : "lazy"
        }
    
    elif rssi_anomalies:
        sorted_targets = sorted(rssi_anomalies.items(), key=lambda x: x[1]['variance'], reverse=True)
        primary_target_bssid, target_data = sorted_targets[0]
        print("\n [!] Irregular signal range of SSID detected: ")

        print (f"Primary Target identified: {target_data['ssid']} ({primary_target_bssid})")
        print(f"Signal changed by {target_data['variance']} dBm across packets")
    else: 
        primary_target_bssid = None
        target_data = None
    
    return primary_target_bssid, target_data   

def level_2_check(interface, target_bssid, target_data):
    target_channel = target_data["channel"]
    target_ssid = target_data["ssid"]
    print(f"[*] Locking {interface} to channel {target_channel}")
    try:
        subprocess.run(["sudo", "iw", "dev", interface, "set", "channel", str(target_channel)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to lock channel: {e}")
        return
    print("[*] Montioring sequence loops, and disas/deauth floods")
    print("[*] Press Ctrl+C to stop\n")

    #-------------------------------------- tracking sequence
    last_seq = {"value" : None}
    alert_counter = {"count": 0}
    SEQ_ALERT_LIMIT = 1
    #-------------------------------------- track flooding over time
    flood_tracker = defaultdict(int)
    FLD_ALERT_LIMIT = 50
    #-----------------------------------------------------------SEQ------------------

    def level_2_filter(packet):
        if not packet.haslayer(Dot11):
            return
        
        if packet.type == 0 and packet.subtype == 8: #beacon frame
            if packet[Dot11].addr3 == target_bssid:
                current_seq = packet[Dot11].SC >> 4

                if last_seq["value"] is not None:
                    prev_seq = last_seq["value"]
                    seq_attack_detected = False

                    if current_seq < prev_seq and (prev_seq - current_seq) > 5:
                        print(f"[!] Rogue Access Point detected hijacking BSSID: {target_bssid}!")
                        print(f"[!] Detail: Sequence number jumped backwards ({prev_seq} --> {current_seq})")
                        seq_attack_detected = True
 
                    elif (current_seq - prev_seq) > 200:
                        print(f"[!] Rogue Access Point detected hijacking BSSID: {target_bssid}!")
                        print(f"[!] Detail: Massive sequence number gap skip detected ({prev_seq} --> {current_seq})")
                        seq_attack_detected = True

                    if seq_attack_detected:
                        alert_counter["count"] += 1
                        if alert_counter["count"] >= SEQ_ALERT_LIMIT:
                            print("\n[-] Defense tool taking action: Shutting down Level 2 monitoring. [==]")
                            # This cleanly breaks out of Scapy's sniff loop by throwing a harmless exception
                            raise SystemExit                        
                last_seq["value"] = current_seq
    #-----------------------------------------------------------FLOOD------------------
    
        if packet.type == 0 and packet.subtype in [10,12]:
            addr1 = packet[Dot11].addr1 #Dest
            addr2 = packet[Dot11].addr2 #sender
            addr3 = packet[Dot11].addr3 #BSSID

            if target_bssid in [addr1,addr2,addr3]:
                frame_type = "DEAUTH" if packet.subtype == 12 else "DISAS"

                flood_key = f"{frame_type}_{addr2} -> {addr1}"
                flood_tracker[flood_key] +=1

                if flood_tracker[flood_key] > FLD_ALERT_LIMIT:
                    print("\n[-] Defense tool taking action: Shutting down Level 2 monitoring. [==]")
                    # This cleanly breaks out of Scapy's sniff loop by throwing a harmless exception
                    raise SystemExit  

                if flood_tracker[flood_key] == 10:
                    print(f"[!] {frame_type} flood detected involving target AP")
                    print(f"Source : {addr2} -> Destination : {addr1}")
                elif flood_tracker[flood_key] > 10 and flood_tracker[flood_key] % 10 == 0:
                    print(f"[!] Ongoing attack {flood_tracker[flood_key]} frames intercepted")
  
    try:
        sniff(iface=interface, filter="", prn=level_2_filter, store=False)
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Stopping Level 2 monitoring.")



def main():
    set_monitor_mode(INTERFACE)
    if TEST:
        target_bssid = "d0:cf:0e:4d:de:c4"
        target_data = {
            "ssid" : "inbar",
            "channel" : 3
        }
        print("[*] TEST manually invoke level 2")
        level_2_check(INTERFACE,target_bssid,target_data)

    target = level_1_check(INTERFACE)
    
    if target[0] is not None:
        # target_bssid = "22:22:22:22:22:22"
        # target_data  = {"ssid": "Home_WiFi", "channel": 1, "variance": 42}

        # unpacks the tuple into two separate, easy-to-use variables
        target_bssid, target_data = target
        level_2_check(INTERFACE, target_bssid, target_data)

    else:
        print("\n[+] Scan clean, no anomalies found.")
    
if __name__ == "__main__":
    main()