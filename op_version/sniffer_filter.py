# =====================================================================
#                   SNIFFER & FILTER
# =====================================================================
"""
1.1. set adapter to monitor
1.2. start channel hopper
1.3. scan for 1 minutes for beacon packets
1.4. filter by bssid
1.5. stop hopper thread
1.6. return list of ap's to main

2.1 scanning for victims
2.2 filter and save, return clients to main

"""
import os
import sys
import subprocess
import time
import threading
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Disas, RadioTap, sendp, conf
conf.verb = 0
aps_dict = {}
victims_dic = {}
stop_chopper = threading.Event()

def set_monitor_mode(interface_name):
    print("[*] Setting up hardware changes for STAGE 1: Sniffing..")
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


def scan_networks(interface_name, scan_time):
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface_name,), daemon=True)
    hopper_thread.start()
    print(f"[*] Starting scanning for networks for {scan_time} seconds ..")
    sniff(iface=interface_name, prn=filter_network, store=False, timeout =scan_time)
    
    stop_chopper.set()
    hopper_thread.join()
    # Sniffing completed
    if not aps_dict:
        print("[!] No networks found.")
        return None
    ap_list = list(aps_dict.values())
    print("---- Discovered Networks ----")
    print(f"{'ID':>3}  {'BSSID':<20} {'SSID':<18} {'CH':<3} {'Security'}")
    print("-" * 70)
    for index, ap in enumerate(ap_list, start=1):
        clean_ssid = (ap['ssid'][:15] + '...') if len(ap['ssid']) > 17 else ap['ssid']
        print(
        f"{index:>3}  "
        f"{ap['bssid']:<20} "
        f"{clean_ssid:<18} "
        f"{ap['channel']:>3}  "
        f"{ap['security']:<22}"
        )
    while True:
        try:
            choice = int(input("\nSelect target index to copy: "))
            if 0 < choice  <= len(ap_list):
                chosen_ap = ap_list[choice-1]
                break
            else:
                print("[!] Invalid index. Select again.")
        except ValueError:
            print("Please enter a vaild number.")
    print(f"[+] Target selected: {chosen_ap['bssid']} ({chosen_ap['ssid']}), channel {chosen_ap['channel']}.")
    stop_chopper.clear()
    return chosen_ap
    
def scan_victims(interface_name, ap, scan_time):
    subprocess.run(["sudo","iw","dev", interface_name,"set", "channel", str(ap['channel'])], check=True)
    print(f"\n[*] Channel set to target channel: {ap['channel']}")
    print(f"[*] Starting scanning for victims for {scan_time} seconds ..")
    sniff(iface=interface_name, prn=lambda pkt: filter_victims(pkt,ap['bssid']) ,store=False, timeout=scan_time)
    
    if not victims_dic:
        print("No victims discovered")
        return None
    
    victims_list = list (victims_dic.values())
    print("---- Discovered victims ----")
    for index, victim in enumerate(victims_list, start=1):
        print(f"[{index: >2}] BSSID: {victim['bssid']} | Packets: {victim['packets']}")
    while True:
        try:
            choice = int(input("\nSelect victim index to target: "))
            if 0 < choice <= len(victims_list):
                chosen_victim = victims_list[choice-1]
                break
            else:
                print("[!] Invalid index, select again")

        except ValueError:
            print("Please enter a vaild number.")
    print(f"[+] Victim selected: {chosen_victim['bssid']}")
    return chosen_victim


def filter_network(packet):
    # Check if beacon type
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr3
    # Check if already in list
        if bssid not in aps_dict:
            ssid = "<Hidden SSID>"
            channel = "Unknown"
            security = "OPEN"
            
            if packet.haslayer(Dot11Elt):
    # Ignores error if AP is broadcasting differently to prevent crashing
                elt = packet[Dot11Elt]
                if elt.ID ==0:
                    if elt.len != 0 and not all(byte == 0 for byte in elt.info):
                        ssid=elt.info.decode('utf-8', errors='ignore')
                
    # parse Information Elements        
                current_layer = packet[Dot11Elt]
                while isinstance(current_layer, Dot11Elt):
                    # ID 3 is DS parameter
                    if current_layer.ID == 3:
                        channel = current_layer.info[0]
                    # ID 48 is RSN (WPA2 /WPA3)
                    elif current_layer.ID == 48:
                        rsn_bytes = current_layer.info
                    
                        wpa2 = b"\x00\x0f\xac\x02" in rsn_bytes
                        wpa3 = b"\x00\x0f\xac\x08" in rsn_bytes or b"\x00\x0f\xac\x09" in rsn_bytes
                    
                        if wpa2 and wpa3:
                            security = "WPA3/WPA2-Transition"
                        elif wpa3:
                            security = "WPA3"
                        elif wpa2:
                            security = "WPA2"
                    # ID 221 to check for WPA
                    elif current_layer.ID == 221 and current_layer.info.startswith(b"\x00\x50\xf2\x01"):
                        if security not in ["WPA2", "WPA3", "WPA3/WPA2-Transition"]:
                            security = "WPA"
                
                    current_layer = current_layer.payload
                    # check for WEP if not have anything else
                if security == "OPEN":
                    capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                    if "privacy" in capability:
                        security = "WEP"
            
                aps_dict[bssid] = {
                    "bssid" : bssid,
                    "ssid" : ssid,
                    "channel" : channel,
                    "security" : security
                }
    
def filter_victims(packet, bssid):
    target_bssid = bssid.lower()

    if not packet.haslayer(Dot11):
        return
    
    dot = packet[Dot11]
    
    if target_bssid not in [dot.addr1, dot.addr2, dot.addr3]:
        return
    
    #only for management and control type , type 0 subtypes:  8(beacon) 5(probe response), 11(authentication)    
    if dot.type not in [0,2] or (dot.type == 0 and dot.subtype in [5,8,11]):
        return
    
    victim_mac = None
    
    src_mac = dot.addr2
    dst_mac = dot.addr1
    bssid_mac = dot.addr3
    
    # Victim --> AP
    if target_bssid == dst_mac:
        victim_mac = src_mac
    # AP --> Victim
    elif target_bssid == src_mac:
        victim_mac = dst_mac
    # Case for bssid in addr3 and not the src, the transmitter is the victim
    elif target_bssid == bssid_mac:
        if target_bssid != src_mac:
            victim_mac = src_mac
    
    if victim_mac:
    # Drop if broadcast (ff:ff....) ot IPv6 multicast(33:33))
        if victim_mac != "ff:ff:ff:ff:ff:ff" and not victim_mac.startswith("33:33"):
            if victim_mac not in victims_dic:
    # Keeping track of the amount of traffic for each victim
                victims_dic[victim_mac] = {
                    "bssid" : victim_mac,
                    "packets" : 0
                }
            victims_dic[victim_mac]['packets']+= 1


