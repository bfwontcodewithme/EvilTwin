import subprocess
import sys
import threading

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Disas, RadioTap, sendp

"""
    let's scan the traffic around for 2 things:
        1. beacons of ap and compare the ssid name and the bssid, if bssid is different there is an imposter!
            scan_networks
            filter networks
        2. large amount of disas packets sent in general(?) or to one target
            scan traffic and filter disas packets

"""
INTERFACE = "wlxe84e06aed7c3"

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

def filter_packets():

    pass

def scan_ap(interface_name):
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface_name,), daemon=True)
    hopper_thread.start()
    sniff(iface=interface_name, prn=, store=False, timeout =10)
    
    stop_chopper.set()
    hopper_thread.join()
    # Sniffing completed
    pass

def main():
    set_monitor_mode(INTERFACE)
    scan_ap(INTERFACE)
    

    pass
