import os
import sys
import subprocess
import time
import threading
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Disas, RadioTap, sendp
import app


def setup_interface_stage1(main_interface):
    print("[*] Setting up hardware changes for STAGE 1: sniffing...")
    try:
        print("\n[*] Clearing background network services to prevent conflicts...")
        subprocess.run(["sudo","systemctl", "stop", "NetworkManager"],check=True)
        subprocess.run(["sudo","systemctl","stop","wpa_supplicant"],check=True)
        print(f"[*] {main_interface} is going down")
        subprocess.run(["sudo","ip","link","set", main_interface, "down"], check=True)
        print(f"[*] Switching {main_interface} to monitor mode")
        subprocess.run(["sudo","iw", main_interface,"set", "type", "monitor"], check=True)
        print(f"[*] Wakey Wakey {main_interface}")
        subprocess.run(["sudo","ip","link","set", main_interface, "up"], check=True)
        print(f"[+] {main_interface} is awake, isolated and locked in Monitor Mode!")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to set adapter: {e}")
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
