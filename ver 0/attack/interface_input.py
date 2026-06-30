from scapy.all import conf, sniff # or whatever scapy functions you need

def interface_select(job_name="Sniffing", exclude=None):
    # Fetch all interfaces recognized by Scapy
    all_ifaces = conf.ifaces.values()
    
    # Filter out loopback (127.0.0.1) and inactive/invalid interfaces
    # This keeps the list clean for the user
    valid_ifaces = []
    for iface in all_ifaces:
        # 1. Skip the local loopback interface (usually named 'lo' on Linux)
        if iface.name == "lo" or (iface.ip and iface.ip.startswith("127.")):
            continue
            
        # 2. Skip internal/virtual docker interfaces if present
        if "docker" in iface.name:
            continue
            
        valid_ifaces.append(iface)

    if not valid_ifaces:
        print("[-] No active network adapters found.")
        return None

    print("\n=== Select Adapter for: {job_name} ===")
    for idx, iface in enumerate(valid_ifaces):
        ip_display = iface.ip if iface.ip else "No IP Assigned"
        print(f"[{idx}] Name: {iface.name} | Description: {iface.description} | IP: {ip_display}")  
    # Prompt the user for a choice

    while True:
        try:
            choice = input(f"Select index for {job_name} (0-{len(valid_ifaces)-1}): ").strip()
            choice_idx = int(choice)
            if 0 <= choice_idx < len(valid_ifaces):
                selected_iface = valid_ifaces[choice_idx]
                print(f"[+] Assigned {selected_iface.name} to {job_name}.\n")
                return selected_iface.name
            else:
                print(f"[-] Invalid selection.")
        except ValueError:
            print("[-] Please enter a valid number.")


if __name__ == "__main__":
    interface_select()