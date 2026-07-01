
# Evil Twin Attack & Defense Tools

## Attack tool
Running evil twin attack.
- Scanning for nearby networks for a minute.
- Choosing network to match and scanning for its users in traffic.
- Choosing user, mask as the ap and send deauthentication packet and disconnect the user from good twin.
- Creating evil twin of the targeted network and direct any user connecting to login page (via flask).


## Defense tool
Defense tool to monitor nearby networks and notify about suspicious traffic in two level tests.

### Level 1
- defense from lazy attacker, alerts when network is with the same name as another but different bssid.  
- defense from smarter one , alerts when network is with the same name and bssid as another and found substantial jumps between rssi values in packets.
any chosen suspect network move to deeper check in level 2

### Level 2
Gets a networks name set on their channel and monitor:  
- The sequence number of packets, alerts when there are jumps backwards and when jumped forward too much to be usual.  
- Alerting if found flood of disasocciation or deauthentication packets involving with the suspect network.


## 📂 Repository Structure
```text
EvilTwin/
├── v0/                # Main source code and tool orchestration engines
├── poc/               # Proof-of-concept pcap and video demonstrations
├── gitignore         
├── requirements.txt   # Python dependencies
└── README.md          # Project documentation
```
## Supported Devices & Environment
The tool has been physically tested and verified on the following hardware:
* **DragonOS**
* **Lenovo ThinkPad E14** (Host System)
* **OnePlus 12R** (Target)
  
### Hardware Requirements:  
To run the full attack pipeline, your system requires **two (2) separate wireless network adapters** with the following capabilities:
1. **Rogue Access Point Interface:**
   * **Requirement:** Must support **Monitor Mode & Access Point (AP) Mode**. This allows the adapter to broadcast a beaconing network and authenticate connecting clients.
   * **Verified Example:** `Edup WiFi 6E AX3000` *(MediaTek MT7921AU)*

2. **Monitoring & Injection Interface:**
   * **Requirement:** Must support **Monitor Mode** and **Packet Injection**. This allows the adapter to sniff raw management frames from the air and send targeted deauthentication frames to isolate clients.
   * **Verified Example:** `Tenda UH150 High-Power` *(Ralink/MediaTek RT3070 chipset)*

## Known Issues & Limitations
This section tracks current behavior quirks and active development priorities:
- Target device not connecting to the evil AP automatically with 100% consistency. As a result,the captive login page fails to pop up automatically.
  **Tests needed to analyze the affects of mobile device OS and Wifi setting**
  
### Questions
- Why when scanning nearby networks between scans change the amount of networks detecting without any physical change?
- Why while scanning after a few runs scan stuck on one channel (channel hopper and setting are correct, unstuck after reboot or adapter plugged again after a second)?


