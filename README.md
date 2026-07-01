
# Evil Twin Attack & Defense Tools
### v0 contains:
- source code files
- requirments txt.
- hostapd & dnsmasq examples
  
### poc contains:
- **2 videos demonstrations**
- pcpng file of traffic during the attack, not sliced

  
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


## Known Issues & Limitations
This section tracks current behavior quirks and active development priorities:
- Target device not connecting to the evil AP automatically with 100% consistency. As a result,the captive login page fails to pop up automatically.
  **Tests needed to analyze the affects of mobile device OS and Wifi setting**


  
## Supported Devices & Environment
The tool has been physically tested and verified on the following hardware:
* **DragonOS**
* **Lenovo ThinkPad E14** (Host System)
* **OnePlus 12R** (Target)

### Questions
- Why when scanning nearby networks between scans change the amount of networks detecting without any physical change?
- Why while scanning after a few runs scan stuck on one channel (channel hopper and setting are correct, unstuck after reboot or adapter plugged again after a second)?


