
Platform DragonOS + requirements.txt
- vr1 is basic not organized
- op_version is structured and based on vr1

## Attack tool
Running evil twin attack.
- Scanning for nearby networks for a minute.
- Choosing network to match and scanning for its users in traffic.
- Choosing user, mask as the ap and send disassociation packet and disconnect the user from good twin.
- Creating evil twin of the targeted network and direct any user connecting to login page (via flask).


## Defense tool
Defense tool to monitor nearby networks and notify about suspicious traffic in two level tests.


### Level 1
- defense from lazy attacker, alerts when network is with the same name as another but different bssid.  
- defense from smarter one , alertswhen network is with the same name and bssid as another and found substantial jumps between rssi values in packets.
any chosen suspect network move to deeper check in level 2

### Level 2
Gets a networks name set on their channel and monitor:  
- The sequence number of packets, alerts when there are jumps backwards and when jumped forward too much to be usual.  
- Alerting if found flood of disasocciation or deauthentication packets involving with the suspect network. 

## Update
### Issues
- User connectiong to evil twin - worked before, now showing the device trying to connect and disappear to show again in available networks (can show connection failed after a while).
  Happens in different devices (target network is oneplus 12r hotspot with wpa2-personal devices trying to connect: samsung tab s9, samsung galaxy s22(?)).
  Flask is working, can access from the terminal to open login page in browser. checking on dnsmasq.conf
  
  
### Questions
- Why when scanning nearby networks between scans change the amount of networks detecting without any physical change?
- AP's changing their channel based on the nearby networks?
- Why while scanning after a few runs scan stuck on one channel (channel hopper and setting are correct, unstuck after reboot or adapter plugged again after a second)?
- Is there any pattern to Mac addresses assign to devices in a networks, like the beginning of the manefuctor of the ap in the same network?

### Files
- python code files.
- requirments txt.
- hostapd & dnsmasq from testing.
- will add video showing the current state.
