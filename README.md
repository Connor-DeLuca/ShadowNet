# ShadowNet

A lightweight LAN anomaly detection tool for IT/Home network monitoring and blue team defense. It currently scans all DNS requests on your network and checks for suspicious requests using an extremely large dataset of known malicious domains. It will also notify you if it sees any potential ARC spoofing. Most of the time you will see nothing while it is running unless you or a device on your network attempts to connect to a suspicious domain. 

For example, a cheap smart thermostat you bought from China that is secretly sending your data to a bad actor overseas would be caught by ShadowNet and it would warn you, assuming the domain is already known to be suspicious.

#### NOTE: A version of Npcap must be installed on the system for ShadowNet to run correctly. It is free and can be found here: https://npcap.com/#download

#### To run, cd into the root directory of the project and type python3 -m shadownet.main -i Wi-Fi, replacing Wi-Fi with the name of your PC's wifi adapter (type ifconfig in linux/mac terminal or netsh wlan show interfaces in Windows CMD to find it)