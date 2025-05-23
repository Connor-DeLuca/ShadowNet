# ShadowNet

A lightweight LAN anomaly detection tool for IT/Home network monitoring and blue team defense. 
#### NOTE: A version of Npcap must be installed on the system for main.py to run correctly.

#### To run, cd into the root directory of the project and type python3 -m shadownet.main -i Wi-Fi, replacing Wi-Fi with the name of your PC's wifi adapter (type ifconfig in linux/mac terminal or netsh wlan show interfaces in Windows CMD to find it)