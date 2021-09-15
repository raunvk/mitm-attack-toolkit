# mitm-attack-toolkit

**Description** : Man in the Middle Attack Tools

**Requisite** : Make sure you have Python3 and Pip installed in your System.

**How to Run (Linux)** :

1. Install requirements.txt to install necessary packages [**$ python3 -m pip install -r requirements.txt**]  

2. Install colored library [**$ pip3 install colored**]

3. Run mac-changer.py to change your MAC address into any other MAC address [**$ sudo python3 mac-changer.py -i 〈interface〉 -m 〈MAC〉**]

4. Run arp-spoofer.py to spoof your Gateway (router) IP address to become Man in the Middle [**$ sudo python3 arp-spoofer.py -t 〈targetIP〉 -g 〈gatewayIP〉**]

5. Run arp-spoofer.py PLUS http-sniffer.py to capture Login credentials over HTTP web pages [**$ sudo python3 http-sniffer.py -i 〈interface〉**]

6. Run arp-spoofer.py PLUS packet-analyzer.py to capture and analyze Ethernet packets and obtain crucial information [**$ sudo python3 packet-analyzer.py**]
