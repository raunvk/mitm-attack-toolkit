#!/usr/bin/evn python3

import subprocess
import argparse
import re

try:
    file1 = open('mac-changer-header.txt', 'r')
    print(' ')
    print (file1.read())
    file1.close()
except IOError:
    print('\nBanner File not found!')
    

# get interface to change mac along with new mac
def get_arguements():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Use -i flag to specify Interface on which to change MAC")
    parser.add_argument("-m", "--mac", dest="new_mac", help="Use -m flag to specify new MAC address to change into")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify Interface on which to change MAC. Use --help for instructions.")
    elif not options.new_mac:
        parser.error("[-] Please specify new MAC address to change into. Use --help for instructions.")

    return options


# get current mac of mentioned interface
def current_mac(interface):
    ifconfig = str(subprocess.check_output(["ifconfig", interface]))
    result = str(re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig))
    start = result.find("='")
    end = len(result)
    curr_mac = result[start+2:end-2]

    if curr_mac:
        return curr_mac
    else:
        curr_mac = "[-] No MAC address found"
        return curr_mac


# change mac of mentioned interface
def change_mac(interface, new_mac):
    print("\n[+] Changing MAC address of " + interface + " to : " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


options = get_arguements()


# get previous mac address
curr_mac = current_mac(options.interface)
print("\n[+] Previous MAC address of " + str(options.interface) + " : " + str(curr_mac))


change_mac(options.interface, options.new_mac)


# get current mac address
curr_mac = current_mac(options.interface)
if curr_mac == options.new_mac:
    print("\n[+] Successfully changed MAC address of " + options.interface)
    print("\n[+] Current MAC address of " + str(options.interface) + " : " + str(curr_mac))
else:
    print("\n[-] Failed to change MAC address. Try again.")

