#!/usr/bin/env python3

import socket
import struct
import textwrap
import time


try:
    file1 = open('packet-analyzer-header.txt', 'r')
    print(' ')
    print (file1.read())
    file1.close()
except IOError:
    print('\nBanner File not found!')


def main():
    # create socket
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("\n[+] Packet Analyzer is active. Displaying detailed Packet analysis on current interface.")

    # infinite loop to sniff packets
    while True:
        raw_data, addr = connect.recvfrom(65535)
        dest_mac, src_mac, protocol, data = ethernet_frame(raw_data)
        print('\n\n-------------------------------------------------------------------------------------------------------------------------')
        print('\n\n[+] Ethernet Frame =>')
        print('\t - Destination MAC : {}, Source MAC : {}, Protocol : {}'.format(dest_mac, src_mac, protocol))

        # for ethernet protocol 8 (regular ipv4 traffic)
        if protocol == 8:
            (version, headerlength, ttl, protocol, src, dest, data) = ipv4_packet(data)
            print('\n[+] IPv4 Header =>' )
            print('\t - Version : {}, Header Length : {}, TTL : {}'.format(version, headerlength, ttl))
            print('\t - Protocol : {}, Source : {}, Destination : {}'.format(protocol, src, dest))

            # icmp packet
            if protocol == 1:
                (type, code, checksum, data) = icmp_packet(data)
                print('\n[+] ICMP Packet =>')
                print('\t - Type : {}, Code : {}, Checksum : {}'.format(type, code, checksum))
                print('\t - Payload : ')
                print(multi_line_formatter('\t\t   ', data))

            # tcp packet
            elif protocol == 6:
                (src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_packet(data)
                print('\n[+] TCP Packet =>')
                print('\t - Source Port : {}, Destination Port : {}'.format(src_port, dest_port))
                print('\t - Sequence : {}, Acknowledgment : {}'.format(sequence, ack))
                print('\t - Flags : ')
                print('\t\t   URG : {}, ACK : {}, PSH : {}, RST : {}, SYN : {}, FIN : {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t - Payload : ')
                print(multi_line_formatter('\t\t   ', data))

            # udp packet
            elif protocol == 17:
                (src_port, dest_port, size, data) = udp_packet(data)
                print('\n[+] TCP Packet =>')
                print('\t - Source Port : {}, Destination Port : {}, Length : {}'.format(src_port, dest_port, size))
                print('\t - Payload : ')
                print(multi_line_formatter('\t\t   ', data))

            # other packets
            else:
                print('\n[+] Unidentified Packet =>')
                print('\t - Payload : ')
                print(multi_line_formatter('\t\t   ', data))

        time.sleep(5)


# unpack ethernet frame (total 14 bytes of sender, receiver and frame length info)
def ethernet_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return mac_formatter(dest_mac), mac_formatter(src_mac), socket.htons(protocol), data[14:]


# format mac address to human readable format (Ex: AA:BB:CC:DD:EE:FF)
def mac_formatter(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


# unpack ipv4 packet (header and payload)
def ipv4_packet(data):
    version_headerlength = data[0]
    version = version_headerlength >> 4
    headerlength = (version_headerlength & 15) * 4
    ttl, protocol, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerlength, ttl, protocol, ipv4_formatter(src), ipv4_formatter(dest), data[headerlength:]


# format ipv4 address to human readable format (Ex: 255.255.255.255)
def ipv4_formatter(addr):
    return '.'.join(map(str, addr))


# unpack icmp packet
def icmp_packet(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum, data[4:]


# unpack tcp packet
def tcp_packet(data):
    (src_port, dest_port, sequence, ack, offset_reserved_tcpflags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_tcpflags >> 12) * 4
    flag_urg = (offset_reserved_tcpflags & 32) >> 5
    flag_ack = (offset_reserved_tcpflags & 16) >> 4
    flag_psh = (offset_reserved_tcpflags & 8) >> 3
    flag_rst = (offset_reserved_tcpflags & 4) >> 2
    flag_syn = (offset_reserved_tcpflags & 2) >> 1
    flag_fin = offset_reserved_tcpflags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# unpack udp packet
def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# format multi-line data
def multi_line_formatter(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
