import sys
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

eth = Ether(dst="ff:ff:ff:ff:ff:ff")

legit_arp1 = ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
legit_arp2 = ARP(op=2, psrc="192.168.1.100", hwsrc="aa:bb:cc:dd:ee:ff")

spoofed_arp = ARP(op=2, psrc="192.168.1.1", hwsrc="66:77:88:99:00:11")

packets = [eth/legit_arp1, eth/legit_arp2, eth/spoofed_arp]

filename = sys.argv[1]
wrpcap(filename, packets)
print(f"[+] Fake ARP Spoofing PCAP Generated: {filename}")