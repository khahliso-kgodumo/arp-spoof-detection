from scapy.all import rdpcap, ARP
from collections import defaultdict
import sys
    

def analyse_pcap(pcap_file):
    print(f"[*] Analysing {pcap_file}")
    packets = rdpcap(pcap_file)
    arp_packets = [p for p in packets if p.haslayer(ARP)]
    print(f"[*] Total ARP Packets to Analyse:{len(arp_packets)} ")
    ipmac_map = defaultdict(list)  # IP: [list of MACs]
    for pkt in rdpcap(pcap_file):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            
            if ip in ipmac_map and mac not in ipmac_map[ip]:
                print(f"[!] ARP Spoofing Detected: {ip} -> {ipmac_map[ip]} to {mac}")
            
            if mac not in ipmac_map[ip]:
                ipmac_map[ip].append(mac)
    if not any(len(macs) > 1 for macs in ipmac_map.values()):
        print("[*] No ARP Spoofind Detected.")

if __name__ == "__main__":
    analyse_pcap(sys.argv[1])