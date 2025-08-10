# arp-spoof-detection
A python based security tool that detects ARP spoofing attacks from a PCAP file. Analses ARP traffic to identify malicious activity where an attacker attempts to intercept network communication,

## Key Features
- PCAP analysis for forensic investigation
- IP-MAC conflict detection
- Pure Python implementation using Scapy

## Use Cases
- Network security monitoring
- Cybersecurity education
- Penetration testing validation
- Network forensic analysis

## Quick Start
Install `Scapy` and run the file
```
pip install scapy
python3 arp_spoof_generator.py fake_arp.pcap
python3 detect_arp_spoof.py fake_arp.pcap
```
