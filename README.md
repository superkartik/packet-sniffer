# Educational Packet Sniffer

A simple, Scapy-based packet sniffer for learning how network protocols and
packet structures work. Displays source/destination IPs, protocol, ports,
and a safe printable preview of payload data.

## ⚠️ Legal & Ethical Notice
Only run this on your own machine/network, or on a network/lab you have
explicit written authorization to test (e.g. your own home lab or a VPN-based
CTF range). Capturing traffic you're not authorized to monitor is illegal in
most jurisdictions.

## Requirements
```
pip install scapy
```
Packet capture needs elevated privileges:
- Linux/macOS: `sudo python3 packet_sniffer.py`
- Windows: run as Administrator (Npcap required)

## Usage
```bash
# List available interfaces
python3 packet_sniffer.py --list-interfaces

# Basic capture
sudo python3 packet_sniffer.py -i eth0

# Capture only TCP, show payload preview
sudo python3 packet_sniffer.py -i eth0 -f "tcp" -p

# Capture 50 packets with verbose IP header info
sudo python3 packet_sniffer.py -i eth0 -c 50 -v
```

## Options
| Flag | Description |
|---|---|
| `-i, --iface` | Interface to sniff on |
| `-c, --count` | Number of packets to capture (0 = unlimited) |
| `-f, --filter` | BPF filter, e.g. `"tcp port 80"` |
| `-p, --payload` | Show printable payload preview |
| `-v, --verbose` | Show TTL, length, ID |
| `--list-interfaces` | List available interfaces |
