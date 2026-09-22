#!/usr/bin/env python3
"""
Educational Packet Sniffer
===========================
Captures live network packets on a chosen interface and displays:
  - Source / destination IP addresses
  - Protocol (TCP / UDP / ICMP / other)
  - Source / destination ports (for TCP/UDP)
  - A safe, printable preview of the payload

INTENDED USE
------------
This tool is for learning how network protocols and packet structures work,
for debugging your own applications/networks, and for authorized security
testing/labs (e.g. your own home lab, TryHackMe/HTB VPN ranges, or systems
you have explicit written permission to monitor).

LEGAL / ETHICAL NOTICE
-----------------------
Capturing network traffic that is not your own, or that you do not have
explicit authorization to monitor, is illegal in most jurisdictions
(e.g. under wiretapping / computer misuse laws) and violates the terms of
service of most networks. Only run this on:
  1. Your own machine/network, OR
  2. A network/lab you have explicit written authorization to test.

Never use this to intercept credentials, private messages, or any traffic
belonging to others without consent.

REQUIREMENTS
------------
  pip install scapy
  Run with elevated privileges (packet capture needs raw socket access):
    Linux/macOS: sudo python3 packet_sniffer.py
    Windows:     run terminal as Administrator (and install Npcap first)
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
except ImportError:
    print("[!] Scapy is not installed. Install it with: pip install scapy")
    sys.exit(1)


# ----------------------------------------------------------------------
# Simple stats tracker
# ----------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.total = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.other = 0

    def record(self, proto):
        self.total += 1
        if proto == "TCP":
            self.tcp += 1
        elif proto == "UDP":
            self.udp += 1
        elif proto == "ICMP":
            self.icmp += 1
        else:
            self.other += 1

    def summary(self):
        return (
            f"\n{'-'*50}\n"
            f"Capture summary\n"
            f"  Total packets : {self.total}\n"
            f"  TCP           : {self.tcp}\n"
            f"  UDP           : {self.udp}\n"
            f"  ICMP          : {self.icmp}\n"
            f"  Other         : {self.other}\n"
            f"{'-'*50}"
        )


stats = Stats()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def safe_payload_preview(raw_bytes, max_len=64):
    """Return a printable, truncated preview of payload bytes (no crashes on binary data)."""
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:max_len]
    printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in snippet)
    suffix = "..." if len(raw_bytes) > max_len else ""
    return f'"{printable}{suffix}" ({len(raw_bytes)} bytes)'


def classify_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


# ----------------------------------------------------------------------
# Packet handler
# ----------------------------------------------------------------------
def handle_packet(pkt, verbose=False, show_payload=False):
    if not pkt.haslayer(IP):
        return  # Skip non-IP traffic (ARP, etc.) for this simple tool

    ip_layer = pkt[IP]
    proto = classify_protocol(pkt)
    stats.record(proto)

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    src = ip_layer.src
    dst = ip_layer.dst
    line = f"[{timestamp}] {proto:5} {src:15} -> {dst:15}"

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        line += f"  sport={tcp_layer.sport:<5} dport={tcp_layer.dport:<5} flags={tcp_layer.flags}"
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        line += f"  sport={udp_layer.sport:<5} dport={udp_layer.dport:<5}"
    elif pkt.haslayer(ICMP):
        icmp_layer = pkt[ICMP]
        line += f"  type={icmp_layer.type} code={icmp_layer.code}"

    print(line)

    if show_payload and pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        print(f"    payload: {safe_payload_preview(payload)}")

    if verbose:
        print(f"    ttl={ip_layer.ttl} len={ip_layer.len} id={ip_layer.id}")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Educational packet sniffer (Scapy-based). "
                     "Use only on networks/systems you own or are authorized to monitor."
    )
    parser.add_argument("-i", "--iface", help="Network interface to sniff on (default: Scapy's default).")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = capture until Ctrl+C).")
    parser.add_argument("-f", "--filter", default="ip",
                         help="BPF filter, e.g. 'tcp port 80', 'udp', 'icmp'. Default: 'ip'.")
    parser.add_argument("-p", "--payload", action="store_true",
                         help="Show a printable preview of payload data.")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show extra IP header details (TTL, length, ID).")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="List available network interfaces and exit.")
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        return

    print("=" * 60)
    print(" Educational Packet Sniffer")
    print(" For learning / authorized testing only.")
    print("=" * 60)
    print(f"Interface : {args.iface or 'default'}")
    print(f"Filter    : {args.filter}")
    print(f"Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 60)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=lambda pkt: handle_packet(pkt, verbose=args.verbose, show_payload=args.payload),
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Packet capture requires elevated privileges.")
        print("    Try: sudo python3 packet_sniffer.py  (Linux/macOS)")
        print("    Or run as Administrator with Npcap installed (Windows).")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print(stats.summary())


if __name__ == "__main__":
    main()
