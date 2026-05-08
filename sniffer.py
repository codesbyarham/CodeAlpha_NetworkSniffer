#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship — Task 1
Basic Network Sniffer
Author: Arham
Description: Captures and analyzes live network packets using Scapy.
             Displays source/destination IPs, protocols, and payload data.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
from datetime import datetime
import argparse
import sys

# ─────────────────────────────────────────────
#  Color codes for terminal output
# ─────────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

packet_count = 0

def get_protocol_name(proto_num):
    """Return human-readable protocol name from IP protocol number."""
    protocols = {
        1:  "ICMP",
        6:  "TCP",
        17: "UDP",
    }
    return protocols.get(proto_num, f"UNKNOWN({proto_num})")


def format_payload(raw_data, max_bytes=64):
    """Format raw payload: printable ASCII + hex dump."""
    if not raw_data:
        return None
    # Printable ASCII
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data[:max_bytes])
    # Hex
    hex_str = ' '.join(f'{b:02x}' for b in raw_data[:max_bytes])
    return printable, hex_str


def process_packet(packet):
    """Callback: called for every captured packet."""
    global packet_count

    # Only handle IP packets
    if not packet.haslayer(IP):
        return

    packet_count += 1
    ip_layer = packet[IP]
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst
    proto    = get_protocol_name(ip_layer.proto)
    ttl      = ip_layer.ttl
    pkt_len  = len(packet)

    # ── Header ───────────────────────────────
    print(f"\n{Color.BOLD}{'─'*60}{Color.RESET}")
    print(f"  {Color.CYAN}Packet #{packet_count}{Color.RESET}  [{timestamp}]")
    print(f"  {Color.YELLOW}Protocol : {proto}{Color.RESET}")
    print(f"  {Color.GREEN}Source   : {src_ip}{Color.RESET}  →  {Color.RED}Destination : {dst_ip}{Color.RESET}")
    print(f"  TTL      : {ttl}   |   Length : {pkt_len} bytes")

    # ── TCP Layer ────────────────────────────
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = tcp.sprintf("%flags%")
        print(f"  {Color.CYAN}TCP Ports: {tcp.sport} → {tcp.dport}   Flags: {flags}{Color.RESET}")

        # Common service detection
        service_map = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                       25: "SMTP", 53: "DNS", 3306: "MySQL", 3389: "RDP"}
        for port in (tcp.sport, tcp.dport):
            if port in service_map:
                print(f"  {Color.YELLOW}⚡ Service detected: {service_map[port]}{Color.RESET}")

    # ── UDP Layer ────────────────────────────
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"  {Color.CYAN}UDP Ports: {udp.sport} → {udp.dport}{Color.RESET}")

    # ── ICMP Layer ───────────────────────────
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                      11: "Time Exceeded"}
        icmp_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
        print(f"  {Color.CYAN}ICMP Type : {icmp_name}{Color.RESET}")

    # ── Payload ──────────────────────────────
    if packet.haslayer(Raw):
        raw = bytes(packet[Raw].load)
        result = format_payload(raw)
        if result:
            printable, hex_str = result
            print(f"  Payload  : {printable}")
            print(f"  Hex      : {hex_str[:48]}{'...' if len(hex_str) > 48 else ''}")


def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha — Basic Network Sniffer (Task 1)"
    )
    parser.add_argument("-c", "--count",     type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="Network interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-f", "--filter",    type=str, default="ip",
                        help="BPF filter string (default: 'ip')")
    args = parser.parse_args()

    print(f"{Color.BOLD}{Color.CYAN}")
    print("╔══════════════════════════════════════════════╗")
    print("║     CodeAlpha — Basic Network Sniffer        ║")
    print("║     Cybersecurity Internship — Task 1        ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"{Color.RESET}")
    print(f"  Interface : {args.interface or 'default'}")
    print(f"  Filter    : {args.filter}")
    print(f"  Count     : {'Unlimited' if args.count == 0 else args.count}")
    print(f"\n  {Color.YELLOW}Starting capture... Press Ctrl+C to stop.{Color.RESET}\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=process_packet,
            count=args.count,
            store=False          # Don't store in memory — saves RAM
        )
    except KeyboardInterrupt:
        print(f"\n\n  {Color.GREEN}Capture stopped. Total packets: {packet_count}{Color.RESET}\n")
    except PermissionError:
        print(f"\n  {Color.RED}[!] Permission denied. Run with sudo.{Color.RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
