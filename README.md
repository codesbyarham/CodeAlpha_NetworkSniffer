# 🔍 CodeAlpha — Basic Network Sniffer (Task 1)

A Python-based network packet sniffer built using **Scapy**. Captures live traffic and displays protocol info, IPs, ports, and payload data in real time.

## Features
- Captures TCP, UDP, and ICMP packets
- Shows source/destination IPs and ports
- Detects common services (HTTP, HTTPS, SSH, FTP, etc.)
- Displays raw payload (ASCII + hex)
- BPF filter support
- Color-coded terminal output

## Requirements
```bash
pip install scapy
```

## Usage
```bash
# Basic capture (unlimited)
sudo python3 sniffer.py

# Capture 20 packets
sudo python3 sniffer.py -c 20

# Specific interface
sudo python3 sniffer.py -i eth0

# Custom BPF filter (only TCP)
sudo python3 sniffer.py -f "tcp"

# Filter by port
sudo python3 sniffer.py -f "port 80"
```

> **Note:** Requires root/sudo privileges for raw packet access.

## Educational Purpose
This tool is built for learning how network packets are structured and how data flows across protocols. It should only be used on networks you own or have explicit permission to monitor.

---
**CodeAlpha Cybersecurity Internship**
