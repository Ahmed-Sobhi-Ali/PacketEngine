# PacketEngine

**Advanced Scapy-Based Custom Packet Generator**

PacketEngine is a professional Python-based tool that enables the creation and transmission of custom network packets. Designed for network engineers, penetration testers, and researchers, it provides flexible control over all protocol layers, including Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, and ARP.

## 📌 Description

This tool leverages the power of the Scapy library to allow for deep packet customization and transmission. Whether for simulation, testing, or educational purposes, PacketEngine supports a wide range of packet types and options, giving users precise control over:

- MAC and IP addressing
- TCP/UDP port assignments
- Protocol flags and options
- Payload customization

## 🔧 Key Features

- 🔄 Supports multiple protocol layers: Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, and ARP
- 🎛️ Full control over MAC/IP addresses, ports, flags, TTL, payloads, etc.
- 🚀 Send packets over a selected network interface
- 📁 Save packets to `.pcap` for offline analysis
- ⚙️ Load/save configurations in JSON format
- 📉 Rate-limiting and delay options for traffic shaping

## 🧑‍💻 Usage

Run the script from your terminal and pass arguments to define your packet parameters. You can also load configurations or save them for reuse.

```bash
# Send 5 ICMP echo requests with a custom source IP
sudo python packet_engine.py --type icmp --count 5 --src-ip 192.168.2.10

# Send an HTTP GET request to a specific host
sudo python packet_engine.py --type http --http-host example.com --http-path /index.html

# Load a saved config
sudo python packet_engine.py --load-config my_config.json
```

Run the help command to view all options:
```bash
python packet_engine.py -h
```

## ⚙️ Options Overview

### 🧩 General
- `--type`: Packet type to send (`icmp`, `tcp`, `udp`, `dns`, `http`, `arp`)
- `--count`: Number of packets to send
- `--delay`: Delay (in seconds) between packets
- `--rate-limit`: Max packets per second (`0` = no limit)
- `--iface`: Network interface to use
- `--save-pcap`: Save packets to a `.pcap` file
- `--load-config`: Load arguments from a `.json` file
- `--save-config`: Save current config to a `.json` file

---

### 🧱 Ethernet Layer
- `--src-mac`: Source MAC address
- `--dst-mac`: Destination MAC address

---

### 🌐 IP Layer
- `--src-ip`: Source IP address
- `--dst-ip`: Destination IP address
- `--ttl`: Time To Live value
- `--ip-id`: IP packet ID
- `--ip-flags`: IP flags

---

### 🔗 TCP Layer
- `--tcp-sport`: Source TCP port
- `--tcp-dport`: Destination TCP port
- `--tcp-flags`: TCP flags (e.g., SYN, ACK, etc.)

---

### 📡 UDP Layer
- `--udp-sport`: Source UDP port
- `--udp-dport`: Destination UDP port

---

### 📶 ICMP Layer
- `--icmp-type`: ICMP type (e.g., `8` for Echo Request)
- `--icmp-code`: ICMP code
- `--icmp-id`: ICMP identifier
- `--icmp-seq`: ICMP sequence number

---

### 🧾 Payload
- `--payload`: Payload data for TCP, UDP, or ICMP packets

---

### 🌍 HTTP (for `--type http`)
- `--http-method`: HTTP method (e.g., `GET`, `POST`)
- `--http-host`: Target host
- `--http-path`: Request path
- `--http-headers`: Custom HTTP headers (in JSON format)
- `--http-body`: Optional HTTP body

---

### 🧠 DNS (for `--type dns`)
- `--dns-qname`: Query name
- `--dns-qtype`: Query type (e.g., `A`, `MX`)
- `--dns-rd`: Recursion desired flag

---

### 🧭 ARP (for `--type arp`)
- `--arp-pdst`: Target IP address for ARP request

## 📦 Requirements

- Python 3.x
- [`scapy`](https://scapy.readthedocs.io/) (Install via `pip install scapy`)
- Root privileges to send raw packets

## ⚠️ Disclaimer

> Use PacketEngine responsibly. Unauthorized generation of network traffic can disrupt services and may be illegal. Always obtain permission before testing on any system or network you do not own or administer.

---

**Author:** Ahmed Sobhi Ali - Security Analyst | Cyber Security Engineer | Purple Team Specialist
