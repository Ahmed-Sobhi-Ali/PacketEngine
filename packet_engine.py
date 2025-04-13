"""
Advanced Packet Generator

This Python script enables the creation and transmission of custom network packets, offering flexible customization for each protocol layer. It supports various application-layer protocols and provides advanced options for controlling packet characteristics such as MAC addresses, IP addresses, ports, flags, and payloads.

Description:
    This tool leverages the Scapy library to facilitate the creation of arbitrary network packets,
    enabling comprehensive network testing, simulation, and analysis. It supports the construction
    of packets spanning the Ethernet, IP, TCP, UDP, and ICMP layers, as well as specialized
    packet structures for common protocols such as DNS, HTTP, and ARP. Users can meticulously
    define parameters at each layer, including MAC and IP addresses, port numbers, protocol flags,
    and custom payloads.

Key Features:
    - Flexible command-line interface for specifying packet parameters.
    - Supports multiple protocol layers: Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, and ARP.
    - Customizable packet fields, including source and destination MAC/IP addresses, ports, flags, and data payload.
    - Built-in rate-limiting for packet sending to control transmission speed.
    - Option to save packets to a PCAP file for later analysis.
    - Supports sending packets over specific network interfaces.

Author: Ahmed Sobhi Ali

Usage:
    Execute the script from the command line with various arguments to define the desired packet type
    and its characteristics. Refer to the command-line help (`python your_script_name.py -h`) for a
    comprehensive list of available options and their usage.

    Examples:
        - Send 5 ICMP echo requests with a specific source IP:
          `sudo python your_script_name.py --type icmp --count 5 --src-ip 192.168.2.10`
        - Send an HTTP GET request to a specific host and path:
          `sudo python your_script_name.py --type http --http-host example.com --http-path /index.html`
        - Load a previously saved configuration:
          `sudo python your_script_name.py --load-config my_config.json`

Requirements:
    - Python 3.x
    - scapy library (install via `pip install scapy`)
    - Root privileges for sending raw packets
    
Disclaimer:
    Use this tool responsibly and ethically. Generating and sending network traffic without proper
    authorization can have serious consequences. Ensure you have explicit permission before testing
    or simulating traffic on any network or system you do not own or administer.

"""


import argparse
import time
from scapy.all import *
import json
import os

DEFAULT_SRC_MAC = "00:0c:29:ab:cd:ef"
DEFAULT_DST_MAC = "00:50:56:ff:ff:fe"
DEFAULT_SRC_IP = "10.10.10.10"
DEFAULT_DST_IP = "192.168.1.1"
DEFAULT_TCP_SPORT = 12344
DEFAULT_TCP_DPORT = 80
DEFAULT_UDP_SPORT = 12345
DEFAULT_UDP_DPORT = 53
DEFAULT_ICMP_TYPE = 8
DEFAULT_ICMP_CODE = 0
DEFAULT_ICMP_ID = 1234
DEFAULT_ICMP_SEQ = 1

def build_ethernet_layer(src_mac=DEFAULT_SRC_MAC, dst_mac=DEFAULT_DST_MAC):
    return Ether(src=src_mac, dst=dst_mac, type=0x0800)

def build_ip_layer(src_ip=DEFAULT_SRC_IP, dst_ip=DEFAULT_DST_IP, ttl=64, id_val=1000, flags="DF"):
    return IP(src=src_ip, dst=dst_ip, ttl=ttl, id=id_val, flags=flags)

def build_tcp_layer(sport=DEFAULT_TCP_SPORT, dport=DEFAULT_TCP_DPORT, flags="S"):
    return TCP(sport=sport, dport=dport, flags=flags)

def build_udp_layer(sport=DEFAULT_UDP_SPORT, dport=DEFAULT_UDP_DPORT):
    return UDP(sport=sport, dport=dport)

def build_icmp_layer(type=DEFAULT_ICMP_TYPE, code=DEFAULT_ICMP_CODE, id_val=DEFAULT_ICMP_ID, seq=DEFAULT_ICMP_SEQ):
    return ICMP(type=type, code=code, id=id_val, seq=seq)

def build_arp_layer(pdst):
    return ARP(pdst=pdst)

def build_payload(data="Hello Ahmed!"):
    return Raw(load=data.encode())

def build_http_payload(method="GET", path="/", host="google.com", headers=None, body=None):
    http_str = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    if headers:
        for header, value in headers.items():
            http_str += f"{header}: {value}\r\n"
    http_str += "\r\n"
    if body:
        http_str += body
    return http_str.encode()

def build_dns_query(qname="google.com", qtype="A", rd=1):
    return DNS(rd=rd, qd=DNSQR(qname=qname, qtype=qtype))

def build_packet(args):
    eth = build_ethernet_layer(args.src_mac, args.dst_mac)
    ip = build_ip_layer(args.src_ip, args.dst_ip, args.ttl, args.ip_id, args.ip_flags)

    if args.type == "icmp":
        icmp = build_icmp_layer(args.icmp_type, args.icmp_code, args.icmp_id, args.icmp_seq)
        payload = build_payload(args.payload)
        return eth / ip / icmp / payload
        # return ip / icmp # For a real ping request (without Ethernet layer)
    elif args.type == "tcp":
        tcp = build_tcp_layer(args.tcp_sport, args.tcp_dport, args.tcp_flags)
        payload = build_payload(args.payload)
        return eth / ip / tcp / payload
    elif args.type == "udp":
        udp = build_udp_layer(args.udp_sport, args.udp_dport)
        payload = build_payload(args.payload)
        return eth / ip / udp / payload
    elif args.type == "dns":
        dns = build_dns_query(args.dns_qname, args.dns_qtype, args.dns_rd)
        udp = build_udp_layer(args.udp_sport, 53) # DNS usually uses port 53
        return eth / ip / udp / dns
    elif args.type == "http":
        http_payload_data = build_http_payload(args.http_method, args.http_path,
                                                args.http_host, args.http_headers,
                                                args.http_body)
        tcp = build_tcp_layer(args.tcp_sport, args.tcp_dport) # HTTP usually uses port 80 or 443
        return eth / ip / tcp / Raw(load=http_payload_data)
    elif args.type == "arp":
        arp = build_arp_layer(args.arp_pdst)
        return eth / arp
    else:
        raise ValueError(f"Unsupported packet type: {args.type}")

def send_packets(packets, args):
    sent_count = 0
    start_time = time.time()
    try:
        for i, pkt in enumerate(packets):
            if pkt.haslayer(Ether):
                print(f"[*] Sending packet {i+1}/{len(packets)} via Layer 2 on {args.iface}...")
                sendp(pkt, iface=args.iface, verbose=0)
            else:
                print(f"[*] Sending packet {i+1}/{len(packets)} via Layer 3...")
                send(pkt, verbose=0)
            sent_count += 1
            if args.rate_limit > 0:
                time_elapsed = time.time() - start_time
                target_time = (sent_count / args.rate_limit)
                sleep_duration = target_time - time_elapsed
                if sleep_duration > 0:
                    time.sleep(sleep_duration)
            elif args.delay > 0:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print("[!] Sending interrupted by user.")
    finally:
        print(f"[+] Sent {sent_count} packets.")

def load_config(config_file):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    return {}

def save_config(config_file, args_dict):
    with open(config_file, 'w') as f:
        json.dump(args_dict, f, indent=4)
    print(f"[*] Configuration saved to {config_file}")

def main():
    parser = argparse.ArgumentParser(description="Ahmed's Advanced Custom Packet Generator")

    # General options
    parser.add_argument("--type", required=True, choices=["icmp", "tcp", "udp", "dns", "http", "arp"], help="Type of packet to send")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between packets (seconds)")
    parser.add_argument("--rate-limit", type=float, default=0, help="Maximum packets per second (0 for no limit)")
    parser.add_argument("--iface", default="eth0", help="Interface to send packets on")
    parser.add_argument("--save-pcap", metavar="FILENAME", help="Save packets to a PCAP file (optional)")
    parser.add_argument("--load-config", metavar="FILENAME", help="Load arguments from a JSON config file")
    parser.add_argument("--save-config", metavar="FILENAME", help="Save current arguments to a JSON config file")

    # Ethernet layer options
    parser.add_argument("--src-mac", default=DEFAULT_SRC_MAC, help="Source MAC address")
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC, help="Destination MAC address")

    # IP layer options
    parser.add_argument("--src-ip", default=DEFAULT_SRC_IP, help="Source IP address")
    parser.add_argument("--dst-ip", default=DEFAULT_DST_IP, help="Destination IP address")
    parser.add_argument("--ttl", type=int, default=64, help="IP Time-to-Live")
    parser.add_argument("--ip-id", type=int, default=1000, help="IP Identification field")
    parser.add_argument("--ip-flags", default="DF", help="IP Flags (e.g., DF, MF, 0)")

    # TCP layer options
    parser.add_argument("--tcp-sport", type=int, default=DEFAULT_TCP_SPORT, help="Source TCP port")
    parser.add_argument("--tcp-dport", type=int, default=DEFAULT_TCP_DPORT, help="Destination TCP port")
    parser.add_argument("--tcp-flags", default="S", help="TCP flags (e.g., S, A, F, P, R, U)")

    # UDP layer options
    parser.add_argument("--udp-sport", type=int, default=DEFAULT_UDP_SPORT, help="Source UDP port")
    parser.add_argument("--udp-dport", type=int, default=DEFAULT_UDP_DPORT, help="Destination UDP port")

    # ICMP layer options
    parser.add_argument("--icmp-type", type=int, default=DEFAULT_ICMP_TYPE, help="ICMP Type")
    parser.add_argument("--icmp-code", type=int, default=DEFAULT_ICMP_CODE, help="ICMP Code")
    parser.add_argument("--icmp-id", type=int, default=DEFAULT_ICMP_ID, help="ICMP Identifier")
    parser.add_argument("--icmp-seq", type=int, default=DEFAULT_ICMP_SEQ, help="ICMP Sequence Number")

    # Payload option
    parser.add_argument("--payload", default="Hello Ahmed!", help="Custom payload for TCP/UDP/ICMP packets")

    # HTTP options
    parser.add_argument("--http-method", default="GET", help="HTTP method (GET, POST, etc.)")
    parser.add_argument("--http-path", default="/", help="HTTP path")
    parser.add_argument("--http-host", default="google.com", help="HTTP Host header")
    parser.add_argument("--http-headers", type=json.loads, default=None, help='HTTP headers in JSON format (e.g., \'{"User-Agent": "MyAgent"}\')')
    parser.add_argument("--http-body", default=None, help="HTTP request body")

    # DNS options
    parser.add_argument("--dns-qname", default="google.com", help="DNS query name")
    parser.add_argument("--dns-qtype", default="A", help="DNS query type (A, AAAA, MX, etc.)")
    parser.add_argument("--dns-rd", type=int, default=1, help="DNS Recursion Desired flag (0 or 1)")

    # ARP options
    parser.add_argument("--arp-pdst", help="ARP target IP address")

    args = parser.parse_args()

    # Load configuration if specified
    if args.load_config:
        config = load_config(args.load_config)
        parser.set_defaults(**config)
        args = parser.parse_args() # Re-parse with loaded defaults

    # Save configuration if specified
    if args.save_config:
        save_config(args.save_config, vars(args))

    packets = []
    for i in range(args.count):
        try:
            pkt = build_packet(args)
            packets.append(pkt)
            print(f"[*] Built packet {i + 1}/{args.count} of type {args.type}")
        except ValueError as e:
            print(f"[!] Error building packet {i + 1}: {e}")
            return

    # Save to PCAP if requested
    if args.save_pcap:
        try:
            wrpcap(args.save_pcap, packets)
            print(f"[*] Packets saved to {args.save_pcap}")
        except Exception as e:
            print(f"[!] Error saving to PCAP: {e}")

    # Send packets
    if packets:
        send_packets(packets, args)

    print("[+] Done.")

if __name__ == "__main__":
    main()
