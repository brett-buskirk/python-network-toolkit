#!/usr/bin/env python3
"""
Network Packet Sniffer

A cross-platform packet capture utility that decodes and displays network traffic.
Requires root/administrator privileges to run.

Usage:
    sudo python3 sniffer.py [options]

Examples:
    sudo python3 sniffer.py --count 10
    sudo python3 sniffer.py --protocol tcp --port 80
    sudo python3 sniffer.py --output json --save capture.pcap
"""

import argparse
import ctypes
import json
import os
import signal
import socket
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

# Protocol numbers
PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

# ICMP type codes
ICMP_TYPES = {
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    4: 'Source Quench',
    5: 'Redirect',
    8: 'Echo Request',
    11: 'Time Exceeded',
}

# TCP flags
TCP_FLAGS = {
    0x01: 'FIN',
    0x02: 'SYN',
    0x04: 'RST',
    0x08: 'PSH',
    0x10: 'ACK',
    0x20: 'URG',
    0x40: 'ECE',
    0x80: 'CWR',
}


class PacketStats:
    """Track packet capture statistics."""

    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.dest_ips = defaultdict(int)
        self.ports = defaultdict(int)
        self.start_time = None
        self.end_time = None

    def update(self, packet_info: dict, raw_length: int):
        """Update statistics with a new packet."""
        if self.start_time is None:
            self.start_time = time.time()
        self.end_time = time.time()

        self.total_packets += 1
        self.total_bytes += raw_length

        if 'protocol_name' in packet_info:
            self.protocols[packet_info['protocol_name']] += 1
        if 'src_ip' in packet_info:
            self.source_ips[packet_info['src_ip']] += 1
        if 'dst_ip' in packet_info:
            self.dest_ips[packet_info['dst_ip']] += 1
        if 'src_port' in packet_info:
            self.ports[packet_info['src_port']] += 1
        if 'dst_port' in packet_info:
            self.ports[packet_info['dst_port']] += 1

    def summary(self) -> str:
        """Generate a summary of captured statistics."""
        duration = (self.end_time - self.start_time) if self.start_time and self.end_time else 0

        lines = [
            "\n" + "=" * 60,
            "CAPTURE STATISTICS",
            "=" * 60,
            f"Duration: {duration:.2f} seconds",
            f"Total packets: {self.total_packets}",
            f"Total bytes: {self.total_bytes}",
            f"Packets/sec: {self.total_packets / duration:.2f}" if duration > 0 else "Packets/sec: N/A",
            "",
            "Protocols:",
        ]

        for proto, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {proto}: {count}")

        lines.append("")
        lines.append("Top 5 Source IPs:")
        for ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            lines.append(f"  {ip}: {count}")

        lines.append("")
        lines.append("Top 5 Destination IPs:")
        for ip, count in sorted(self.dest_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            lines.append(f"  {ip}: {count}")

        lines.append("=" * 60)

        return "\n".join(lines)


class PcapWriter:
    """Write packets in pcap format."""

    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_VERSION_MAJOR = 2
    PCAP_VERSION_MINOR = 4
    PCAP_THISZONE = 0
    PCAP_SIGFIGS = 0
    PCAP_SNAPLEN = 65535
    PCAP_LINKTYPE = 101  # Raw IP

    def __init__(self, filename: str):
        self.filename = filename
        self.file = None

    def open(self):
        """Open the pcap file and write the header."""
        self.file = open(self.filename, 'wb')
        # Write pcap global header
        header = struct.pack(
            '<IHHIIII',
            self.PCAP_MAGIC,
            self.PCAP_VERSION_MAJOR,
            self.PCAP_VERSION_MINOR,
            self.PCAP_THISZONE,
            self.PCAP_SIGFIGS,
            self.PCAP_SNAPLEN,
            self.PCAP_LINKTYPE
        )
        self.file.write(header)

    def write_packet(self, data: bytes, timestamp: float = None):
        """Write a packet to the pcap file."""
        if self.file is None:
            return

        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)

        # Packet header: timestamp seconds, timestamp microseconds, captured length, original length
        packet_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(packet_header)
        self.file.write(data)

    def close(self):
        """Close the pcap file."""
        if self.file:
            self.file.close()
            self.file = None


def decode_ip_header(data: bytes) -> dict:
    """Decode an IP header from raw bytes."""
    if len(data) < 20:
        return {}

    # Unpack the first 20 bytes of the IP header
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # Header length in bytes

    tos = iph[1]
    total_length = iph[2]
    identification = iph[3]
    flags_fragment = iph[4]
    flags = flags_fragment >> 13
    fragment_offset = flags_fragment & 0x1FFF
    ttl = iph[5]
    protocol = iph[6]
    checksum = iph[7]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    return {
        'version': version,
        'header_length': ihl,
        'tos': tos,
        'total_length': total_length,
        'identification': identification,
        'flags': flags,
        'fragment_offset': fragment_offset,
        'ttl': ttl,
        'protocol': protocol,
        'protocol_name': PROTOCOLS.get(protocol, f'Unknown({protocol})'),
        'checksum': checksum,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
    }


def decode_tcp_header(data: bytes, ip_header_length: int) -> dict:
    """Decode a TCP header from raw bytes."""
    tcp_start = ip_header_length
    if len(data) < tcp_start + 20:
        return {}

    tcph = struct.unpack('!HHLLBBHHH', data[tcp_start:tcp_start + 20])

    src_port = tcph[0]
    dst_port = tcph[1]
    seq_num = tcph[2]
    ack_num = tcph[3]
    data_offset_reserved = tcph[4]
    data_offset = (data_offset_reserved >> 4) * 4
    flags = tcph[5]
    window = tcph[6]
    checksum = tcph[7]
    urgent_ptr = tcph[8]

    # Decode flags
    flag_names = []
    for flag_bit, flag_name in TCP_FLAGS.items():
        if flags & flag_bit:
            flag_names.append(flag_name)

    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq_num': seq_num,
        'ack_num': ack_num,
        'data_offset': data_offset,
        'flags': flags,
        'flag_names': flag_names,
        'window': window,
        'checksum': checksum,
        'urgent_ptr': urgent_ptr,
    }


def decode_udp_header(data: bytes, ip_header_length: int) -> dict:
    """Decode a UDP header from raw bytes."""
    udp_start = ip_header_length
    if len(data) < udp_start + 8:
        return {}

    udph = struct.unpack('!HHHH', data[udp_start:udp_start + 8])

    return {
        'src_port': udph[0],
        'dst_port': udph[1],
        'length': udph[2],
        'checksum': udph[3],
    }


def decode_icmp_header(data: bytes, ip_header_length: int) -> dict:
    """Decode an ICMP header from raw bytes."""
    icmp_start = ip_header_length
    if len(data) < icmp_start + 8:
        return {}

    icmph = struct.unpack('!BBHHH', data[icmp_start:icmp_start + 8])

    icmp_type = icmph[0]
    code = icmph[1]

    return {
        'type': icmp_type,
        'type_name': ICMP_TYPES.get(icmp_type, f'Unknown({icmp_type})'),
        'code': code,
        'checksum': icmph[2],
        'identifier': icmph[3],
        'sequence': icmph[4],
    }


def decode_packet(data: bytes) -> dict:
    """Decode a complete packet."""
    packet_info = {'timestamp': datetime.now().isoformat()}

    # Decode IP header
    ip_info = decode_ip_header(data)
    if not ip_info:
        return packet_info

    packet_info.update(ip_info)

    # Decode transport layer based on protocol
    protocol = ip_info.get('protocol')
    ihl = ip_info.get('header_length', 20)

    if protocol == 6:  # TCP
        tcp_info = decode_tcp_header(data, ihl)
        packet_info.update(tcp_info)
    elif protocol == 17:  # UDP
        udp_info = decode_udp_header(data, ihl)
        packet_info.update(udp_info)
    elif protocol == 1:  # ICMP
        icmp_info = decode_icmp_header(data, ihl)
        packet_info.update(icmp_info)

    return packet_info


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Format bytes as a hex dump."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:04x}  {hex_part:<{bytes_per_line * 3}} {ascii_part}')
    return '\n'.join(lines)


def format_packet_human(packet_info: dict, raw_data: bytes, show_hex: bool = False) -> str:
    """Format a packet for human-readable output."""
    lines = []

    timestamp = packet_info.get('timestamp', '')
    src_ip = packet_info.get('src_ip', '?')
    dst_ip = packet_info.get('dst_ip', '?')
    protocol = packet_info.get('protocol_name', '?')

    # Build summary line
    summary = f"[{timestamp}] {protocol} {src_ip}"

    if 'src_port' in packet_info:
        summary += f":{packet_info['src_port']}"

    summary += f" -> {dst_ip}"

    if 'dst_port' in packet_info:
        summary += f":{packet_info['dst_port']}"

    lines.append(summary)

    # Protocol-specific details
    if protocol == 'TCP' and 'flag_names' in packet_info:
        flags = ','.join(packet_info['flag_names']) or 'none'
        lines.append(f"  Flags: [{flags}] Seq: {packet_info.get('seq_num', '?')} Ack: {packet_info.get('ack_num', '?')} Win: {packet_info.get('window', '?')}")
    elif protocol == 'ICMP' and 'type_name' in packet_info:
        lines.append(f"  Type: {packet_info['type_name']} Code: {packet_info.get('code', '?')}")
    elif protocol == 'UDP':
        lines.append(f"  Length: {packet_info.get('length', '?')}")

    lines.append(f"  TTL: {packet_info.get('ttl', '?')} ID: {packet_info.get('identification', '?')} Len: {packet_info.get('total_length', '?')}")

    if show_hex:
        lines.append("")
        lines.append(format_hex_dump(raw_data))

    return '\n'.join(lines)


def format_packet_json(packet_info: dict, raw_data: bytes) -> str:
    """Format a packet as JSON."""
    output = packet_info.copy()
    output['raw_hex'] = raw_data.hex()
    return json.dumps(output)


def matches_filter(packet_info: dict, args: argparse.Namespace) -> bool:
    """Check if a packet matches the filter criteria."""
    # Protocol filter
    if args.protocol:
        protocol_name = packet_info.get('protocol_name', '').upper()
        if args.protocol.upper() != protocol_name:
            return False

    # Port filter
    if args.port:
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        if src_port != args.port and dst_port != args.port:
            return False

    # Source IP filter
    if args.src_ip:
        if packet_info.get('src_ip') != args.src_ip:
            return False

    # Destination IP filter
    if args.dst_ip:
        if packet_info.get('dst_ip') != args.dst_ip:
            return False

    return True


def get_local_ip() -> str:
    """Get the local IP address."""
    # Method 1: Try connecting to external host to determine local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != '0.0.0.0':
            return ip
    except Exception:
        pass

    # Method 2: Try getting hostname-based IP
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and ip != '127.0.0.1':
            return ip
    except Exception:
        pass

    # Method 3: Fall back to localhost (will only see local traffic)
    return '127.0.0.1'


def get_default_interface() -> str:
    """Get the default network interface name on Linux."""
    try:
        # Read the default route to find the interface
        with open('/proc/net/route', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == '00000000':  # Default route
                    return parts[0]
    except Exception:
        pass
    return 'eth0'


def create_sniffer_socket(host: str, interface: str = None) -> tuple:
    """Create and configure a raw socket for packet sniffing.

    Returns a tuple of (socket, uses_ethernet_header).
    """
    if os.name == 'nt':
        # Windows: Use AF_INET with promiscuous mode
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        try:
            sniffer.bind((host, 0))
        except OSError as e:
            sniffer.close()
            if e.errno == 99:
                raise OSError(
                    f"Cannot bind to address '{host}'. "
                    f"Use --host to specify a valid local IP address, or try:\n"
                    f"  --host 0.0.0.0    (listen on all interfaces)\n"
                    f"  --host 127.0.0.1  (localhost only)\n"
                    f"Run 'ip addr' or 'ifconfig' to see available addresses."
                ) from None
            raise

        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return sniffer, False
    else:
        # Linux: Use AF_PACKET to capture all IP traffic
        # ETH_P_IP = 0x0800 (IP packets only)
        ETH_P_IP = 0x0800
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))

        # Bind to specific interface if provided
        if interface:
            sniffer.bind((interface, 0))
        else:
            # Bind to default interface
            default_iface = get_default_interface()
            sniffer.bind((default_iface, 0))

        return sniffer, True  # True = has Ethernet header (14 bytes to skip)


def cleanup_socket(sniffer: socket.socket):
    """Clean up the sniffer socket."""
    if os.name == 'nt':
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
    sniffer.close()


def main():
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer - Capture and analyze network traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 sniffer.py                     # Capture packets continuously
  sudo python3 sniffer.py --count 10          # Capture 10 packets
  sudo python3 sniffer.py --protocol tcp      # Capture only TCP packets
  sudo python3 sniffer.py --port 80           # Capture packets on port 80
  sudo python3 sniffer.py --output json       # Output in JSON format
  sudo python3 sniffer.py --save capture.pcap # Save to pcap file
  sudo python3 sniffer.py --hex               # Show hex dump of packets
        """
    )

    parser.add_argument('--host', '-H', type=str, default=None,
                        help='Host IP address to listen on (default: auto-detect)')
    parser.add_argument('--count', '-c', type=int, default=0,
                        help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('--protocol', '-p', type=str, choices=['tcp', 'udp', 'icmp', 'TCP', 'UDP', 'ICMP'],
                        help='Filter by protocol')
    parser.add_argument('--port', type=int,
                        help='Filter by port number (source or destination)')
    parser.add_argument('--src-ip', type=str,
                        help='Filter by source IP address')
    parser.add_argument('--dst-ip', type=str,
                        help='Filter by destination IP address')
    parser.add_argument('--output', '-o', type=str, choices=['human', 'json', 'raw'], default='human',
                        help='Output format (default: human)')
    parser.add_argument('--hex', '-x', action='store_true',
                        help='Show hex dump of packets (human output mode)')
    parser.add_argument('--save', '-s', type=str,
                        help='Save packets to pcap file')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress packet output, only show statistics at end')
    parser.add_argument('--no-stats', action='store_true',
                        help='Do not show statistics at end')
    parser.add_argument('--interface', '-i', type=str, default=None,
                        help='Network interface to capture on (Linux only, default: auto-detect)')

    args = parser.parse_args()

    # Determine host to listen on
    host = args.host if args.host else get_local_ip()

    # Check for root/admin privileges
    if os.name == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Error: This program requires administrator privileges.", file=sys.stderr)
            print("Please run as administrator.", file=sys.stderr)
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("Error: This program requires root privileges.", file=sys.stderr)
            print("Please run with sudo.", file=sys.stderr)
            sys.exit(1)

    # Initialize components
    stats = PacketStats()
    pcap_writer = None
    sniffer = None
    running = True

    if args.save:
        pcap_writer = PcapWriter(args.save)
        pcap_writer.open()
        print(f"Saving packets to: {args.save}")

    # Signal handler for graceful shutdown
    def signal_handler(sig, frame):
        nonlocal running
        running = False
        print("\n\nInterrupted, stopping capture...")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Create sniffer socket
        sniffer, has_eth_header = create_sniffer_socket(host, args.interface)

        # Ethernet header is 14 bytes (6 dst MAC + 6 src MAC + 2 ethertype)
        eth_header_len = 14 if has_eth_header else 0

        if os.name == 'nt':
            print(f"Sniffer started on {host}")
        else:
            iface = args.interface or get_default_interface()
            print(f"Sniffer started on interface {iface}")
        if args.count > 0:
            print(f"Capturing {args.count} packets...")
        else:
            print("Capturing packets (Press Ctrl+C to stop)...")

        if args.protocol:
            print(f"Filter: protocol={args.protocol.upper()}")
        if args.port:
            print(f"Filter: port={args.port}")
        if args.src_ip:
            print(f"Filter: src_ip={args.src_ip}")
        if args.dst_ip:
            print(f"Filter: dst_ip={args.dst_ip}")

        print("-" * 60)

        packets_captured = 0

        while running:
            # Check if we've reached the packet limit
            if args.count > 0 and packets_captured >= args.count:
                break

            try:
                # Set timeout to allow checking running flag
                sniffer.settimeout(1.0)
                raw_data, addr = sniffer.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as e:
                if running:
                    print(f"Error receiving packet: {e}", file=sys.stderr)
                break

            # Strip Ethernet header if present (Linux AF_PACKET)
            ip_data = raw_data[eth_header_len:] if eth_header_len > 0 else raw_data

            # Decode the packet
            packet_info = decode_packet(ip_data)

            # Apply filters
            if not matches_filter(packet_info, args):
                continue

            packets_captured += 1

            # Update statistics
            stats.update(packet_info, len(ip_data))

            # Save to pcap if enabled (save IP packet without Ethernet header)
            if pcap_writer:
                pcap_writer.write_packet(ip_data)

            # Output the packet
            if not args.quiet:
                if args.output == 'human':
                    print(format_packet_human(packet_info, ip_data, args.hex))
                    print()
                elif args.output == 'json':
                    print(format_packet_json(packet_info, ip_data))
                elif args.output == 'raw':
                    print(ip_data)
                    print()

    except PermissionError:
        print("Error: Permission denied. Please run with elevated privileges.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Cleanup
        if sniffer:
            cleanup_socket(sniffer)
        if pcap_writer:
            pcap_writer.close()
            print(f"Packets saved to: {args.save}")

        # Show statistics
        if not args.no_stats and stats.total_packets > 0:
            print(stats.summary())


if __name__ == '__main__':
    main()
