"""Packet decoding functions for IPv4, TCP, UDP, and ICMP headers."""

import socket
import struct
from datetime import datetime

from .protocols import ICMP_TYPES, PROTOCOLS, TCP_FLAGS


def decode_ip_header(data: bytes) -> dict:
    """Decode an IPv4 header from raw bytes.

    Returns an empty dict if the data is too short to contain a valid header.
    """
    if len(data) < 20:
        return {}

    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # header length in bytes

    flags_fragment = iph[4]

    return {
        "version": version,
        "header_length": ihl,
        "tos": iph[1],
        "total_length": iph[2],
        "identification": iph[3],
        "flags": flags_fragment >> 13,
        "fragment_offset": flags_fragment & 0x1FFF,
        "ttl": iph[5],
        "protocol": iph[6],
        "protocol_name": PROTOCOLS.get(iph[6], f"Unknown({iph[6]})"),
        "checksum": iph[7],
        "src_ip": socket.inet_ntoa(iph[8]),
        "dst_ip": socket.inet_ntoa(iph[9]),
    }


def decode_tcp_header(data: bytes, ip_header_length: int) -> dict:
    """Decode a TCP header from raw bytes.

    Returns an empty dict if the data is too short.
    """
    tcp_start = ip_header_length
    if len(data) < tcp_start + 20:
        return {}

    tcph = struct.unpack("!HHLLBBHHH", data[tcp_start : tcp_start + 20])

    flags_byte = tcph[5]
    flag_names = [
        name for bit, name in TCP_FLAGS.items() if flags_byte & bit
    ]

    return {
        "src_port": tcph[0],
        "dst_port": tcph[1],
        "seq_num": tcph[2],
        "ack_num": tcph[3],
        "data_offset": (tcph[4] >> 4) * 4,
        "flags": flags_byte,
        "flag_names": flag_names,
        "window": tcph[6],
        "checksum": tcph[7],
        "urgent_ptr": tcph[8],
    }


def decode_udp_header(data: bytes, ip_header_length: int) -> dict:
    """Decode a UDP header from raw bytes.

    Returns an empty dict if the data is too short.
    """
    udp_start = ip_header_length
    if len(data) < udp_start + 8:
        return {}

    udph = struct.unpack("!HHHH", data[udp_start : udp_start + 8])

    return {
        "src_port": udph[0],
        "dst_port": udph[1],
        "length": udph[2],
        "checksum": udph[3],
    }


def decode_icmp_header(data: bytes, ip_header_length: int) -> dict:
    """Decode an ICMP header from raw bytes.

    Returns an empty dict if the data is too short.
    """
    icmp_start = ip_header_length
    if len(data) < icmp_start + 8:
        return {}

    icmph = struct.unpack("!BBHHH", data[icmp_start : icmp_start + 8])

    icmp_type = icmph[0]
    return {
        "type": icmp_type,
        "type_name": ICMP_TYPES.get(icmp_type, f"Unknown({icmp_type})"),
        "code": icmph[1],
        "checksum": icmph[2],
        "identifier": icmph[3],
        "sequence": icmph[4],
    }


def decode_packet(data: bytes) -> dict:
    """Decode a complete IP packet, including its transport-layer header."""
    packet_info: dict = {"timestamp": datetime.now().isoformat()}

    ip_info = decode_ip_header(data)
    if not ip_info:
        return packet_info

    packet_info.update(ip_info)

    protocol = ip_info.get("protocol")
    ihl = ip_info.get("header_length", 20)

    if protocol == 6:
        packet_info.update(decode_tcp_header(data, ihl))
    elif protocol == 17:
        packet_info.update(decode_udp_header(data, ihl))
    elif protocol == 1:
        packet_info.update(decode_icmp_header(data, ihl))

    return packet_info
