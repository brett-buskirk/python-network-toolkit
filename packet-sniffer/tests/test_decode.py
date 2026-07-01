"""Tests for packet decoding functions.

Synthetic packets are constructed with struct.pack so that tests run
without requiring root privileges or a live network.
"""

import socket
import struct

import pytest

from network_packet_sniffer.decode import (
    decode_icmp_header,
    decode_ip_header,
    decode_packet,
    decode_tcp_header,
    decode_udp_header,
)


# ---------------------------------------------------------------------------
# Helpers to construct synthetic packet bytes
# ---------------------------------------------------------------------------

def _ip_header(
    src_ip: str = "192.168.1.1",
    dst_ip: str = "192.168.1.2",
    protocol: int = 6,
    ttl: int = 64,
    total_length: int = 40,
) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,               # version=4, IHL=5 (20 bytes)
        0,                  # TOS
        total_length,
        1234,               # identification
        0x4000,             # flags (Don't Fragment), fragment offset=0
        ttl,
        protocol,
        0,                  # header checksum (not verified in decoder)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )


def _tcp_header(
    src_port: int = 12345,
    dst_port: int = 80,
    seq: int = 100,
    ack: int = 200,
    flags: int = 0x02,  # SYN
    window: int = 8192,
) -> bytes:
    data_offset_reserved = (5 << 4)  # data offset = 5 (20 bytes), reserved = 0
    return struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset_reserved,
        flags,
        window,
        0,  # checksum
        0,  # urgent pointer
    )


def _udp_header(
    src_port: int = 54321,
    dst_port: int = 53,
    length: int = 12,
) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def _icmp_header(
    icmp_type: int = 8,  # Echo Request
    code: int = 0,
    identifier: int = 1,
    sequence: int = 1,
) -> bytes:
    return struct.pack("!BBHHH", icmp_type, code, 0, identifier, sequence)


# ---------------------------------------------------------------------------
# decode_ip_header
# ---------------------------------------------------------------------------

class TestDecodeIpHeader:
    def test_returns_empty_dict_for_short_data(self):
        assert decode_ip_header(b"\x00" * 10) == {}

    def test_returns_empty_dict_for_empty_data(self):
        assert decode_ip_header(b"") == {}

    def test_parses_version(self):
        result = decode_ip_header(_ip_header())
        assert result["version"] == 4

    def test_parses_header_length(self):
        result = decode_ip_header(_ip_header())
        assert result["header_length"] == 20

    def test_parses_ttl(self):
        result = decode_ip_header(_ip_header(ttl=128))
        assert result["ttl"] == 128

    def test_parses_protocol_number(self):
        result = decode_ip_header(_ip_header(protocol=6))
        assert result["protocol"] == 6

    def test_parses_protocol_name_tcp(self):
        result = decode_ip_header(_ip_header(protocol=6))
        assert result["protocol_name"] == "TCP"

    def test_parses_protocol_name_udp(self):
        result = decode_ip_header(_ip_header(protocol=17))
        assert result["protocol_name"] == "UDP"

    def test_parses_protocol_name_icmp(self):
        result = decode_ip_header(_ip_header(protocol=1))
        assert result["protocol_name"] == "ICMP"

    def test_unknown_protocol_name(self):
        result = decode_ip_header(_ip_header(protocol=99))
        assert "Unknown" in result["protocol_name"]

    def test_parses_src_ip(self):
        result = decode_ip_header(_ip_header(src_ip="10.0.0.1"))
        assert result["src_ip"] == "10.0.0.1"

    def test_parses_dst_ip(self):
        result = decode_ip_header(_ip_header(dst_ip="8.8.8.8"))
        assert result["dst_ip"] == "8.8.8.8"

    def test_parses_total_length(self):
        result = decode_ip_header(_ip_header(total_length=60))
        assert result["total_length"] == 60


# ---------------------------------------------------------------------------
# decode_tcp_header
# ---------------------------------------------------------------------------

class TestDecodeTcpHeader:
    def test_returns_empty_dict_for_short_data(self):
        data = _ip_header() + b"\x00" * 5  # only 5 bytes of TCP, need 20
        assert decode_tcp_header(data, 20) == {}

    def test_parses_src_port(self):
        data = _ip_header() + _tcp_header(src_port=55000)
        result = decode_tcp_header(data, 20)
        assert result["src_port"] == 55000

    def test_parses_dst_port(self):
        data = _ip_header() + _tcp_header(dst_port=443)
        result = decode_tcp_header(data, 20)
        assert result["dst_port"] == 443

    def test_parses_seq_number(self):
        data = _ip_header() + _tcp_header(seq=99999)
        result = decode_tcp_header(data, 20)
        assert result["seq_num"] == 99999

    def test_parses_ack_number(self):
        data = _ip_header() + _tcp_header(ack=88888)
        result = decode_tcp_header(data, 20)
        assert result["ack_num"] == 88888

    def test_parses_syn_flag(self):
        data = _ip_header() + _tcp_header(flags=0x02)  # SYN
        result = decode_tcp_header(data, 20)
        assert "SYN" in result["flag_names"]

    def test_parses_ack_flag(self):
        data = _ip_header() + _tcp_header(flags=0x10)  # ACK
        result = decode_tcp_header(data, 20)
        assert "ACK" in result["flag_names"]

    def test_parses_multiple_flags(self):
        data = _ip_header() + _tcp_header(flags=0x12)  # SYN + ACK
        result = decode_tcp_header(data, 20)
        assert "SYN" in result["flag_names"]
        assert "ACK" in result["flag_names"]

    def test_no_flags_yields_empty_list(self):
        data = _ip_header() + _tcp_header(flags=0x00)
        result = decode_tcp_header(data, 20)
        assert result["flag_names"] == []

    def test_parses_window(self):
        data = _ip_header() + _tcp_header(window=65535)
        result = decode_tcp_header(data, 20)
        assert result["window"] == 65535

    def test_data_offset(self):
        data = _ip_header() + _tcp_header()
        result = decode_tcp_header(data, 20)
        assert result["data_offset"] == 20  # 5 * 4 bytes


# ---------------------------------------------------------------------------
# decode_udp_header
# ---------------------------------------------------------------------------

class TestDecodeUdpHeader:
    def test_returns_empty_dict_for_short_data(self):
        data = _ip_header() + b"\x00" * 4  # only 4 bytes, need 8
        assert decode_udp_header(data, 20) == {}

    def test_parses_src_port(self):
        data = _ip_header(protocol=17) + _udp_header(src_port=12000)
        result = decode_udp_header(data, 20)
        assert result["src_port"] == 12000

    def test_parses_dst_port(self):
        data = _ip_header(protocol=17) + _udp_header(dst_port=5353)
        result = decode_udp_header(data, 20)
        assert result["dst_port"] == 5353

    def test_parses_length(self):
        data = _ip_header(protocol=17) + _udp_header(length=28)
        result = decode_udp_header(data, 20)
        assert result["length"] == 28


# ---------------------------------------------------------------------------
# decode_icmp_header
# ---------------------------------------------------------------------------

class TestDecodeIcmpHeader:
    def test_returns_empty_dict_for_short_data(self):
        data = _ip_header() + b"\x00" * 4  # only 4 bytes, need 8
        assert decode_icmp_header(data, 20) == {}

    def test_parses_type(self):
        data = _ip_header(protocol=1) + _icmp_header(icmp_type=8)
        result = decode_icmp_header(data, 20)
        assert result["type"] == 8

    def test_parses_known_type_name(self):
        data = _ip_header(protocol=1) + _icmp_header(icmp_type=8)
        result = decode_icmp_header(data, 20)
        assert result["type_name"] == "Echo Request"

    def test_parses_echo_reply_type_name(self):
        data = _ip_header(protocol=1) + _icmp_header(icmp_type=0)
        result = decode_icmp_header(data, 20)
        assert result["type_name"] == "Echo Reply"

    def test_unknown_type_name(self):
        data = _ip_header(protocol=1) + _icmp_header(icmp_type=99)
        result = decode_icmp_header(data, 20)
        assert "Unknown" in result["type_name"]

    def test_parses_code(self):
        data = _ip_header(protocol=1) + _icmp_header(code=3)
        result = decode_icmp_header(data, 20)
        assert result["code"] == 3

    def test_parses_identifier(self):
        data = _ip_header(protocol=1) + _icmp_header(identifier=42)
        result = decode_icmp_header(data, 20)
        assert result["identifier"] == 42

    def test_parses_sequence(self):
        data = _ip_header(protocol=1) + _icmp_header(sequence=7)
        result = decode_icmp_header(data, 20)
        assert result["sequence"] == 7


# ---------------------------------------------------------------------------
# decode_packet (integration of the above)
# ---------------------------------------------------------------------------

class TestDecodePacket:
    def test_returns_dict_with_timestamp(self):
        data = _ip_header() + _tcp_header()
        result = decode_packet(data)
        assert "timestamp" in result
        assert isinstance(result["timestamp"], str)

    def test_tcp_packet_includes_ip_fields(self):
        data = _ip_header(src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol=6)
        data += _tcp_header()
        result = decode_packet(data)
        assert result["src_ip"] == "1.2.3.4"
        assert result["dst_ip"] == "5.6.7.8"
        assert result["protocol_name"] == "TCP"

    def test_tcp_packet_includes_tcp_fields(self):
        data = _ip_header(protocol=6) + _tcp_header(src_port=5000, dst_port=443)
        result = decode_packet(data)
        assert result["src_port"] == 5000
        assert result["dst_port"] == 443

    def test_udp_packet_includes_udp_fields(self):
        data = _ip_header(protocol=17) + _udp_header(src_port=9999, dst_port=53)
        result = decode_packet(data)
        assert result["protocol_name"] == "UDP"
        assert result["src_port"] == 9999
        assert result["dst_port"] == 53

    def test_icmp_packet_includes_icmp_fields(self):
        data = _ip_header(protocol=1) + _icmp_header(icmp_type=8)
        result = decode_packet(data)
        assert result["protocol_name"] == "ICMP"
        assert result["type"] == 8
        assert result["type_name"] == "Echo Request"

    def test_too_short_data_returns_timestamp_only(self):
        result = decode_packet(b"\x00" * 5)
        assert "timestamp" in result
        assert "src_ip" not in result

    def test_empty_data_returns_timestamp_only(self):
        result = decode_packet(b"")
        assert "timestamp" in result
        assert "src_ip" not in result
