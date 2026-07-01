"""Tests for packet output formatting functions."""

import json

import pytest

from network_packet_sniffer.output import (
    format_hex_dump,
    format_packet_human,
    format_packet_json,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tcp_packet_info():
    return {
        "timestamp": "2025-01-01T12:00:00",
        "protocol_name": "TCP",
        "src_ip": "192.168.1.1",
        "dst_ip": "93.184.216.34",
        "src_port": 54321,
        "dst_port": 80,
        "flag_names": ["SYN"],
        "seq_num": 1000,
        "ack_num": 0,
        "window": 65535,
        "ttl": 64,
        "identification": 1234,
        "total_length": 60,
    }


@pytest.fixture
def udp_packet_info():
    return {
        "timestamp": "2025-01-01T12:00:01",
        "protocol_name": "UDP",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "src_port": 43210,
        "dst_port": 53,
        "length": 28,
        "ttl": 64,
        "identification": 5678,
        "total_length": 48,
    }


@pytest.fixture
def icmp_packet_info():
    return {
        "timestamp": "2025-01-01T12:00:02",
        "protocol_name": "ICMP",
        "src_ip": "192.168.1.5",
        "dst_ip": "8.8.8.8",
        "type": 8,
        "type_name": "Echo Request",
        "code": 0,
        "ttl": 64,
        "identification": 9012,
        "total_length": 28,
    }


SAMPLE_BYTES = bytes(range(32))


# ---------------------------------------------------------------------------
# format_hex_dump
# ---------------------------------------------------------------------------

class TestFormatHexDump:
    def test_returns_string(self):
        assert isinstance(format_hex_dump(SAMPLE_BYTES), str)

    def test_empty_bytes_returns_empty_string(self):
        assert format_hex_dump(b"") == ""

    def test_single_byte(self):
        result = format_hex_dump(b"\xab")
        assert "ab" in result

    def test_contains_offset(self):
        result = format_hex_dump(b"\x00" * 20)
        assert "0000" in result

    def test_second_line_offset(self):
        result = format_hex_dump(b"\x00" * 20, bytes_per_line=16)
        assert "0010" in result

    def test_non_printable_shown_as_dot(self):
        result = format_hex_dump(b"\x01\x02")
        assert "." in result

    def test_printable_chars_shown_as_ascii(self):
        result = format_hex_dump(b"Hello")
        assert "Hello" in result

    def test_custom_bytes_per_line(self):
        lines = format_hex_dump(b"\x00" * 8, bytes_per_line=4).split("\n")
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# format_packet_human
# ---------------------------------------------------------------------------

class TestFormatPacketHuman:
    def test_returns_string(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert isinstance(result, str)

    def test_contains_protocol(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "TCP" in result

    def test_contains_src_ip(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "192.168.1.1" in result

    def test_contains_dst_ip(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "93.184.216.34" in result

    def test_contains_src_port(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "54321" in result

    def test_contains_dst_port(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "80" in result

    def test_tcp_shows_flags(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "SYN" in result

    def test_tcp_shows_seq(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "1000" in result

    def test_udp_shows_length(self, udp_packet_info):
        result = format_packet_human(udp_packet_info, SAMPLE_BYTES)
        assert "28" in result

    def test_icmp_shows_type_name(self, icmp_packet_info):
        result = format_packet_human(icmp_packet_info, SAMPLE_BYTES)
        assert "Echo Request" in result

    def test_no_hex_by_default(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, b"\xde\xad\xbe\xef")
        assert "dead" not in result

    def test_hex_dump_included_when_requested(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, b"\xde\xad\xbe\xef", show_hex=True)
        assert "de ad be ef" in result

    def test_contains_ttl(self, tcp_packet_info):
        result = format_packet_human(tcp_packet_info, SAMPLE_BYTES)
        assert "TTL" in result

    def test_missing_fields_use_question_mark(self):
        result = format_packet_human({}, b"")
        assert "?" in result


# ---------------------------------------------------------------------------
# format_packet_json
# ---------------------------------------------------------------------------

class TestFormatPacketJson:
    def test_returns_valid_json_string(self, tcp_packet_info):
        result = format_packet_json(tcp_packet_info, SAMPLE_BYTES)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_contains_raw_hex(self, tcp_packet_info):
        result = format_packet_json(tcp_packet_info, b"\xca\xfe")
        parsed = json.loads(result)
        assert parsed["raw_hex"] == "cafe"

    def test_contains_src_ip(self, tcp_packet_info):
        parsed = json.loads(format_packet_json(tcp_packet_info, b""))
        assert parsed["src_ip"] == "192.168.1.1"

    def test_does_not_mutate_input(self, tcp_packet_info):
        original_keys = set(tcp_packet_info.keys())
        format_packet_json(tcp_packet_info, b"")
        assert set(tcp_packet_info.keys()) == original_keys

    def test_empty_packet_info(self):
        result = format_packet_json({}, b"\x00")
        parsed = json.loads(result)
        assert parsed["raw_hex"] == "00"
