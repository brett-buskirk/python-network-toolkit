"""Tests for the packet filter logic."""

import pytest

from network_packet_sniffer.filters import matches_filter


@pytest.fixture
def tcp_packet():
    return {
        "protocol_name": "TCP",
        "src_ip": "192.168.1.10",
        "dst_ip": "93.184.216.34",
        "src_port": 54321,
        "dst_port": 80,
    }


@pytest.fixture
def udp_packet():
    return {
        "protocol_name": "UDP",
        "src_ip": "10.0.0.5",
        "dst_ip": "8.8.8.8",
        "src_port": 43210,
        "dst_port": 53,
    }


@pytest.fixture
def icmp_packet():
    return {
        "protocol_name": "ICMP",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
    }


class TestNoFilters:
    def test_tcp_packet_passes(self, tcp_packet):
        assert matches_filter(tcp_packet) is True

    def test_udp_packet_passes(self, udp_packet):
        assert matches_filter(udp_packet) is True

    def test_icmp_packet_passes(self, icmp_packet):
        assert matches_filter(icmp_packet) is True

    def test_empty_packet_passes(self):
        assert matches_filter({}) is True


class TestProtocolFilter:
    def test_matching_protocol_lowercase(self, tcp_packet):
        assert matches_filter(tcp_packet, protocol="tcp") is True

    def test_matching_protocol_uppercase(self, tcp_packet):
        assert matches_filter(tcp_packet, protocol="TCP") is True

    def test_matching_protocol_mixed_case(self, tcp_packet):
        assert matches_filter(tcp_packet, protocol="Tcp") is True

    def test_non_matching_protocol_rejected(self, tcp_packet):
        assert matches_filter(tcp_packet, protocol="udp") is False

    def test_udp_match(self, udp_packet):
        assert matches_filter(udp_packet, protocol="udp") is True

    def test_icmp_match(self, icmp_packet):
        assert matches_filter(icmp_packet, protocol="icmp") is True


class TestPortFilter:
    def test_matches_destination_port(self, tcp_packet):
        assert matches_filter(tcp_packet, port=80) is True

    def test_matches_source_port(self, tcp_packet):
        assert matches_filter(tcp_packet, port=54321) is True

    def test_non_matching_port_rejected(self, tcp_packet):
        assert matches_filter(tcp_packet, port=443) is False

    def test_udp_port_match(self, udp_packet):
        assert matches_filter(udp_packet, port=53) is True

    def test_packet_without_ports_rejected(self, icmp_packet):
        assert matches_filter(icmp_packet, port=80) is False


class TestSrcIpFilter:
    def test_matching_src_ip(self, tcp_packet):
        assert matches_filter(tcp_packet, src_ip="192.168.1.10") is True

    def test_non_matching_src_ip_rejected(self, tcp_packet):
        assert matches_filter(tcp_packet, src_ip="10.0.0.1") is False

    def test_packet_without_src_ip_rejected(self):
        assert matches_filter({}, src_ip="192.168.1.10") is False


class TestDstIpFilter:
    def test_matching_dst_ip(self, tcp_packet):
        assert matches_filter(tcp_packet, dst_ip="93.184.216.34") is True

    def test_non_matching_dst_ip_rejected(self, tcp_packet):
        assert matches_filter(tcp_packet, dst_ip="1.2.3.4") is False

    def test_packet_without_dst_ip_rejected(self):
        assert matches_filter({}, dst_ip="8.8.8.8") is False


class TestCombinedFilters:
    def test_all_filters_match(self, tcp_packet):
        assert matches_filter(
            tcp_packet,
            protocol="tcp",
            port=80,
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
        ) is True

    def test_one_filter_fails_rejects_packet(self, tcp_packet):
        assert matches_filter(
            tcp_packet,
            protocol="tcp",
            port=443,  # wrong port
        ) is False

    def test_protocol_and_src_ip_match(self, tcp_packet):
        assert matches_filter(tcp_packet, protocol="tcp", src_ip="192.168.1.10") is True

    def test_protocol_match_src_ip_fail(self, tcp_packet):
        assert matches_filter(tcp_packet, protocol="tcp", src_ip="1.2.3.4") is False
