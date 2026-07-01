"""Tests for PacketStats."""

import time

import pytest

from network_packet_sniffer.stats import PacketStats


@pytest.fixture
def stats():
    return PacketStats()


@pytest.fixture
def tcp_packet():
    return {
        "protocol_name": "TCP",
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "src_port": 12345,
        "dst_port": 80,
    }


@pytest.fixture
def udp_packet():
    return {
        "protocol_name": "UDP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 54321,
        "dst_port": 53,
    }


class TestPacketStatsInit:
    def test_starts_at_zero(self, stats):
        assert stats.total_packets == 0
        assert stats.total_bytes == 0

    def test_start_time_is_none(self, stats):
        assert stats.start_time is None

    def test_end_time_is_none(self, stats):
        assert stats.end_time is None

    def test_protocol_dict_is_empty(self, stats):
        assert len(stats.protocols) == 0


class TestPacketStatsUpdate:
    def test_increments_total_packets(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert stats.total_packets == 1

    def test_accumulates_total_bytes(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        stats.update(tcp_packet, 40)
        assert stats.total_bytes == 100

    def test_records_protocol(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert stats.protocols["TCP"] == 1

    def test_records_source_ip(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert stats.source_ips["192.168.1.1"] == 1

    def test_records_destination_ip(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert stats.dest_ips["192.168.1.2"] == 1

    def test_records_ports(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert stats.ports[12345] == 1
        assert stats.ports[80] == 1

    def test_sets_start_time_on_first_update(self, stats, tcp_packet):
        before = time.time()
        stats.update(tcp_packet, 60)
        assert stats.start_time is not None
        assert stats.start_time >= before

    def test_start_time_does_not_change_on_subsequent_updates(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        first_start = stats.start_time
        stats.update(tcp_packet, 60)
        assert stats.start_time == first_start

    def test_multiple_protocols_counted_separately(self, stats, tcp_packet, udp_packet):
        stats.update(tcp_packet, 60)
        stats.update(udp_packet, 40)
        assert stats.protocols["TCP"] == 1
        assert stats.protocols["UDP"] == 1

    def test_ignores_missing_optional_fields(self, stats):
        # Packet with no ports or IPs — should not raise
        stats.update({"protocol_name": "ICMP"}, 28)
        assert stats.total_packets == 1
        assert len(stats.source_ips) == 0
        assert len(stats.ports) == 0


class TestPacketStatsSummary:
    def test_returns_string(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        result = stats.summary()
        assert isinstance(result, str)

    def test_contains_total_packets(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert "Total packets: 1" in stats.summary()

    def test_contains_total_bytes(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert "Total bytes: 60" in stats.summary()

    def test_contains_protocol_name(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert "TCP" in stats.summary()

    def test_contains_source_ip(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert "192.168.1.1" in stats.summary()

    def test_contains_destination_ip(self, stats, tcp_packet):
        stats.update(tcp_packet, 60)
        assert "192.168.1.2" in stats.summary()

    def test_handles_zero_duration(self, stats, tcp_packet):
        # start_time == end_time should yield "N/A" for packets/sec
        stats.update(tcp_packet, 60)
        stats.start_time = stats.end_time  # force duration = 0
        summary = stats.summary()
        assert "N/A" in summary
