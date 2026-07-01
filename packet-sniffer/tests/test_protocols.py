"""Tests for protocol constant definitions."""

import pytest

from network_packet_sniffer.protocols import ICMP_TYPES, PROTOCOLS, TCP_FLAGS


class TestProtocols:
    def test_protocols_contains_required_entries(self):
        assert PROTOCOLS[1] == "ICMP"
        assert PROTOCOLS[6] == "TCP"
        assert PROTOCOLS[17] == "UDP"

    def test_protocols_has_at_least_three_entries(self):
        assert len(PROTOCOLS) >= 3

    def test_protocols_values_are_strings(self):
        for value in PROTOCOLS.values():
            assert isinstance(value, str)

    def test_protocols_keys_are_ints(self):
        for key in PROTOCOLS.keys():
            assert isinstance(key, int)


class TestIcmpTypes:
    def test_echo_reply(self):
        assert ICMP_TYPES[0] == "Echo Reply"

    def test_echo_request(self):
        assert ICMP_TYPES[8] == "Echo Request"

    def test_destination_unreachable(self):
        assert ICMP_TYPES[3] == "Destination Unreachable"

    def test_time_exceeded(self):
        assert ICMP_TYPES[11] == "Time Exceeded"

    def test_has_at_least_four_entries(self):
        assert len(ICMP_TYPES) >= 4

    def test_values_are_strings(self):
        for value in ICMP_TYPES.values():
            assert isinstance(value, str)


class TestTcpFlags:
    def test_syn_flag(self):
        assert TCP_FLAGS[0x02] == "SYN"

    def test_ack_flag(self):
        assert TCP_FLAGS[0x10] == "ACK"

    def test_fin_flag(self):
        assert TCP_FLAGS[0x01] == "FIN"

    def test_rst_flag(self):
        assert TCP_FLAGS[0x04] == "RST"

    def test_psh_flag(self):
        assert TCP_FLAGS[0x08] == "PSH"

    def test_has_eight_flags(self):
        assert len(TCP_FLAGS) == 8

    def test_all_keys_are_powers_of_two(self):
        for key in TCP_FLAGS.keys():
            assert key > 0 and (key & (key - 1)) == 0, f"{key:#x} is not a power of two"

    def test_values_are_strings(self):
        for value in TCP_FLAGS.values():
            assert isinstance(value, str)
