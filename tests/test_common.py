"""Tests for shared socket and output helpers."""

import socket
import threading

from network_toolkit.common import create_tcp_client, create_tcp_listener, format_hex_dump


class TestCreateTcpListener:
    def test_binds_and_listens(self):
        sock = create_tcp_listener("127.0.0.1", 0)
        try:
            host, port = sock.getsockname()
            assert host == "127.0.0.1"
            assert port > 0
        finally:
            sock.close()

    def test_sets_reuse_addr_by_default(self):
        sock = create_tcp_listener("127.0.0.1", 0)
        try:
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0
        finally:
            sock.close()

    def test_reuse_addr_can_be_disabled(self):
        sock = create_tcp_listener("127.0.0.1", 0, reuse_addr=False)
        try:
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        finally:
            sock.close()

    def test_accepts_a_connection(self):
        listener = create_tcp_listener("127.0.0.1", 0)
        try:
            host, port = listener.getsockname()
            with socket.create_connection((host, port), timeout=3):
                conn, _ = listener.accept()
                conn.close()
        finally:
            listener.close()

    def test_custom_backlog_is_accepted(self):
        sock = create_tcp_listener("127.0.0.1", 0, backlog=100)
        sock.close()

    def test_reuse_addr_allows_immediate_rebind_after_close(self):
        # Regression test for the "Address already in use" restart issue this
        # helper was introduced to fix (tcp-server.py and tcp-proxy.py used to
        # skip SO_REUSEADDR entirely).
        first = create_tcp_listener("127.0.0.1", 0)
        port = first.getsockname()[1]
        first.close()

        second = create_tcp_listener("127.0.0.1", port)
        try:
            assert second.getsockname()[1] == port
        finally:
            second.close()


class TestCreateTcpClient:
    def test_connects_to_a_listener(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()

        accepted = {}

        def accept_one():
            conn, addr = listener.accept()
            accepted["conn"] = conn
            accepted["addr"] = addr

        t = threading.Thread(target=accept_one)
        t.start()
        try:
            client = create_tcp_client(host, port)
            t.join(timeout=3)
            assert "conn" in accepted
            client.close()
            accepted["conn"].close()
        finally:
            listener.close()


class TestFormatHexDump:
    def test_empty_input_returns_empty_string(self):
        assert format_hex_dump(b"") == ""

    def test_single_byte(self):
        result = format_hex_dump(b"\xab")
        assert result.startswith("0000")
        assert "ab" in result

    def test_printable_ascii_shown_as_is(self):
        result = format_hex_dump(b"Hi")
        assert result.endswith("Hi")

    def test_non_printable_bytes_shown_as_dot(self):
        result = format_hex_dump(b"\x00\x01")
        assert result.endswith("..")

    def test_multi_line_output(self):
        result = format_hex_dump(b"\x00" * 20, bytes_per_line=16)
        lines = result.split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("0000")
        assert lines[1].startswith("0010")

    def test_custom_bytes_per_line(self):
        lines = format_hex_dump(b"\x00" * 8, bytes_per_line=4).split("\n")
        assert len(lines) == 2
