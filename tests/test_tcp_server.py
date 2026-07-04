"""Tests for the basic TCP server."""

import socket
import threading
import time

import network_toolkit.tcp.server as tcp_server


def _wait_for_port(host, port, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class TestMain:
    def test_accepts_a_connection_and_replies_ack(self, monkeypatch):
        port = 29998
        monkeypatch.setattr(tcp_server, "IP", "127.0.0.1")
        monkeypatch.setattr(tcp_server, "PORT", port)

        thread = threading.Thread(target=tcp_server.main, daemon=True)
        thread.start()

        assert _wait_for_port("127.0.0.1", port)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.sendall(b"hello")
            resp = s.recv(64)
            assert resp == b"ACK"
