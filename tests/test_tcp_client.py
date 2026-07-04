"""Tests for the basic TCP client."""

import socket
import threading

import network_toolkit.tcp.client as tcp_client
from network_toolkit.common import create_tcp_client


class TestMain:
    def test_sends_a_get_request_and_prints_the_response(self, monkeypatch, capsys):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        received_request = {}

        def serve_one():
            conn, _ = listener.accept()
            received_request["data"] = conn.recv(4096)
            # A single sendall() so tcp/client.py's one-shot recv(4096) reliably
            # gets the whole response in one read.
            conn.sendall(b"HTTP/1.1 200 OK\r\n\r\ntcp-client reached me")
            conn.close()

        thread = threading.Thread(target=serve_one)
        thread.start()
        try:
            monkeypatch.setattr(
                tcp_client, "create_tcp_client", lambda _host, _port: create_tcp_client(host, port)
            )
            tcp_client.main()
            out = capsys.readouterr().out
            assert "tcp-client reached me" in out
            assert b"GET / HTTP/1.1" in received_request["data"]
        finally:
            thread.join(timeout=3)
            listener.close()
