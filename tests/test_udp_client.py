"""Tests for the basic UDP client."""

import socket
import threading

import network_toolkit.udp.client as udp_client


class TestMain:
    def test_sends_data_and_prints_the_reply(self, capsys):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 9997))  # matches udp_client's hardcoded target
        server.settimeout(3)

        def echo_once():
            data, addr = server.recvfrom(4096)
            server.sendto(data, addr)

        thread = threading.Thread(target=echo_once)
        thread.start()
        try:
            udp_client.main()
            out = capsys.readouterr().out
            assert "AAABBBCCC" in out
        finally:
            thread.join(timeout=3)
            server.close()
