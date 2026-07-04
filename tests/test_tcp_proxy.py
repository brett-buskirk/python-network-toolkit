"""Tests for the inspecting TCP proxy."""

import socket
import threading
import time

import network_toolkit.tcp.proxy as tcp_proxy


def _wait_for_port(host, port, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _start_echo_backend(port):
    """A "remote" server that echoes back whatever it receives, one connection
    at a time, each on its own thread (the proxy may open more than one
    connection to it, e.g. while readiness-probing the proxy's own port)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)

    def handle_one(conn):
        data = conn.recv(4096)
        if data:
            conn.sendall(b"ECHO:" + data)
        time.sleep(0.1)
        conn.close()

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle_one, args=(conn,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv


class TestReceiveFrom:
    def test_returns_all_data_until_peer_closes(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()

        def send_and_close():
            with socket.create_connection((host, port), timeout=3) as s:
                s.sendall(b"hello world")

        t = threading.Thread(target=send_and_close)
        t.start()
        conn, _ = listener.accept()
        try:
            assert tcp_proxy.receive_from(conn) == b"hello world"
        finally:
            conn.close()
            listener.close()
            t.join(timeout=3)


class TestServerLoop:
    def _run_case(self, receive_first, local_port, remote_port):
        remote = _start_echo_backend(remote_port)
        thread = threading.Thread(
            target=tcp_proxy.server_loop,
            args=("127.0.0.1", local_port, "127.0.0.1", remote_port, receive_first),
            daemon=True,
        )
        thread.start()
        try:
            assert _wait_for_port("127.0.0.1", local_port)
            with socket.create_connection(("127.0.0.1", local_port), timeout=10) as s:
                s.sendall(b"PING")
                s.shutdown(socket.SHUT_WR)
                resp = s.recv(64)
                assert resp == b"ECHO:PING"
        finally:
            remote.close()

    def test_forwards_client_to_remote_and_back(self):
        self._run_case(receive_first=False, local_port=29600, remote_port=29601)

    def test_receive_first_also_forwards_correctly(self):
        self._run_case(receive_first=True, local_port=29610, remote_port=29611)
