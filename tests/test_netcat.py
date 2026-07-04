"""Tests for the netcat-style connect/listen tool."""

import argparse
import socket
import subprocess
import threading
import time

import pytest

from network_toolkit.common import create_tcp_client
from network_toolkit.netcat import NetCat, execute


def _wait_for_port(host, port, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _args(port, **overrides):
    defaults = dict(target="127.0.0.1", port=port, listen=False, command=False, execute=None, upload=None)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestExecute:
    def test_runs_a_command_and_returns_output(self):
        assert execute("echo hello").strip() == "hello"

    def test_blank_command_returns_none(self):
        assert execute("   ") is None

    def test_raises_on_nonzero_exit(self):
        with pytest.raises(subprocess.CalledProcessError):
            execute("false")


class TestNetCatExecuteMode:
    def test_listener_executes_command_and_replies(self):
        port = 29555
        nc = NetCat(_args(port, listen=True, execute="echo exec_ok"))
        thread = threading.Thread(target=nc.listen, daemon=True)
        thread.start()
        try:
            assert _wait_for_port("127.0.0.1", port)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
                data = s.recv(4096)
                assert b"exec_ok" in data
        finally:
            nc.socket.close()


class TestNetCatUploadMode:
    def test_listener_saves_uploaded_file(self, tmp_path):
        port = 29556
        target = tmp_path / "uploaded.txt"
        nc = NetCat(_args(port, listen=True, upload=str(target)))
        thread = threading.Thread(target=nc.listen, daemon=True)
        thread.start()
        try:
            assert _wait_for_port("127.0.0.1", port)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
                s.sendall(b"payload contents")
                s.shutdown(socket.SHUT_WR)
                resp = s.recv(4096)
                assert b"Saved file" in resp
            time.sleep(0.2)
            assert target.read_bytes() == b"payload contents"
        finally:
            nc.socket.close()


class TestNetCatCommandShellMode:
    def test_listener_serves_a_command_prompt(self):
        port = 29557
        nc = NetCat(_args(port, listen=True, command=True))
        thread = threading.Thread(target=nc.listen, daemon=True)
        thread.start()
        try:
            assert _wait_for_port("127.0.0.1", port)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
                prompt = s.recv(64)
                assert prompt == b"BHP: #> "
                s.sendall(b"echo cmdshell_ok\n")
                resp = s.recv(4096)
                assert b"cmdshell_ok" in resp
        finally:
            nc.socket.close()


class TestNetCatSend:
    def test_send_connects_and_transmits_buffer(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()

        received = {}

        def accept_and_read():
            conn, _ = listener.accept()
            received["data"] = conn.recv(4096)
            conn.close()

        t = threading.Thread(target=accept_and_read)
        t.start()
        nc = NetCat(_args(port, target=host), buffer=b"hello from client")
        try:
            # send() blocks afterward on an input()-driven response loop, so only
            # exercise the connect+initial-send portion directly rather than via run().
            nc.socket = create_tcp_client(host, port)
            nc.socket.send(nc.buffer)
            t.join(timeout=3)
            assert received.get("data") == b"hello from client"
        finally:
            nc.socket.close()
            listener.close()
