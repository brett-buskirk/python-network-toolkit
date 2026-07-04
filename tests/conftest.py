"""Shared fixtures for SSH tool tests."""

import threading

import paramiko
import pytest

from network_toolkit.common import create_tcp_listener


@pytest.fixture
def ssh_host_key(tmp_path):
    """A throwaway RSA host key, generated fresh for each test."""
    key_path = tmp_path / "test_host_key.rsa"
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    return paramiko.RSAKey(filename=str(key_path))


@pytest.fixture
def run_ssh_session(ssh_host_key):
    """Start network_toolkit.ssh.server.Server on loopback and run *controller*
    (a function of the accepted paramiko Channel) against it in a background
    thread. Returns the port the caller should connect to."""
    from network_toolkit.ssh.server import Server

    listeners = []
    threads = []

    def start(controller, host="127.0.0.1"):
        listener = create_tcp_listener(host, 0)
        listeners.append(listener)
        port = listener.getsockname()[1]

        def serve():
            client_sock, _ = listener.accept()
            transport = paramiko.Transport(client_sock)
            try:
                transport.add_server_key(ssh_host_key)
                server = Server()
                transport.start_server(server=server)
                chan = transport.accept(20)
                if chan is not None:
                    controller(chan)
            finally:
                transport.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        threads.append(thread)
        return port

    yield start

    for thread in threads:
        thread.join(timeout=3)
    for listener in listeners:
        listener.close()
