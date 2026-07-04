"""Tests for the SSH command-running client.

network_toolkit.ssh.server's own Server class doesn't implement
check_channel_exec_request (it's built for the reverse-shell pairing in
ssh/reverse_shell.py, not for SSHClient.exec_command()), so this uses a
small, dedicated exec-capable ServerInterface to exercise ssh_command()'s
real connect + exec_command + output-reading behavior end-to-end.
"""

import subprocess
import threading

import paramiko

from network_toolkit.common import create_tcp_listener
from network_toolkit.ssh.client import main, ssh_command


class _ExecServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username == "tester" and password == "testpass":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode()
        self.event.set()
        return True


def _start_exec_server(host_key):
    listener = create_tcp_listener("127.0.0.1", 0)
    port = listener.getsockname()[1]

    def serve():
        client_sock, _ = listener.accept()
        transport = paramiko.Transport(client_sock)
        try:
            transport.add_server_key(host_key)
            server = _ExecServer()
            transport.start_server(server=server)
            chan = transport.accept(20)
            if chan is None:
                return
            server.event.wait(5)
            result = subprocess.run(
                server.command, shell=True, capture_output=True, text=True
            )
            chan.send(result.stdout)
            chan.send_stderr(result.stderr)
            chan.send_exit_status(result.returncode)
            chan.close()
        finally:
            transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, listener, thread


class TestSshCommand:
    def test_connects_runs_a_command_and_prints_its_output(self, ssh_host_key, capsys):
        port, listener, thread = _start_exec_server(ssh_host_key)
        try:
            ssh_command("127.0.0.1", port, "tester", "testpass", "echo hello_from_exec")
            thread.join(timeout=5)
            out = capsys.readouterr().out
            assert "hello_from_exec" in out
        finally:
            listener.close()


class TestMain:
    def test_wires_prompted_values_into_ssh_command(self, monkeypatch):
        prompts = iter(["myuser", "10.0.0.5", "2200", "whoami"])
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(prompts))
        monkeypatch.setattr("getpass.getpass", lambda _prompt="": "mypassword")

        calls = []
        monkeypatch.setattr(
            "network_toolkit.ssh.client.ssh_command",
            lambda *args: calls.append(args),
        )

        main()

        assert calls == [("10.0.0.5", 2200, "myuser", "mypassword", "whoami")]

    def test_blank_prompts_fall_back_to_defaults(self, monkeypatch):
        prompts = iter(["myuser", "", "", ""])
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(prompts))
        monkeypatch.setattr("getpass.getpass", lambda _prompt="": "mypassword")

        calls = []
        monkeypatch.setattr(
            "network_toolkit.ssh.client.ssh_command",
            lambda *args: calls.append(args),
        )

        main()

        assert calls == [("192.168.1.203", 2222, "myuser", "mypassword", "id")]
