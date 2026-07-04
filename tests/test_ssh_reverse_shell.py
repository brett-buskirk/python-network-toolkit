"""Tests for the SSH reverse-shell agent.

Pairs with network_toolkit.ssh.server.Server -- the same controller/agent
relationship the tools are designed for (ssh-server.py is the controller
that sends commands; ssh-rcmd.py is the agent that runs on the target and
executes them), driven here via the shared run_ssh_session fixture.
"""

import time

import paramiko
import pytest

from network_toolkit.ssh.reverse_shell import main, ssh_command


class TestSshCommand:
    def test_full_round_trip_runs_a_command_and_returns_output(self, run_ssh_session):
        result = {}

        def controller(chan):
            result["greeting"] = chan.recv(1024)
            chan.send("Welcome to bh_ssh")  # the initial ack ssh/server.py's main() sends
            time.sleep(0.3)  # avoid the two sends coalescing into one recv() on the agent side
            chan.send("echo revshell_ok")
            result["output"] = chan.recv(8192)
            chan.send("exit")

        port = run_ssh_session(controller)

        ssh_command("127.0.0.1", port, "brett", "sekret", "ClientConnected")

        assert result["greeting"] == b"ClientConnected"
        assert b"revshell_ok" in result["output"]

    def test_wrong_credentials_raise_an_auth_error(self, run_ssh_session):
        def controller(chan):
            pass  # never reached -- auth fails before a channel opens

        port = run_ssh_session(controller)

        with pytest.raises(paramiko.AuthenticationException):
            ssh_command("127.0.0.1", port, "brett", "wrong-password", "ClientConnected")


class TestMain:
    def test_wires_prompted_values_into_ssh_command(self, monkeypatch):
        monkeypatch.setattr("getpass.getuser", lambda: "myuser")
        monkeypatch.setattr("getpass.getpass", lambda _prompt="": "mypassword")
        prompts = iter(["10.0.0.5", "2200"])
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(prompts))

        calls = []
        monkeypatch.setattr(
            "network_toolkit.ssh.reverse_shell.ssh_command",
            lambda *args: calls.append(args),
        )

        main()

        assert calls == [("10.0.0.5", 2200, "myuser", "mypassword", "ClientConnected")]
