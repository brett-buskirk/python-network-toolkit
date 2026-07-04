"""Tests for the minimal paramiko SSH server."""

import paramiko

from network_toolkit.ssh.server import Server


class TestServerAuth:
    def test_accepts_correct_credentials(self):
        assert Server().check_auth_password("brett", "sekret") == paramiko.AUTH_SUCCESSFUL

    def test_rejects_wrong_password(self):
        assert Server().check_auth_password("brett", "wrong") == paramiko.AUTH_FAILED

    def test_rejects_wrong_username(self):
        assert Server().check_auth_password("someone-else", "sekret") == paramiko.AUTH_FAILED


class TestServerChannelRequests:
    def test_accepts_session_channels(self):
        assert Server().check_channel_request("session", 0) == paramiko.OPEN_SUCCEEDED

    def test_rejects_other_channel_kinds(self):
        result = Server().check_channel_request("direct-tcpip", 0)
        assert result == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class TestRealAuthentication:
    def test_paramiko_client_authenticates_through_the_shared_listener(self, run_ssh_session):
        def controller(chan):
            chan.recv(1024)

        port = run_ssh_session(controller)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect("127.0.0.1", port=port, username="brett", password="sekret", timeout=5)
            assert client.get_transport().is_active()
            # Open a channel so the server side's transport.accept(20) returns
            # promptly instead of waiting out its full timeout.
            client.get_transport().open_session().close()
        finally:
            client.close()
