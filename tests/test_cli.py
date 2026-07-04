"""Tests for the unified netk CLI dispatcher."""

import sys
from unittest.mock import MagicMock

import pytest

import network_toolkit.cli as cli


class TestUsage:
    def test_no_args_prints_usage_and_lists_every_subcommand(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["netk"])
        cli.main()
        out = capsys.readouterr().out
        assert "usage: netk <subcommand> [args...]" in out
        for name in cli.SUBCOMMANDS:
            assert name in out

    def test_help_flag_prints_usage(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["netk", "--help"])
        cli.main()
        assert "usage: netk" in capsys.readouterr().out

    def test_short_help_flag_prints_usage(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["netk", "-h"])
        cli.main()
        assert "usage: netk" in capsys.readouterr().out


class TestUnknownSubcommand:
    def test_exits_nonzero_and_prints_to_stderr(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["netk", "bogus-cmd"])
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "unknown subcommand 'bogus-cmd'" in err


class TestDispatch:
    def test_sniff_is_called_with_argv_list_and_sys_argv_is_untouched(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["netk", "sniff", "--count", "5"])
        fake_module = MagicMock()
        monkeypatch.setattr(cli.importlib, "import_module", lambda name: fake_module)

        cli.main()

        fake_module.main.assert_called_once_with(["--count", "5"])
        assert sys.argv == ["netk", "sniff", "--count", "5"]

    def test_other_subcommands_rewrite_argv_and_call_main_with_no_args(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["netk", "nc", "-l", "-p", "5555"])
        fake_module = MagicMock()
        monkeypatch.setattr(cli.importlib, "import_module", lambda name: fake_module)

        cli.main()

        fake_module.main.assert_called_once_with()
        assert sys.argv == ["netk nc", "-l", "-p", "5555"]

    def test_dispatches_to_the_correct_module_for_each_subcommand(self, monkeypatch):
        for subcommand, (module_name, _) in cli.SUBCOMMANDS.items():
            monkeypatch.setattr(sys, "argv", ["netk", subcommand])
            fake_module = MagicMock()
            imported = {}

            def fake_import(name, _imported=imported):
                _imported["name"] = name
                return fake_module

            monkeypatch.setattr(cli.importlib, "import_module", fake_import)
            cli.main()
            assert imported["name"] == module_name
