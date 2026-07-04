"""Unified `netk` CLI — dispatches to each tool as a subcommand."""

import importlib
import sys

# subcommand -> (module to dispatch to, one-line description)
SUBCOMMANDS = {
    "sniff": ("network_packet_sniffer.cli", "capture and decode live network traffic"),
    "nc": ("network_toolkit.netcat", "netcat-style connect/listen tool"),
    "tcp-server": ("network_toolkit.tcp.server", "a basic TCP server"),
    "tcp-client": ("network_toolkit.tcp.client", "a basic TCP client"),
    "tcp-proxy": ("network_toolkit.tcp.proxy", "an inspecting TCP proxy"),
    "udp-client": ("network_toolkit.udp.client", "a basic UDP client"),
    "ssh-server": ("network_toolkit.ssh.server", "a minimal SSH server (paramiko)"),
    "ssh-client": ("network_toolkit.ssh.client", "run a command over SSH (paramiko)"),
    "ssh-revshell": ("network_toolkit.ssh.reverse_shell", "SSH reverse-shell agent (paramiko)"),
}


def _print_usage(file=None):
    if file is None:
        file = sys.stdout
    print("usage: netk <subcommand> [args...]", file=file)
    print(file=file)
    print("subcommands:", file=file)
    width = max(len(name) for name in SUBCOMMANDS)
    for name, (_, description) in SUBCOMMANDS.items():
        print(f"  {name:<{width}}  {description}", file=file)


def main() -> None:
    argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        _print_usage()
        return

    subcommand, rest = argv[0], argv[1:]

    if subcommand not in SUBCOMMANDS:
        print(f"netk: unknown subcommand '{subcommand}'\n", file=sys.stderr)
        _print_usage(file=sys.stderr)
        sys.exit(2)

    module_name, _ = SUBCOMMANDS[subcommand]
    module = importlib.import_module(module_name)

    if subcommand == "sniff":
        # network_packet_sniffer.cli.main() already accepts an argv list, and its
        # own sudo re-exec reads raw sys.argv -- leave sys.argv untouched so that
        # re-exec reconstructs the full `netk sniff ...` invocation correctly.
        module.main(rest)
    else:
        # These tools' main() functions read sys.argv directly (or ignore args
        # entirely) -- rewrite argv[0] so they see exactly what they'd see run
        # standalone.
        sys.argv = [f"netk {subcommand}"] + rest
        module.main()


if __name__ == "__main__":
    main()
