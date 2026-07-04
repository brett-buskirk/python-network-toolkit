# Python Network Toolkit

A hands-on collection of small, dependency-light networking tools written in Python — built to
understand the wire up close: packet capture, raw TCP/UDP clients and servers, a TCP proxy, and
SSH client / server / reverse-shell implementations.

## Usage

Every tool is exposed as a subcommand of the unified `netk` CLI:

```bash
netk --help              # list every subcommand
netk sniff --count 10    # capture 10 packets
netk nc -l -p 5555       # netcat-style listener
netk tcp-proxy 127.0.0.1 9000 10.0.0.5 9000 False
```

`netk <subcommand> --help` forwards to that tool's own help. Tools with no CLI flags yet
(`tcp-client`, `udp-client`, `ssh-server`, `ssh-client`, `ssh-revshell`) just run with `netk <name>`.

## Tools

**Packet capture**
- [`src/network_packet_sniffer/`](src/network_packet_sniffer/) ([docs](docs/packet-sniffer.md)) — cross-platform packet capture that decodes and displays live traffic.

**Netcat**
- [`src/network_toolkit/netcat.py`](src/network_toolkit/netcat.py) ([docs](docs/netcat.md)) — a netcat-style connect/listen tool.

**TCP**
- [`src/network_toolkit/tcp/`](src/network_toolkit/tcp/) — a TCP server ([docs](docs/tcp-server.md)), client ([docs](docs/tcp-client.md)), and an inspecting proxy ([docs](docs/tcp-proxy.md)).

**UDP**
- [`src/network_toolkit/udp/`](src/network_toolkit/udp/) ([docs](docs/udp-client.md)) — a UDP client.

**SSH (Paramiko)**
- [`src/network_toolkit/ssh/`](src/network_toolkit/ssh/) — a minimal SSH server ([docs](docs/ssh-server.md)), a command-running client ([docs](docs/ssh-client.md)), and a reverse SSH channel ([docs](docs/ssh-reverse-shell.md)).

## Development

One root `pyproject.toml` covers the whole toolkit (`src/` layout, `pytest`, `ruff`, `mypy`):

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

This also installs the `netk` and `netsniff` console scripts into `.venv/bin/`. Each tool can also be
run directly as a module, e.g. `python -m network_toolkit.tcp.server` — useful during development
without reinstalling. See [ROADMAP.md](ROADMAP.md) for what's next (v0.3.0's shared argument-parsing
library, which will give every tool the same flag conventions `netk` currently just passes through).

## Why
These began as focused exercises in the networking and SSH layers — sockets, protocols, framing —
and are collected here as one readable reference toolkit rather than scattered one-off repos.

## Security & responsible use
These are educational, **authorized-use** tools — use them only on systems and networks you own or
have explicit permission to test. See [SECURITY.md](SECURITY.md).

## License
MIT © 2026 Brett Buskirk
