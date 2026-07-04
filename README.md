# Python Network Toolkit

A hands-on collection of small, dependency-light networking tools written in Python — built to
understand the wire up close: packet capture, raw TCP/UDP clients and servers, a TCP proxy, and
SSH client / server / reverse-shell implementations.

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

A unified `netk` CLI exposing every tool as a subcommand is planned for v0.2.0 — see
[ROADMAP.md](ROADMAP.md). For now each tool is run as a module, e.g.
`python -m network_toolkit.tcp.server`, or via the packet sniffer's own `netsniff` console script.

## Why
These began as focused exercises in the networking and SSH layers — sockets, protocols, framing —
and are collected here as one readable reference toolkit rather than scattered one-off repos.

## Security & responsible use
These are educational, **authorized-use** tools — use them only on systems and networks you own or
have explicit permission to test. See [SECURITY.md](SECURITY.md).

## License
MIT © 2026 Brett Buskirk
