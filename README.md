# Python Network Toolkit

A hands-on collection of small, dependency-light networking tools written in Python — built to
understand the wire up close: packet capture, raw TCP/UDP clients and servers, a TCP proxy, and
SSH client / server / reverse-shell implementations.

## Tools

**Packet capture**
- [`packet-sniffer/`](packet-sniffer/) — cross-platform packet capture that decodes and displays live traffic.

**Netcat**
- [`netcat/`](netcat/) — a netcat-style connect/listen tool.

**TCP**
- [`tcp/server/`](tcp/server/) · [`tcp/client/`](tcp/client/) · [`tcp/proxy/`](tcp/proxy/) — a TCP server, client, and an inspecting proxy.

**UDP**
- [`udp/client/`](udp/client/) — a UDP client.

**SSH (Paramiko)**
- [`ssh/server/`](ssh/server/) · [`ssh/client/`](ssh/client/) · [`ssh/reverse-shell/`](ssh/reverse-shell/) — a minimal SSH server, a command-running client, and a reverse SSH channel.

## Why
These began as focused exercises in the networking and SSH layers — sockets, protocols, framing —
and are collected here as one readable reference toolkit rather than scattered one-off repos.

## Security & responsible use
These are educational, **authorized-use** tools — use them only on systems and networks you own or
have explicit permission to test. See [SECURITY.md](SECURITY.md).

## License
MIT © 2026 Brett Buskirk
