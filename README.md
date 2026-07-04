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

- [Packet Sniffer](#packet-sniffer-netk-sniff) (`netk sniff`) — cross-platform packet capture that decodes and displays live traffic
- [Netcat](#netcat-netk-nc) (`netk nc`) — a netcat-style connect/listen tool
- [TCP Server](#tcp-server-netk-tcp-server) (`netk tcp-server`) — a minimal TCP server that ACKs whatever it receives
- [TCP Client](#tcp-client-netk-tcp-client) (`netk tcp-client`) — a bare-socket HTTP GET demo
- [TCP Proxy](#tcp-proxy-netk-tcp-proxy) (`netk tcp-proxy`) — an inspecting TCP proxy with hex-dump output
- [UDP Client](#udp-client-netk-udp-client) (`netk udp-client`) — a minimal UDP client demo
- [SSH Server](#ssh-server-netk-ssh-server) (`netk ssh-server`) — a minimal paramiko SSH server for reverse-shell demos
- [SSH Client](#ssh-client-netk-ssh-client) (`netk ssh-client`) — run a single command over SSH
- [SSH Reverse Shell](#ssh-reverse-shell-netk-ssh-revshell) (`netk ssh-revshell`) — the agent side of the SSH server's reverse shell

### Packet Sniffer (`netk sniff`)

A cross-platform packet capture utility that decodes and displays network traffic. Built with Python
using raw sockets — no third-party dependencies.

**Requirements:** root/Administrator privileges (required for raw sockets). On Linux, if you're not
already root the tool re-launches itself under `sudo` automatically. On Windows, run your terminal as
Administrator.

| Option | Short | Description |
|--------|-------|-------------|
| `--host` | `-H` | IP address to listen on (default: auto-detect) |
| `--count` | `-c` | Number of packets to capture (0 = unlimited) |
| `--protocol` | `-p` | Filter by protocol: `tcp`, `udp`, or `icmp` |
| `--port` | | Filter by port number (source or destination) |
| `--src-ip` | | Filter by source IP address |
| `--dst-ip` | | Filter by destination IP address |
| `--output` | `-o` | Output format: `human`, `json`, or `raw` (default: `human`) |
| `--hex` | `-x` | Include hex dump in human output |
| `--save` | `-s` | Save packets to a pcap file |
| `--quiet` | `-q` | Suppress per-packet output; only show statistics |
| `--no-stats` | | Do not print statistics on exit |
| `--interface` | `-i` | Network interface to capture on (Linux only, default: auto-detect) |
| `--version` | | Show version and exit |

```bash
netk sniff                            # capture continuously until Ctrl+C
netk sniff --count 10                 # capture exactly 10 packets then exit
netk sniff --protocol tcp --port 443 --hex   # HTTPS traffic with a hex dump
netk sniff --output json --count 5    # JSON output, useful for piping to jq
netk sniff --save capture.pcap --count 100   # save a capture for Wireshark
netk sniff --interface lo --port 3000 # capture a local dev server's traffic
```

Sample output:

```
[2026-01-26T10:30:45.123456] TCP 192.168.1.100:54321 -> 142.250.80.46:443
  Flags: [SYN] Seq: 123456789 Ack: 0 Win: 65535
  TTL: 64 ID: 12345 Len: 60
```

**Platform notes:** Linux uses `AF_PACKET` sockets and auto-detects the default interface from the
routing table; Windows uses `AF_INET` raw sockets with promiscuous mode (`SIO_RCVALL`) and binds to an
IP address rather than an interface name.

### Netcat (`netk nc`)

A netcat-style connect/listen tool.

| Option | Description |
|--------|-------------|
| `-t`, `--target` | Target IP (default: `192.168.1.108`) |
| `-p`, `--port` | Target/listen port (default: `5555`) |
| `-l`, `--listen` | Listen instead of connect |
| `-c`, `--command` | Serve an interactive command shell |
| `-e`, `--execute` | Execute one command and return its output |
| `-u`, `--upload` | Save the received stream to a file |

```bash
netk nc -t 192.168.1.108 -p 5555 -l -c              # command shell
netk nc -t 192.168.1.108 -p 5555 -l -u mytest.txt   # upload to a file
netk nc -t 192.168.1.108 -p 5555 -l -e "cat /etc/passwd"  # execute one command
echo 'ABC' | netk nc -t 192.168.1.108 -p 135         # send text to a port
netk nc -t 192.168.1.108 -p 5555                     # connect and chat interactively
```

### TCP Server (`netk tcp-server`)

A minimal TCP server for connectivity testing — no flags. Listens on `0.0.0.0:9998`, prints whatever
it receives, and replies `ACK`.

```bash
netk tcp-server
```

### TCP Client (`netk tcp-client`)

A bare-socket demo client — no flags. Connects to `www.google.com:80`, sends a raw HTTP `GET /`
request, and prints the response. Illustrates the socket calls behind an HTTP request without any
library abstracting them away.

```bash
netk tcp-client
```

### TCP Proxy (`netk tcp-proxy`)

An inspecting TCP proxy — useful for understanding unknown protocols, modifying traffic in flight, or
building test cases for fuzzers. Prints a hex dump of everything passing through in both directions.

```bash
netk tcp-proxy <local_host> <local_port> <remote_host> <remote_port> <receive_first>
netk tcp-proxy 127.0.0.1 9000 10.12.132.1 9000 True
```

`receive_first` (`True`/`False`) controls whether the proxy waits for the remote side to speak first
(e.g. a banner-based protocol) before forwarding the client's first message.

### UDP Client (`netk udp-client`)

A minimal UDP client demo — no flags. Sends `AAABBBCCC` to `127.0.0.1:9997` and prints whatever comes
back. There's no bundled UDP server to pair it with yet — see [ROADMAP.md](ROADMAP.md)'s v1.1.0
candidates.

```bash
netk udp-client
```

### SSH Server (`netk ssh-server`)

A minimal `paramiko`-based SSH server built to pair with `ssh-revshell` as a reverse-shell controller
— no flags yet. Currently hardcoded to listen on `192.168.1.207:2222` with a single login
(`brett`/`sekret`); edit `src/network_toolkit/ssh/server.py` to change either for your own network
(a CLI flag for this is a good `v1.1.0` candidate).

Needs an RSA host key at `src/network_toolkit/ssh/test_rsa.key` (gitignored — generate your own, e.g.
`paramiko.RSAKey.generate(2048).write_private_key_file(...)`). Once a client connects and
authenticates, it prompts *you* interactively for commands to send to that client.

```bash
netk ssh-server
```

### SSH Client (`netk ssh-client`)

Runs a single command over SSH via `paramiko` and prints its output — no flags. Prompts interactively
for username, password, server IP (default `192.168.1.203`), port (default `2222`), and the command to
run (default `id`).

```bash
netk ssh-client
```

### SSH Reverse Shell (`netk ssh-revshell`)

The agent side of `ssh-server`'s reverse shell — run this on the machine you want to control remotely.
No flags; prompts for the controller's IP and port, uses your current OS username, and prompts for a
password. Once connected, it executes whatever commands the controller (`netk ssh-server`) sends until
it receives `exit`.

```bash
netk ssh-revshell
```

## Development

One root `pyproject.toml` covers the whole toolkit (`src/` layout, `pytest`, `ruff`, `mypy`):

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

This also installs the `netk` and `netsniff` console scripts into `.venv/bin/`. Each tool can also be
run directly as a module, e.g. `python -m network_toolkit.tcp.server` — useful during development
without reinstalling. See [ROADMAP.md](ROADMAP.md) for what's next.

## Why
These began as focused exercises in the networking and SSH layers — sockets, protocols, framing —
and are collected here as one readable reference toolkit rather than scattered one-off repos.

## Security & responsible use
These are educational, **authorized-use** tools — use them only on systems and networks you own or
have explicit permission to test. See [SECURITY.md](SECURITY.md).

## License
MIT © 2026 Brett Buskirk
