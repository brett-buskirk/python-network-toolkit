# Network Packet Sniffer

A cross-platform packet capture utility that decodes and displays network traffic. Built with Python using raw sockets — no third-party dependencies required.

## Features

- **Packet Decoding**: Parses IP, TCP, UDP, and ICMP headers with human-readable output
- **Filtering**: Filter by protocol, port, source IP, or destination IP
- **Multiple Output Formats**: Human-readable, JSON, or raw bytes
- **Pcap Export**: Save captures to pcap format for analysis in Wireshark
- **Statistics**: Track packet counts, bytes, protocols, and top talkers
- **Hex Dump**: Optional hex dump display for packet inspection
- **Cross-Platform**: Works on Linux and Windows
- **Auto-elevation**: On Linux, automatically re-runs under `sudo` if needed — just run `netsniff`

## Requirements

- Python 3.10+
- Root/Administrator privileges (required for raw sockets)

## Installation

```bash
pipx install network-packet-sniffer
```

Or with pip:

```bash
pip install network-packet-sniffer
```

## Usage

```bash
netsniff [options]
```

On Linux, if you are not already root the tool will automatically re-launch itself under `sudo` and prompt for your password. On Windows, run your terminal as Administrator.

### Options

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

### Examples

```bash
# Capture packets continuously until Ctrl+C
netsniff

# Capture exactly 10 packets then exit
netsniff --count 10

# Capture only TCP traffic
netsniff --protocol tcp

# Capture HTTP traffic (port 80)
netsniff --protocol tcp --port 80

# Capture HTTPS traffic with hex dump
netsniff --protocol tcp --port 443 --hex

# Output in JSON format (useful for scripting or piping to jq)
netsniff --output json --count 5

# Save a capture to a pcap file for Wireshark
netsniff --save capture.pcap --count 100

# Quiet mode — only show the statistics summary
netsniff --quiet --count 50

# Filter by a specific source IP
netsniff --src-ip 192.168.1.100

# Capture on a specific network interface
netsniff --interface eth0
```

### Capturing Localhost Traffic

To inspect traffic from a local development server, bind to the loopback interface:

```bash
# Capture all loopback traffic
netsniff --interface lo

# Capture traffic on a specific port (e.g. a dev server on port 3000)
netsniff --interface lo --port 3000

# Capture localhost API traffic on port 8080
netsniff --interface lo --port 8080 --protocol tcp

# Save localhost traffic to a pcap file
netsniff --interface lo --port 5174 --save localhost.pcap
```

## Sample Output

### Human-Readable (default)

```
[2026-01-26T10:30:45.123456] TCP 192.168.1.100:54321 -> 142.250.80.46:443
  Flags: [SYN] Seq: 123456789 Ack: 0 Win: 65535
  TTL: 64 ID: 12345 Len: 60

[2026-01-26T10:30:45.234567] TCP 142.250.80.46:443 -> 192.168.1.100:54321
  Flags: [SYN,ACK] Seq: 987654321 Ack: 123456790 Win: 65535
  TTL: 117 ID: 0 Len: 60
```

### JSON Output

```json
{"timestamp": "2026-01-26T10:30:45.123456", "version": 4, "header_length": 20, "ttl": 64, "protocol": 6, "protocol_name": "TCP", "src_ip": "192.168.1.100", "dst_ip": "142.250.80.46", "src_port": 54321, "dst_port": 443, "flag_names": ["SYN"], "raw_hex": "..."}
```

### Statistics Summary

```
============================================================
CAPTURE STATISTICS
============================================================
Duration: 10.25 seconds
Total packets: 150
Total bytes: 12450
Packets/sec: 14.63

Protocols:
  TCP: 120
  UDP: 25
  ICMP: 5

Top 5 Source IPs:
  192.168.1.100: 75
  142.250.80.46: 45
  8.8.8.8: 20
  192.168.1.1: 10

Top 5 Destination IPs:
  142.250.80.46: 80
  192.168.1.100: 50
  8.8.8.8: 15
  192.168.1.255: 5
============================================================
```

## Platform Notes

### Linux
- Uses `AF_PACKET` sockets to capture all IP traffic (TCP, UDP, ICMP)
- Supports interface selection with `--interface` (e.g., `eth0`, `lo`, `wlan0`)
- Auto-detects the default interface from the routing table
- Automatically re-runs under `sudo` if not already root

### Windows
- Requires running the terminal as Administrator
- Uses `AF_INET` raw sockets with promiscuous mode (`SIO_RCVALL`)
- Binds to an IP address rather than an interface name

## Development

Clone the repo and set up a virtual environment:

```bash
git clone https://github.com/brett-buskirk/network-packet-sniffer.git
cd network-packet-sniffer
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

### Running the test suite

The unit tests cover packet decoding, filtering, output formatting, and statistics. No root privileges or live network are required.

```bash
.venv/bin/pytest
```

### Local install testing

Before publishing to PyPI, verify the full install experience locally using one of the following approaches.

**Install directly from the project directory** (quickest):

```bash
pipx install .
netsniff --version
netsniff --count 5
```

To reinstall after making changes:

```bash
pipx install --force .
```

**Install from the built wheel** (closest to what PyPI users get):

```bash
pyproject-build
pipx install dist/network_packet_sniffer-0.1.0-py3-none-any.whl --force
```

**Dry run via TestPyPI** (full end-to-end without touching the real index):

```bash
twine upload --repository testpypi dist/*
pipx install --index-url https://test.pypi.org/simple/ network-packet-sniffer
```

TestPyPI ([test.pypi.org](https://test.pypi.org)) is a separate sandbox with its own account and API token.

## License

MIT License
