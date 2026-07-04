"""Shared socket and output helpers used by more than one tool."""

import socket


def create_tcp_listener(host: str, port: int, backlog: int = 5, reuse_addr: bool = True) -> socket.socket:
    """Create, bind, and start listening on a TCP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if reuse_addr:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(backlog)
    return sock


def create_tcp_client(host: str, port: int) -> socket.socket:
    """Create a TCP socket and connect it to (host, port)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Return a hex dump of *data* with ASCII representation."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{bytes_per_line * 3}} {ascii_part}")
    return "\n".join(lines)
