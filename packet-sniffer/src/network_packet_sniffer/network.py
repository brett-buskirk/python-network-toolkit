"""Raw socket creation and network interface utilities."""

import os
import socket


def get_local_ip() -> str:
    """Detect and return the local machine's primary IP address."""
    # Method 1: connect to an external host (no data sent) to discover the
    # outgoing interface's IP.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "0.0.0.0":
            return ip
    except Exception:
        pass

    # Method 2: hostname-based lookup.
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass

    # Method 3: fall back to loopback.
    return "127.0.0.1"


def get_default_interface() -> str:
    """Return the default network interface name (Linux only)."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == "00000000":  # default route destination
                    return parts[0]
    except Exception:
        pass
    return "eth0"


def create_sniffer_socket(host: str, interface: str = None) -> tuple:
    """Create a raw socket suitable for packet sniffing.

    Returns:
        A ``(socket, has_ethernet_header)`` tuple.  The boolean indicates
        whether received frames include a 14-byte Ethernet header that must
        be stripped before parsing the IP layer (Linux ``AF_PACKET``).

    Raises:
        OSError: If the socket cannot be created or bound.
        PermissionError: If the process lacks the necessary privileges.
    """
    if os.name == "nt":
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        try:
            sniffer.bind((host, 0))
        except OSError as e:
            sniffer.close()
            if e.errno == 99:
                raise OSError(
                    f"Cannot bind to address '{host}'. "
                    "Use --host to specify a valid local IP address, or try:\n"
                    "  --host 0.0.0.0    (listen on all interfaces)\n"
                    "  --host 127.0.0.1  (localhost only)\n"
                    "Run 'ipconfig' to see available addresses."
                ) from None
            raise
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return sniffer, False

    # Linux: AF_PACKET captures full Ethernet frames.
    ETH_P_IP = 0x0800
    sniffer = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP)
    )
    iface = interface or get_default_interface()
    sniffer.bind((iface, 0))
    return sniffer, True  # caller must strip the 14-byte Ethernet header


def cleanup_socket(sniffer: socket.socket) -> None:
    """Disable promiscuous mode (Windows) and close the socket."""
    if os.name == "nt":
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
    sniffer.close()
