"""Command-line interface entry point for network-packet-sniffer."""

import argparse
import os
import signal
import socket
import sys

from . import __version__
from .decode import decode_packet
from .filters import matches_filter
from .network import cleanup_socket, create_sniffer_socket, get_default_interface, get_local_ip
from .output import format_packet_human, format_packet_json
from .pcap import PcapWriter
from .stats import PacketStats


def _check_privileges() -> None:
    """Ensure the process has the privileges needed to open raw sockets.

    On Linux: re-executes the current command under sudo automatically so the
    user never has to type ``sudo`` themselves.
    On Windows: prints an error and exits (automatic elevation requires a GUI
    UAC prompt which is impractical in a terminal tool).
    """
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Error: This program requires administrator privileges.", file=sys.stderr)
            print("Please run this terminal as Administrator.", file=sys.stderr)
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            # Re-exec the exact same command under sudo so the user never has
            # to figure out where pipx installed the binary.
            os.execvp("sudo", ["sudo", sys.argv[0]] + sys.argv[1:])


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsniff",
        description="Network Packet Sniffer — capture and analyze network traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netsniff                          # capture packets continuously
  netsniff --count 10               # capture 10 packets then exit
  netsniff --protocol tcp           # TCP packets only
  netsniff --port 80                # filter by port
  netsniff --output json            # JSON output
  netsniff --save capture.pcap      # save to pcap file
  netsniff --hex                    # include hex dump

Note: raw sockets require root. On Linux the tool re-runs itself under
sudo automatically, so you will see a password prompt if needed.
        """,
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument(
        "--host", "-H",
        help="IP address to listen on (default: auto-detect)",
    )
    parser.add_argument(
        "--count", "-c", type=int, default=0,
        help="number of packets to capture (0 = unlimited)",
    )
    parser.add_argument(
        "--protocol", "-p",
        choices=["tcp", "udp", "icmp", "TCP", "UDP", "ICMP"],
        help="filter by protocol",
    )
    parser.add_argument(
        "--port", type=int,
        help="filter by port number (source or destination)",
    )
    parser.add_argument("--src-ip", help="filter by source IP address")
    parser.add_argument("--dst-ip", help="filter by destination IP address")
    parser.add_argument(
        "--output", "-o",
        choices=["human", "json", "raw"], default="human",
        help="output format (default: human)",
    )
    parser.add_argument(
        "--hex", "-x", action="store_true",
        help="include hex dump in human output",
    )
    parser.add_argument("--save", "-s", help="save packets to a pcap file")
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="suppress per-packet output; only show statistics at end",
    )
    parser.add_argument(
        "--no-stats", action="store_true",
        help="do not print capture statistics on exit",
    )
    parser.add_argument(
        "--interface", "-i",
        help="network interface to capture on (Linux only; default: auto-detect)",
    )

    return parser


def main(argv=None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    _check_privileges()

    host = args.host or get_local_ip()

    stats = PacketStats()
    pcap_writer: PcapWriter | None = None
    sniffer: socket.socket | None = None
    running = True

    if args.save:
        pcap_writer = PcapWriter(args.save)
        pcap_writer.open()
        print(f"Saving packets to: {args.save}")

    def signal_handler(sig, frame):
        nonlocal running
        running = False
        print("\n\nInterrupted, stopping capture...")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        sniffer, has_eth_header = create_sniffer_socket(host, args.interface)
        eth_header_len = 14 if has_eth_header else 0

        if os.name == "nt":
            print(f"Sniffer started on {host}")
        else:
            iface = args.interface or get_default_interface()
            print(f"Sniffer started on interface {iface}")

        if args.count > 0:
            print(f"Capturing {args.count} packets...")
        else:
            print("Capturing packets (Press Ctrl+C to stop)...")

        if args.protocol:
            print(f"Filter: protocol={args.protocol.upper()}")
        if args.port:
            print(f"Filter: port={args.port}")
        if args.src_ip:
            print(f"Filter: src_ip={args.src_ip}")
        if args.dst_ip:
            print(f"Filter: dst_ip={args.dst_ip}")

        print("-" * 60)

        packets_captured = 0

        while running:
            if args.count > 0 and packets_captured >= args.count:
                break

            try:
                sniffer.settimeout(1.0)
                raw_data, _ = sniffer.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as exc:
                if running:
                    print(f"Error receiving packet: {exc}", file=sys.stderr)
                break

            ip_data = raw_data[eth_header_len:] if eth_header_len else raw_data
            packet_info = decode_packet(ip_data)

            if not matches_filter(
                packet_info,
                protocol=args.protocol,
                port=args.port,
                src_ip=args.src_ip,
                dst_ip=args.dst_ip,
            ):
                continue

            packets_captured += 1
            stats.update(packet_info, len(ip_data))

            if pcap_writer:
                pcap_writer.write_packet(ip_data)

            if not args.quiet:
                if args.output == "human":
                    print(format_packet_human(packet_info, ip_data, args.hex))
                    print()
                elif args.output == "json":
                    print(format_packet_json(packet_info, ip_data))
                elif args.output == "raw":
                    print(ip_data)
                    print()

    except PermissionError:
        print(
            "Error: Permission denied. Please run with elevated privileges.",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if sniffer:
            cleanup_socket(sniffer)
        if pcap_writer:
            pcap_writer.close()
            print(f"Packets saved to: {args.save}")
        if not args.no_stats and stats.total_packets > 0:
            print(stats.summary())
