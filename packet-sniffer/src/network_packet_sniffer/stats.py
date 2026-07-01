"""Packet capture statistics tracking."""

import time
from collections import defaultdict


class PacketStats:
    """Track and summarize packet capture statistics."""

    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols: dict = defaultdict(int)
        self.source_ips: dict = defaultdict(int)
        self.dest_ips: dict = defaultdict(int)
        self.ports: dict = defaultdict(int)
        self.start_time: float | None = None
        self.end_time: float | None = None

    def update(self, packet_info: dict, raw_length: int) -> None:
        """Update statistics with a newly captured packet."""
        if self.start_time is None:
            self.start_time = time.time()
        self.end_time = time.time()

        self.total_packets += 1
        self.total_bytes += raw_length

        if "protocol_name" in packet_info:
            self.protocols[packet_info["protocol_name"]] += 1
        if "src_ip" in packet_info:
            self.source_ips[packet_info["src_ip"]] += 1
        if "dst_ip" in packet_info:
            self.dest_ips[packet_info["dst_ip"]] += 1
        if "src_port" in packet_info:
            self.ports[packet_info["src_port"]] += 1
        if "dst_port" in packet_info:
            self.ports[packet_info["dst_port"]] += 1

    def summary(self) -> str:
        """Return a formatted summary of captured statistics."""
        duration = (
            (self.end_time - self.start_time)
            if self.start_time and self.end_time
            else 0
        )

        lines = [
            "\n" + "=" * 60,
            "CAPTURE STATISTICS",
            "=" * 60,
            f"Duration: {duration:.2f} seconds",
            f"Total packets: {self.total_packets}",
            f"Total bytes: {self.total_bytes}",
            f"Packets/sec: {self.total_packets / duration:.2f}"
            if duration > 0
            else "Packets/sec: N/A",
            "",
            "Protocols:",
        ]

        for proto, count in sorted(
            self.protocols.items(), key=lambda x: x[1], reverse=True
        ):
            lines.append(f"  {proto}: {count}")

        lines.append("")
        lines.append("Top 5 Source IPs:")
        for ip, count in sorted(
            self.source_ips.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            lines.append(f"  {ip}: {count}")

        lines.append("")
        lines.append("Top 5 Destination IPs:")
        for ip, count in sorted(
            self.dest_ips.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            lines.append(f"  {ip}: {count}")

        lines.append("=" * 60)

        return "\n".join(lines)
