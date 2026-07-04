"""Packet output formatting functions."""

import json


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Return a hex dump of *data* with ASCII representation."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{bytes_per_line * 3}} {ascii_part}")
    return "\n".join(lines)


def format_packet_human(
    packet_info: dict, raw_data: bytes, show_hex: bool = False
) -> str:
    """Return a human-readable string representation of a packet."""
    timestamp = packet_info.get("timestamp", "")
    src_ip = packet_info.get("src_ip", "?")
    dst_ip = packet_info.get("dst_ip", "?")
    protocol = packet_info.get("protocol_name", "?")

    summary = f"[{timestamp}] {protocol} {src_ip}"
    if "src_port" in packet_info:
        summary += f":{packet_info['src_port']}"
    summary += f" -> {dst_ip}"
    if "dst_port" in packet_info:
        summary += f":{packet_info['dst_port']}"

    lines = [summary]

    if protocol == "TCP" and "flag_names" in packet_info:
        flags = ",".join(packet_info["flag_names"]) or "none"
        lines.append(
            f"  Flags: [{flags}]"
            f" Seq: {packet_info.get('seq_num', '?')}"
            f" Ack: {packet_info.get('ack_num', '?')}"
            f" Win: {packet_info.get('window', '?')}"
        )
    elif protocol == "ICMP" and "type_name" in packet_info:
        lines.append(
            f"  Type: {packet_info['type_name']} Code: {packet_info.get('code', '?')}"
        )
    elif protocol == "UDP":
        lines.append(f"  Length: {packet_info.get('length', '?')}")

    lines.append(
        f"  TTL: {packet_info.get('ttl', '?')}"
        f" ID: {packet_info.get('identification', '?')}"
        f" Len: {packet_info.get('total_length', '?')}"
    )

    if show_hex:
        lines.append("")
        lines.append(format_hex_dump(raw_data))

    return "\n".join(lines)


def format_packet_json(packet_info: dict, raw_data: bytes) -> str:
    """Return a JSON string representation of a packet."""
    output = packet_info.copy()
    output["raw_hex"] = raw_data.hex()
    return json.dumps(output)
