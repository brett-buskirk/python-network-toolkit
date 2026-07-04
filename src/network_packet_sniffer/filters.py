"""Packet filtering logic."""


def matches_filter(
    packet_info: dict,
    *,
    protocol: str = None,
    port: int = None,
    src_ip: str = None,
    dst_ip: str = None,
) -> bool:
    """Return True if *packet_info* satisfies all of the supplied filter criteria.

    All parameters are optional; omitting one means that criterion is not applied.

    Args:
        packet_info: Decoded packet dictionary from :func:`decode.decode_packet`.
        protocol:    Case-insensitive protocol name to match (e.g. ``"tcp"``).
        port:        Port number that must appear as either src or dst port.
        src_ip:      Source IP address that must match exactly.
        dst_ip:      Destination IP address that must match exactly.
    """
    if protocol is not None:
        if protocol.upper() != packet_info.get("protocol_name", "").upper():
            return False

    if port is not None:
        if packet_info.get("src_port") != port and packet_info.get("dst_port") != port:
            return False

    if src_ip is not None:
        if packet_info.get("src_ip") != src_ip:
            return False

    if dst_ip is not None:
        if packet_info.get("dst_ip") != dst_ip:
            return False

    return True
