"""Protocol constants for packet decoding."""

# IP protocol numbers → name
PROTOCOLS: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# ICMP type codes → description
ICMP_TYPES: dict[int, str] = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}

# TCP flag bitmasks → name
TCP_FLAGS: dict[int, str] = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}
