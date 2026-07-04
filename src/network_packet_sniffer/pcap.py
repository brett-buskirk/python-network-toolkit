"""PCAP file writer for Wireshark-compatible packet capture files."""

import struct
import time


class PcapWriter:
    """Write packets in standard pcap format."""

    PCAP_MAGIC = 0xA1B2C3D4
    PCAP_VERSION_MAJOR = 2
    PCAP_VERSION_MINOR = 4
    PCAP_THISZONE = 0
    PCAP_SIGFIGS = 0
    PCAP_SNAPLEN = 65535
    PCAP_LINKTYPE = 101  # Raw IP

    def __init__(self, filename: str):
        self.filename = filename
        self.file = None

    def open(self) -> None:
        """Open the pcap file and write the global header."""
        self.file = open(self.filename, "wb")
        header = struct.pack(
            "<IHHIIII",
            self.PCAP_MAGIC,
            self.PCAP_VERSION_MAJOR,
            self.PCAP_VERSION_MINOR,
            self.PCAP_THISZONE,
            self.PCAP_SIGFIGS,
            self.PCAP_SNAPLEN,
            self.PCAP_LINKTYPE,
        )
        self.file.write(header)

    def write_packet(self, data: bytes, timestamp: float = None) -> None:
        """Write a single packet record to the pcap file."""
        if self.file is None:
            return

        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)

        packet_header = struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data))
        self.file.write(packet_header)
        self.file.write(data)

    def close(self) -> None:
        """Close the pcap file."""
        if self.file:
            self.file.close()
            self.file = None
