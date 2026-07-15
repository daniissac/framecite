"""Streaming PCAP ingestion into payload-free immutable records."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw
from scapy.utils import PcapReader

from framecite.models import Capture, PacketRecord, clean_text


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture_file:
        for chunk in iter(lambda: capture_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _question(dns: DNS) -> DNSQR | None:
    question = dns.qd
    if isinstance(question, list):
        question = question[0] if question else None
    return question if isinstance(question, DNSQR) else None


def _packet_record(packet: object, packet_number: int, first_timestamp: float) -> PacketRecord:
    timestamp = float(packet.time)  # type: ignore[attr-defined]
    layers: list[str] = []
    if packet.haslayer(Ether):  # type: ignore[attr-defined]
        layers.append("Ethernet")
    if packet.haslayer(Dot1Q):  # type: ignore[attr-defined]
        layers.append("VLAN")
    if packet.haslayer(IP):  # type: ignore[attr-defined]
        layers.append("IPv4")
    if packet.haslayer(IPv6):  # type: ignore[attr-defined]
        layers.append("IPv6")
    if packet.haslayer(TCP):  # type: ignore[attr-defined]
        layers.append("TCP")
    elif packet.haslayer(UDP):  # type: ignore[attr-defined]
        layers.append("UDP")
    elif packet.haslayer(ICMP):  # type: ignore[attr-defined]
        layers.append("ICMP")
    if packet.haslayer(DNS):  # type: ignore[attr-defined]
        layers.append("DNS")

    src_ip: str | None = None
    dst_ip: str | None = None
    if packet.haslayer(IP):  # type: ignore[attr-defined]
        src_ip = clean_text(packet[IP].src, 64)  # type: ignore[index]
        dst_ip = clean_text(packet[IP].dst, 64)  # type: ignore[index]
    elif packet.haslayer(IPv6):  # type: ignore[attr-defined]
        src_ip = clean_text(packet[IPv6].src, 64)  # type: ignore[index]
        dst_ip = clean_text(packet[IPv6].dst, 64)  # type: ignore[index]

    protocol = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    tcp_sequence: int | None = None
    tcp_acknowledgment: int | None = None
    tcp_window: int | None = None

    if packet.haslayer(TCP):  # type: ignore[attr-defined]
        protocol = "TCP"
        tcp = packet[TCP]  # type: ignore[index]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = clean_text(tcp.sprintf("%TCP.flags%"), 16)
        tcp_sequence = int(tcp.seq)
        tcp_acknowledgment = int(tcp.ack)
        tcp_window = int(tcp.window)
    elif packet.haslayer(UDP):  # type: ignore[attr-defined]
        protocol = "UDP"
        udp = packet[UDP]  # type: ignore[index]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
    elif packet.haslayer(ICMP):  # type: ignore[attr-defined]
        protocol = "ICMP"
    elif packet.haslayer(IPv6):  # type: ignore[attr-defined]
        protocol = "IPv6"
    elif packet.haslayer(IP):  # type: ignore[attr-defined]
        protocol = "IPv4"
    elif packet.haslayer(Ether):  # type: ignore[attr-defined]
        protocol = "ETHERNET"

    dns_id: int | None = None
    dns_is_response: bool | None = None
    dns_rcode: int | None = None
    dns_qname: str | None = None
    dns_qtype: int | None = None
    if packet.haslayer(DNS):  # type: ignore[attr-defined]
        dns = packet[DNS]  # type: ignore[index]
        dns_id = int(dns.id)
        dns_is_response = bool(dns.qr)
        dns_rcode = int(dns.rcode)
        question = _question(dns)
        if question is not None:
            raw_name = question.qname
            if isinstance(raw_name, bytes):
                raw_name = raw_name.decode("utf-8", errors="replace")
            dns_qname = clean_text(raw_name, 255).rstrip(".")
            dns_qtype = int(question.qtype)

    icmp_type: int | None = None
    icmp_code: int | None = None
    if packet.haslayer(ICMP):  # type: ignore[attr-defined]
        icmp = packet[ICMP]  # type: ignore[index]
        icmp_type = int(icmp.type)
        icmp_code = int(icmp.code)

    payload_length = 0
    if packet.haslayer(Raw):  # type: ignore[attr-defined]
        payload_length = len(bytes(packet[Raw].load))  # type: ignore[index]

    return PacketRecord(
        packet_number=packet_number,
        time_offset_us=max(0, round((timestamp - first_timestamp) * 1_000_000)),
        length_bytes=len(packet),  # type: ignore[arg-type]
        layers=tuple(layers),
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        tcp_sequence=tcp_sequence,
        tcp_acknowledgment=tcp_acknowledgment,
        tcp_window=tcp_window,
        dns_id=dns_id,
        dns_is_response=dns_is_response,
        dns_rcode=dns_rcode,
        dns_qname=dns_qname,
        dns_qtype=dns_qtype,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        payload_length=payload_length,
    )


def parse_capture(
    *,
    capture_id: str,
    path: Path,
    initial_stat: os.stat_result,
    max_packets: int,
) -> Capture:
    """Stream a capture once and retain only bounded, sanitized packet metadata."""

    records: list[PacketRecord] = []
    first_timestamp: float | None = None
    truncated = False

    try:
        with PcapReader(str(path)) as reader:
            for packet_number, packet in enumerate(reader, start=1):
                if packet_number > max_packets:
                    truncated = True
                    break
                timestamp = float(packet.time)
                if first_timestamp is None:
                    first_timestamp = timestamp
                records.append(_packet_record(packet, packet_number, first_timestamp))
    except (EOFError, OSError, Scapy_Exception, ValueError) as exc:
        raise ValueError("Capture could not be parsed as PCAP or PCAPNG.") from exc

    try:
        final_stat = path.stat()
    except OSError as exc:
        raise ValueError("Capture changed or became unavailable while being read.") from exc

    initial_identity = (
        initial_stat.st_dev,
        initial_stat.st_ino,
        initial_stat.st_size,
        initial_stat.st_mtime_ns,
    )
    final_identity = (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_size,
        final_stat.st_mtime_ns,
    )
    if initial_identity != final_identity:
        raise ValueError("Capture changed while being read; retry with a stable file.")

    sha256 = _file_sha256(path)
    try:
        hashed_stat = path.stat()
    except OSError as exc:
        raise ValueError("Capture changed or became unavailable while being hashed.") from exc
    hashed_identity = (
        hashed_stat.st_dev,
        hashed_stat.st_ino,
        hashed_stat.st_size,
        hashed_stat.st_mtime_ns,
    )
    if initial_identity != hashed_identity:
        raise ValueError("Capture changed while being hashed; retry with a stable file.")

    duration_us = records[-1].time_offset_us if records else 0
    return Capture(
        capture_id=capture_id,
        path=path,
        filename=path.name,
        sha256=sha256,
        size_bytes=final_stat.st_size,
        records=tuple(records),
        duration_us=duration_us,
        truncated=truncated,
    )
