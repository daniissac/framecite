"""Streaming PCAP ingestion into payload-free immutable records."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import replace
from decimal import ROUND_HALF_EVEN, Decimal
from itertools import pairwise
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import NoPayload, Packet, Raw
from scapy.utils import PcapReader

from framecite.models import Capture, PacketRecord, clean_text

_PCAP_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
_PCAPNG_SECTION_TYPE = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}


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


def dns_qname_token(redaction_key: bytes, qname: str) -> str:
    """Return a session-local token that permits matching without exposing a DNS name."""

    normalized = clean_text(qname, 255).rstrip(".").lower().encode("utf-8")
    digest = hmac.new(redaction_key, normalized, hashlib.sha256).hexdigest()[:16]
    return f"dns-{digest}"


def _validate_pcap_structure(path: Path, endian: str) -> None:
    size = path.stat().st_size
    with path.open("rb") as capture_file:
        if len(capture_file.read(24)) != 24:
            raise ValueError("Classic PCAP global header is incomplete.")

        while capture_file.tell() < size:
            record_header = capture_file.read(16)
            if len(record_header) != 16:
                raise ValueError("Classic PCAP packet header is incomplete.")
            captured_length, wire_length = struct.unpack(f"{endian}II", record_header[8:16])
            if captured_length > wire_length:
                raise ValueError("Classic PCAP captured length exceeds the wire length.")
            if captured_length > size - capture_file.tell():
                raise ValueError("Classic PCAP packet data is incomplete.")
            capture_file.seek(captured_length, os.SEEK_CUR)


def _validate_pcapng_structure(path: Path) -> None:
    size = path.stat().st_size
    position = 0
    endian: str | None = None
    seen_section = False

    with path.open("rb") as capture_file:
        while position < size:
            capture_file.seek(position)
            header = capture_file.read(12)
            if len(header) != 12:
                raise ValueError("PCAPNG block header is incomplete.")

            block_type = header[:4]
            if block_type == _PCAPNG_SECTION_TYPE:
                try:
                    endian = _PCAPNG_BYTE_ORDER[header[8:12]]
                except KeyError as exc:
                    raise ValueError("PCAPNG section byte order is invalid.") from exc
                seen_section = True
            elif endian is None:
                raise ValueError("PCAPNG must begin with a section header block.")

            if endian is None:
                raise ValueError("PCAPNG section byte order is unavailable.")
            block_length = struct.unpack(f"{endian}I", header[4:8])[0]
            minimum_length = 28 if block_type == _PCAPNG_SECTION_TYPE else 12
            if block_length < minimum_length or block_length % 4:
                raise ValueError("PCAPNG block length is invalid.")
            if block_length > size - position:
                raise ValueError("PCAPNG block data is incomplete.")

            capture_file.seek(position + block_length - 4)
            trailing = capture_file.read(4)
            if len(trailing) != 4 or struct.unpack(f"{endian}I", trailing)[0] != block_length:
                raise ValueError("PCAPNG block lengths do not match.")
            position += block_length

    if not seen_section:
        raise ValueError("PCAPNG section header is missing.")


def _validate_capture_structure(path: Path) -> None:
    with path.open("rb") as capture_file:
        magic = capture_file.read(4)
    if magic in _PCAP_ENDIAN:
        _validate_pcap_structure(path, _PCAP_ENDIAN[magic])
    elif magic == _PCAPNG_SECTION_TYPE:
        _validate_pcapng_structure(path)
    else:
        raise ValueError("Capture magic is not PCAP or PCAPNG.")


def _layer_chain(packet: object) -> list[Packet]:
    chain: list[Packet] = []
    current = packet
    seen: set[int] = set()
    while isinstance(current, Packet) and not isinstance(current, NoPayload):
        identity = id(current)
        if identity in seen or len(chain) >= 256:
            break
        seen.add(identity)
        chain.append(current)
        current = current.payload
    return chain


def _direct_dns(transport: Packet | None) -> DNS | None:
    if not isinstance(transport, (TCP, UDP)):
        return None
    current = transport.payload
    for _ in range(8):
        if isinstance(current, DNS):
            return current
        if isinstance(current, (NoPayload, Raw, IP, IPv6, TCP, UDP, ICMP, _ICMPv6)):
            return None
        if not isinstance(current, Packet):
            return None
        current = current.payload
    return None


def _timestamp_ns(packet: object) -> int:
    timestamp = Decimal(str(packet.time))  # type: ignore[attr-defined]
    return int((timestamp * 1_000_000_000).to_integral_value(rounding=ROUND_HALF_EVEN))


def _packet_record(
    packet: object,
    packet_number: int,
    *,
    time_offset_us: int,
    redaction_key: bytes,
) -> PacketRecord:
    chain = _layer_chain(packet)
    transport = next(
        (layer for layer in chain if isinstance(layer, (TCP, UDP, ICMP, _ICMPv6))), None
    )
    transport_index = chain.index(transport) if transport is not None else len(chain)
    network = next(
        (layer for layer in reversed(chain[:transport_index]) if isinstance(layer, (IP, IPv6))),
        None,
    )
    if network is None:
        network = next((layer for layer in reversed(chain) if isinstance(layer, (IP, IPv6))), None)
    dns = _direct_dns(transport)

    layers: list[str] = []
    if any(isinstance(layer, Ether) for layer in chain):
        layers.append("Ethernet")
    if any(isinstance(layer, Dot1Q) for layer in chain):
        layers.append("VLAN")
    if any(isinstance(layer, IP) for layer in chain):
        layers.append("IPv4")
    if any(isinstance(layer, IPv6) for layer in chain):
        layers.append("IPv6")
    if isinstance(transport, TCP):
        layers.append("TCP")
    elif isinstance(transport, UDP):
        layers.append("UDP")
    elif isinstance(transport, ICMP):
        layers.append("ICMP")
    elif isinstance(transport, _ICMPv6):
        layers.append("ICMPv6")
    if dns is not None:
        layers.append("DNS")

    src_ip: str | None = None
    dst_ip: str | None = None
    if isinstance(network, (IP, IPv6)):
        src_ip = clean_text(network.src, 64)
        dst_ip = clean_text(network.dst, 64)

    protocol = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    tcp_sequence: int | None = None
    tcp_acknowledgment: int | None = None
    tcp_window: int | None = None

    if isinstance(transport, TCP):
        protocol = "TCP"
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        tcp_flags = clean_text(transport.sprintf("%TCP.flags%"), 16)
        tcp_sequence = int(transport.seq)
        tcp_acknowledgment = int(transport.ack)
        tcp_window = int(transport.window)
    elif isinstance(transport, UDP):
        protocol = "UDP"
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
    elif isinstance(transport, ICMP):
        protocol = "ICMP"
    elif isinstance(transport, _ICMPv6):
        protocol = "ICMPv6"
    elif isinstance(network, IPv6):
        protocol = "IPv6"
    elif isinstance(network, IP):
        protocol = "IPv4"
    elif any(isinstance(layer, Ether) for layer in chain):
        protocol = "ETHERNET"

    dns_id: int | None = None
    dns_is_response: bool | None = None
    dns_rcode: int | None = None
    dns_name_token: str | None = None
    dns_name_length: int | None = None
    dns_name_labels: int | None = None
    dns_qtype: int | None = None
    dns_qclass: int | None = None
    if dns is not None:
        dns_id = int(dns.id)
        dns_is_response = bool(dns.qr)
        dns_rcode = int(dns.rcode)
        question = _question(dns)
        if question is not None:
            raw_name = question.qname
            if isinstance(raw_name, bytes):
                raw_name = raw_name.decode("utf-8", errors="replace")
            safe_name = clean_text(raw_name, 255).rstrip(".")
            dns_name_token = dns_qname_token(redaction_key, safe_name)
            dns_name_length = len(safe_name)
            dns_name_labels = len([label for label in safe_name.split(".") if label])
            dns_qtype = int(question.qtype)
            dns_qclass = int(question.qclass)

    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_version: int | None = None
    if isinstance(transport, (ICMP, _ICMPv6)):
        icmp_type = int(transport.type)
        icmp_code = int(transport.code)
        icmp_version = 4 if isinstance(transport, ICMP) else 6

    payload_length = 0
    if transport is not None and not isinstance(transport.payload, NoPayload):
        payload_length = len(bytes(transport.payload))
    else:
        raw = next((layer for layer in chain if isinstance(layer, Raw)), None)
        if raw is not None:
            payload_length = len(bytes(raw.load))

    captured_length = len(packet)  # type: ignore[arg-type]
    raw_wire_length = getattr(packet, "wirelen", None)
    wire_length = int(raw_wire_length) if raw_wire_length is not None else captured_length
    wire_length = max(captured_length, wire_length)

    return PacketRecord(
        packet_number=packet_number,
        time_offset_us=time_offset_us,
        captured_length_bytes=captured_length,
        wire_length_bytes=wire_length,
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
        dns_qname_token=dns_name_token,
        dns_qname_length=dns_name_length,
        dns_qname_labels=dns_name_labels,
        dns_qtype=dns_qtype,
        dns_qclass=dns_qclass,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        icmp_version=icmp_version,
        payload_length=payload_length,
    )


def parse_capture(
    *,
    capture_id: str,
    path: Path,
    initial_stat: os.stat_result,
    max_packets: int,
    redaction_key: bytes,
) -> Capture:
    """Stream a capture once and retain only bounded, sanitized packet metadata."""

    timed_records: list[tuple[int, PacketRecord]] = []
    truncated = False

    try:
        _validate_capture_structure(path)
        with PcapReader(str(path)) as reader:
            for packet_number, packet in enumerate(reader, start=1):
                if packet_number > max_packets:
                    truncated = True
                    break
                timed_records.append(
                    (
                        _timestamp_ns(packet),
                        _packet_record(
                            packet,
                            packet_number,
                            time_offset_us=0,
                            redaction_key=redaction_key,
                        ),
                    )
                )
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

    if timed_records:
        timestamps = [timestamp for timestamp, _ in timed_records]
        earliest_timestamp = min(timestamps)
        records = tuple(
            replace(record, time_offset_us=(timestamp - earliest_timestamp) // 1_000)
            for timestamp, record in timed_records
        )
        duration_us = (max(timestamps) - earliest_timestamp) // 1_000
        timestamp_regressions = sum(
            current < previous for previous, current in pairwise(timestamps)
        )
    else:
        records = ()
        duration_us = 0
        timestamp_regressions = 0

    return Capture(
        capture_id=capture_id,
        path=path,
        filename=path.name,
        sha256=sha256,
        size_bytes=final_stat.st_size,
        records=records,
        duration_us=duration_us,
        timestamp_regressions=timestamp_regressions,
        truncated=truncated,
    )
