"""Sanitized capture records and evidence-bearing findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


def clean_text(value: object, limit: int = 255) -> str:
    """Strip controls and bound decoded, capture-controlled metadata."""

    text = str(value)
    cleaned = "".join(character for character in text if character.isprintable())
    return cleaned.strip()[:limit]


def endpoint(address: str | None, port: int | None) -> str | None:
    if address is None:
        return None
    if port is None:
        return address
    separator = "]:" if ":" in address else ":"
    prefix = "[" if ":" in address else ""
    return f"{prefix}{address}{separator}{port}"


@dataclass(frozen=True, slots=True)
class PacketRecord:
    packet_number: int
    time_offset_us: int
    captured_length_bytes: int
    wire_length_bytes: int
    layers: tuple[str, ...]
    protocol: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    tcp_sequence: int | None = None
    tcp_acknowledgment: int | None = None
    tcp_window: int | None = None
    dns_id: int | None = None
    dns_is_response: bool | None = None
    dns_rcode: int | None = None
    dns_qname_token: str | None = None
    dns_qname_length: int | None = None
    dns_qname_labels: int | None = None
    dns_qtype: int | None = None
    dns_qclass: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_version: int | None = None
    payload_length: int = 0

    def public(self) -> dict[str, Any]:
        """Return only allowlisted headers; raw payload is never retained or returned."""

        details: dict[str, Any] = {}
        if self.tcp_flags is not None:
            details["tcp"] = {
                "flags": self.tcp_flags,
                "sequence": self.tcp_sequence,
                "acknowledgment": self.tcp_acknowledgment,
                "window": self.tcp_window,
            }
        if self.dns_id is not None:
            details["dns"] = {
                "id": self.dns_id,
                "is_response": self.dns_is_response,
                "rcode": self.dns_rcode,
                "qname": (
                    {
                        "redacted": True,
                        "token": self.dns_qname_token,
                        "length_chars": self.dns_qname_length,
                        "label_count": self.dns_qname_labels,
                    }
                    if self.dns_qname_token is not None
                    else None
                ),
                "qtype": self.dns_qtype,
                "qclass": self.dns_qclass,
            }
        if self.icmp_type is not None:
            details["icmp"] = {
                "version": self.icmp_version,
                "type": self.icmp_type,
                "code": self.icmp_code,
            }

        return {
            "packet_number": self.packet_number,
            "time_offset_us": self.time_offset_us,
            "captured_length_bytes": self.captured_length_bytes,
            "wire_length_bytes": self.wire_length_bytes,
            "layers": list(self.layers),
            "protocol": self.protocol,
            "source": endpoint(self.src_ip, self.src_port),
            "destination": endpoint(self.dst_ip, self.dst_port),
            "details": details,
            "payload": {"redacted": True, "length_bytes": self.payload_length},
        }


@dataclass(frozen=True, slots=True)
class Capture:
    capture_id: str
    path: Path
    filename: str
    sha256: str
    size_bytes: int
    records: tuple[PacketRecord, ...]
    duration_us: int
    timestamp_regressions: int
    truncated: bool

    def manifest(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        endpoints: set[str] = set()
        for record in self.records:
            counts[record.protocol] = counts.get(record.protocol, 0) + 1
            if record.src_ip:
                endpoints.add(record.src_ip)
            if record.dst_ip:
                endpoints.add(record.dst_ip)
        return {
            "capture_id": self.capture_id,
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "packet_count": len(self.records),
            "duration_us": self.duration_us,
            "timestamp_regressions": self.timestamp_regressions,
            "protocol_counts": dict(sorted(counts.items())),
            "endpoint_count": len(endpoints),
            "payloads_redacted": True,
            "packet_limit_reached": self.truncated,
        }

    def packet(self, packet_number: int) -> PacketRecord:
        if packet_number < 1 or packet_number > len(self.records):
            raise ValueError("packet_number is outside the loaded capture range.")
        return self.records[packet_number - 1]


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    packet_number: int
    time_offset_us: int
    observation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_number": self.packet_number,
            "time_offset_us": self.time_offset_us,
            "observation": self.observation,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    level: str
    conclusion: str
    evidence: tuple[EvidenceRef, ...]
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("Every finding must cite at least one packet.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "level": self.level,
            "conclusion": self.conclusion,
            "evidence": [item.to_dict() for item in self.evidence],
            "limitations": list(self.limitations),
            "method": "deterministic",
        }
