"""Deterministic conversation, TCP, DNS, and summary analysis."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from framecite.models import Capture, EvidenceRef, Finding, PacketRecord, endpoint

MAX_EVIDENCE = 8
ICMP_ERROR_TYPES = {3, 4, 5, 11, 12}


def _conversation_key(record: PacketRecord) -> tuple[str, tuple[str, int], tuple[str, int]] | None:
    if (
        record.protocol not in {"TCP", "UDP"}
        or record.src_ip is None
        or record.dst_ip is None
        or record.src_port is None
        or record.dst_port is None
    ):
        return None
    endpoints = sorted(((record.src_ip, record.src_port), (record.dst_ip, record.dst_port)))
    return record.protocol, endpoints[0], endpoints[1]


def conversation_id(record: PacketRecord) -> str | None:
    key = _conversation_key(record)
    if key is None:
        return None
    encoded = json.dumps(key, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return f"{record.protocol.lower()}-{hashlib.sha256(encoded).hexdigest()[:12]}"


def conversations(capture: Capture, protocol: str = "any") -> list[dict[str, Any]]:
    normalized = protocol.lower()
    if normalized not in {"any", "tcp", "udp"}:
        raise ValueError("protocol must be one of: any, tcp, udp.")

    grouped: dict[str, list[PacketRecord]] = defaultdict(list)
    for record in capture.records:
        identifier = conversation_id(record)
        if identifier is None:
            continue
        if normalized != "any" and record.protocol.lower() != normalized:
            continue
        grouped[identifier].append(record)

    result: list[dict[str, Any]] = []
    for identifier, records in sorted(grouped.items()):
        first = records[0]
        key = _conversation_key(first)
        assert key is not None
        _, left, right = key
        packet_numbers = [record.packet_number for record in records]
        result.append(
            {
                "conversation_id": identifier,
                "protocol": first.protocol,
                "endpoint_a": endpoint(left[0], left[1]),
                "endpoint_b": endpoint(right[0], right[1]),
                "packet_count": len(records),
                "bytes_on_wire": sum(record.length_bytes for record in records),
                "first_time_offset_us": records[0].time_offset_us,
                "last_time_offset_us": records[-1].time_offset_us,
                "evidence": {
                    "first_packet": packet_numbers[0],
                    "last_packet": packet_numbers[-1],
                    "sample_packets": packet_numbers[:MAX_EVIDENCE],
                },
            }
        )
    return result


def _evidence(records: Iterable[PacketRecord], observation: str) -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(record.packet_number, record.time_offset_us, observation)
        for record in list(records)[:MAX_EVIDENCE]
    )


def tcp_findings(capture: Capture, selected_conversation: str | None = None) -> list[Finding]:
    tcp_records = [
        record
        for record in capture.records
        if record.protocol == "TCP"
        and (selected_conversation is None or conversation_id(record) == selected_conversation)
    ]
    if selected_conversation is not None and not tcp_records:
        raise ValueError("conversation_id does not identify a TCP conversation in this capture.")

    findings: list[Finding] = []
    resets = [record for record in tcp_records if record.tcp_flags and "R" in record.tcp_flags]
    if resets:
        findings.append(
            Finding(
                "tcp-reset",
                "warning",
                f"{len(resets)} TCP reset packet(s) were observed.",
                _evidence(resets, "TCP RST flag is set."),
            )
        )

    zero_windows = [record for record in tcp_records if record.tcp_window == 0]
    if zero_windows:
        findings.append(
            Finding(
                "tcp-zero-window",
                "warning",
                f"{len(zero_windows)} TCP packet(s) advertised a zero receive window.",
                _evidence(zero_windows, "Advertised TCP receive window is zero."),
            )
        )

    syn_groups: dict[tuple[object, ...], list[PacketRecord]] = defaultdict(list)
    syn_ack_keys: set[tuple[object, ...]] = set()
    for record in tcp_records:
        flags = record.tcp_flags or ""
        forward = (record.src_ip, record.dst_ip, record.src_port, record.dst_port)
        reverse = (record.dst_ip, record.src_ip, record.dst_port, record.src_port)
        if "S" in flags and "A" not in flags:
            syn_groups[forward].append(record)
        elif "S" in flags and "A" in flags:
            syn_ack_keys.add(reverse)

    retries = [record for records in syn_groups.values() if len(records) > 1 for record in records]
    if retries:
        findings.append(
            Finding(
                "tcp-syn-repeat",
                "warning",
                "Repeated TCP SYN attempts were observed for one or more endpoint pairs.",
                _evidence(retries, "SYN without ACK repeats for the same four-tuple."),
                ("Capture duplication can resemble repeated SYN attempts.",),
            )
        )

    unanswered = [records[0] for key, records in syn_groups.items() if key not in syn_ack_keys]
    if unanswered:
        findings.append(
            Finding(
                "tcp-no-syn-ack",
                "warning",
                f"No matching SYN-ACK is present for {len(unanswered)} TCP connection attempt(s).",
                _evidence(
                    unanswered, "Initial SYN has no matching reverse SYN-ACK in the capture."
                ),
                ("Capture boundaries or asymmetric capture can hide the response.",),
            )
        )

    sequence_groups: dict[tuple[object, ...], list[PacketRecord]] = defaultdict(list)
    for record in tcp_records:
        if record.payload_length and record.tcp_sequence is not None:
            key = (
                record.src_ip,
                record.dst_ip,
                record.src_port,
                record.dst_port,
                record.tcp_sequence,
                record.payload_length,
            )
            sequence_groups[key].append(record)
    repeats = [
        record for records in sequence_groups.values() if len(records) > 1 for record in records
    ]
    if repeats:
        findings.append(
            Finding(
                "tcp-sequence-repeat",
                "warning",
                "Repeated TCP sequence ranges with equal payload lengths are present.",
                _evidence(repeats, "Direction, sequence number, and payload length repeat."),
                (
                    "This can indicate retransmission or duplicate capture; "
                    "payload is not inspected.",
                ),
            )
        )

    return sorted(findings, key=lambda finding: finding.rule_id)


def dns_findings(
    capture: Capture, qname: str | None = None
) -> tuple[list[Finding], dict[str, int]]:
    normalized_qname = qname.rstrip(".").lower() if qname else None
    dns_records = [
        record
        for record in capture.records
        if record.dns_id is not None
        and (normalized_qname is None or (record.dns_qname or "").lower() == normalized_qname)
    ]
    queries = [record for record in dns_records if record.dns_is_response is False]
    responses = [record for record in dns_records if record.dns_is_response is True]
    findings: list[Finding] = []

    errors = [record for record in responses if record.dns_rcode not in {None, 0}]
    if errors:
        findings.append(
            Finding(
                "dns-error-response",
                "warning",
                f"{len(errors)} DNS response(s) contain a non-zero response code.",
                _evidence(errors, "DNS response code is non-zero."),
            )
        )

    def transaction_key(record: PacketRecord, *, response: bool = False) -> tuple[object, ...]:
        normalized_name = (
            record.dns_qname.rstrip(".").lower() if record.dns_qname is not None else None
        )
        if response:
            source = (record.dst_ip, record.dst_port)
            destination = (record.src_ip, record.src_port)
        else:
            source = (record.src_ip, record.src_port)
            destination = (record.dst_ip, record.dst_port)
        return (
            record.protocol,
            record.dns_id,
            normalized_name,
            record.dns_qtype,
            source,
            destination,
        )

    response_keys = {transaction_key(record, response=True) for record in responses}
    unresolved = [record for record in queries if transaction_key(record) not in response_keys]
    if unresolved:
        findings.append(
            Finding(
                "dns-no-matching-response",
                "warning",
                f"No matching response is present for {len(unresolved)} DNS query packet(s).",
                _evidence(
                    unresolved, "DNS query has no reverse response with the same ID and name."
                ),
                ("Capture boundaries, packet loss, or asymmetric capture can hide responses.",),
            )
        )

    query_groups: dict[tuple[object, ...], list[PacketRecord]] = defaultdict(list)
    for record in queries:
        query_groups[transaction_key(record)].append(record)
    retries = [
        record for records in query_groups.values() if len(records) > 1 for record in records
    ]
    if retries:
        findings.append(
            Finding(
                "dns-query-repeat",
                "info",
                "Repeated identical DNS queries are present.",
                _evidence(retries, "DNS ID, name, source, and destination repeat."),
                ("Capture duplication can resemble a DNS retry.",),
            )
        )

    facts = {
        "dns_packets": len(dns_records),
        "queries": len(queries),
        "responses": len(responses),
    }
    return sorted(findings, key=lambda finding: finding.rule_id), facts


def summary_findings(capture: Capture) -> list[Finding]:
    findings = tcp_findings(capture)
    dns, _ = dns_findings(capture)
    findings.extend(dns)
    icmp_errors = [record for record in capture.records if record.icmp_type in ICMP_ERROR_TYPES]
    if icmp_errors:
        findings.append(
            Finding(
                "icmp-error",
                "warning",
                f"{len(icmp_errors)} ICMP error packet(s) were observed.",
                _evidence(icmp_errors, "ICMP type is an error-reporting type."),
            )
        )
    return sorted(findings, key=lambda finding: (finding.level != "warning", finding.rule_id))
