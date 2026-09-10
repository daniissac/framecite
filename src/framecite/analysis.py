"""Deterministic conversation, TCP, DNS, and summary analysis."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from itertools import pairwise
from typing import Any

from framecite.models import Capture, EvidenceRef, Finding, PacketRecord, endpoint

MAX_EVIDENCE = 8

ICMP_CATEGORIES = {
    (4, 3): ("icmp-destination-unreachable", "ICMPv4 destination unreachable", "warning"),
    (4, 4): ("icmp-source-quench", "deprecated ICMPv4 source quench", "info"),
    (4, 5): ("icmp-redirect", "ICMPv4 redirect", "info"),
    (4, 11): ("icmp-time-exceeded", "ICMPv4 time exceeded", "warning"),
    (4, 12): ("icmp-parameter-problem", "ICMPv4 parameter problem", "warning"),
    (6, 1): ("icmpv6-destination-unreachable", "ICMPv6 destination unreachable", "warning"),
    (6, 2): ("icmpv6-packet-too-big", "ICMPv6 packet too big", "warning"),
    (6, 3): ("icmpv6-time-exceeded", "ICMPv6 time exceeded", "warning"),
    (6, 4): ("icmpv6-parameter-problem", "ICMPv6 parameter problem", "warning"),
}

ICMP_CODE_NAMES = {
    (4, 3, 0): "network unreachable",
    (4, 3, 1): "host unreachable",
    (4, 3, 2): "protocol unreachable",
    (4, 3, 3): "port unreachable",
    (4, 3, 4): "fragmentation needed",
    (4, 3, 9): "network administratively prohibited",
    (4, 3, 10): "host administratively prohibited",
    (4, 3, 13): "communication administratively prohibited",
    (4, 11, 0): "TTL expired in transit",
    (4, 11, 1): "fragment reassembly time exceeded",
    (6, 1, 0): "no route to destination",
    (6, 1, 1): "communication administratively prohibited",
    (6, 1, 3): "address unreachable",
    (6, 1, 4): "port unreachable",
    (6, 3, 0): "hop limit exceeded in transit",
    (6, 3, 1): "fragment reassembly time exceeded",
}


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
        a_to_b = [
            record
            for record in records
            if (record.src_ip, record.src_port) == left
            and (record.dst_ip, record.dst_port) == right
        ]
        b_to_a = [
            record
            for record in records
            if (record.src_ip, record.src_port) == right
            and (record.dst_ip, record.dst_port) == left
        ]
        directionality = (
            "bidirectional" if a_to_b and b_to_a else "a_to_b_only" if a_to_b else "b_to_a_only"
        )
        result.append(
            {
                "conversation_id": identifier,
                "protocol": first.protocol,
                "endpoint_a": endpoint(left[0], left[1]),
                "endpoint_b": endpoint(right[0], right[1]),
                "packet_count": len(records),
                "captured_bytes": sum(record.captured_length_bytes for record in records),
                "wire_bytes": sum(record.wire_length_bytes for record in records),
                "packets_a_to_b": len(a_to_b),
                "packets_b_to_a": len(b_to_a),
                "wire_bytes_a_to_b": sum(record.wire_length_bytes for record in a_to_b),
                "wire_bytes_b_to_a": sum(record.wire_length_bytes for record in b_to_a),
                "directionality": directionality,
                "first_time_offset_us": min(record.time_offset_us for record in records),
                "last_time_offset_us": max(record.time_offset_us for record in records),
                "evidence": {
                    "first_packet": packet_numbers[0],
                    "last_packet": packet_numbers[-1],
                    "sample_packets": packet_numbers[:MAX_EVIDENCE],
                },
            }
        )
    return sorted(
        result,
        key=lambda row: (-row["wire_bytes"], row["first_time_offset_us"], row["conversation_id"]),
    )


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

    zero_windows = [
        record
        for record in tcp_records
        if record.tcp_window == 0 and "R" not in (record.tcp_flags or "")
    ]
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
    syn_ack_groups: dict[tuple[object, ...], list[PacketRecord]] = defaultdict(list)
    for record in tcp_records:
        flags = record.tcp_flags or ""
        forward = (record.src_ip, record.dst_ip, record.src_port, record.dst_port)
        reverse = (record.dst_ip, record.src_ip, record.dst_port, record.src_port)
        if "S" in flags and "A" not in flags:
            syn_groups[(*forward, record.tcp_sequence)].append(record)
        elif "S" in flags and "A" in flags:
            syn_ack_groups[reverse].append(record)

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

    used_syn_acks: set[int] = set()
    unanswered: list[PacketRecord] = []
    for key, records in sorted(syn_groups.items(), key=lambda item: item[1][0].packet_number):
        four_tuple = key[:4]
        sequence = key[4]
        expected_ack = ((int(sequence) + 1) & 0xFFFFFFFF) if sequence is not None else None
        matching = next(
            (
                candidate
                for candidate in syn_ack_groups.get(four_tuple, [])
                if candidate.packet_number > records[0].packet_number
                and candidate.packet_number not in used_syn_acks
                and candidate.tcp_acknowledgment == expected_ack
            ),
            None,
        )
        if matching is None:
            unanswered.append(records[0])
        else:
            used_syn_acks.add(matching.packet_number)
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
    capture: Capture, qname_token: str | None = None
) -> tuple[list[Finding], dict[str, int]]:
    dns_records = [
        record
        for record in capture.records
        if record.dns_id is not None
        and (qname_token is None or record.dns_qname_token == qname_token)
    ]
    queries = [record for record in dns_records if record.dns_is_response is False]
    responses = [record for record in dns_records if record.dns_is_response is True]
    multicast_dns = [
        record for record in dns_records if record.src_port == 5353 or record.dst_port == 5353
    ]
    analyzable_queries = [record for record in queries if record not in multicast_dns]
    analyzable_responses = [record for record in responses if record not in multicast_dns]
    findings: list[Finding] = []

    errors = [record for record in analyzable_responses if record.dns_rcode not in {None, 0}]
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
        if response:
            source = (record.dst_ip, record.dst_port)
            destination = (record.src_ip, record.src_port)
        else:
            source = (record.src_ip, record.src_port)
            destination = (record.dst_ip, record.dst_port)
        return (
            record.protocol,
            record.dns_id,
            record.dns_qname_token,
            record.dns_qtype,
            record.dns_qclass,
            source,
            destination,
        )

    responses_by_key: dict[tuple[object, ...], list[PacketRecord]] = defaultdict(list)
    for response in analyzable_responses:
        responses_by_key[transaction_key(response, response=True)].append(response)

    unresolved: list[PacketRecord] = []
    matched: list[tuple[PacketRecord, PacketRecord]] = []
    for query in analyzable_queries:
        matching = next(
            (
                response
                for response in responses_by_key.get(transaction_key(query), [])
                if response.packet_number > query.packet_number
            ),
            None,
        )
        if matching is None:
            unresolved.append(query)
        else:
            matched.append((query, matching))
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
    for record in analyzable_queries:
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

    response_times = [response.time_offset_us - query.time_offset_us for query, response in matched]
    timing_reliable = capture.timestamp_regressions == 0
    facts = {
        "dns_packets": len(dns_records),
        "queries": len(queries),
        "responses": len(responses),
        "multicast_dns_packets": len(multicast_dns),
        "matched_queries": len(matched),
        "timing_reliable": timing_reliable,
        "response_time_min_us": min(response_times) if response_times and timing_reliable else None,
        "response_time_max_us": max(response_times) if response_times and timing_reliable else None,
        "response_time_average_us": (
            round(sum(response_times) / len(response_times))
            if response_times and timing_reliable
            else None
        ),
    }
    return sorted(findings, key=lambda finding: finding.rule_id), facts


def icmp_findings(capture: Capture) -> list[Finding]:
    """Classify ICMP path signals without inferring their originating flow."""

    grouped: dict[str, list[PacketRecord]] = defaultdict(list)
    metadata: dict[str, tuple[str, str]] = {}
    for record in capture.records:
        category = ICMP_CATEGORIES.get((record.icmp_version, record.icmp_type))
        if category is None:
            continue
        rule_id, label, level = category
        if rule_id == "icmp-destination-unreachable" and record.icmp_code == 4:
            rule_id, label = "icmp-fragmentation-needed", "ICMPv4 fragmentation needed"
        grouped[rule_id].append(record)
        metadata[rule_id] = (label, level)

    findings: list[Finding] = []
    for rule_id, records in sorted(grouped.items()):
        label, level = metadata[rule_id]
        evidence_items: list[EvidenceRef] = []
        for record in records[:MAX_EVIDENCE]:
            code_name = ICMP_CODE_NAMES.get(
                (record.icmp_version, record.icmp_type, record.icmp_code),
                f"code {record.icmp_code}",
            )
            evidence_items.append(
                EvidenceRef(record.packet_number, record.time_offset_us, f"{label}; {code_name}.")
            )
        findings.append(
            Finding(
                rule_id,
                level,
                f"{len(records)} {label} packet(s) were observed.",
                tuple(evidence_items),
                ("The quoted originating flow is not correlated by this rule.",),
            )
        )
    return findings


def capture_quality_findings(capture: Capture) -> list[Finding]:
    """Report capture defects that can limit downstream troubleshooting."""

    findings: list[Finding] = []
    shortened = [
        record
        for record in capture.records
        if record.captured_length_bytes < record.wire_length_bytes
    ]
    if shortened:
        findings.append(
            Finding(
                "capture-short-frame",
                "warning",
                f"{len(shortened)} packet(s) were shorter in the capture than on the wire.",
                _evidence(shortened, "Captured length is smaller than original wire length."),
                ("Headers or data beyond the snapshot length are unavailable.",),
            )
        )

    regressions = [
        current
        for previous, current in pairwise(capture.records)
        if current.time_offset_us < previous.time_offset_us
    ]
    if regressions:
        findings.append(
            Finding(
                "capture-timestamp-regression",
                "warning",
                f"Capture timestamps moved backward {len(regressions)} time(s).",
                _evidence(regressions, "Timestamp is earlier than the preceding packet."),
                ("Latency and ordering conclusions may be unreliable.",),
            )
        )

    if capture.truncated and capture.records:
        findings.append(
            Finding(
                "capture-packet-limit",
                "warning",
                "Analysis stopped at the operator-configured packet limit.",
                _evidence([capture.records[-1]], "This is the last retained packet."),
                ("Later packets are unavailable to every analyzer.",),
            )
        )
    return findings


def summary_findings(capture: Capture) -> list[Finding]:
    findings = tcp_findings(capture)
    dns, _ = dns_findings(capture)
    findings.extend(dns)
    findings.extend(icmp_findings(capture))
    findings.extend(capture_quality_findings(capture))
    return sorted(findings, key=lambda finding: (finding.level != "warning", finding.rule_id))
