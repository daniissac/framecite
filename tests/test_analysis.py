from __future__ import annotations

from dataclasses import replace

from framecite.analysis import (
    capture_quality_findings,
    conversations,
    dns_findings,
    icmp_findings,
    summary_findings,
    tcp_findings,
)
from framecite.config import Settings
from framecite.store import CaptureStore
from tests.factories import (
    write_dns_case_variant_pcap,
    write_dns_port_reuse_pcap,
    write_dns_response_before_query_pcap,
    write_dns_retry_then_response_pcap,
    write_icmp_path_signals_pcap,
    write_icmp_quoted_dns_pcap,
    write_icmpv6_error_pcap,
    write_mdns_pcap,
    write_tcp_rst_zero_window_pcap,
    write_tcp_syn_order_pcap,
    write_tcp_syn_repeat_pcap,
)

DNS_COUNT_KEYS = ("dns_packets", "queries", "responses", "multicast_dns_packets")


def dns_counts(facts: dict[str, object]) -> dict[str, object]:
    return {key: facts[key] for key in DNS_COUNT_KEYS}


def test_conversations_are_stable_and_packet_cited(loaded_capture) -> None:
    first = conversations(loaded_capture)
    second = conversations(loaded_capture)
    assert first == second
    assert first
    assert [item["wire_bytes"] for item in first] == sorted(
        (item["wire_bytes"] for item in first), reverse=True
    )
    for item in first:
        assert item["evidence"]["first_packet"] >= 1
        assert item["evidence"]["last_packet"] <= len(loaded_capture.records)
        assert item["evidence"]["sample_packets"]
        assert item["packets_a_to_b"] + item["packets_b_to_a"] == item["packet_count"]
        assert item["wire_bytes_a_to_b"] + item["wire_bytes_b_to_a"] == item["wire_bytes"]
        assert item["directionality"] in {"bidirectional", "a_to_b_only", "b_to_a_only"}


def test_tcp_rules_are_deterministic_and_evidence_linked(loaded_capture) -> None:
    findings = tcp_findings(loaded_capture)
    rule_ids = {finding.rule_id for finding in findings}
    assert {
        "tcp-no-syn-ack",
        "tcp-reset",
        "tcp-sequence-repeat",
        "tcp-zero-window",
    }.issubset(rule_ids)
    for finding in findings:
        assert finding.evidence
        assert all(1 <= evidence.packet_number <= 16 for evidence in finding.evidence)
        assert finding.to_dict()["method"] == "deterministic"


def test_tcp_evidence_satisfies_each_rule(loaded_capture) -> None:
    records = {record.packet_number: record for record in loaded_capture.records}
    by_rule = {finding.rule_id: finding for finding in tcp_findings(loaded_capture)}
    assert all(
        "R" in (records[item.packet_number].tcp_flags or "")
        for item in by_rule["tcp-reset"].evidence
    )
    assert all(
        records[item.packet_number].tcp_window == 0 for item in by_rule["tcp-zero-window"].evidence
    )


def test_tcp_syn_repeat_has_exact_synthetic_packet_evidence(capture_root) -> None:
    path = write_tcp_syn_repeat_pcap(capture_root / "tcp-syn-repeat.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    by_rule = {finding.rule_id: finding for finding in tcp_findings(capture)}

    assert [item.packet_number for item in by_rule["tcp-syn-repeat"].evidence] == [1, 2]
    assert [item.packet_number for item in by_rule["tcp-no-syn-ack"].evidence] == [1]


def test_tcp_rst_is_not_mislabeled_as_zero_window(capture_root) -> None:
    path = write_tcp_rst_zero_window_pcap(capture_root / "tcp-rst-window.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    by_rule = {finding.rule_id: finding for finding in tcp_findings(capture)}

    assert [item.packet_number for item in by_rule["tcp-reset"].evidence] == [1]
    assert [item.packet_number for item in by_rule["tcp-zero-window"].evidence] == [2]


def test_tcp_syn_ack_must_follow_and_ack_the_matching_sequence(capture_root) -> None:
    path = write_tcp_syn_order_pcap(capture_root / "tcp-syn-order.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    by_rule = {finding.rule_id: finding for finding in tcp_findings(capture)}

    assert "tcp-syn-repeat" not in by_rule
    assert [item.packet_number for item in by_rule["tcp-no-syn-ack"].evidence] == [3]


def test_dns_rules_pair_queries_without_claiming_timeouts(loaded_capture) -> None:
    findings, facts = dns_findings(loaded_capture)
    rule_ids = {finding.rule_id for finding in findings}
    assert dns_counts(facts) == {
        "dns_packets": 6,
        "queries": 4,
        "responses": 2,
        "multicast_dns_packets": 0,
    }
    assert facts["matched_queries"] == 2
    assert facts["response_time_min_us"] == 10_000
    assert facts["response_time_max_us"] == 10_000
    assert facts["response_time_average_us"] == 10_000
    assert {"dns-error-response", "dns-no-matching-response", "dns-query-repeat"} == rule_ids
    unanswered = next(
        finding for finding in findings if finding.rule_id == "dns-no-matching-response"
    )
    assert "timeout" not in unanswered.conclusion.lower()
    assert unanswered.limitations


def test_dns_pairing_distinguishes_reused_ids_on_different_ports(capture_root) -> None:
    path = write_dns_port_reuse_pcap(capture_root / "dns-port-reuse.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))

    findings, facts = dns_findings(capture)
    by_rule = {finding.rule_id: finding for finding in findings}

    assert dns_counts(facts) == {
        "dns_packets": 3,
        "queries": 2,
        "responses": 1,
        "multicast_dns_packets": 0,
    }
    assert facts["matched_queries"] == 1
    assert facts["response_time_min_us"] == 20_000
    assert "dns-query-repeat" not in by_rule
    assert [item.packet_number for item in by_rule["dns-no-matching-response"].evidence] == [2]

    _, unreliable_facts = dns_findings(replace(capture, timestamp_regressions=1))
    assert unreliable_facts["timing_reliable"] is False
    assert unreliable_facts["response_time_min_us"] is None
    assert unreliable_facts["response_time_max_us"] is None
    assert unreliable_facts["response_time_average_us"] is None


def test_dns_pairing_treats_names_as_case_insensitive(capture_root) -> None:
    path = write_dns_case_variant_pcap(capture_root / "dns-case-variant.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))

    findings, facts = dns_findings(capture)

    assert dns_counts(facts) == {
        "dns_packets": 2,
        "queries": 1,
        "responses": 1,
        "multicast_dns_packets": 0,
    }
    assert "dns-no-matching-response" not in {finding.rule_id for finding in findings}


def test_dns_response_must_follow_the_query(capture_root) -> None:
    path = write_dns_response_before_query_pcap(capture_root / "dns-response-order.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    findings, _ = dns_findings(capture)
    by_rule = {finding.rule_id: finding for finding in findings}

    assert [item.packet_number for item in by_rule["dns-no-matching-response"].evidence] == [2]


def test_one_dns_response_satisfies_identical_retry_queries(capture_root) -> None:
    path = write_dns_retry_then_response_pcap(capture_root / "dns-retry-response.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    findings, _ = dns_findings(capture)
    rule_ids = {finding.rule_id for finding in findings}

    assert "dns-query-repeat" in rule_ids
    assert "dns-no-matching-response" not in rule_ids


def test_multicast_dns_is_not_forced_into_unicast_pairing(capture_root) -> None:
    path = write_mdns_pcap(capture_root / "mdns.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    findings, facts = dns_findings(capture)

    assert facts["multicast_dns_packets"] == 2
    assert "dns-no-matching-response" not in {finding.rule_id for finding in findings}


def test_quoted_dns_inside_icmp_is_not_analyzed_as_live_dns(capture_root) -> None:
    path = write_icmp_quoted_dns_pcap(capture_root / "icmp-quoted-dns.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))

    findings, facts = dns_findings(capture)

    assert dns_counts(facts) == {
        "dns_packets": 2,
        "queries": 1,
        "responses": 1,
        "multicast_dns_packets": 0,
    }
    assert not findings
    assert capture.packet(1).dns_id is None


def test_icmpv6_errors_are_packet_cited(capture_root) -> None:
    path = write_icmpv6_error_pcap(capture_root / "icmpv6-error.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    findings = {finding.rule_id: finding for finding in summary_findings(capture)}

    assert capture.packet(1).protocol == "ICMPv6"
    assert [item.packet_number for item in findings["icmpv6-destination-unreachable"].evidence] == [
        1
    ]


def test_icmp_path_signals_are_classified_without_root_cause_claims(capture_root) -> None:
    path = write_icmp_path_signals_pcap(capture_root / "icmp-path-signals.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    findings = {finding.rule_id: finding for finding in icmp_findings(capture)}

    assert set(findings) == {
        "icmp-destination-unreachable",
        "icmp-fragmentation-needed",
        "icmp-redirect",
        "icmp-time-exceeded",
        "icmpv6-packet-too-big",
        "icmpv6-time-exceeded",
    }
    assert "port unreachable" in findings["icmp-destination-unreachable"].evidence[0].observation
    assert all(finding.limitations for finding in findings.values())


def test_capture_quality_findings_identify_unreliable_evidence(loaded_capture) -> None:
    records = list(loaded_capture.records)
    records[0] = replace(
        records[0],
        wire_length_bytes=records[0].captured_length_bytes + 20,
        time_offset_us=1_000,
    )
    records[1] = replace(records[1], time_offset_us=0)
    capture = replace(
        loaded_capture,
        records=tuple(records),
        timestamp_regressions=1,
        truncated=True,
    )
    findings = {finding.rule_id: finding for finding in capture_quality_findings(capture)}

    assert [item.packet_number for item in findings["capture-short-frame"].evidence] == [1]
    assert [item.packet_number for item in findings["capture-timestamp-regression"].evidence] == [2]
    assert [item.packet_number for item in findings["capture-packet-limit"].evidence] == [16]


def test_every_summary_conclusion_has_packet_evidence(loaded_capture) -> None:
    findings = summary_findings(loaded_capture)
    assert findings
    assert {finding.rule_id for finding in findings} >= {
        "icmp-destination-unreachable",
        "tcp-reset",
    }
    assert all(finding.evidence for finding in findings)
