from __future__ import annotations

from framecite.analysis import conversations, dns_findings, summary_findings, tcp_findings
from framecite.config import Settings
from framecite.store import CaptureStore
from tests.factories import (
    write_dns_case_variant_pcap,
    write_dns_port_reuse_pcap,
    write_tcp_syn_repeat_pcap,
)


def test_conversations_are_stable_and_packet_cited(loaded_capture) -> None:
    first = conversations(loaded_capture)
    second = conversations(loaded_capture)
    assert first == second
    assert first
    for item in first:
        assert item["evidence"]["first_packet"] >= 1
        assert item["evidence"]["last_packet"] <= len(loaded_capture.records)
        assert item["evidence"]["sample_packets"]


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


def test_dns_rules_pair_queries_without_claiming_timeouts(loaded_capture) -> None:
    findings, facts = dns_findings(loaded_capture)
    rule_ids = {finding.rule_id for finding in findings}
    assert facts == {"dns_packets": 6, "queries": 4, "responses": 2}
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

    assert facts == {"dns_packets": 3, "queries": 2, "responses": 1}
    assert "dns-query-repeat" not in by_rule
    assert [item.packet_number for item in by_rule["dns-no-matching-response"].evidence] == [2]


def test_dns_pairing_treats_names_as_case_insensitive(capture_root) -> None:
    path = write_dns_case_variant_pcap(capture_root / "dns-case-variant.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))

    findings, facts = dns_findings(capture)

    assert facts == {"dns_packets": 2, "queries": 1, "responses": 1}
    assert "dns-no-matching-response" not in {finding.rule_id for finding in findings}


def test_every_summary_conclusion_has_packet_evidence(loaded_capture) -> None:
    findings = summary_findings(loaded_capture)
    assert findings
    assert {finding.rule_id for finding in findings} >= {"icmp-error", "tcp-reset"}
    assert all(finding.evidence for finding in findings)
