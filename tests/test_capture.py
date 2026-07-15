from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

import framecite.capture as capture_module
from framecite.config import Settings
from framecite.store import CaptureStore
from tests.factories import (
    SECRET_PAYLOAD,
    write_icmp_quoted_dns_pcap,
    write_out_of_order_timestamps_pcap,
    write_troubleshooting_pcapng,
)


def test_streaming_parser_preserves_one_based_packet_numbers(loaded_capture) -> None:
    assert len(loaded_capture.records) == 16
    assert [record.packet_number for record in loaded_capture.records] == list(range(1, 17))
    assert loaded_capture.records[-1].layers == ("Ethernet", "VLAN", "IPv6", "UDP")


def test_manifest_is_bounded_and_records_redaction(loaded_capture) -> None:
    manifest = loaded_capture.manifest()
    assert manifest["packet_count"] == 16
    assert manifest["payloads_redacted"] is True
    assert manifest["protocol_counts"]["TCP"] == 8
    assert manifest["protocol_counts"]["UDP"] == 7


def test_raw_payload_is_never_retained_or_returned(loaded_capture) -> None:
    serialized = json.dumps([record.public() for record in loaded_capture.records])
    secret = SECRET_PAYLOAD.decode()
    assert secret not in serialized
    packet = loaded_capture.packet(4).public()
    assert packet["payload"] == {"redacted": True, "length_bytes": len(SECRET_PAYLOAD)}


def test_dns_names_are_session_tokenized_and_never_returned(capture_root: Path) -> None:
    path = write_icmp_quoted_dns_pcap(capture_root / "dns-name-redaction.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    serialized = json.dumps([record.public() for record in capture.records])

    assert "quoted-secret.internal" not in serialized
    assert "direct-secret.internal" not in serialized
    query_name = capture.packet(2).public()["details"]["dns"]["qname"]
    response_name = capture.packet(3).public()["details"]["dns"]["qname"]
    assert query_name == response_name
    assert query_name["redacted"] is True
    assert query_name["token"].startswith("dns-")


def test_packet_limit_is_disclosed(capture_root: Path, capture_path: Path) -> None:
    store = CaptureStore(Settings(roots=(capture_root,), max_packets=3))
    capture = store.open(str(capture_path))
    assert len(capture.records) == 3
    assert capture.truncated is True
    assert capture.manifest()["packet_limit_reached"] is True


def test_pcapng_is_supported(capture_root: Path) -> None:
    path = write_troubleshooting_pcapng(capture_root / "known.pcapng")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))
    assert len(capture.records) == 16


def test_malformed_capture_is_rejected(capture_root: Path) -> None:
    path = capture_root / "malformed.pcap"
    path.write_bytes(b"not-a-packet-capture")
    with pytest.raises(ValueError, match="parsed"):
        CaptureStore(Settings(roots=(capture_root,))).open(str(path))


def test_truncated_classic_pcap_header_and_body_are_rejected(capture_root: Path) -> None:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
    packet_header = struct.pack("<IIII", 1, 0, 10, 10)

    header_path = capture_root / "truncated-header.pcap"
    header_path.write_bytes(global_header + packet_header[:8])
    body_path = capture_root / "truncated-body.pcap"
    body_path.write_bytes(global_header + packet_header + b"\x00" * 9)

    store = CaptureStore(Settings(roots=(capture_root,)))
    with pytest.raises(ValueError, match="parsed"):
        store.open(str(header_path))
    with pytest.raises(ValueError, match="parsed"):
        store.open(str(body_path))


def test_truncated_pcapng_block_is_rejected(capture_root: Path) -> None:
    valid = write_troubleshooting_pcapng(capture_root / "valid.pcapng")
    path = capture_root / "truncated.pcapng"
    path.write_bytes(valid.read_bytes()[:-1])

    with pytest.raises(ValueError, match="parsed"):
        CaptureStore(Settings(roots=(capture_root,))).open(str(path))


def test_snaplen_capture_preserves_captured_and_wire_lengths(capture_root: Path) -> None:
    path = capture_root / "snaplen.pcap"
    path.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 10, 1)
        + struct.pack("<IIII", 1, 0, 10, 100)
        + b"\x00" * 10
    )

    record = CaptureStore(Settings(roots=(capture_root,))).open(str(path)).packet(1)

    assert record.captured_length_bytes == 10
    assert record.wire_length_bytes == 100


def test_timestamp_regressions_are_preserved_and_disclosed(capture_root: Path) -> None:
    path = write_out_of_order_timestamps_pcap(capture_root / "clock-regression.pcap")
    capture = CaptureStore(Settings(roots=(capture_root,))).open(str(path))

    assert [record.time_offset_us for record in capture.records] == [100_000, 0]
    assert capture.duration_us == 100_000
    assert capture.timestamp_regressions == 1
    assert capture.manifest()["timestamp_regressions"] == 1


def test_capture_changed_during_hashing_is_rejected(
    capture_root: Path, capture_path: Path, monkeypatch
) -> None:
    original_hash = capture_module._file_sha256

    def mutate_after_hash(path: Path) -> str:
        digest = original_hash(path)
        path.write_bytes(path.read_bytes() + b"changed")
        return digest

    monkeypatch.setattr(capture_module, "_file_sha256", mutate_after_hash)
    with pytest.raises(ValueError, match="changed while being hashed"):
        CaptureStore(Settings(roots=(capture_root,))).open(str(capture_path))
