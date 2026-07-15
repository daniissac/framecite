from __future__ import annotations

import json
from pathlib import Path

import pytest

import framecite.capture as capture_module
from framecite.config import Settings
from framecite.store import CaptureStore
from tests.factories import SECRET_PAYLOAD, write_troubleshooting_pcapng


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
