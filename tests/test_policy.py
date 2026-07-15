from __future__ import annotations

import os
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from framecite.config import PolicyError, Settings
from framecite.models import Capture
from framecite.store import CaptureStore
from tests.factories import write_troubleshooting_pcap


def test_upload_only_mode_does_not_require_a_local_root() -> None:
    settings = Settings(roots=())
    assert settings.roots == ()
    assert settings.allow_extension_uploads is True


def test_local_path_is_disabled_without_a_configured_root(capture_path: Path) -> None:
    with pytest.raises(PolicyError, match="attach"):
        Settings(roots=()).resolve_capture(str(capture_path))


def test_at_least_one_ingestion_route_is_required() -> None:
    with pytest.raises(PolicyError, match="Enable extension uploads"):
        Settings(roots=(), allow_extension_uploads=False)


@pytest.mark.parametrize(
    "host",
    [
        "https://files.oaiusercontent.com",
        "files.oaiusercontent.com:443",
        "127.0.0.1",
        "127.1",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "169.254.43518",
        "localhost",
        "bad_host.example",
        "faß.de",
    ],
)
def test_extension_upload_hosts_must_be_exact_dns_names(host: str) -> None:
    with pytest.raises(PolicyError, match="host"):
        Settings(roots=(), extension_upload_hosts=(host,))


def test_path_outside_root_is_rejected(
    tmp_path: Path, capture_root: Path, capture_path: Path
) -> None:
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(capture_path.read_bytes())
    settings = Settings(roots=(capture_root,))
    with pytest.raises(PolicyError, match="outside"):
        settings.resolve_capture(str(outside))


def test_symlink_escape_is_rejected(tmp_path: Path, capture_root: Path, capture_path: Path) -> None:
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(capture_path.read_bytes())
    link = capture_root / "escape.pcap"
    link.symlink_to(outside)
    with pytest.raises(PolicyError, match="outside"):
        Settings(roots=(capture_root,)).resolve_capture(str(link))


def test_non_capture_extension_is_rejected(capture_root: Path) -> None:
    path = capture_root / "capture.txt"
    path.write_text("not a capture")
    with pytest.raises(PolicyError, match="pcap"):
        Settings(roots=(capture_root,)).resolve_capture(str(path))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is not available")
def test_non_regular_file_is_rejected(capture_root: Path) -> None:
    fifo = capture_root / "pipe.pcap"
    os.mkfifo(fifo)
    with pytest.raises(PolicyError, match="regular"):
        Settings(roots=(capture_root,)).resolve_capture(str(fifo))


def test_file_size_limit_is_enforced(capture_root: Path, capture_path: Path) -> None:
    store = CaptureStore(Settings(roots=(capture_root,), max_file_bytes=10))
    with pytest.raises(PolicyError, match="size"):
        store.open(str(capture_path))


def test_uploaded_capture_retains_no_temporary_path(capture_path: Path) -> None:
    capture = CaptureStore(Settings(roots=())).open_uploaded(capture_path, "uploaded.pcap")

    assert capture.path == Path("<extension-upload>")
    assert capture.filename == "uploaded.pcap"


def test_capture_cache_is_bounded(capture_root: Path) -> None:
    first_path = write_troubleshooting_pcap(capture_root / "first.pcap")
    second_path = write_troubleshooting_pcap(capture_root / "second.pcap")
    store = CaptureStore(Settings(roots=(capture_root,), max_captures=1))
    first = store.open(str(first_path))
    second = store.open(str(second_path))
    with pytest.raises(ValueError, match="evicted"):
        store.get(first.capture_id)
    assert store.get(second.capture_id) == second


def test_manifest_snapshot_is_safe_during_cache_updates(
    monkeypatch: pytest.MonkeyPatch,
    capture_root: Path,
) -> None:
    first = CaptureStore(Settings(roots=(capture_root,))).open(
        str(write_troubleshooting_pcap(capture_root / "seed.pcap"))
    )
    store = CaptureStore(Settings(roots=(capture_root,)))
    stored = store.open(str(capture_root / "seed.pcap"))
    original_manifest = Capture.manifest
    reading = threading.Event()
    proceed = threading.Event()
    wrote = threading.Event()
    failures: list[BaseException] = []

    def blocking_manifest(capture: Capture):
        if capture.capture_id == stored.capture_id:
            reading.set()
            proceed.wait(timeout=2)
        return original_manifest(capture)

    def read_manifests() -> None:
        try:
            store.manifests()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def update_cache() -> None:
        store.remember(replace(first, capture_id="concurrent-capture"))
        wrote.set()

    monkeypatch.setattr(Capture, "manifest", blocking_manifest)
    reader = threading.Thread(target=read_manifests)
    reader.start()
    assert reading.wait(timeout=1)
    writer = threading.Thread(target=update_cache)
    writer.start()
    wrote_before_release = wrote.wait(timeout=1)
    proceed.set()
    reader.join(timeout=2)
    writer.join(timeout=2)

    assert not reader.is_alive()
    assert not writer.is_alive()
    assert wrote_before_release
    assert failures == []


def test_cursor_is_bound_to_capture_and_query(capture_root: Path, capture_path: Path) -> None:
    store = CaptureStore(Settings(roots=(capture_root,)))
    capture = store.open(str(capture_path))
    cursor = store.make_cursor(capture.capture_id, "tcp", 3)
    assert store.cursor_offset(cursor, capture.capture_id, "tcp") == 3
    with pytest.raises(ValueError, match="mismatched"):
        store.cursor_offset(cursor, capture.capture_id, "dns")
