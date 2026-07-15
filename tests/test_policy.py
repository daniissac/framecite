from __future__ import annotations

import os
from pathlib import Path

import pytest

from framecite.config import PolicyError, Settings
from framecite.store import CaptureStore
from tests.factories import write_troubleshooting_pcap


def test_root_is_required() -> None:
    with pytest.raises(PolicyError, match="root"):
        Settings(roots=())


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


def test_capture_cache_is_bounded(capture_root: Path) -> None:
    first_path = write_troubleshooting_pcap(capture_root / "first.pcap")
    second_path = write_troubleshooting_pcap(capture_root / "second.pcap")
    store = CaptureStore(Settings(roots=(capture_root,), max_captures=1))
    first = store.open(str(first_path))
    second = store.open(str(second_path))
    with pytest.raises(ValueError, match="evicted"):
        store.get(first.capture_id)
    assert store.get(second.capture_id) == second


def test_cursor_is_bound_to_capture_and_query(capture_root: Path, capture_path: Path) -> None:
    store = CaptureStore(Settings(roots=(capture_root,)))
    capture = store.open(str(capture_path))
    cursor = store.make_cursor(capture.capture_id, "tcp", 3)
    assert store.cursor_offset(cursor, capture.capture_id, "tcp") == 3
    with pytest.raises(ValueError, match="mismatched"):
        store.cursor_offset(cursor, capture.capture_id, "dns")
