from __future__ import annotations

from pathlib import Path

import pytest

from framecite.config import Settings
from framecite.store import CaptureStore
from tests.factories import write_troubleshooting_pcap


@pytest.fixture
def capture_root(tmp_path: Path) -> Path:
    root = tmp_path / "captures"
    root.mkdir()
    return root


@pytest.fixture
def capture_path(capture_root: Path) -> Path:
    return write_troubleshooting_pcap(capture_root / "known.pcap")


@pytest.fixture
def settings(capture_root: Path) -> Settings:
    return Settings(roots=(capture_root,), max_packets=1_000, max_captures=2)


@pytest.fixture
def loaded_capture(settings: Settings, capture_path: Path):
    return CaptureStore(settings).open(str(capture_path))
