"""Bounded capture cache and capture-bound opaque cursors."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import stat
from collections import OrderedDict
from dataclasses import replace
from os import stat_result
from pathlib import Path
from threading import RLock

from framecite.capture import dns_qname_token, parse_capture
from framecite.config import Settings
from framecite.models import Capture


class CaptureStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._captures: OrderedDict[str, Capture] = OrderedDict()
        self._capture_lock = RLock()
        self._cursor_key = secrets.token_bytes(32)
        self._redaction_key = secrets.token_bytes(32)

    def open(self, raw_path: str) -> Capture:
        return self.remember(self.parse(raw_path))

    def parse(self, raw_path: str) -> Capture:
        """Parse a root-confined capture without changing the bounded cache."""

        path, file_stat = self.settings.resolve_capture(raw_path)
        return self._parse(path, file_stat)

    def open_uploaded(self, path: Path, display_name: str) -> Capture:
        return self.remember(self.parse_uploaded(path, display_name))

    def parse_uploaded(self, path: Path, display_name: str) -> Capture:
        """Parse one downloader-created temporary file without widening path access."""

        if display_name not in {"uploaded.pcap", "uploaded.pcapng"}:
            raise ValueError("The staged extension capture has an invalid internal name.")
        try:
            file_stat = path.stat()
        except OSError as exc:
            raise ValueError("The staged extension capture is unavailable.") from exc
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("The staged extension capture is not a regular file.")
        if file_stat.st_size > self.settings.max_file_bytes:
            raise ValueError("The staged extension capture exceeds the file-size limit.")
        return self._parse(path, file_stat, display_name=display_name)

    def _parse(
        self,
        path: Path,
        file_stat: stat_result,
        *,
        display_name: str | None = None,
    ) -> Capture:
        capture_id = secrets.token_urlsafe(9)
        capture = parse_capture(
            capture_id=capture_id,
            path=path,
            initial_stat=file_stat,
            max_packets=self.settings.max_packets,
            redaction_key=self._redaction_key,
        )
        if display_name is not None:
            capture = replace(
                capture,
                path=Path("<extension-upload>"),
                filename=display_name,
            )
        return capture

    def remember(self, capture: Capture) -> Capture:
        """Insert a fully validated capture into the bounded in-memory cache."""

        with self._capture_lock:
            self._captures[capture.capture_id] = capture
            self._captures.move_to_end(capture.capture_id)
            while len(self._captures) > self.settings.max_captures:
                self._captures.popitem(last=False)
        return capture

    def dns_qname_token(self, qname: str) -> str:
        return dns_qname_token(self._redaction_key, qname)

    def get(self, capture_id: str) -> Capture:
        with self._capture_lock:
            try:
                capture = self._captures[capture_id]
            except KeyError as exc:
                raise ValueError("Unknown or evicted capture_id.") from exc
            self._captures.move_to_end(capture_id)
            return capture

    def manifests(self) -> list[dict[str, object]]:
        with self._capture_lock:
            captures = tuple(self._captures.values())
        return [capture.manifest() for capture in captures]

    def make_cursor(self, capture_id: str, kind: str, offset: int) -> str:
        body = json.dumps(
            {"capture_id": capture_id, "kind": kind, "offset": offset},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        signature = hmac.new(self._cursor_key, body, hashlib.sha256).digest()[:12]
        return base64.urlsafe_b64encode(body + signature).decode("ascii").rstrip("=")

    def cursor_offset(self, cursor: str | None, capture_id: str, kind: str) -> int:
        if cursor is None:
            return 0
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            body, signature = decoded[:-12], decoded[-12:]
            expected = hmac.new(self._cursor_key, body, hashlib.sha256).digest()[:12]
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            data = json.loads(body)
            if data["capture_id"] != capture_id or data["kind"] != kind:
                raise ValueError
            offset = int(data["offset"])
            if offset < 0:
                raise ValueError
            return offset
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid or capture-mismatched cursor.") from exc
