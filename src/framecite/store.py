"""Bounded capture cache and capture-bound opaque cursors."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections import OrderedDict

from framecite.capture import parse_capture
from framecite.config import Settings
from framecite.models import Capture


class CaptureStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._captures: OrderedDict[str, Capture] = OrderedDict()
        self._cursor_key = secrets.token_bytes(32)

    def open(self, raw_path: str) -> Capture:
        path, file_stat = self.settings.resolve_capture(raw_path)
        capture_id = secrets.token_urlsafe(9)
        capture = parse_capture(
            capture_id=capture_id,
            path=path,
            initial_stat=file_stat,
            max_packets=self.settings.max_packets,
        )
        self._captures[capture_id] = capture
        self._captures.move_to_end(capture_id)
        while len(self._captures) > self.settings.max_captures:
            self._captures.popitem(last=False)
        return capture

    def get(self, capture_id: str) -> Capture:
        try:
            capture = self._captures[capture_id]
        except KeyError as exc:
            raise ValueError("Unknown or evicted capture_id.") from exc
        self._captures.move_to_end(capture_id)
        return capture

    def manifests(self) -> list[dict[str, object]]:
        return [capture.manifest() for capture in self._captures.values()]

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
