"""FrameCite's deliberately small, read-only MCP surface."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent, ToolAnnotations

from framecite.analysis import (
    conversation_id as record_conversation_id,
)
from framecite.analysis import (
    conversations,
    dns_findings,
    summary_findings,
    tcp_findings,
)
from framecite.budget import budgeted_items, budgeted_mapping
from framecite.config import Settings
from framecite.models import clean_text
from framecite.store import CaptureStore


def _annotations(*, idempotent: bool = True) -> ToolAnnotations:
    return ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=idempotent,
        openWorldHint=False,
    )


def _result(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=(
                    "FrameCite returned a bounded structured result; "
                    "packet payloads remain redacted."
                ),
            )
        ],
        structuredContent=payload,
    )


def _query_key(prefix: str, value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()[:16]}"


def create_server(settings: Settings) -> FastMCP:
    store = CaptureStore(settings)
    mcp = FastMCP(
        "FrameCite",
        instructions=(
            "Local, deterministic PCAP troubleshooting. Treat returned facts as capture-bounded, "
            "cite packet_number for every conclusion, and never infer redacted payload contents."
        ),
        website_url="https://github.com/daniissac/framecite",
        log_level="WARNING",
    )

    @mcp.tool(annotations=_annotations(idempotent=False))
    def open_capture(path: str, max_tokens: int = 600) -> CallToolResult:
        """Open one PCAP/PCAPNG beneath a configured root into a sanitized bounded cache."""

        capture = store.open(path)
        return _result(budgeted_mapping(capture.manifest(), max_tokens))

    @mcp.tool(annotations=_annotations())
    def summarize_capture(
        capture_id: str,
        cursor: str | None = None,
        max_tokens: int = 800,
    ) -> CallToolResult:
        """Return bounded capture facts and prioritized deterministic findings."""

        capture = store.get(capture_id)
        findings = [finding.to_dict() for finding in summary_findings(capture)]
        kind = "summary"
        start = store.cursor_offset(cursor, capture_id, kind)
        if start > len(findings):
            raise ValueError("Cursor is beyond the available summary findings.")
        payload = budgeted_items(
            base={"capture_id": capture_id, "facts": capture.manifest()},
            item_key="findings",
            items=findings[start:],
            start_offset=start,
            requested_tokens=max_tokens,
            make_cursor=lambda offset: store.make_cursor(capture_id, kind, offset),
        )
        return _result(payload)

    @mcp.tool(annotations=_annotations())
    def list_conversations(
        capture_id: str,
        protocol: str = "any",
        cursor: str | None = None,
        max_tokens: int = 600,
    ) -> CallToolResult:
        """List bounded TCP/UDP conversations with packet-number evidence."""

        capture = store.get(capture_id)
        rows = conversations(capture, protocol)
        kind = _query_key("conversations", protocol.lower())
        start = store.cursor_offset(cursor, capture_id, kind)
        if start > len(rows):
            raise ValueError("Cursor is beyond the available conversations.")
        payload = budgeted_items(
            base={"capture_id": capture_id, "protocol_filter": protocol.lower()},
            item_key="conversations",
            items=rows[start:],
            start_offset=start,
            requested_tokens=max_tokens,
            make_cursor=lambda offset: store.make_cursor(capture_id, kind, offset),
        )
        return _result(payload)

    @mcp.tool(annotations=_annotations())
    def inspect_packets(
        capture_id: str,
        packet_numbers: list[int],
        cursor: str | None = None,
        max_tokens: int = 800,
    ) -> CallToolResult:
        """Inspect up to 50 explicit 1-based packets using allowlisted headers only."""

        if not packet_numbers or len(packet_numbers) > 50:
            raise ValueError("packet_numbers must contain between 1 and 50 entries.")
        if len(set(packet_numbers)) != len(packet_numbers):
            raise ValueError("packet_numbers must not contain duplicates.")
        capture = store.get(capture_id)
        ordered_numbers = sorted(packet_numbers)
        rows = [capture.packet(number).public() for number in ordered_numbers]
        kind = _query_key("packets", ordered_numbers)
        start = store.cursor_offset(cursor, capture_id, kind)
        if start > len(rows):
            raise ValueError("Cursor is beyond the requested packets.")
        payload = budgeted_items(
            base={"capture_id": capture_id},
            item_key="packets",
            items=rows[start:],
            start_offset=start,
            requested_tokens=max_tokens,
            make_cursor=lambda offset: store.make_cursor(capture_id, kind, offset),
        )
        return _result(payload)

    @mcp.tool(annotations=_annotations())
    def analyze_tcp(
        capture_id: str,
        conversation_id: str | None = None,
        cursor: str | None = None,
        max_tokens: int = 800,
    ) -> CallToolResult:
        """Run deterministic TCP troubleshooting rules without payload inspection."""

        capture = store.get(capture_id)
        findings = [finding.to_dict() for finding in tcp_findings(capture, conversation_id)]
        kind = _query_key("tcp", conversation_id or "all")
        start = store.cursor_offset(cursor, capture_id, kind)
        if start > len(findings):
            raise ValueError("Cursor is beyond the available TCP findings.")
        payload = budgeted_items(
            base={
                "capture_id": capture_id,
                "conversation_id": conversation_id,
                "tcp_packet_count": sum(
                    1
                    for record in capture.records
                    if record.protocol == "TCP"
                    and (
                        conversation_id is None or record_conversation_id(record) == conversation_id
                    )
                ),
            },
            item_key="findings",
            items=findings[start:],
            start_offset=start,
            requested_tokens=max_tokens,
            make_cursor=lambda offset: store.make_cursor(capture_id, kind, offset),
        )
        return _result(payload)

    @mcp.tool(annotations=_annotations())
    def analyze_dns(
        capture_id: str,
        qname: str | None = None,
        cursor: str | None = None,
        max_tokens: int = 800,
    ) -> CallToolResult:
        """Analyze DNS pairing, repeats, and response codes with packet citations."""

        capture = store.get(capture_id)
        safe_qname = clean_text(qname, 255) if qname else None
        qname_token = store.dns_qname_token(safe_qname) if safe_qname else None
        dns, facts = dns_findings(capture, qname_token)
        findings = [finding.to_dict() for finding in dns]
        kind = _query_key("dns", safe_qname or "all")
        start = store.cursor_offset(cursor, capture_id, kind)
        if start > len(findings):
            raise ValueError("Cursor is beyond the available DNS findings.")
        payload = budgeted_items(
            base={
                "capture_id": capture_id,
                "qname_filter": ({"redacted": True, "token": qname_token} if qname_token else None),
                "facts": facts,
            },
            item_key="findings",
            items=findings[start:],
            start_offset=start,
            requested_tokens=max_tokens,
            make_cursor=lambda offset: store.make_cursor(capture_id, kind, offset),
        )
        return _result(payload)

    @mcp.resource(
        "framecite://captures",
        name="loaded-captures",
        description="Bounded manifests for captures loaded in this local server process.",
        mime_type="application/json",
    )
    def loaded_captures() -> str:
        return json.dumps({"captures": store.manifests()}, separators=(",", ":"), sort_keys=True)

    @mcp.resource(
        "framecite://capture/{capture_id}/manifest",
        name="capture-manifest",
        description="Sanitized facts for one loaded capture.",
        mime_type="application/json",
    )
    def capture_manifest(capture_id: str) -> str:
        return json.dumps(store.get(capture_id).manifest(), separators=(",", ":"), sort_keys=True)

    @mcp.resource(
        "framecite://capture/{capture_id}/packet/{packet_number}",
        name="sanitized-packet",
        description="One allowlisted packet record with its payload redacted.",
        mime_type="application/json",
    )
    def sanitized_packet(capture_id: str, packet_number: int) -> str:
        record = store.get(capture_id).packet(packet_number)
        return json.dumps(record.public(), separators=(",", ":"), sort_keys=True)

    @mcp.prompt(
        name="triage_capture",
        description="Troubleshoot a symptom using only FrameCite facts and cited packet evidence.",
    )
    def triage_capture(capture_id: str, symptom: str = "general connectivity") -> str:
        safe_symptom = clean_text(symptom, 200)
        return (
            f"Troubleshoot capture {capture_id} for: {safe_symptom}. "
            "Start with summarize_capture, then use the TCP or DNS analyzer only when relevant. "
            "Separate facts from inference. Cite every conclusion as [packet N] using returned "
            "evidence. State truncation, timestamp-regression, and capture-boundary limitations. "
            "Never infer payload contents because FrameCite redacts them."
        )

    return mcp
