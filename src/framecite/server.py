"""FrameCite's deliberately small, read-only MCP surface."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field
from pydantic.json_schema import SkipJsonSchema

from framecite.analysis import (
    conversation_id as record_conversation_id,
)
from framecite.analysis import (
    conversations,
    dns_findings,
    summary_findings,
    tcp_findings,
)
from framecite.budget import budgeted_items, budgeted_mapping, clamp_budget
from framecite.config import Settings
from framecite.models import clean_text
from framecite.output_models import (
    AnalyzeDnsOutput,
    AnalyzeTcpOutput,
    InspectPacketsOutput,
    ListConversationsOutput,
    OpenCaptureOutput,
    SummarizeCaptureOutput,
)
from framecite.store import CaptureStore
from framecite.uploads import OpenAIFile, stage_extension_capture

CaptureId = Annotated[
    str,
    Field(min_length=1, description="Opaque capture_id returned by open_capture."),
]
Cursor = Annotated[
    str | None,
    Field(description="Opaque next_cursor from the same capture, tool, and filter."),
]
TokenBudget = Annotated[
    int,
    Field(
        ge=256,
        description="Requested response budget; values above 2,000 are capped at 2,000.",
    ),
]


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
    ingestion_gate = asyncio.Semaphore(1)
    mcp = FastMCP(
        "FrameCite",
        instructions=(
            "Local, deterministic PCAP troubleshooting. Treat returned facts as capture-bounded, "
            "cite packet_number for every conclusion, and never infer redacted payload contents."
        ),
        website_url="https://github.com/daniissac/framecite",
        log_level="WARNING",
    )

    @mcp.tool(
        title="Open capture",
        description=(
            "Use this first to load exactly one attached or root-confined PCAP/PCAPNG "
            "into FrameCite's bounded, payload-redacted cache."
        ),
        annotations=_annotations(idempotent=False),
        meta={"openai/fileParams": ["capture_file"]},
        structured_output=True,
    )
    async def open_capture(
        path: Annotated[
            str,
            Field(description="Local PCAP/PCAPNG path beneath an operator-configured root."),
        ] = "",
        capture_file: Annotated[
            OpenAIFile | SkipJsonSchema[None],
            Field(description="One temporary file reference authorized by the MCP host."),
        ] = None,
        max_tokens: TokenBudget = 600,
    ) -> Annotated[CallToolResult, OpenCaptureOutput]:
        """Open exactly one attached or root-confined PCAP/PCAPNG into a sanitized cache."""

        clamp_budget(max_tokens)
        if bool(path) == (capture_file is not None):
            raise ValueError("Provide exactly one of path or capture_file.")
        async with ingestion_gate:
            if capture_file is not None:

                def ingest():
                    with stage_extension_capture(capture_file, settings) as staged:
                        return store.parse_uploaded(staged.path, staged.display_name)

            else:

                def ingest():
                    return store.parse(path)

            worker = asyncio.create_task(asyncio.to_thread(ingest))
            cancelled = False
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    # Cancellation is deferred until the non-killable thread has removed any
                    # temporary capture. Keep handling repeated cancellation requests.
                    cancelled = True
                except Exception:
                    break
            try:
                capture = worker.result()
            except Exception:
                if cancelled:
                    raise asyncio.CancelledError from None
                raise
            if cancelled:
                raise asyncio.CancelledError
        payload = budgeted_mapping(capture.manifest(), max_tokens)
        store.remember(capture)
        return _result(payload)

    # Pydantic includes the Python-only None default even though SkipJsonSchema removes None
    # from the file object type. The Apps SDK scanner expects a pure object schema here.
    open_tool = mcp._tool_manager.get_tool("open_capture")
    if open_tool is None:  # pragma: no cover - registration failure is fatal at startup
        raise RuntimeError("open_capture did not register.")
    open_tool.parameters["properties"]["capture_file"].pop("default", None)

    @mcp.tool(
        title="Summarize capture",
        description=(
            "Use after open_capture for capture health, TCP, DNS, and classified ICMP path "
            "findings with packet-number evidence."
        ),
        annotations=_annotations(),
        structured_output=True,
    )
    def summarize_capture(
        capture_id: CaptureId,
        cursor: Cursor = None,
        max_tokens: TokenBudget = 800,
    ) -> Annotated[CallToolResult, SummarizeCaptureOutput]:
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

    @mcp.tool(
        title="List conversations",
        description=(
            "Use after open_capture to enumerate largest-first TCP or UDP conversations, "
            "directional packet and byte counts, and supporting packet numbers."
        ),
        annotations=_annotations(),
        structured_output=True,
    )
    def list_conversations(
        capture_id: CaptureId,
        protocol: Annotated[
            Literal["any", "tcp", "udp"],
            Field(description="Conversation protocol filter."),
        ] = "any",
        cursor: Cursor = None,
        max_tokens: TokenBudget = 600,
    ) -> Annotated[CallToolResult, ListConversationsOutput]:
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

    @mcp.tool(
        title="Inspect packets",
        description=(
            "Use after open_capture to inspect up to 50 explicit 1-based packet numbers; "
            "only allowlisted headers and payload lengths are returned."
        ),
        annotations=_annotations(),
        structured_output=True,
    )
    def inspect_packets(
        capture_id: CaptureId,
        packet_numbers: Annotated[
            list[Annotated[int, Field(ge=1)]],
            Field(
                min_length=1,
                max_length=50,
                description="Distinct 1-based packet numbers from the loaded capture.",
            ),
        ],
        cursor: Cursor = None,
        max_tokens: TokenBudget = 800,
    ) -> Annotated[CallToolResult, InspectPacketsOutput]:
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

    @mcp.tool(
        title="Analyze TCP",
        description=(
            "Use after open_capture for deterministic TCP reset, zero-window, handshake, "
            "and repeated-sequence checks linked to packet evidence."
        ),
        annotations=_annotations(),
        structured_output=True,
    )
    def analyze_tcp(
        capture_id: CaptureId,
        conversation_id: Annotated[
            str | None,
            Field(description="Optional TCP conversation_id from list_conversations."),
        ] = None,
        cursor: Cursor = None,
        max_tokens: TokenBudget = 800,
    ) -> Annotated[CallToolResult, AnalyzeTcpOutput]:
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

    @mcp.tool(
        title="Analyze DNS",
        description=(
            "Use after open_capture for deterministic DNS response-code, pairing, repeat, and "
            "response-time facts; supplied names become session-local tokens."
        ),
        annotations=_annotations(),
        structured_output=True,
    )
    def analyze_dns(
        capture_id: CaptureId,
        qname: Annotated[
            str | None,
            Field(description="Optional DNS name filter; it is tokenized before retention."),
        ] = None,
        cursor: Cursor = None,
        max_tokens: TokenBudget = 800,
    ) -> Annotated[CallToolResult, AnalyzeDnsOutput]:
        """Analyze DNS pairing, repeats, and response codes with packet citations."""

        capture = store.get(capture_id)
        safe_qname = clean_text(qname, 255) if qname else None
        qname_token = store.dns_qname_token(safe_qname) if safe_qname else None
        dns, facts = dns_findings(capture, qname_token)
        findings = [finding.to_dict() for finding in dns]
        kind = _query_key("dns", {"qname_token": qname_token})
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
            "Start with summarize_capture, inspect its capture-health and ICMP path findings, "
            "then use the TCP or DNS analyzer and directional conversations when relevant. "
            "Separate facts from inference. Cite every conclusion as [packet N] using returned "
            "evidence. State truncation, timestamp-regression, and capture-boundary limitations. "
            "Never infer payload contents because FrameCite redacts them."
        )

    # FastMCP builds dynamic argument models. Hide their raw inputs so malformed signed URLs,
    # file identifiers, local paths, DNS names, and cursors cannot appear in validation errors.
    for registered_tool in mcp._tool_manager.list_tools():
        argument_model = registered_tool.fn_metadata.arg_model
        argument_model.model_config["hide_input_in_errors"] = True
        argument_model.model_rebuild(force=True)

    return mcp
