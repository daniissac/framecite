from __future__ import annotations

import asyncio
import json
import threading
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pydantic import AnyUrl

import framecite.server as server_module
import framecite.uploads as upload_module
from framecite.config import Settings
from framecite.output_models import (
    AnalyzeDnsOutput,
    AnalyzeTcpOutput,
    InspectPacketsOutput,
    ListConversationsOutput,
    OpenCaptureOutput,
    SummarizeCaptureOutput,
)
from framecite.server import create_server
from framecite.uploads import StagedCapture
from tests.factories import SECRET_PAYLOAD, write_dns_literal_all_pcap


@pytest.mark.asyncio
async def test_mcp_surface_is_small_read_only_and_closed_world(settings, capture_path) -> None:
    server = create_server(settings)
    async with create_connected_server_and_client_session(server) as session:
        listed = await session.list_tools()
        assert {tool.name for tool in listed.tools} == {
            "open_capture",
            "summarize_capture",
            "list_conversations",
            "inspect_packets",
            "analyze_tcp",
            "analyze_dns",
        }
        output_models = {
            "open_capture": OpenCaptureOutput,
            "summarize_capture": SummarizeCaptureOutput,
            "list_conversations": ListConversationsOutput,
            "inspect_packets": InspectPacketsOutput,
            "analyze_tcp": AnalyzeTcpOutput,
            "analyze_dns": AnalyzeDnsOutput,
        }
        for tool in listed.tools:
            assert tool.title
            assert tool.outputSchema == output_models[tool.name].model_json_schema()
            assert tool.outputSchema["type"] == "object"
            assert tool.outputSchema["additionalProperties"] is False
            assert tool.annotations is not None
            assert tool.annotations.readOnlyHint is True
            assert tool.annotations.destructiveHint is False
            assert tool.annotations.idempotentHint is (tool.name != "open_capture")
            assert tool.annotations.openWorldHint is False

        open_tool = next(tool for tool in listed.tools if tool.name == "open_capture")
        descriptor = open_tool.model_dump(by_alias=True, exclude_none=True)
        assert descriptor["_meta"] == {"openai/fileParams": ["capture_file"]}
        file_schema = open_tool.inputSchema["$defs"]["OpenAIFile"]
        assert set(file_schema["properties"]) == {
            "download_url",
            "file_id",
            "mime_type",
            "file_name",
        }
        assert file_schema["required"] == ["download_url", "file_id"]
        assert file_schema["additionalProperties"] is False
        assert all(
            property_schema["type"] == "string"
            for property_schema in file_schema["properties"].values()
        )
        assert open_tool.inputSchema["properties"]["capture_file"]["$ref"].endswith("/OpenAIFile")
        assert "default" not in open_tool.inputSchema["properties"]["capture_file"]
        assert open_tool.inputSchema["properties"]["max_tokens"]["minimum"] == 256

        opened = await session.call_tool(
            "open_capture", {"path": str(capture_path), "max_tokens": 600}
        )
        assert opened.isError is False
        assert opened.content[0].text.startswith("FrameCite returned a bounded structured result")
        capture_id = opened.structuredContent["capture_id"]

        inspected = await session.call_tool(
            "inspect_packets",
            {"capture_id": capture_id, "packet_numbers": [4, 10, 16], "max_tokens": 800},
        )
        assert inspected.isError is False
        serialized = json.dumps(inspected.structuredContent)
        assert SECRET_PAYLOAD.decode() not in serialized
        assert all(
            packet["payload"]["redacted"] for packet in inspected.structuredContent["packets"]
        )

        dns = await session.call_tool(
            "analyze_dns",
            {
                "capture_id": capture_id,
                "qname": "unanswered.example",
                "max_tokens": 800,
            },
        )
        serialized_dns = json.dumps(dns.structuredContent)
        assert "unanswered.example" not in serialized_dns
        assert dns.structuredContent["qname_filter"]["redacted"] is True


@pytest.mark.asyncio
async def test_extension_file_upload_is_ephemeral_and_analysis_remains_local(
    monkeypatch: pytest.MonkeyPatch,
    capture_path: Path,
) -> None:
    capture_bytes = capture_path.read_bytes()
    download_url = "https://files.oaiusercontent.com/capture?token=private-signed-token"
    file_id = "file_private_identifier"
    original_name = "customer-secret-name.pcap"
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, content=capture_bytes)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        upload_module,
        "_client",
        lambda: httpx.Client(transport=transport, trust_env=False),
    )
    server = create_server(Settings(roots=(), max_packets=1_000, max_captures=2))

    async with create_connected_server_and_client_session(server) as session:
        opened = await session.call_tool(
            "open_capture",
            {
                "capture_file": {
                    "download_url": download_url,
                    "file_id": file_id,
                    "mime_type": "application/vnd.tcpdump.pcap",
                    "file_name": original_name,
                },
                "max_tokens": 600,
            },
        )
        assert opened.isError is False
        assert request_count == 1
        opened_payload = opened.structuredContent
        assert opened_payload["filename"] == "uploaded.pcap"
        serialized = json.dumps(opened_payload)
        assert "private-signed-token" not in serialized
        assert file_id not in serialized
        assert original_name not in serialized

        capture_id = opened_payload["capture_id"]
        monkeypatch.setattr(
            upload_module,
            "_client",
            lambda: (_ for _ in ()).throw(AssertionError("analysis attempted network access")),
        )
        calls = [
            ("summarize_capture", {"capture_id": capture_id, "max_tokens": 2_000}),
            ("list_conversations", {"capture_id": capture_id, "max_tokens": 2_000}),
            (
                "inspect_packets",
                {"capture_id": capture_id, "packet_numbers": [1, 4], "max_tokens": 2_000},
            ),
            ("analyze_tcp", {"capture_id": capture_id, "max_tokens": 2_000}),
            ("analyze_dns", {"capture_id": capture_id, "max_tokens": 2_000}),
        ]
        for tool_name, arguments in calls:
            result = await session.call_tool(tool_name, arguments)
            assert result.isError is False

        neither = await session.call_tool("open_capture", {})
        both = await session.call_tool(
            "open_capture",
            {
                "path": str(capture_path),
                "capture_file": {"download_url": download_url, "file_id": file_id},
            },
        )
        assert neither.isError is True
        assert both.isError is True
        assert "exactly one" in neither.content[0].text
        assert "exactly one" in both.content[0].text

        malformed = await session.call_tool(
            "open_capture",
            {
                "capture_file": {
                    "download_url": (
                        "https://files.oaiusercontent.com/capture?token=validation-secret"
                    ),
                    "unexpected": "private-file-metadata",
                }
            },
        )
        malformed_error = malformed.content[0].text
        assert malformed.isError is True
        assert "validation-secret" not in malformed_error
        assert "private-file-metadata" not in malformed_error


@pytest.mark.asyncio
async def test_mcp_findings_resources_and_prompt_are_evidence_linked(
    settings, capture_path
) -> None:
    server = create_server(settings)
    async with create_connected_server_and_client_session(server) as session:
        opened = await session.call_tool("open_capture", {"path": str(capture_path)})
        capture_id = opened.structuredContent["capture_id"]

        summary = await session.call_tool(
            "summarize_capture", {"capture_id": capture_id, "max_tokens": 1_600}
        )
        assert summary.isError is False
        for finding in summary.structuredContent["findings"]:
            assert finding["evidence"]
            assert all(item["packet_number"] >= 1 for item in finding["evidence"])

        resource = await session.read_resource(AnyUrl(f"framecite://capture/{capture_id}/packet/4"))
        resource_text = resource.contents[0].text
        assert SECRET_PAYLOAD.decode() not in resource_text
        assert json.loads(resource_text)["payload"]["redacted"] is True

        prompt = await session.get_prompt(
            "triage_capture", {"capture_id": capture_id, "symptom": "failed HTTPS"}
        )
        prompt_text = prompt.messages[0].content.text
        assert "[packet N]" in prompt_text
        assert "Never infer payload" in prompt_text


@pytest.mark.asyncio
async def test_mcp_output_respects_conservative_budget(settings, capture_path) -> None:
    server = create_server(settings)
    async with create_connected_server_and_client_session(server) as session:
        opened = await session.call_tool("open_capture", {"path": str(capture_path)})
        capture_id = opened.structuredContent["capture_id"]
        result = await session.call_tool(
            "list_conversations", {"capture_id": capture_id, "max_tokens": 300}
        )
        assert result.isError is False
        budget = result.structuredContent["budget"]
        assert budget["estimated_tokens"] <= budget["applied_tokens"]


@pytest.mark.asyncio
async def test_failed_open_does_not_change_the_capture_cache(settings, capture_path) -> None:
    server = create_server(settings)
    async with create_connected_server_and_client_session(server) as session:
        opened = await session.call_tool("open_capture", {"path": str(capture_path)})
        capture_id = opened.structuredContent["capture_id"]

        rejected = await session.call_tool(
            "open_capture",
            {"path": str(capture_path), "max_tokens": 1},
        )
        assert rejected.isError is True

        resource = await session.read_resource(AnyUrl("framecite://captures"))
        manifests = json.loads(resource.contents[0].text)["captures"]
        assert [manifest["capture_id"] for manifest in manifests] == [capture_id]


@pytest.mark.asyncio
async def test_cancelled_upload_waits_for_temporary_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    capture_path: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    cleaned = threading.Event()

    @contextmanager
    def staged_capture(capture_file, settings):
        entered.set()
        release.wait(timeout=2)
        try:
            yield StagedCapture(path=capture_path, display_name="uploaded.pcap")
        finally:
            cleaned.set()

    monkeypatch.setattr(server_module, "stage_extension_capture", staged_capture)
    server = create_server(Settings(roots=()))
    open_tool = server._tool_manager.get_tool("open_capture")
    assert open_tool is not None
    operation = asyncio.create_task(
        open_tool.fn(
            capture_file={
                "download_url": "https://files.oaiusercontent.com/capture",
                "file_id": "file_cancel_test",
            }
        )
    )

    assert await asyncio.to_thread(entered.wait, 1)
    operation.cancel()
    await asyncio.sleep(0.05)
    assert not operation.done()
    operation.cancel()
    await asyncio.sleep(0.05)
    assert not operation.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert cleaned.is_set()


@pytest.mark.asyncio
async def test_dns_cursor_distinguishes_unfiltered_from_literal_all(capture_root) -> None:
    path = write_dns_literal_all_pcap(capture_root / "literal-all.pcap")
    server = create_server(Settings(roots=(capture_root,)))

    async with create_connected_server_and_client_session(server) as session:
        opened = await session.call_tool("open_capture", {"path": str(path)})
        capture_id = opened.structuredContent["capture_id"]
        unfiltered = await session.call_tool(
            "analyze_dns", {"capture_id": capture_id, "max_tokens": 300}
        )
        cursor = unfiltered.structuredContent["budget"]["next_cursor"]
        assert cursor is not None

        filtered = await session.call_tool(
            "analyze_dns",
            {
                "capture_id": capture_id,
                "qname": "all",
                "cursor": cursor,
                "max_tokens": 2_000,
            },
        )
        assert filtered.isError is True
