from __future__ import annotations

import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pydantic import AnyUrl

from framecite.config import Settings
from framecite.server import create_server
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
        for tool in listed.tools:
            assert tool.annotations is not None
            assert tool.annotations.readOnlyHint is True
            assert tool.annotations.destructiveHint is False
            assert tool.annotations.idempotentHint is (tool.name != "open_capture")
            assert tool.annotations.openWorldHint is False

        opened = await session.call_tool(
            "open_capture", {"path": str(capture_path), "max_tokens": 600}
        )
        assert opened.isError is False
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
