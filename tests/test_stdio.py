from __future__ import annotations

import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_real_stdio_process_lists_tools_and_opens_capture(capture_root, capture_path) -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "framecite", "--root", str(capture_root)],
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        assert len(listed.tools) == 6
        opened = await session.call_tool("open_capture", {"path": str(capture_path)})
        assert opened.isError is False
        assert opened.structuredContent["packet_count"] == 16


@pytest.mark.asyncio
async def test_real_stdio_process_starts_in_upload_only_mode_without_root() -> None:
    parameters = StdioServerParameters(command=sys.executable, args=["-m", "framecite"])
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        open_tool = next(tool for tool in listed.tools if tool.name == "open_capture")
        assert open_tool.meta == {"openai/fileParams": ["capture_file"]}
