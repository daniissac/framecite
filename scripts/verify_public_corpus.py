#!/usr/bin/env python3
"""Download, verify, and exercise FrameCite against pinned public captures."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import fields
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session
from scapy.layers.dns import DNSQR
from scapy.utils import PcapReader

from framecite.analysis import (
    conversation_id,
    conversations,
    dns_findings,
    summary_findings,
    tcp_findings,
)
from framecite.budget import estimated_tokens
from framecite.config import Settings
from framecite.models import PacketRecord
from framecite.server import create_server
from framecite.store import CaptureStore

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests" / "public_corpus" / "manifest.json"
PINNED_REVISION = re.compile(r"/[0-9a-f]{40}/")
PACKET_KEYS = {
    "packet_number",
    "time_offset_us",
    "captured_length_bytes",
    "wire_length_bytes",
    "layers",
    "protocol",
    "source",
    "destination",
    "details",
    "payload",
}


class CorpusError(RuntimeError):
    """Raised when a public-corpus invariant fails."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CorpusError(message)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == 1, "Unsupported public corpus schema.")
    require(
        isinstance(manifest.get("max_download_bytes"), int) and manifest["max_download_bytes"] > 0,
        "max_download_bytes must be a positive integer.",
    )
    samples = manifest.get("samples")
    require(isinstance(samples, list) and samples, "Public corpus must contain samples.")

    identifiers: set[str] = set()
    filenames: set[str] = set()
    for sample in samples:
        identifier = sample.get("id")
        filename = sample.get("filename")
        url = sample.get("url", "")
        require(isinstance(identifier, str) and identifier, "Every sample needs an id.")
        require(identifier not in identifiers, f"Duplicate sample id: {identifier}")
        require(
            isinstance(filename, str)
            and filename == Path(filename).name
            and Path(filename).suffix.lower() in {".pcap", ".pcapng"},
            f"Unsafe capture filename for {identifier}.",
        )
        require(filename not in filenames, f"Duplicate sample filename: {filename}")
        require(
            isinstance(url, str)
            and url.startswith("https://")
            and PINNED_REVISION.search(url) is not None,
            f"{identifier} must use an HTTPS URL pinned to a 40-character revision.",
        )
        require(
            re.fullmatch(r"[0-9a-f]{64}", sample.get("sha256", "")) is not None,
            f"{identifier} has an invalid SHA-256.",
        )
        require(
            isinstance(sample.get("size_bytes"), int)
            and 0 < sample["size_bytes"] <= manifest["max_download_bytes"],
            f"{identifier} has an invalid size.",
        )
        require(
            str(sample.get("source_url", "")).startswith("https://")
            and str(sample.get("license_url", "")).startswith("https://"),
            f"{identifier} needs source and license links.",
        )
        identifiers.add(identifier)
        filenames.add(filename)
    return manifest


def download_sample(sample: dict[str, Any], destination: Path, maximum: int) -> Path:
    path = destination / sample["filename"]
    partial = path.with_suffix(f"{path.suffix}.partial")
    request = urllib.request.Request(
        sample["url"], headers={"User-Agent": "FrameCite-public-corpus/1"}
    )
    last_error: Exception | None = None

    for attempt in range(1, 4):
        partial.unlink(missing_ok=True)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                require(
                    response.geturl().startswith("https://"),
                    f"{sample['id']} redirected away from HTTPS.",
                )
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    require(
                        int(content_length) == sample["size_bytes"],
                        f"{sample['id']} Content-Length changed.",
                    )
                received = 0
                with partial.open("wb") as output:
                    while chunk := response.read(64 * 1024):
                        received += len(chunk)
                        require(received <= maximum, f"{sample['id']} exceeded the size limit.")
                        output.write(chunk)
            require(received == sample["size_bytes"], f"{sample['id']} size changed.")
            require(file_sha256(partial) == sample["sha256"], f"{sample['id']} hash changed.")
            partial.replace(path)
            return path
        except (CorpusError, OSError, TimeoutError, urllib.error.URLError) as exc:
            last_error = exc
            partial.unlink(missing_ok=True)
            if attempt < 3:
                time.sleep(attempt)

    raise CorpusError(f"Could not download {sample['id']}: {last_error}")


def source_dns_names(path: Path) -> set[str]:
    names: set[str] = set()
    with PcapReader(str(path)) as reader:
        for packet in reader:
            question = packet.getlayer(DNSQR)
            if question is None:
                continue
            raw_name = question.qname
            if isinstance(raw_name, bytes):
                raw_name = raw_name.decode("utf-8", errors="replace")
            name = str(raw_name).rstrip(".")
            if len(name) >= 6:
                names.add(name)
    return names


def validate_packet_shape(record: PacketRecord, sample_id: str) -> dict[str, Any]:
    public = record.public()
    require(set(public) == PACKET_KEYS, f"{sample_id} returned an unexpected packet field.")
    require(
        public["payload"].get("redacted") is True
        and set(public["payload"]) == {"redacted", "length_bytes"},
        f"{sample_id} returned an invalid payload-redaction shape.",
    )
    require(
        public["wire_length_bytes"] >= public["captured_length_bytes"] >= 0,
        f"{sample_id} returned invalid packet lengths.",
    )
    dns = public["details"].get("dns")
    if dns is not None and dns["qname"] is not None:
        redacted_name = dns["qname"]
        require(
            redacted_name.get("redacted") is True
            and re.fullmatch(r"dns-[0-9a-f]{16}", redacted_name.get("token", "")) is not None,
            f"{sample_id} returned an unredacted DNS name.",
        )
    for field in fields(record):
        require(
            not isinstance(getattr(record, field.name), bytes),
            f"{sample_id} retained bytes in PacketRecord.{field.name}.",
        )
    return public


def validate_evidence(capture: Any, findings: list[Any], sample_id: str) -> None:
    for finding in findings:
        rendered = finding.to_dict()
        require(rendered["method"] == "deterministic", f"{sample_id} method changed.")
        require(rendered["evidence"], f"{sample_id} emitted evidence-free finding.")
        for evidence in finding.evidence:
            require(
                1 <= evidence.packet_number <= len(capture.records),
                f"{sample_id} cited an invalid packet number.",
            )
            record = capture.packet(evidence.packet_number)
            require(
                evidence.time_offset_us == record.time_offset_us,
                f"{sample_id} cited a mismatched timestamp.",
            )
            require(bool(evidence.observation), f"{sample_id} emitted an empty observation.")


def validate_conversation_evidence(
    capture: Any, rows: list[dict[str, Any]], sample_id: str
) -> None:
    packet_numbers: dict[str, set[int]] = {}
    for record in capture.records:
        identifier = conversation_id(record)
        if identifier is not None:
            packet_numbers.setdefault(identifier, set()).add(record.packet_number)
    for row in rows:
        valid = packet_numbers[row["conversation_id"]]
        cited = {
            row["evidence"]["first_packet"],
            row["evidence"]["last_packet"],
            *row["evidence"]["sample_packets"],
        }
        require(cited <= valid, f"{sample_id} conversation evidence crossed a flow.")


def validate_core_sample(
    store: CaptureStore, sample: dict[str, Any], path: Path, temporary_root: Path
) -> dict[str, Any]:
    capture = store.open(str(path))
    manifest = capture.manifest()
    sample_id = sample["id"]
    require(manifest["sha256"] == sample["sha256"], f"{sample_id} parsed hash changed.")
    require(manifest["size_bytes"] == sample["size_bytes"], f"{sample_id} parsed size changed.")
    require(
        manifest["packet_count"] == sample["packet_count"],
        f"{sample_id} packet count changed.",
    )
    require(
        manifest["protocol_counts"] == sample["protocol_counts"],
        f"{sample_id} protocol coverage changed.",
    )
    require(manifest["packet_limit_reached"] is False, f"{sample_id} was truncated.")

    public_records = [validate_packet_shape(record, sample_id) for record in capture.records]
    require(
        [record.packet_number for record in capture.records]
        == list(range(1, len(capture.records) + 1)),
        f"{sample_id} packet numbering changed.",
    )
    require(
        all(record.time_offset_us >= 0 for record in capture.records),
        f"{sample_id} returned a negative time offset.",
    )
    observed_layers = sorted({layer for record in capture.records for layer in record.layers})
    require(observed_layers == sample["layers"], f"{sample_id} layer coverage changed.")
    if "time_offsets_us" in sample:
        require(
            [record.time_offset_us for record in capture.records] == sample["time_offsets_us"],
            f"{sample_id} nanosecond timestamp conversion changed.",
        )
    require(
        sum(record.payload_length for record in capture.records)
        >= sample.get("minimum_payload_bytes", 0),
        f"{sample_id} lost captured payload-length accounting.",
    )

    rows = conversations(capture)
    dns, dns_facts = dns_findings(capture)
    summary = summary_findings(capture)
    tcp = tcp_findings(capture)
    require(len(rows) == sample["conversation_count"], f"{sample_id} flow count changed.")
    require(dns_facts == sample["dns_facts"], f"{sample_id} DNS facts changed.")
    finding_rules = sorted(finding.rule_id for finding in summary)
    require(finding_rules == sample["finding_rules"], f"{sample_id} findings changed.")
    forbidden = set(sample.get("forbidden_finding_rules", []))
    require(forbidden.isdisjoint(finding_rules), f"{sample_id} emitted a forbidden finding.")
    validate_evidence(capture, summary + tcp + dns, sample_id)
    validate_conversation_evidence(capture, rows, sample_id)

    serialized = json.dumps(
        {"manifest": manifest, "packets": public_records, "conversations": rows},
        separators=(",", ":"),
        sort_keys=True,
    )
    require(str(temporary_root) not in serialized, f"{sample_id} exposed its local path.")
    dns_names = source_dns_names(path)
    for qname in dns_names:
        require(qname not in serialized, f"{sample_id} exposed a source DNS name.")

    repeated = store.open(str(path))
    require(
        [record.public() for record in repeated.records] == public_records,
        f"{sample_id} sanitized records were not deterministic within one session.",
    )
    require(
        [finding.to_dict() for finding in summary_findings(repeated)]
        == [finding.to_dict() for finding in summary],
        f"{sample_id} findings were not deterministic.",
    )

    print(
        f"PASS {sample_id}: {len(capture.records)} packets, "
        f"{len(rows)} conversations, {len(summary)} findings"
    )
    return {"source_dns_names": dns_names}


def validate_budget(payload: dict[str, Any], sample_id: str, tool: str) -> None:
    budget = payload.get("budget")
    require(isinstance(budget, dict), f"{sample_id} {tool} omitted its budget.")
    require(
        budget["estimated_tokens"] == estimated_tokens(payload),
        f"{sample_id} {tool} reported an incorrect token estimate.",
    )
    require(
        budget["estimated_tokens"] <= budget["applied_tokens"] <= 2_000,
        f"{sample_id} {tool} exceeded its token budget.",
    )


async def validate_mcp(
    root: Path, samples: list[dict[str, Any]], source_names: dict[str, set[str]]
) -> None:
    settings = Settings(roots=(root,), max_captures=len(samples) + 1)
    server = create_server(settings)
    capture_ids: dict[str, str] = {}

    async with create_connected_server_and_client_session(server) as session:
        listed = await session.list_tools()
        require(len(listed.tools) == 6, "The MCP tool surface is no longer six tools.")
        for sample in samples:
            sample_id = sample["id"]
            opened = await session.call_tool(
                "open_capture", {"path": str(root / sample["filename"]), "max_tokens": 600}
            )
            require(opened.isError is False, f"{sample_id} could not open through MCP.")
            opened_payload = opened.structuredContent
            validate_budget(opened_payload, sample_id, "open_capture")
            require(
                opened_payload["packet_count"] == sample["packet_count"],
                f"{sample_id} MCP packet count changed.",
            )
            capture_id = opened_payload["capture_id"]
            capture_ids[sample_id] = capture_id
            packet_numbers = sorted(
                {1, max(1, sample["packet_count"] // 2), sample["packet_count"]}
            )
            calls = [
                ("summarize_capture", {"capture_id": capture_id, "max_tokens": 2_000}),
                ("list_conversations", {"capture_id": capture_id, "max_tokens": 2_000}),
                (
                    "inspect_packets",
                    {
                        "capture_id": capture_id,
                        "packet_numbers": packet_numbers,
                        "max_tokens": 2_000,
                    },
                ),
                ("analyze_tcp", {"capture_id": capture_id, "max_tokens": 2_000}),
                ("analyze_dns", {"capture_id": capture_id, "max_tokens": 2_000}),
            ]
            for tool, arguments in calls:
                result = await session.call_tool(tool, arguments)
                require(result.isError is False, f"{sample_id} {tool} returned an error.")
                payload = result.structuredContent
                validate_budget(payload, sample_id, tool)
                serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
                require(str(root) not in serialized, f"{sample_id} {tool} exposed its path.")
                for qname in source_names[sample_id]:
                    require(qname not in serialized, f"{sample_id} {tool} exposed a DNS name.")
                for packet in payload.get("packets", []):
                    require(
                        packet["payload"]["redacted"] is True,
                        f"{sample_id} {tool} returned payload content.",
                    )

        mixed_id = "tcpreplay-mixed-workload"
        expected = sample_by_id(samples, mixed_id)["conversation_count"]
        cursor: str | None = None
        identifiers: list[str] = []
        while True:
            result = await session.call_tool(
                "list_conversations",
                {
                    "capture_id": capture_ids[mixed_id],
                    "cursor": cursor,
                    "max_tokens": 500,
                },
            )
            require(result.isError is False, "Public-corpus pagination returned an error.")
            payload = result.structuredContent
            validate_budget(payload, mixed_id, "list_conversations pagination")
            identifiers.extend(item["conversation_id"] for item in payload["conversations"])
            cursor = payload["budget"]["next_cursor"]
            if cursor is None:
                break
        require(len(identifiers) == expected, "Pagination skipped public-corpus conversations.")
        require(len(set(identifiers)) == expected, "Pagination duplicated conversations.")

    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "framecite", "--root", str(root)],
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        require(len(listed.tools) == 6, "Real stdio process exposed the wrong tool count.")
        for filename in ("dhcp-nanosecond.pcapng", "tcp-rst-diagnostic.pcap"):
            result = await session.call_tool("open_capture", {"path": str(root / filename)})
            require(result.isError is False, f"Real stdio process could not open {filename}.")

    print("PASS MCP: all six tools, pagination, budgets, and real stdio")


def sample_by_id(samples: list[dict[str, Any]], identifier: str) -> dict[str, Any]:
    return next(sample for sample in samples if sample["id"] == identifier)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify FrameCite against hash-pinned public PCAP/PCAPNG samples."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = load_manifest(args.manifest.resolve())
    samples: list[dict[str, Any]] = manifest["samples"]
    with tempfile.TemporaryDirectory(prefix="framecite-public-") as temporary:
        root = Path(temporary)
        paths = {
            sample["id"]: download_sample(sample, root, manifest["max_download_bytes"])
            for sample in samples
        }
        store = CaptureStore(
            Settings(roots=(root,), max_captures=len(samples) * 2, max_packets=50_000)
        )
        results = {
            sample["id"]: validate_core_sample(store, sample, paths[sample["id"]], root)
            for sample in samples
        }
        source_names = {
            identifier: result["source_dns_names"] for identifier, result in results.items()
        }
        asyncio.run(validate_mcp(root, samples, source_names))
        total_packets = sum(sample["packet_count"] for sample in samples)
        total_bytes = sum(sample["size_bytes"] for sample in samples)
        print(
            f"Verified {len(samples)} public captures, {total_packets} packets, "
            f"and {total_bytes} downloaded bytes; temporary files deleted."
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CorpusError as exc:
        raise SystemExit(f"Public corpus verification failed: {exc}") from exc
