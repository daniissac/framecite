"""Strict schemas for FrameCite's bounded structured tool results."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import NotRequired, TypedDict


class StrictOutput(BaseModel):
    """Reject coercion and undeclared fields when FastMCP validates a result."""

    model_config = ConfigDict(extra="forbid", strict=True)


class BudgetOutput(StrictOutput):
    requested_tokens: int = Field(ge=256)
    applied_tokens: int = Field(ge=256, le=2_000)
    estimated_tokens: int = Field(ge=1)
    truncated: bool
    omitted_items: int = Field(ge=0)
    next_cursor: str | None


class CaptureManifestOutput(StrictOutput):
    capture_id: str
    filename: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    packet_count: int = Field(ge=0)
    duration_us: int = Field(ge=0)
    timestamp_regressions: int = Field(ge=0)
    protocol_counts: dict[str, int]
    endpoint_count: int = Field(ge=0)
    payloads_redacted: Literal[True]
    packet_limit_reached: bool


class EvidenceOutput(StrictOutput):
    packet_number: int = Field(ge=1)
    time_offset_us: int
    observation: str


class FindingOutput(StrictOutput):
    rule_id: str
    level: Literal["info", "warning"]
    conclusion: str
    evidence: list[EvidenceOutput] = Field(min_length=1, max_length=8)
    limitations: list[str]
    method: Literal["deterministic"]


class ConversationEvidenceOutput(StrictOutput):
    first_packet: int = Field(ge=1)
    last_packet: int = Field(ge=1)
    sample_packets: list[int] = Field(min_length=1, max_length=8)


class ConversationOutput(StrictOutput):
    conversation_id: str
    protocol: Literal["TCP", "UDP"]
    endpoint_a: str
    endpoint_b: str
    packet_count: int = Field(ge=1)
    captured_bytes: int = Field(ge=0)
    wire_bytes: int = Field(ge=0)
    first_time_offset_us: int
    last_time_offset_us: int
    evidence: ConversationEvidenceOutput


class PayloadOutput(StrictOutput):
    redacted: Literal[True]
    length_bytes: int = Field(ge=0)


class TcpDetailsOutput(StrictOutput):
    flags: str
    sequence: int | None
    acknowledgment: int | None
    window: int | None


class DnsNameOutput(StrictOutput):
    redacted: Literal[True]
    token: str = Field(pattern=r"^dns-[0-9a-f]{16}$")
    length_chars: int | None
    label_count: int | None


class DnsDetailsOutput(StrictOutput):
    id: int
    is_response: bool | None
    rcode: int | None
    qname: DnsNameOutput | None
    qtype: int | None
    qclass: int | None


class IcmpDetailsOutput(StrictOutput):
    version: Literal[4, 6] | None
    type: int
    code: int | None


class PacketDetailsOutput(TypedDict):
    __pydantic_config__ = ConfigDict(extra="forbid", strict=True)

    tcp: NotRequired[TcpDetailsOutput]
    dns: NotRequired[DnsDetailsOutput]
    icmp: NotRequired[IcmpDetailsOutput]


class PacketOutput(StrictOutput):
    packet_number: int = Field(ge=1)
    time_offset_us: int
    captured_length_bytes: int = Field(ge=0)
    wire_length_bytes: int = Field(ge=0)
    layers: list[str]
    protocol: str
    source: str | None
    destination: str | None
    details: PacketDetailsOutput
    payload: PayloadOutput


class DnsFactsOutput(StrictOutput):
    dns_packets: int = Field(ge=0)
    queries: int = Field(ge=0)
    responses: int = Field(ge=0)
    multicast_dns_packets: int = Field(ge=0)


class QnameFilterOutput(StrictOutput):
    redacted: Literal[True]
    token: str = Field(pattern=r"^dns-[0-9a-f]{16}$")


class OpenCaptureOutput(CaptureManifestOutput):
    budget: BudgetOutput


class SummarizeCaptureOutput(StrictOutput):
    capture_id: str
    facts: CaptureManifestOutput
    findings: list[FindingOutput]
    budget: BudgetOutput


class ListConversationsOutput(StrictOutput):
    capture_id: str
    protocol_filter: Literal["any", "tcp", "udp"]
    conversations: list[ConversationOutput]
    budget: BudgetOutput


class InspectPacketsOutput(StrictOutput):
    capture_id: str
    packets: list[PacketOutput]
    budget: BudgetOutput


class AnalyzeTcpOutput(StrictOutput):
    capture_id: str
    conversation_id: str | None
    tcp_packet_count: int = Field(ge=0)
    findings: list[FindingOutput]
    budget: BudgetOutput


class AnalyzeDnsOutput(StrictOutput):
    capture_id: str
    qname_filter: QnameFilterOutput | None
    facts: DnsFactsOutput
    findings: list[FindingOutput]
    budget: BudgetOutput
