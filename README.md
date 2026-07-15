# FrameCite

[![CI](https://github.com/daniissac/framecite/actions/workflows/ci.yml/badge.svg)](https://github.com/daniissac/framecite/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP: stdio](https://img.shields.io/badge/MCP-stdio-5b5bd6.svg)](https://modelcontextprotocol.io/)

**Local PCAP troubleshooting with packet-level citations.**

FrameCite is a deliberately small Model Context Protocol server that turns packet captures into bounded facts and deterministic troubleshooting findings. It uses Scapy directly—no Wireshark, TShark, cloud service, embedded chat UI, or model API key.

<!-- mcp-name: io.github.daniissac/framecite -->

> [!IMPORTANT]
> Packet captures can contain credentials, private addresses, personal data, and proprietary traffic. FrameCite processes only local files beneath directories you explicitly allow. Raw payload bytes are discarded during ingestion and can never be returned by its MCP tools.

## Why FrameCite

- **No Wireshark/TShark dependency:** streaming PCAP and PCAPNG parsing uses Scapy.
- **Local-only by default:** the server exposes only MCP `stdio`; it has no HTTP transport or runtime network client.
- **Payload redaction is mandatory:** tools return allowlisted headers plus payload length, never payload content.
- **Token-budgeted output:** every tool applies a conservative UTF-8 JSON budget and paginates only at whole-item boundaries.
- **Packet-level evidence:** every generated conclusion contains one or more 1-based packet citations.
- **Small, safe surface:** six read-only troubleshooting tools; no capture, injection, shell, arbitrary filter, write, or raw-byte tools.
- **Synthetic verification:** tests generate known PCAP and PCAPNG scenarios for TCP, DNS, ICMP, IPv6, VLAN, privacy, path confinement, evidence, and MCP behavior.

![FrameCite architecture](docs/architecture.svg)

## Start in one command

Until the first PyPI release, run directly from GitHub with [`uvx`](https://docs.astral.sh/uv/guides/tools/):

```bash
uvx --from git+https://github.com/daniissac/framecite framecite --root /absolute/path/to/captures
```

The `--root` option is required. Repeat it to allow another capture directory. FrameCite resolves symlinks before enforcing those boundaries.

An MCP client configuration uses the same command:

```json
{
  "mcpServers": {
    "framecite": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/daniissac/framecite",
        "framecite",
        "--root",
        "/absolute/path/to/captures"
      ]
    }
  }
}
```

After the PyPI release, the command becomes `uvx framecite --root /absolute/path/to/captures`.

## MCP surface

| Tool | Purpose |
|---|---|
| `open_capture` | Stream one allowed PCAP/PCAPNG into a bounded, payload-free in-memory model. |
| `summarize_capture` | Return capture facts and prioritized deterministic findings. |
| `list_conversations` | List TCP/UDP conversations with first, last, and sampled packet evidence. |
| `inspect_packets` | Inspect up to 50 explicit 1-based packets using allowlisted headers. |
| `analyze_tcp` | Check resets, zero windows, SYN repeats, missing SYN-ACKs, and repeated sequence ranges. |
| `analyze_dns` | Check response codes, matching responses, and repeated identical queries. |

FrameCite also provides sanitized manifest and packet resources under `framecite://` plus a `triage_capture` prompt that requires the host model to distinguish fact from inference and cite `[packet N]`.

### Evidence shape

```json
{
  "rule_id": "tcp-reset",
  "level": "warning",
  "conclusion": "1 TCP reset packet(s) were observed.",
  "evidence": [
    {
      "packet_number": 7,
      "time_offset_us": 60000,
      "observation": "TCP RST flag is set."
    }
  ],
  "limitations": [],
  "method": "deterministic"
}
```

Findings are capture-bounded observations, not proof of root cause. FrameCite explicitly reports boundary limitations where missing traffic or asymmetric capture could change an interpretation.

## Safety limits

The person starting the server controls limits; the model cannot increase them:

```text
--root PATH          required; repeatable allowed directory
--max-file-mb 100    maximum capture size
--max-packets 50000  maximum packets retained per capture
--max-captures 4     maximum sanitized captures in memory
```

Additional guarantees:

- Only regular `.pcap` and `.pcapng` files are accepted.
- Paths are confined after strict resolution, blocking traversal and symlink escape.
- Files are re-checked after parsing and rejected if they changed.
- Raw Scapy packets and payload bytes are never retained in the capture cache.
- Tool budgets accept 256–2,000 tokens; smaller requests fail explicitly and larger requests are capped.
- DNS names and decoded metadata are treated as untrusted, stripped of controls, and length-limited.
- Tool annotations declare read-only, non-destructive, closed-world behavior; repeatable analysis calls are also marked idempotent. The code enforces the restrictions independently.
- Logs use standard error so they cannot corrupt MCP `stdio` messages.

See [SECURITY.md](SECURITY.md) for the threat model and reporting process.

## Known limits

- Scapy is not a replacement for Wireshark's full dissector collection or TCP reassembly engine.
- Encrypted payloads such as TLS and DoH remain opaque.
- A capture may begin or end mid-conversation, omit one direction, or contain duplicate packets.
- Token counts are conservative estimates because the server does not know the host model's tokenizer.
- FrameCite analyzes existing files only; it intentionally does not perform live capture.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest
python -m build
```

Tests run with internet sockets disabled. Synthetic fixtures include secrets and prompt-injection text so every MCP result and resource can be checked for leakage without publishing a real capture.

## Contributing

Focused issues and pull requests are welcome. Do not attach real or sensitive packet captures to public issues; add a minimal synthetic fixture instead. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
