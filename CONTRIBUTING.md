# Contributing to FrameCite

Thank you for helping make packet troubleshooting safer and more reproducible.

## Before opening a change

- Keep the MCP tool surface small and read-only.
- Prefer deterministic facts over heuristic labels.
- Give every generated conclusion at least one valid packet-number citation.
- Never add a raw-payload return path, live capture, packet injection, shell command, or runtime network dependency.
- Reproduce packet behavior with synthetic Scapy fixtures; never commit a private capture.

## Local checks

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest
python -m build
```

Add tests for normal behavior, malformed input, boundaries, privacy, output budgets, and MCP schemas whenever they are relevant.
