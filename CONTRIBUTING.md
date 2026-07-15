# Contributing to FrameCite

Thank you for helping make packet troubleshooting safer and more reproducible.

## Before opening a change

- Keep the MCP tool surface small and read-only.
- Prefer deterministic facts over heuristic labels.
- Give every generated conclusion at least one valid packet-number citation.
- Never add a raw-payload return path, live capture, packet injection, shell command, or general-purpose runtime network client. Extension-file retrieval must remain the single audited, bounded network path.
- Reproduce packet behavior with synthetic Scapy fixtures; never commit a private capture.
- Keep public-corpus entries metadata-only, pinned to immutable upstream revisions, and accompanied by exact size, SHA-256, source, and license links.

## Local checks

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest
python -m build
```

Add tests for normal behavior, malformed input, boundaries, privacy, output budgets, and MCP schemas whenever they are relevant.

The optional networked compatibility check is `python scripts/verify_public_corpus.py`. It downloads verified upstream captures only into a temporary directory and deletes them after the run. Do not add public or private capture files to the repository or upload them as workflow artifacts.
