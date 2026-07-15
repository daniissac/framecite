"""Console entry point for the local stdio MCP server."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from framecite import __version__
from framecite.config import PolicyError, Settings
from framecite.server import create_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="framecite",
        description="Run the local, evidence-first FrameCite MCP server over stdio.",
    )
    parser.add_argument(
        "--root",
        action="append",
        required=True,
        type=Path,
        help="Allowed capture directory. Repeat to allow another directory.",
    )
    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=100,
        help="Maximum capture size in MiB (default: 100).",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=50_000,
        help="Maximum packets retained per capture (default: 50000).",
    )
    parser.add_argument(
        "--max-captures",
        type=int,
        default=4,
        help="Maximum sanitized captures retained in memory (default: 4).",
    )
    parser.add_argument("--version", action="version", version=f"FrameCite {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    try:
        settings = Settings(
            roots=tuple(args.root),
            max_file_bytes=args.max_file_mb * 1024 * 1024,
            max_packets=args.max_packets,
            max_captures=args.max_captures,
        )
    except PolicyError as exc:
        build_parser().error(str(exc))
    create_server(settings).run(transport="stdio")
    return 0
