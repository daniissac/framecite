from __future__ import annotations

import ast
from pathlib import Path


def test_runtime_has_no_network_shell_or_capture_primitives() -> None:
    source_root = Path(__file__).parents[1] / "src" / "framecite"
    banned_modules = {"httpx", "requests", "socket", "subprocess"}
    banned_scapy_names = {"send", "sendp", "sniff", "sr", "sr1", "srp", "srp1", "wrpcap"}

    for source_file in source_root.glob("*.py"):
        tree = ast.parse(source_file.read_text(), filename=str(source_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = {alias.name.split(".")[0] for alias in node.names}
                assert imported.isdisjoint(banned_modules), source_file
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]
                assert module not in banned_modules, source_file
                if module == "scapy":
                    names = {alias.name for alias in node.names}
                    assert names.isdisjoint(banned_scapy_names), source_file
