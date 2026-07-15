from __future__ import annotations

import ast
from pathlib import Path


def test_runtime_networking_is_confined_to_extension_file_ingress() -> None:
    source_root = Path(__file__).parents[1] / "src" / "framecite"
    banned_modules = {"requests", "socket", "subprocess"}
    banned_url_modules = {"urllib.error", "urllib.request"}
    banned_scapy_names = {"send", "sendp", "sniff", "sr", "sr1", "srp", "srp1", "wrpcap"}
    network_importers: set[str] = set()

    for source_file in source_root.glob("*.py"):
        tree = ast.parse(source_file.read_text(), filename=str(source_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                full_imports = {alias.name for alias in node.names}
                imported = {name.split(".")[0] for name in full_imports}
                assert imported.isdisjoint(banned_modules), source_file
                assert full_imports.isdisjoint(banned_url_modules), source_file
                if "httpx" in imported:
                    network_importers.add(source_file.name)
            elif isinstance(node, ast.ImportFrom):
                full_module = node.module or ""
                module = full_module.split(".")[0]
                assert module not in banned_modules, source_file
                assert full_module not in banned_url_modules, source_file
                if module == "scapy":
                    names = {alias.name for alias in node.names}
                    assert names.isdisjoint(banned_scapy_names), source_file

    assert network_importers == {"uploads.py"}
