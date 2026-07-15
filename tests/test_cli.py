from __future__ import annotations

import subprocess
import sys

import pytest

import framecite.cli as cli_module


def test_cli_help_documents_both_ingestion_routes() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "framecite", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "--root" in completed.stdout
    assert "--extension-uploads" in completed.stdout
    assert "--no-extension-uploads" in completed.stdout
    assert "--extension-upload-host" in completed.stdout
    assert "stdio" in completed.stdout


def test_cli_accepts_upload_only_mode_without_root(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    class Server:
        def run(self, *, transport: str) -> None:
            observed["transport"] = transport

    def create_server(settings):
        observed["settings"] = settings
        return Server()

    monkeypatch.setattr(cli_module, "create_server", create_server)

    assert cli_module.main([]) == 0
    settings = observed["settings"]
    assert settings.roots == ()
    assert settings.allow_extension_uploads is True
    assert observed["transport"] == "stdio"


def test_cli_refuses_to_disable_every_ingestion_route() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "framecite", "--no-extension-uploads"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "extension uploads" in completed.stderr


def test_registry_boolean_can_disable_extension_uploads() -> None:
    args = cli_module.build_parser().parse_args(["--extension-uploads=false"])
    assert args.extension_uploads is False
