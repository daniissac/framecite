"""Server policy and local-file confinement."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from os import stat_result
from pathlib import Path


class PolicyError(ValueError):
    """Raised when a capture violates a configured safety policy."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable safety limits chosen by the person starting the server."""

    roots: tuple[Path, ...]
    max_file_bytes: int = 100 * 1024 * 1024
    max_packets: int = 50_000
    max_captures: int = 4

    def __post_init__(self) -> None:
        if not self.roots:
            raise PolicyError("At least one capture root is required.")
        if self.max_file_bytes < 1 or self.max_packets < 1 or self.max_captures < 1:
            raise PolicyError("All safety limits must be positive integers.")

        normalized: list[Path] = []
        for root in self.roots:
            resolved = root.expanduser().resolve(strict=True)
            if not resolved.is_dir():
                raise PolicyError("Every configured root must be an existing directory.")
            normalized.append(resolved)
        object.__setattr__(self, "roots", tuple(normalized))

    def resolve_capture(self, raw_path: str) -> tuple[Path, stat_result]:
        """Resolve and validate a capture without exposing configured paths in errors."""

        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate

        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise PolicyError("Capture file does not exist or cannot be resolved.") from exc

        if not any(resolved == root or resolved.is_relative_to(root) for root in self.roots):
            raise PolicyError("Capture path is outside the configured roots.")

        try:
            file_stat = resolved.stat()
        except OSError as exc:
            raise PolicyError("Capture file cannot be inspected.") from exc

        if not stat.S_ISREG(file_stat.st_mode):
            raise PolicyError("Capture path must identify a regular file.")
        if resolved.suffix.lower() not in {".pcap", ".pcapng"}:
            raise PolicyError("Only .pcap and .pcapng files are accepted.")
        if file_stat.st_size > self.max_file_bytes:
            raise PolicyError("Capture exceeds the configured file-size limit.")

        return resolved, file_stat
