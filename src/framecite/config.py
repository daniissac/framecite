"""Server policy for local paths and extension-provided capture files."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from os import stat_result
from pathlib import Path


class PolicyError(ValueError):
    """Raised when a capture violates a configured safety policy."""


def _is_ipv4_numeric_alias(host: str) -> bool:
    """Recognize legacy inet_aton forms without performing resolution or network I/O."""

    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return False
    values: list[int] = []
    for part in parts:
        lowered = part.lower()
        if lowered.startswith("0x"):
            digits, base = lowered[2:], 16
        elif len(lowered) > 1 and lowered.startswith("0"):
            digits, base = lowered[1:], 8
        else:
            digits, base = lowered, 10
        if not digits:
            return False
        try:
            values.append(int(digits, base))
        except ValueError:
            return False
    final_limit = (1 << (8 * (5 - len(values)))) - 1
    return all(value <= 255 for value in values[:-1]) and values[-1] <= final_limit


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable safety limits chosen by the person starting the server."""

    roots: tuple[Path, ...] = ()
    max_file_bytes: int = 100 * 1024 * 1024
    max_packets: int = 50_000
    max_captures: int = 4
    allow_extension_uploads: bool = True
    extension_upload_hosts: tuple[str, ...] = ("files.oaiusercontent.com",)

    def __post_init__(self) -> None:
        if self.max_file_bytes < 1 or self.max_packets < 1 or self.max_captures < 1:
            raise PolicyError("All safety limits must be positive integers.")
        if not self.roots and not self.allow_extension_uploads:
            raise PolicyError("Enable extension uploads or configure at least one capture root.")

        normalized: list[Path] = []
        for root in self.roots:
            resolved = root.expanduser().resolve(strict=True)
            if not resolved.is_dir():
                raise PolicyError("Every configured root must be an existing directory.")
            normalized.append(resolved)
        object.__setattr__(self, "roots", tuple(normalized))

        normalized_hosts: list[str] = []
        for host in self.extension_upload_hosts:
            normalized_host = self._normalize_upload_host(host)
            if normalized_host not in normalized_hosts:
                normalized_hosts.append(normalized_host)
        if self.allow_extension_uploads and not normalized_hosts:
            raise PolicyError("Extension uploads require at least one trusted download host.")
        object.__setattr__(self, "extension_upload_hosts", tuple(normalized_hosts))

    @staticmethod
    def _normalize_upload_host(raw_host: str) -> str:
        """Normalize one exact HTTPS host without accepting URLs, ports, or IP literals."""

        candidate = raw_host.strip()
        if not candidate.isascii():
            raise PolicyError("Every extension upload host must use an ASCII DNS name.")
        host = candidate.rstrip(".").lower()
        if not host or len(host) > 253 or any(mark in host for mark in ("://", "/", "@", ":")):
            raise PolicyError("Every extension upload host must be a bare DNS hostname.")
        labels = host.split(".")
        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            raise PolicyError("Every extension upload host must be a valid DNS hostname.")
        if _is_ipv4_numeric_alias(host):
            raise PolicyError("Extension upload hosts cannot be IP literals or numeric aliases.")
        return host

    def permits_extension_upload_host(self, host: str) -> bool:
        """Return whether a URL hostname exactly matches an operator-approved host."""

        try:
            normalized = self._normalize_upload_host(host)
        except PolicyError:
            return False
        return normalized in self.extension_upload_hosts

    def resolve_capture(self, raw_path: str) -> tuple[Path, stat_result]:
        """Resolve and validate a capture without exposing configured paths in errors."""

        if not self.roots:
            raise PolicyError("Local capture paths are disabled; attach a capture file instead.")

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
