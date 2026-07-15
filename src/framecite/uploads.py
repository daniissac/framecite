"""Bounded, ephemeral ingestion of extension-provided capture files."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urljoin

import httpx
from pydantic import ConfigDict, with_config
from typing_extensions import Required, TypedDict

from framecite.config import PolicyError, Settings

_CLASSIC_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 2
_MAX_URL_LENGTH = 8_192
_MAX_METADATA_LENGTH = 255
_TOTAL_DOWNLOAD_SECONDS = 30.0


@with_config(ConfigDict(extra="forbid"))
class OpenAIFile(TypedDict, total=False):
    """Exact file object supplied for an OpenAI extension file parameter."""

    download_url: Required[str]
    file_id: Required[str]
    mime_type: str
    file_name: str


@dataclass(frozen=True, slots=True)
class StagedCapture:
    """A private temporary capture that exists only inside its context manager."""

    path: Path
    display_name: str


def _client() -> httpx.Client:
    return httpx.Client(
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "FrameCite-extension-upload/1",
        },
    )


def _validate_metadata(capture_file: OpenAIFile) -> None:
    file_id = capture_file["file_id"]
    if (
        not file_id
        or len(file_id) > _MAX_METADATA_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in file_id)
    ):
        raise PolicyError("The extension file identifier is invalid.")
    for field in ("mime_type", "file_name"):
        value = capture_file.get(field)
        if value is not None and (
            len(value) > _MAX_METADATA_LENGTH
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise PolicyError("Extension file metadata is invalid.")


def _validate_url(raw_url: str, settings: Settings) -> str:
    if (
        not raw_url
        or len(raw_url) > _MAX_URL_LENGTH
        or not raw_url.isascii()
        or any(ord(character) < 32 or ord(character) == 127 for character in raw_url)
    ):
        raise PolicyError("The extension download URL is invalid.")
    try:
        parsed = httpx.URL(raw_url)
    except (httpx.InvalidURL, UnicodeError, ValueError):
        raise PolicyError("The extension download URL is invalid.") from None
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.host.endswith(".")
        or parsed.userinfo
        or parsed.fragment
        or parsed.port not in (None, 443)
        or not settings.permits_extension_upload_host(parsed.host)
    ):
        raise PolicyError("The extension download URL is outside the trusted HTTPS hosts.")
    return str(parsed)


def _declared_length(response: httpx.Response, maximum: int) -> int | None:
    raw_length = response.headers.get("Content-Length")
    if raw_length is None:
        return None
    try:
        length = int(raw_length)
    except ValueError:
        raise PolicyError("The extension response has an invalid content length.") from None
    if length < 0 or length > maximum:
        raise PolicyError("The extension capture exceeds the configured file-size limit.")
    return length


def _capture_suffix(path: Path) -> str:
    with path.open("rb") as uploaded:
        magic = uploaded.read(4)
    if magic in _CLASSIC_PCAP_MAGICS:
        return ".pcap"
    if magic == _PCAPNG_MAGIC:
        return ".pcapng"
    raise PolicyError("The extension file is not a PCAP or PCAPNG capture.")


def _download(
    client: httpx.Client,
    capture_file: OpenAIFile,
    settings: Settings,
    destination: Path,
) -> None:
    current_url = _validate_url(capture_file["download_url"], settings)
    deadline = time.monotonic() + _TOTAL_DOWNLOAD_SECONDS

    for redirect_count in range(_MAX_REDIRECTS + 1):
        if time.monotonic() >= deadline:
            raise PolicyError("The extension capture download timed out.")
        try:
            with client.stream("GET", current_url) as response:
                if response.status_code in _REDIRECT_STATUSES:
                    if redirect_count >= _MAX_REDIRECTS:
                        raise PolicyError("The extension capture exceeded the redirect limit.")
                    location = response.headers.get("Location")
                    if not location:
                        raise PolicyError("The extension response has an invalid redirect.")
                    current_url = _validate_url(urljoin(current_url, location), settings)
                    continue
                if response.status_code != 200:
                    raise PolicyError("The extension capture could not be downloaded.")
                if response.headers.get("Content-Range") is not None:
                    raise PolicyError("Partial extension responses are not accepted.")
                encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
                if encoding not in {"", "identity"}:
                    raise PolicyError("Compressed extension responses are not accepted.")
                declared = _declared_length(response, settings.max_file_bytes)
                received = 0
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    with os.fdopen(descriptor, "wb") as output:
                        for chunk in response.iter_bytes():
                            if time.monotonic() >= deadline:
                                raise PolicyError("The extension capture download timed out.")
                            received += len(chunk)
                            if received > settings.max_file_bytes:
                                raise PolicyError(
                                    "The extension capture exceeds the configured file-size limit."
                                )
                            output.write(chunk)
                except BaseException:
                    destination.unlink(missing_ok=True)
                    raise
                if declared is not None and received != declared:
                    destination.unlink(missing_ok=True)
                    raise PolicyError("The extension response size changed during download.")
                return
        except PolicyError:
            raise
        except (httpx.HTTPError, httpx.InvalidURL, OSError, TimeoutError, UnicodeError):
            raise PolicyError("The extension capture could not be downloaded safely.") from None

    raise PolicyError("The extension capture could not be downloaded.")


@contextmanager
def stage_extension_capture(
    capture_file: OpenAIFile,
    settings: Settings,
) -> Iterator[StagedCapture]:
    """Download one authorized file reference, yield it privately, then delete it."""

    if not settings.allow_extension_uploads:
        raise PolicyError("Extension capture uploads are disabled by the server operator.")
    _validate_metadata(capture_file)

    with TemporaryDirectory(prefix="framecite-upload-") as temporary:
        partial = Path(temporary) / "capture.download"
        with _client() as client:
            _download(client, capture_file, settings, partial)
        suffix = _capture_suffix(partial)
        capture_path = partial.with_name(f"uploaded{suffix}")
        partial.replace(capture_path)
        yield StagedCapture(path=capture_path, display_name=capture_path.name)
