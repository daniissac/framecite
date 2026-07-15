from __future__ import annotations

import stat
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

import framecite.uploads as upload_module
from framecite.config import PolicyError, Settings
from framecite.uploads import OpenAIFile, stage_extension_capture

UPLOAD_URL = "https://files.oaiusercontent.com/capture?token=do-not-expose"


def _reference(**overrides: str) -> OpenAIFile:
    reference: OpenAIFile = {
        "download_url": UPLOAD_URL,
        "file_id": "file_capture_123",
    }
    reference.update(overrides)  # type: ignore[typeddict-item]
    return reference


def _mock_client(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        upload_module,
        "_client",
        lambda: httpx.Client(
            transport=transport,
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
        ),
    )


def test_extension_upload_is_private_and_ephemeral(
    monkeypatch: pytest.MonkeyPatch, capture_path: Path
) -> None:
    body = capture_path.read_bytes()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"Content-Length": str(len(body))}, content=body)

    _mock_client(monkeypatch, handler)
    settings = Settings(roots=())

    with stage_extension_capture(_reference(file_name="private-name.pcap"), settings) as staged:
        staged_path = staged.path
        staged_parent = staged.path.parent
        assert staged.display_name == "uploaded.pcap"
        assert staged.path.read_bytes() == body
        assert stat.S_IMODE(staged.path.stat().st_mode) == 0o600

    assert len(requests) == 1
    assert requests[0].headers["accept-encoding"] == "identity"
    assert not staged_path.exists()
    assert not staged_parent.exists()


@pytest.mark.parametrize(
    ("magic", "suffix"),
    [
        (b"\xd4\xc3\xb2\xa1", ".pcap"),
        (b"\xa1\xb2\xc3\xd4", ".pcap"),
        (b"\x4d\x3c\xb2\xa1", ".pcap"),
        (b"\xa1\xb2\x3c\x4d", ".pcap"),
        (b"\x0a\x0d\x0d\x0a", ".pcapng"),
    ],
)
def test_all_capture_magics_are_recognized(
    monkeypatch: pytest.MonkeyPatch, magic: bytes, suffix: str
) -> None:
    _mock_client(monkeypatch, lambda request: httpx.Response(200, content=magic + b"fixture"))

    with stage_extension_capture(_reference(), Settings(roots=())) as staged:
        assert staged.path.suffix == suffix


@pytest.mark.parametrize(
    "url",
    [
        "http://files.oaiusercontent.com/capture",
        "https://user@files.oaiusercontent.com/capture",
        "https://files.oaiusercontent.com:444/capture",
        "https://files.oaiusercontent.com/capture#fragment",
        "https://files.oaiusercontent.com./capture",
        "https://sub.files.oaiusercontent.com/capture",
        "https://files.oaiusercontent.com.evil.example/capture",
        "https://localhost/capture",
        "https://127.0.0.1/capture",
        "https://faß.de/capture",
        "https://files.oaiusercontent.com/\ud800",
    ],
)
def test_untrusted_download_urls_are_rejected(url: str) -> None:
    with (
        pytest.raises(PolicyError, match="invalid|trusted HTTPS hosts"),
        stage_extension_capture(_reference(download_url=url), Settings(roots=())),
    ):
        pass


def test_operator_can_configure_an_exact_alternate_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"\xd4\xc3\xb2\xa1fixture"
    _mock_client(monkeypatch, lambda request: httpx.Response(200, content=body))
    settings = Settings(roots=(), extension_upload_hosts=("uploads.example.com",))
    reference = _reference(download_url="https://uploads.example.com/file")

    with stage_extension_capture(reference, settings) as staged:
        assert staged.path.suffix == ".pcap"


def test_unicode_hostname_cannot_alias_an_ascii_allowlist() -> None:
    settings = Settings(roots=(), extension_upload_hosts=("fass.de",))
    reference = _reference(download_url="https://faß.de/file")

    with (
        pytest.raises(PolicyError, match="invalid"),
        stage_extension_capture(reference, settings),
    ):
        pass


def test_relative_redirect_is_revalidated_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"\xd4\xc3\xb2\xa1fixture"
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path == "/capture":
            return httpx.Response(302, headers={"Location": "/authorized-download"})
        return httpx.Response(200, content=body)

    _mock_client(monkeypatch, handler)
    with stage_extension_capture(_reference(), Settings(roots=())):
        pass

    assert seen == [UPLOAD_URL, "https://files.oaiusercontent.com/authorized-download"]


@pytest.mark.parametrize(
    "location",
    [
        "http://files.oaiusercontent.com/file",
        "https://evil.example/file",
        "https://sub.files.oaiusercontent.com/file",
    ],
)
def test_redirects_cannot_escape_the_trusted_origin(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    _mock_client(
        monkeypatch,
        lambda request: httpx.Response(302, headers={"Location": location}),
    )

    with (
        pytest.raises(PolicyError, match="trusted HTTPS hosts"),
        stage_extension_capture(_reference(), Settings(roots=())),
    ):
        pass


def test_redirect_loop_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_client(
        monkeypatch,
        lambda request: httpx.Response(302, headers={"Location": "/capture"}),
    )

    with (
        pytest.raises(PolicyError, match="redirect limit"),
        stage_extension_capture(_reference(), Settings(roots=())),
    ):
        pass


@pytest.mark.parametrize(
    ("status", "headers", "body", "message"),
    [
        (206, {}, b"\xd4\xc3\xb2\xa1fixture", "could not be downloaded"),
        (200, {"Content-Range": "bytes 0-7/8"}, b"fixture", "Partial"),
        (200, {"Content-Encoding": "gzip"}, b"fixture", "Compressed"),
        (200, {"Content-Length": "invalid"}, b"fixture", "content length"),
        (200, {"Content-Length": "11"}, b"fixture", "file-size limit"),
    ],
)
def test_unsafe_http_responses_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    headers: dict[str, str],
    body: bytes,
    message: str,
) -> None:
    _mock_client(
        monkeypatch,
        lambda request: httpx.Response(
            status,
            headers=headers,
            stream=httpx.ByteStream(body),
        ),
    )

    with (
        pytest.raises(PolicyError, match=message),
        stage_extension_capture(_reference(), Settings(roots=(), max_file_bytes=10)),
    ):
        pass


def test_streaming_size_limit_does_not_require_content_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=iter([b"123456", b"78901"]))

    _mock_client(monkeypatch, handler)
    with (
        pytest.raises(PolicyError, match="file-size limit"),
        stage_extension_capture(_reference(), Settings(roots=(), max_file_bytes=10)),
    ):
        pass


def test_network_errors_are_generic_and_do_not_expose_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("failure containing token=do-not-expose", request=request)

    _mock_client(monkeypatch, handler)
    reference = _reference(file_id="file-secret-identifier", file_name="secret-name.pcap")

    with (
        pytest.raises(PolicyError) as raised,
        stage_extension_capture(reference, Settings(roots=())),
    ):
        pass

    rendered = str(raised.value)
    assert "do-not-expose" not in rendered
    assert "file-secret-identifier" not in rendered
    assert "secret-name.pcap" not in rendered


def test_invalid_magic_is_rejected_and_temporary_file_is_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, lambda request: httpx.Response(200, content=b"not-a-capture"))

    with (
        pytest.raises(PolicyError, match="not a PCAP"),
        stage_extension_capture(_reference(), Settings(roots=())),
    ):
        pass


def test_uploads_can_be_disabled_by_the_operator() -> None:
    settings = Settings(roots=(Path.cwd(),), allow_extension_uploads=False)
    with (
        pytest.raises(PolicyError, match="disabled"),
        stage_extension_capture(_reference(), settings),
    ):
        pass
