from __future__ import annotations

from scripts.verify_public_corpus import DEFAULT_MANIFEST, ROOT, load_manifest


def test_public_corpus_manifest_is_metadata_only_and_pinned() -> None:
    manifest = load_manifest(DEFAULT_MANIFEST)

    assert len(manifest["samples"]) == 11
    assert sum(sample["packet_count"] for sample in manifest["samples"]) == 236
    assert sum(sample["size_bytes"] for sample in manifest["samples"]) == 80_191
    assert not list(ROOT.rglob("*.pcap"))
    assert not list(ROOT.rglob("*.pcapng"))
