from __future__ import annotations

import pytest

from framecite.budget import budgeted_items, budgeted_mapping, estimated_tokens


def test_item_budget_prunes_only_at_item_boundaries() -> None:
    items = [{"packet_number": number, "observation": "x" * 90} for number in range(1, 30)]
    payload = budgeted_items(
        base={"capture_id": "test"},
        item_key="findings",
        items=items,
        start_offset=0,
        requested_tokens=300,
        make_cursor=lambda offset: f"cursor-{offset}",
    )
    assert 0 < len(payload["findings"]) < len(items)
    assert payload["budget"]["truncated"] is True
    assert payload["budget"]["next_cursor"]
    assert estimated_tokens(payload) <= payload["budget"]["applied_tokens"]


def test_mapping_budget_is_conservative() -> None:
    payload = budgeted_mapping({"fact": "small"}, 256)
    assert estimated_tokens(payload) <= 256
    assert payload["budget"]["estimated_tokens"] == estimated_tokens(payload)


def test_non_positive_budget_is_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        budgeted_mapping({"fact": "small"}, 0)


def test_budget_below_supported_minimum_is_rejected_instead_of_raised() -> None:
    with pytest.raises(ValueError, match="at least 256"):
        budgeted_mapping({"fact": "small"}, 255)


def test_empty_item_page_never_returns_an_over_budget_base() -> None:
    with pytest.raises(ValueError, match="fixed response"):
        budgeted_items(
            base={"qname_filter": "\U0001f510" * 255},
            item_key="findings",
            items=[],
            start_offset=0,
            requested_tokens=256,
            make_cursor=lambda offset: f"cursor-{offset}",
        )
