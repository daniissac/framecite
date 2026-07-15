"""Conservative, tokenizer-independent JSON output budgeting."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Sequence
from typing import Any

MIN_TOKEN_BUDGET = 256
MAX_TOKEN_BUDGET = 2_000
BYTES_PER_TOKEN_ESTIMATE = 3


def estimated_tokens(value: object) -> int:
    """Estimate tokens conservatively from compact UTF-8 JSON."""

    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return max(1, math.ceil(len(encoded) / BYTES_PER_TOKEN_ESTIMATE))


def _stabilize_estimate(payload: dict[str, Any]) -> dict[str, Any]:
    for _ in range(8):
        current = estimated_tokens(payload)
        if payload["budget"]["estimated_tokens"] == current:
            break
        payload["budget"]["estimated_tokens"] = current
    return payload


def clamp_budget(requested_tokens: int) -> int:
    if requested_tokens < 1:
        raise ValueError("max_tokens must be a positive integer.")
    if requested_tokens < MIN_TOKEN_BUDGET:
        raise ValueError(f"max_tokens must be at least {MIN_TOKEN_BUDGET} tokens.")
    return min(requested_tokens, MAX_TOKEN_BUDGET)


def budgeted_items(
    *,
    base: dict[str, Any],
    item_key: str,
    items: Sequence[dict[str, Any]],
    start_offset: int,
    requested_tokens: int,
    make_cursor: Callable[[int], str],
) -> dict[str, Any]:
    """Add whole items until the conservative JSON budget is reached."""

    applied = clamp_budget(requested_tokens)
    selected: list[dict[str, Any]] = []

    def build(current: list[dict[str, Any]], *, estimate: int = 0) -> dict[str, Any]:
        next_offset = start_offset + len(current)
        truncated = len(current) < len(items)
        payload = {
            **base,
            item_key: current,
            "budget": {
                "requested_tokens": requested_tokens,
                "applied_tokens": applied,
                "estimated_tokens": estimate,
                "truncated": truncated,
                "omitted_items": len(items) - len(current),
                "next_cursor": make_cursor(next_offset) if truncated and current else None,
            },
        }
        return payload

    for item in items:
        candidate = build([*selected, item])
        if estimated_tokens(candidate) > applied:
            break
        selected.append(item)

    payload = build(selected)
    _stabilize_estimate(payload)

    while selected and estimated_tokens(payload) > applied:
        selected.pop()
        payload = build(selected)
        _stabilize_estimate(payload)

    if estimated_tokens(payload) > applied:
        if items:
            raise ValueError(
                f"max_tokens is too small for one {item_key} item; request a larger budget."
            )
        raise ValueError("max_tokens is too small for this fixed response.")

    return _stabilize_estimate(payload)


def budgeted_mapping(payload: dict[str, Any], requested_tokens: int) -> dict[str, Any]:
    """Attach a budget to an already bounded mapping and verify it fits."""

    applied = clamp_budget(requested_tokens)
    result = {
        **payload,
        "budget": {
            "requested_tokens": requested_tokens,
            "applied_tokens": applied,
            "estimated_tokens": 0,
            "truncated": False,
            "omitted_items": 0,
            "next_cursor": None,
        },
    }
    _stabilize_estimate(result)
    if result["budget"]["estimated_tokens"] > applied:
        raise ValueError("max_tokens is too small for this fixed response.")
    return _stabilize_estimate(result)
