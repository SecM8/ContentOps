# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for SentinelWatchlistPayload validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.handlers.sentinel_watchlist_models import (
    SentinelWatchlistPayload,
    to_watchlist_arm_body,
)


def _csv_payload(**overrides):
    base = dict(
        displayName="HVA",
        provider="Custom",
        source="Local file",
        contentType="text/csv",
        itemsSearchKey="AssetName",
        rawContent="AssetName,Tier\ndc01,0\nceo-laptop,1\n",
    )
    base.update(overrides)
    return base


def test_valid_csv_watchlist() -> None:
    p = SentinelWatchlistPayload(**_csv_payload())
    assert p.itemsSearchKey == "AssetName"


def test_search_key_must_be_in_header() -> None:
    with pytest.raises(ValidationError, match="itemsSearchKey 'Owner' not found"):
        SentinelWatchlistPayload(**_csv_payload(itemsSearchKey="Owner"))


def test_skip_lines_shifts_header_row() -> None:
    raw = "# top-of-file comment\nAssetName,Tier\ndc01,0\n"
    p = SentinelWatchlistPayload(**_csv_payload(rawContent=raw, numberOfLinesToSkip=1))
    assert p.numberOfLinesToSkip == 1


def test_empty_raw_content_accepted_at_schema() -> None:
    """Empty rawContent is permitted at schema load time (matches the
    shape of collected envelopes, where the API omits the CSV body).
    The apply handler's content-guard rejects the deploy just before
    PUT — the schema stays permissive."""
    # Must NOT raise.
    p = SentinelWatchlistPayload(**_csv_payload(rawContent=""))
    # Empty string is preserved as-is; not coerced to None.
    assert p.rawContent == ""


def test_oversize_raw_content_rejected() -> None:
    huge = "AssetName,Tier\n" + ("x,0\n" * 1_000_000)  # ~4 MB
    with pytest.raises(ValidationError, match="3.5 MB"):
        SentinelWatchlistPayload(**_csv_payload(rawContent=huge))


def test_to_watchlist_arm_body_wraps_in_properties() -> None:
    body = to_watchlist_arm_body({"displayName": "x", "rawContent": "h\nv"})
    assert body == {"properties": {"displayName": "x", "rawContent": "h\nv"}}


def test_json_content_type_now_rejected() -> None:
    """Sentinel currently rejects non-CSV watchlists; model must too."""
    with pytest.raises(ValidationError):
        SentinelWatchlistPayload(
            displayName="x", provider="Custom", source="Local file",
            contentType="application/json", itemsSearchKey="anything",
            rawContent='[{"a":1}]',
        )
