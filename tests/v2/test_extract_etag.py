# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared etag-extraction helper (H-2)."""

from __future__ import annotations

from contentops.handlers._verify import extract_etag


def test_extract_etag_top_level() -> None:
    assert extract_etag({"etag": "W/\"abc\""}) == 'W/"abc"'


def test_extract_etag_nested_in_properties() -> None:
    """Some preview API versions place etag under ``properties``;
    callers must not silently miss it."""
    assert extract_etag({"properties": {"etag": "W/\"def\""}}) == 'W/"def"'


def test_extract_etag_prefers_top_level_when_both_present() -> None:
    assert extract_etag({"etag": "top", "properties": {"etag": "nested"}}) == "top"


def test_extract_etag_none_for_missing_remote() -> None:
    assert extract_etag(None) is None
    assert extract_etag({}) is None


def test_extract_etag_handles_non_dict_properties() -> None:
    # ARM nominally always returns a dict for properties, but be defensive.
    assert extract_etag({"properties": "oops"}) is None
