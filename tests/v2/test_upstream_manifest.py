# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the upstream manifest load / diff / write helpers (G3 + G4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contentops.upstream.manifest import (
    SCHEMA_VERSION,
    compute_diff,
    load_manifest,
    write_manifest,
)


def _entry(name: str, version: str = "1.0.0", **extra) -> dict:
    base = {
        "name": name,
        "displayName": name.title(),
        "version": version,
    }
    base.update(extra)
    return base


def test_load_missing_manifest_returns_empty(tmp_path: Path) -> None:
    assert load_manifest(tmp_path / "absent.json") == []


def test_load_empty_file_returns_empty(tmp_path: Path) -> None:
    target = tmp_path / "empty.json"
    target.write_text("", encoding="utf-8")
    assert load_manifest(target) == []


def test_write_then_load_round_trips_entries(tmp_path: Path) -> None:
    entries = [_entry("alpha"), _entry("beta", version="2.0.0")]
    target = tmp_path / "m.json"
    write_manifest(target, entries)
    loaded = load_manifest(target)
    assert loaded == sorted(entries, key=lambda e: e["name"])


def test_write_produces_schema_versioned_payload(tmp_path: Path) -> None:
    target = tmp_path / "m.json"
    write_manifest(target, [_entry("zzz")])
    raw = json.loads(target.read_text(encoding="utf-8"))
    assert raw["schema_version"] == SCHEMA_VERSION
    assert len(raw["entries"]) == 1


def test_write_sorts_entries_for_stable_diff(tmp_path: Path) -> None:
    target = tmp_path / "m.json"
    write_manifest(target, [_entry("zebra"), _entry("alpha"), _entry("mango")])
    raw = json.loads(target.read_text(encoding="utf-8"))
    names = [e["name"] for e in raw["entries"]]
    assert names == ["alpha", "mango", "zebra"]


def test_write_trailing_newline(tmp_path: Path) -> None:
    target = tmp_path / "m.json"
    write_manifest(target, [_entry("a")])
    assert target.read_text(encoding="utf-8").endswith("\n")


def test_diff_empty_inputs() -> None:
    diff = compute_diff([], [])
    assert diff.is_empty
    assert diff.added == [] and diff.removed == [] and diff.changed == []


def test_diff_first_run_treats_all_entries_as_added() -> None:
    new = [_entry("alpha"), _entry("beta")]
    diff = compute_diff([], new)
    assert [e["name"] for e in diff.added] == ["alpha", "beta"]
    assert diff.removed == [] and diff.changed == []


def test_diff_identical_inputs_is_empty() -> None:
    entries = [_entry("alpha"), _entry("beta")]
    assert compute_diff(entries, list(entries)).is_empty


def test_diff_detects_version_bump_as_changed() -> None:
    old = [_entry("alpha", "1.0.0")]
    new = [_entry("alpha", "1.1.0")]
    diff = compute_diff(old, new)
    assert diff.changed and diff.changed[0][0]["version"] == "1.0.0"
    assert diff.changed[0][1]["version"] == "1.1.0"
    assert not diff.added and not diff.removed


def test_diff_detects_removed_entries() -> None:
    diff = compute_diff([_entry("alpha"), _entry("beta")], [_entry("alpha")])
    assert [e["name"] for e in diff.removed] == ["beta"]


def test_diff_changed_is_sorted_for_review_stability() -> None:
    old = [_entry("zebra", "1.0.0"), _entry("alpha", "1.0.0")]
    new = [_entry("zebra", "2.0.0"), _entry("alpha", "2.0.0")]
    diff = compute_diff(old, new)
    assert [pair[1]["name"] for pair in diff.changed] == ["alpha", "zebra"]


def test_load_malformed_json_raises(tmp_path: Path) -> None:
    target = tmp_path / "m.json"
    target.write_text("not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_manifest(target)


def test_load_non_object_raises(tmp_path: Path) -> None:
    target = tmp_path / "m.json"
    target.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(target)
