# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `pipeline snapshot-diff` (F12)."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from contentops.snapshot_diff import (
    SnapshotDiffError,
    diff_archives,
    index_archive,
    render_json,
    render_markdown,
)


# ---------------------------------------------------------------------------
# Archive builder
# ---------------------------------------------------------------------------


def _make_archive(target: Path, files: dict[str, str]) -> Path:
    """Build a .tar.gz at ``target`` with name->yaml-text entries."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, mode="w:gz") as tar:
        for name, body in files.items():
            data = body.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return target


# Synthetic envelopes ---------------------------------------------------------


def _v2_yaml(rule_id: str, query: str = "T | take 1") -> str:
    return f"""\
id: {rule_id}
version: 1.0.0
asset: sentinel_analytic
status: production
payload:
  displayName: X
  query: {query}
"""


def _v1_yaml(rule_id: str, query: str = "T | take 1") -> str:
    return f"""\
id: {rule_id}
version: 0.0.0
platform: sentinel
status: production
sentinel:
  kind: Scheduled
  displayName: X
  severity: Low
  query: {query}
"""


# ---------------------------------------------------------------------------
# index_archive
# ---------------------------------------------------------------------------


def test_index_v2_archive_picks_up_envelope_id_and_asset(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
        "detections/sentinel_analytic/rule-y.yml": _v2_yaml("rule-y"),
    })
    idx = index_archive(archive)
    assert set(idx.keys()) == {
        ("sentinel_analytic", "rule-x"),
        ("sentinel_analytic", "rule-y"),
    }


def test_index_v1_archive_maps_platform_to_asset(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel/rule-x.yml": _v1_yaml("rule-x"),
    })
    idx = index_archive(archive)
    assert ("sentinel_analytic", "rule-x") in idx


def test_index_skips_non_yaml_entries(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
        "logs/collect.log": "garbage",
        "MANIFEST.json": "{}",
    })
    idx = index_archive(archive)
    assert list(idx.keys()) == [("sentinel_analytic", "rule-x")]


def test_index_skips_envelope_without_id(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/bad.yml": "id: \nversion: 1\nasset: sentinel_analytic\nstatus: x\npayload: {}\n",
    })
    idx = index_archive(archive)
    assert idx == {}


def test_index_missing_archive_raises(tmp_path: Path) -> None:
    with pytest.raises(SnapshotDiffError):
        index_archive(tmp_path / "nope.tar.gz")


def test_index_unrecognised_extension_raises(tmp_path: Path) -> None:
    bad = tmp_path / "snap.zip"
    bad.write_bytes(b"PK")
    with pytest.raises(SnapshotDiffError):
        index_archive(bad)


# ---------------------------------------------------------------------------
# diff_archives
# ---------------------------------------------------------------------------


def test_diff_identical_archives_reports_no_changes(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    rep = diff_archives(a, b)
    assert not rep.has_changes()
    assert rep.unchanged == 1


def test_diff_renamed_file_with_same_content_is_unchanged(tmp_path: Path) -> None:
    """The whole point of F12: renames don't show up as changes."""
    a = _make_archive(tmp_path / "a.tar.gz", {
        "detections/sentinel_analytic/old-name.yml": _v2_yaml("rule-x"),
    })
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/different-name.yml": _v2_yaml("rule-x"),
    })
    rep = diff_archives(a, b)
    assert not rep.has_changes()
    assert rep.unchanged == 1


def test_diff_content_change_shows_as_updated(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x", query="T1"),
    })
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x", query="T2"),
    })
    rep = diff_archives(a, b)
    assert len(rep.updated) == 1
    old, new = rep.updated[0]
    assert old.envelope_id == "rule-x"
    assert old.payload_hash != new.payload_hash


def test_diff_only_in_b_is_created(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {})
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    rep = diff_archives(a, b)
    assert len(rep.created) == 1
    assert rep.created[0].envelope_id == "rule-x"


def test_diff_only_in_a_is_deleted(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    b = _make_archive(tmp_path / "b.tar.gz", {})
    rep = diff_archives(a, b)
    assert len(rep.deleted) == 1


def test_diff_totals_are_correct(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x", query="T1"),
        "detections/sentinel_analytic/rule-y.yml": _v2_yaml("rule-y"),
    })
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x", query="T2"),
        "detections/sentinel_analytic/rule-z.yml": _v2_yaml("rule-z"),
    })
    rep = diff_archives(a, b)
    assert len(rep.created) == 1   # rule-z
    assert len(rep.updated) == 1   # rule-x changed
    assert len(rep.deleted) == 1   # rule-y gone
    assert rep.unchanged == 0
    assert rep.total_a == 2
    assert rep.total_b == 2


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_markdown_no_changes(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    md = render_markdown(diff_archives(a, b))
    assert "created 0" in md
    assert "updated 0" in md


def test_render_markdown_includes_each_change_section(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {
        "detections/sentinel_analytic/rule-y.yml": _v2_yaml("rule-y"),
    })
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    md = render_markdown(diff_archives(a, b))
    assert "## Created" in md
    assert "## Deleted" in md


def test_render_json_is_parseable(tmp_path: Path) -> None:
    a = _make_archive(tmp_path / "a.tar.gz", {})
    b = _make_archive(tmp_path / "b.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _v2_yaml("rule-x"),
    })
    parsed = json.loads(render_json(diff_archives(a, b)))
    assert parsed["summary"]["created"] == 1
    assert len(parsed["created"]) == 1
