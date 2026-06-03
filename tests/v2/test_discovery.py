# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for asset discovery — skips templates/ and samples/."""

from __future__ import annotations

from pathlib import Path

from contentops.core.discovery import discover_assets, is_skipped_path


def test_skips_templates_and_samples(tmp_path: Path) -> None:
    (tmp_path / "sentinel_analytic").mkdir()
    (tmp_path / "sentinel_analytic" / "ok.yml").write_text(
        "id: ok\nversion: 1.0.0\nasset: sentinel_analytic\nstatus: test\npayload: {}\n",
    )
    (tmp_path / "sentinel_analytic" / "templates").mkdir()
    (tmp_path / "sentinel_analytic" / "templates" / "tpl.yml").write_text("x: 1")
    (tmp_path / "sentinel_analytic" / "samples").mkdir()
    (tmp_path / "sentinel_analytic" / "samples" / "sample.yml").write_text("x: 1")

    found = discover_assets(tmp_path)
    assert len(found) == 1
    assert found[0].name == "ok.yml"


def test_is_skipped_path_case_insensitive() -> None:
    assert is_skipped_path(Path("a/Templates/x.yml"))
    assert is_skipped_path(Path("a/SAMPLES/x.yml"))
    assert not is_skipped_path(Path("a/sentinel_analytic/x.yml"))


def test_skips_root_control_files(tmp_path: Path) -> None:
    # Control files at the detections/ root (drift_suppressions.yml,
    # dependencies.yml) are NOT asset envelopes — discovery must skip
    # them or parse_envelope raises and breaks lint/plan.
    (tmp_path / "sentinel_analytic").mkdir()
    (tmp_path / "sentinel_analytic" / "ok.yml").write_text(
        "id: ok\nversion: 1.0.0\nasset: sentinel_analytic\nstatus: test\npayload: {}\n",
    )
    (tmp_path / "drift_suppressions.yml").write_text(
        "schema_version: '1.0'\nsuppressions: []\n",
    )
    (tmp_path / "dependencies.yml").write_text("schema_version: '1.0'\n")

    found = discover_assets(tmp_path)
    assert [p.name for p in found] == ["ok.yml"]


def test_is_skipped_path_control_filenames() -> None:
    assert is_skipped_path(Path("detections/drift_suppressions.yml"))
    assert is_skipped_path(Path("detections/dependencies.yml"))
    assert not is_skipped_path(Path("detections/sentinel_analytic/real-rule.yml"))


