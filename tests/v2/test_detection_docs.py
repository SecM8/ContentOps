# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the per-detection markdown generator (`contentops.docs`).

Three layers, mirroring tests/v2/test_catalog.py:

* Pure-function tests for ``render_all`` and ``render_detection``.
* The load-bearing CI gate: every committed file under
  ``docs/detections/`` must equal what ``render_all`` would currently
  produce, with no orphans.
* CLI surface (regenerate + check) round-trips correctly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.config import is_operator_source_repo
from contentops.core.discovery import discover_assets, load_asset
from contentops.docs import DETECTION_DOCS_DIR, INDEX_FILE, render_all, render_detection

REPO_ROOT = Path(__file__).resolve().parents[2]

# The detection-docs drift gate is a source-repo maintenance check. The
# public mirror keeps detections/ but strips docs/detections/, so it
# can't pass there; it skips off-source so a mirror clone is green.
source_only = pytest.mark.skipif(
    not is_operator_source_repo(REPO_ROOT),
    reason="source-repo maintenance gate; skipped off-source "
           "(public mirror / adopter clone — no public-sync.yml)",
)


def _load_repo_envelopes() -> list:
    out = []
    for path in discover_assets(REPO_ROOT / "detections"):
        try:
            out.append(load_asset(path))
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# Rendering layer
# ---------------------------------------------------------------------------


def test_render_all_is_deterministic() -> None:
    """``render_all`` must be a pure function — calling it twice
    against the same envelopes returns byte-identical output.
    """
    envelopes = _load_repo_envelopes()
    a = render_all(envelopes, repo_root=REPO_ROOT)
    b = render_all(envelopes, repo_root=REPO_ROOT)
    assert a == b


def test_render_all_includes_index() -> None:
    envelopes = _load_repo_envelopes()
    rendered = render_all(envelopes, repo_root=REPO_ROOT)
    assert INDEX_FILE in rendered
    assert "# Detection catalog" in rendered[INDEX_FILE]


def test_render_emits_one_file_per_envelope() -> None:
    envelopes = _load_repo_envelopes()
    rendered = render_all(envelopes, repo_root=REPO_ROOT)
    # +1 for the index file.
    assert len(rendered) == len(envelopes) + 1


def test_render_detection_ends_with_single_newline() -> None:
    envelopes = _load_repo_envelopes()
    if not envelopes:
        pytest.skip("no envelopes in detections/")
    body = render_detection(envelopes[0], repo_root=REPO_ROOT)
    assert body.endswith("\n")
    assert not body.endswith("\n\n")


def test_render_detection_emits_section_headers() -> None:
    """Pick a complete authoring envelope (the canonical example) and
    sanity-check the rendered shape so future changes to the renderer
    surface here loudly.
    """
    envelopes = _load_repo_envelopes()
    matching = [
        e for e in envelopes
        if e.envelope.id == "example-suspicious-process-tree"
    ]
    if not matching:
        pytest.skip("canonical example envelope not present")
    body = render_detection(matching[0], repo_root=REPO_ROOT)
    for header in ("## Overview", "## MITRE ATT&CK", "## Description",
                   "## Detection logic", "## False-positive handling",
                   "## Blind spots", "## Response actions", "## References"):
        assert header in body, f"missing section {header!r}"


def test_render_uses_repo_relative_paths() -> None:
    """Cross-platform determinism: source field must be repo-relative
    POSIX. Otherwise Windows operator + Linux CI never converge.
    """
    envelopes = _load_repo_envelopes()
    if not envelopes:
        pytest.skip("no envelopes in detections/")
    body = render_detection(envelopes[0], repo_root=REPO_ROOT)
    assert "C:" not in body
    assert "\\" not in body or "C:\\" not in body


# ---------------------------------------------------------------------------
# CI gate (the load-bearing one)
# ---------------------------------------------------------------------------


@source_only
def test_committed_detection_docs_are_in_sync() -> None:
    """If this fails, the developer changed a detection envelope but
    forgot to run ``contentops detection-docs regenerate`` and commit
    the updated markdown.

    Fix: from the repo root, run

        contentops detection-docs regenerate

    Commit the resulting diff.
    """
    envelopes = _load_repo_envelopes()
    rendered = render_all(envelopes, repo_root=REPO_ROOT)

    docs_dir = REPO_ROOT / DETECTION_DOCS_DIR
    assert docs_dir.exists(), (
        f"{DETECTION_DOCS_DIR}/ is missing — run "
        f"`contentops detection-docs regenerate`."
    )

    missing: list[str] = []
    drifted: list[str] = []
    for rel, expected in rendered.items():
        target = REPO_ROOT / rel
        if not target.exists():
            missing.append(rel)
            continue
        actual = target.read_bytes().decode("utf-8")
        if actual != expected:
            drifted.append(rel)

    expected_paths = {(REPO_ROOT / rel).resolve() for rel in rendered}
    orphans = [
        str(p.relative_to(REPO_ROOT)).replace("\\", "/")
        for p in docs_dir.rglob("*.md")
        if p.resolve() not in expected_paths
    ]

    assert not missing, f"missing {len(missing)} file(s): {missing[:3]}"
    assert not drifted, f"drifted {len(drifted)} file(s): {drifted[:3]}"
    assert not orphans, f"orphan {len(orphans)} file(s): {orphans[:3]}"


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


@source_only
def test_cli_detection_docs_check_passes() -> None:
    runner = CliRunner()
    # Pass --repo-root explicitly: the v2 conftest chdir's each test into
    # a tmp dir, so the command can't infer the repo root from cwd.
    result = runner.invoke(
        cli, ["detection-docs", "check", "--repo-root", str(REPO_ROOT)]
    )
    assert result.exit_code == 0, result.output
    assert "in sync" in result.output


def test_cli_detection_docs_check_skips_off_source(tmp_path: Path) -> None:
    """Off the operator source repo (no public-sync.yml), `detection-docs
    check` no-ops with exit 0 so a public-mirror / adopter clone — which
    keeps detections/ but strips docs/detections/ — is green out of the
    box."""
    assert is_operator_source_repo(tmp_path) is False
    (tmp_path / "detections").mkdir()
    result = CliRunner().invoke(
        cli, ["detection-docs", "check", "--repo-root", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "skipped" in result.output.lower()


def test_cli_detection_docs_regenerate_to_tmp(tmp_path: Path) -> None:
    """The generator should be repo-root-relocatable so tests don't
    have to touch the real ``docs/detections/`` tree.
    """
    # Build a minimal fake repo with one envelope.
    fake = tmp_path / "fake_repo"
    (fake / "detections" / "sentinel_hunting").mkdir(parents=True)
    (fake / "pyproject.toml").write_text("# stub\n", encoding="utf-8")
    sample = REPO_ROOT / "detections" / "sentinel_hunting" / "example-suspicious-process-tree.yml"
    if not sample.exists():
        pytest.skip("canonical sample envelope missing")
    (fake / "detections" / "sentinel_hunting" / sample.name).write_bytes(
        sample.read_bytes()
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["detection-docs", "regenerate", "--repo-root", str(fake)],
    )
    assert result.exit_code == 0, result.output
    assert (
        fake / DETECTION_DOCS_DIR / "sentinel_hunting"
        / "example-suspicious-process-tree.md"
    ).exists()
    assert (fake / INDEX_FILE).exists()
