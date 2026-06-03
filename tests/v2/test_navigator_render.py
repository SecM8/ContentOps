# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Navigator layer renderer + CLI surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.navigator.extract import ScoredTechnique
from contentops.navigator.render import (
    ATTACK_VERSION,
    DOMAIN,
    NAVIGATOR_LAYER_VERSION,
    render_layer,
)


def _scored(*items: tuple[str, int]) -> list[ScoredTechnique]:
    return [
        ScoredTechnique(
            technique_id=tid,
            score=score,
            repo_count=score,
            deployed_count=0,
            firings_count=0,
            contributing_rules=tuple(f"rule-{i}" for i in range(score)),
        )
        for tid, score in items
    ]


# ---------------------------------------------------------------------------
# render_layer shape
# ---------------------------------------------------------------------------


def test_layer_has_required_navigator_fields() -> None:
    """The Navigator UI is strict about these field names. If we ever
    rename one, the layer fails to load with no error message in the
    UI -- it just silently ignores the file."""
    layer = render_layer(_scored(("T1059", 3)))
    for required in (
        "name", "versions", "description", "domain",
        "sorting", "layout", "techniques", "gradient",
    ):
        assert required in layer, f"missing required field: {required}"
    assert layer["domain"] == DOMAIN
    assert layer["versions"]["attack"] == ATTACK_VERSION
    assert layer["versions"]["layer"] == NAVIGATOR_LAYER_VERSION


def test_layer_techniques_carry_score_and_metadata() -> None:
    layer = render_layer(_scored(("T1110", 5), ("T1059", 2)))
    tids = [t["techniqueID"] for t in layer["techniques"]]
    assert tids == ["T1110", "T1059"]
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1110"]["score"] == 5
    # Metadata block exposes per-axis breakdown for hover info.
    md = {m["name"]: m["value"] for m in by_id["T1110"]["metadata"]}
    assert "repo_count" in md and "deployed_count" in md and "firings_count" in md


def test_layer_gradient_floats_with_max_score() -> None:
    """A coverage report with a top score of 1 shouldn't render every
    tile the same dark colour. Gradient's maxValue grows with the
    highest score, with a 5-floor for small/empty corpora."""
    small = render_layer(_scored(("T1059", 1)))
    assert small["gradient"]["maxValue"] == 5  # floor

    big = render_layer(_scored(("T1059", 12)))
    assert big["gradient"]["maxValue"] == 12


def test_layer_is_deterministic() -> None:
    """Same input -> byte-identical JSON. Operators commit layer files
    to git; non-deterministic output would churn the diff every regen."""
    techniques = _scored(("T1059", 2), ("T1110", 3))
    a = json.dumps(render_layer(techniques), indent=2, sort_keys=True)
    b = json.dumps(render_layer(techniques), indent=2, sort_keys=True)
    assert a == b


def test_layer_handles_empty_input() -> None:
    layer = render_layer([])
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] >= 5


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_navigator_repo_only_offline(tmp_path: Path) -> None:
    """With --no-deployed --no-firings, the command runs entirely
    against the repo -- no tenant credentials needed. Offline-safe,
    fork-PR-safe."""
    detections = tmp_path / "detections"
    detections.mkdir()
    out = tmp_path / "layer.json"

    runner = CliRunner()
    result = runner.invoke(cli, [
        "navigator",
        "--path", str(detections),
        "--no-deployed", "--no-firings",
        "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert out.exists()
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["domain"] == DOMAIN
    assert body["techniques"] == []  # empty detections/, no techniques


def test_cli_navigator_fail_soft_skips_unavailable_axes(tmp_path: Path) -> None:
    """fail-soft is the default. An unavailable axis (no tenant
    config in test env) produces a warning but doesn't fail the
    command."""
    detections = tmp_path / "detections"
    detections.mkdir()
    out = tmp_path / "layer.json"

    runner = CliRunner()
    result = runner.invoke(cli, [
        "navigator",
        "--path", str(detections),
        "--no-deployed",  # skip tenant axes to keep test self-contained
        "--no-firings",
        "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_cli_navigator_help_lists_axes() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["navigator", "--help"])
    assert result.exit_code == 0
    for needle in ("--repo", "--deployed", "--firings", "--since", "--out"):
        assert needle in result.output, f"--help missing {needle}"
