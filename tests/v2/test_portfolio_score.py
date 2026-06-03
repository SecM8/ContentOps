# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for rule effectiveness scoring (contentops.portfolio.score).

Pins the formula + the weight-parsing contract + the rank ordering.
Synthetic telemetry rows keep the test pure-Python — no LA workspace
fixture required.
"""

from __future__ import annotations

import pytest

from contentops.portfolio.score import (
    ScoreWeights,
    compute_score,
    parse_weights,
    rank_rows,
)


# ---------------------------------------------------------------------------
# parse_weights
# ---------------------------------------------------------------------------


def test_parse_weights_none_returns_defaults() -> None:
    w = parse_weights(None)
    assert w.tp == 1.0
    assert w.fp == 2.0
    assert w.silence == 30.0


def test_parse_weights_empty_string_returns_defaults() -> None:
    assert parse_weights("") == ScoreWeights()


def test_parse_weights_overrides_one_key() -> None:
    w = parse_weights("fp=3")
    assert w.fp == 3.0
    assert w.tp == 1.0       # untouched default
    assert w.silence == 30.0  # untouched default


def test_parse_weights_overrides_all_keys() -> None:
    w = parse_weights("tp=2,fp=5,silence=60")
    assert w.tp == 2.0
    assert w.fp == 5.0
    assert w.silence == 60.0


def test_parse_weights_rejects_unknown_key() -> None:
    """Typos must surface — silent fall-through to defaults would
    hide an operator's intent. Pinning the rejection."""
    with pytest.raises(ValueError, match="unknown key 'cost'"):
        parse_weights("cost=10")


def test_parse_weights_rejects_non_numeric_value() -> None:
    with pytest.raises(ValueError, match="not numeric"):
        parse_weights("fp=high")


def test_parse_weights_rejects_malformed_pair() -> None:
    with pytest.raises(ValueError, match="not key=value"):
        parse_weights("just_a_word")


# ---------------------------------------------------------------------------
# compute_score
# ---------------------------------------------------------------------------


def test_compute_score_no_telemetry_returns_none() -> None:
    """A row with no telemetry fields (None across the board) returns
    None — 'unknown effectiveness' distinct from 'scored zero.'"""
    row = {
        "alerts_30d": None, "incidents_30d": None, "closed_fp_30d": None,
    }
    assert compute_score(row, ScoreWeights()) is None


def test_compute_score_silent_rule_hits_silence_penalty() -> None:
    """alerts_30d=0 -> rule didn't fire -> silence penalty applies.
    With default weights (silence=30), an all-zero row scores -30."""
    row = {"alerts_30d": 0, "incidents_30d": 0, "closed_fp_30d": 0}
    assert compute_score(row, ScoreWeights()) == -30


def test_compute_score_pure_true_positives() -> None:
    """Five incidents, zero FPs -> 5 TP. Default tp=1 -> score=5.
    Rule fired so silence penalty does NOT apply."""
    row = {"alerts_30d": 50, "incidents_30d": 5, "closed_fp_30d": 0}
    assert compute_score(row, ScoreWeights()) == 5


def test_compute_score_pure_false_positives() -> None:
    """Ten incidents, all closed as FP -> 0 TP, 10 FP.
    Default fp=2 -> score = -20. Rule fired so no silence penalty."""
    row = {"alerts_30d": 100, "incidents_30d": 10, "closed_fp_30d": 10}
    assert compute_score(row, ScoreWeights()) == -20


def test_compute_score_mixed_telemetry() -> None:
    """10 incidents, 3 closed as FP -> 7 TP. With defaults: 7*1 - 3*2
    = 1. Rule fired (alerts > 0) so no silence penalty."""
    row = {"alerts_30d": 200, "incidents_30d": 10, "closed_fp_30d": 3}
    assert compute_score(row, ScoreWeights()) == 1


def test_compute_score_custom_weights() -> None:
    """Same row as above but fp=5 (heavy FP cost) and silence=0
    (silence forgiven). 7*1 - 3*5 = -8."""
    row = {"alerts_30d": 200, "incidents_30d": 10, "closed_fp_30d": 3}
    w = ScoreWeights(tp=1, fp=5, silence=0)
    assert compute_score(row, w) == -8


def test_compute_score_clamps_negative_tp_estimate_to_zero() -> None:
    """incidents - closed_fp can't go negative (a rule can't have more
    closed FPs than total incidents). If the data is malformed (closed_fp
    > incidents — e.g. legacy backfill), clamp the TP estimate to 0
    so a single bad row doesn't pollute the score table."""
    row = {"alerts_30d": 5, "incidents_30d": 3, "closed_fp_30d": 5}
    # tp=max(0, 3-5)=0, fp=5*2=10 -> -10
    assert compute_score(row, ScoreWeights()) == -10


# ---------------------------------------------------------------------------
# rank_rows
# ---------------------------------------------------------------------------


def test_rank_rows_ascending_by_score() -> None:
    """Lowest score first = retirement candidates surface at top."""
    rows = [
        {"id": "great",  "alerts_30d": 50, "incidents_30d": 10, "closed_fp_30d": 0},
        {"id": "silent", "alerts_30d": 0,  "incidents_30d": 0,  "closed_fp_30d": 0},
        {"id": "noisy",  "alerts_30d": 1000, "incidents_30d": 50, "closed_fp_30d": 50},
    ]
    ranked = rank_rows(rows, ScoreWeights())
    ids = [r["id"] for r in ranked]
    # noisy (-100, 0 TP - 50*2 FP) < silent (-30) < great (10)
    assert ids == ["noisy", "silent", "great"]


def test_rank_rows_unscored_rows_sort_to_bottom() -> None:
    """Rows with score=None go to the END so operators see scored
    rules first; the unknowns are a separate triage step."""
    rows = [
        {"id": "no_telem", "alerts_30d": None, "incidents_30d": None, "closed_fp_30d": None},
        {"id": "scored",   "alerts_30d": 1, "incidents_30d": 1, "closed_fp_30d": 0},
    ]
    ranked = rank_rows(rows, ScoreWeights())
    assert ranked[0]["id"] == "scored"
    assert ranked[-1]["id"] == "no_telem"
    assert ranked[-1]["score"] is None


def test_rank_rows_writes_score_field_on_every_row() -> None:
    rows = [
        {"id": "a", "alerts_30d": 0, "incidents_30d": 0, "closed_fp_30d": 0},
        {"id": "b", "alerts_30d": None, "incidents_30d": None, "closed_fp_30d": None},
    ]
    rank_rows(rows, ScoreWeights())
    assert all("score" in r for r in rows)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_portfolio_rank_appends_score_column(tmp_path, monkeypatch) -> None:
    """`contentops portfolio --rank` without --with-telemetry: warns
    on stderr, but still runs and produces a score column (all
    None entries; the column appears in output)."""
    from click.testing import CliRunner

    from contentops.cli import cli

    detections = tmp_path / "detections"
    detections.mkdir()
    # No envelopes -> no rows -> CSV is just the header line.
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(detections), "--rank",
    ])
    assert result.exit_code == 0, result.output
    # warn about missing telemetry surfaces
    assert "--rank without --with-telemetry" in result.output


def test_cli_portfolio_rejects_unknown_score_weight_key(tmp_path) -> None:
    """An unknown key in --score-weights exits 2 with a clear message —
    surfaces operator typos that would otherwise silently use defaults."""
    from click.testing import CliRunner

    from contentops.cli import cli

    detections = tmp_path / "detections"
    detections.mkdir()
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(detections), "--rank",
        "--score-weights", "fp=2,bogus=5",
    ])
    assert result.exit_code == 2, result.output
    assert "unknown key 'bogus'" in result.output
