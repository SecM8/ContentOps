# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/detect_production_promotions.py (Phase 2.2a gate).

The script gates ``experimental`` → ``production`` flips on the
presence of a fresh ``lifecycle.promotedAt`` stamp. ``contentops
lifecycle promote`` writes the stamp; a direct YAML edit bypasses the
CLI and has no stamp. The script exits 1 on any unstamped/stale flip
so ``production-promotion-check.yml`` turns red.

This file exercises ``_stamp_from_envelope`` and ``render_markdown``
directly because that's the pure-Python surface; the
``detect_promotions`` git-walk path is exercised end-to-end in CI on
real PRs.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path


def _load_script_module():
    """Load scripts/detect_production_promotions.py without going via
    package import (it's a top-level script, not a package member).

    The module must be registered in ``sys.modules`` before exec
    because ``@dataclass`` resolves type annotations via
    ``sys.modules[cls.__module__]`` and would otherwise crash with
    ``AttributeError: 'NoneType' object has no attribute '__dict__'``.
    """
    name = "dpp_test_module"
    if name in sys.modules:
        return sys.modules[name]
    script_path = Path(__file__).parents[2] / "scripts" / "detect_production_promotions.py"
    spec = importlib.util.spec_from_file_location(name, script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_stamp_fresh_within_30_days_is_ok() -> None:
    """A lifecycle stamp within the 30-day window is accepted."""
    dpp = _load_script_module()
    head_doc = {
        "lifecycle": {
            "promotedAt": "2026-05-01",
            "promotedBy": "alice",
        }
    }
    promoted_at, promoted_by, age_days, stamp_ok = dpp._stamp_from_envelope(
        head_doc, today=date(2026, 5, 15), max_stamp_age_days=30,
    )
    assert promoted_at == "2026-05-01"
    assert promoted_by == "alice"
    assert age_days == 14
    assert stamp_ok is True


def test_stamp_missing_block_is_rejected() -> None:
    """No lifecycle block at all → stamp_ok=False."""
    dpp = _load_script_module()
    promoted_at, promoted_by, age_days, stamp_ok = dpp._stamp_from_envelope(
        {}, today=date(2026, 5, 15), max_stamp_age_days=30,
    )
    assert promoted_at is None
    assert promoted_by is None
    assert age_days is None
    assert stamp_ok is False


def test_stamp_missing_promotedat_is_rejected() -> None:
    """lifecycle present but promotedAt missing → rejected."""
    dpp = _load_script_module()
    head_doc = {"lifecycle": {"promotedBy": "alice"}}
    _, _, age_days, stamp_ok = dpp._stamp_from_envelope(
        head_doc, today=date(2026, 5, 15), max_stamp_age_days=30,
    )
    assert age_days is None
    assert stamp_ok is False


def test_stamp_missing_promotedby_is_rejected() -> None:
    """lifecycle.promotedAt present but promotedBy missing → rejected.

    Stamping by a real CLI run always writes both fields together; a
    half-stamped envelope was hand-edited."""
    dpp = _load_script_module()
    head_doc = {"lifecycle": {"promotedAt": "2026-05-10"}}
    _, _, _, stamp_ok = dpp._stamp_from_envelope(
        head_doc, today=date(2026, 5, 15), max_stamp_age_days=30,
    )
    assert stamp_ok is False


def test_stamp_older_than_threshold_is_rejected() -> None:
    """A 60-day-old stamp is past the 30-day window → rejected.

    Prevents a stale promotion (e.g. a long-lived branch that was
    promoted months ago then sat unmerged) from sneaking past."""
    dpp = _load_script_module()
    head_doc = {
        "lifecycle": {
            "promotedAt": "2026-01-01",
            "promotedBy": "alice",
        }
    }
    _, _, age_days, stamp_ok = dpp._stamp_from_envelope(
        head_doc, today=date(2026, 5, 15), max_stamp_age_days=30,
    )
    assert age_days == 134
    assert stamp_ok is False


def test_stamp_in_future_is_rejected() -> None:
    """A stamp dated in the future (clock skew or hand-edit) → rejected."""
    dpp = _load_script_module()
    head_doc = {
        "lifecycle": {
            "promotedAt": "2026-12-01",
            "promotedBy": "alice",
        }
    }
    _, _, age_days, stamp_ok = dpp._stamp_from_envelope(
        head_doc, today=date(2026, 5, 15), max_stamp_age_days=30,
    )
    assert age_days < 0  # Negative age = future date
    assert stamp_ok is False


def test_stamp_unparseable_is_rejected() -> None:
    """A non-ISO promotedAt value → rejected, surfaced in the message."""
    dpp = _load_script_module()
    head_doc = {
        "lifecycle": {
            "promotedAt": "last Tuesday",
            "promotedBy": "alice",
        }
    }
    promoted_at, _, age_days, stamp_ok = dpp._stamp_from_envelope(
        head_doc, today=date(2026, 5, 15), max_stamp_age_days=30,
    )
    assert promoted_at == "last Tuesday"
    assert age_days is None
    assert stamp_ok is False


def test_render_markdown_distinguishes_stamped_from_unstamped() -> None:
    """The Markdown report calls out which rule is missing a fresh stamp
    so the reviewer sees the per-rule reason in the sticky PR comment."""
    dpp = _load_script_module()
    good = dpp.Promotion(
        path="detections/sentinel_analytic/good.yml",
        rule_id="good", from_status="experimental", to_status="production",
        promoted_at="2026-05-01", promoted_by="alice",
        stamp_age_days=14, stamp_ok=True,
    )
    missing = dpp.Promotion(
        path="detections/sentinel_analytic/missing.yml",
        rule_id="missing", from_status="experimental", to_status="production",
        promoted_at=None, promoted_by=None,
        stamp_age_days=None, stamp_ok=False,
    )
    stale = dpp.Promotion(
        path="detections/sentinel_analytic/stale.yml",
        rule_id="stale", from_status="experimental", to_status="production",
        promoted_at="2026-01-01", promoted_by="alice",
        stamp_age_days=134, stamp_ok=False,
    )
    md = dpp.render_markdown([good, missing, stale])
    # The stamp column distinguishes the three cases.
    assert "✓" in md  # good
    assert "missing" in md
    assert "stale" in md
    # The rule ids appear so the reviewer can grep.
    assert "good" in md
    assert "stale" in md


def test_render_markdown_empty_for_no_promotions() -> None:
    """No promotions → friendly message, no table."""
    dpp = _load_script_module()
    assert "No production promotions" in dpp.render_markdown([])
