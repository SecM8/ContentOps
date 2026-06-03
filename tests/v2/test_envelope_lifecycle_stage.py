# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the T.2 `lifecycleStage` field on ``EnvelopeV2``.

The new field carries the authoring-workflow stage independent of the
runtime ``status``. This file pins:

* Every valid LifecycleStage value round-trips through parse_envelope.
* Missing lifecycleStage defaults to None (collected envelopes; legacy
  pre-T.2 YAMLs).
* Typo'd values surface as a ValidationError at parse time rather than
  silently dropping the field.
* `lifecycleStage` and `status` are orthogonal — same envelope can hold
  any (stage, status) combination.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.core.envelope import EnvelopeV2, parse_envelope
from contentops.core.lifecycle_stage import LIFECYCLE_STAGES


def _minimal_raw(**overrides) -> dict:
    base = {
        "id": "rule-x",
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "payload": {},
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize("stage", LIFECYCLE_STAGES)
def test_every_lifecycle_stage_round_trips(stage: str) -> None:
    raw = _minimal_raw(lifecycleStage=stage)
    envelope, _ = parse_envelope(raw)
    assert envelope.lifecycleStage == stage


def test_missing_lifecycle_stage_defaults_to_none() -> None:
    """Collected envelopes don't carry lifecycleStage (it's authoring
    metadata, set by humans). Parser must accept this without raising."""
    envelope, _ = parse_envelope(_minimal_raw())
    assert envelope.lifecycleStage is None


def test_explicit_null_lifecycle_stage_is_none() -> None:
    """YAML ``lifecycleStage: null`` and an absent key both yield
    None — be permissive at the boundary."""
    envelope, _ = parse_envelope(_minimal_raw(lifecycleStage=None))
    assert envelope.lifecycleStage is None


def test_typo_lifecycle_stage_raises() -> None:
    """A misspelled stage value (e.g. ``concpet``) must surface at
    parse time so the author sees the error during ``contentops new``
    or PR review, not at deploy time."""
    with pytest.raises(ValidationError):
        parse_envelope(_minimal_raw(lifecycleStage="concpet"))


def test_stage_and_status_are_orthogonal() -> None:
    """A rule can be (engineering, experimental) or (optimization,
    production) or any other combination. The two fields are
    independent — pin this by enumerating a few realistic combinations.
    """
    for status, stage in [
        ("experimental", "engineering"),
        ("experimental", "research"),
        ("production", "optimization"),
        ("production", "feedback"),
        ("deprecated", "feedback"),
    ]:
        envelope, _ = parse_envelope(_minimal_raw(
            status=status, lifecycleStage=stage,
        ))
        assert envelope.status == status
        assert envelope.lifecycleStage == stage


def test_lifecycle_stages_constant_matches_literal() -> None:
    """The LIFECYCLE_STAGES tuple is a convenience for iteration; if
    it ever drifts from the LifecycleStage Literal type, callers
    relying on it for CLI choices / doc generation get out of sync.
    """
    import typing
    from contentops.core.lifecycle_stage import LifecycleStage
    assert tuple(typing.get_args(LifecycleStage)) == LIFECYCLE_STAGES
