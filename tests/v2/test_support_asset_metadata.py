# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``SupportAssetMetadata`` + ``parse_envelope`` routing for support kinds.

Automation rules and playbooks have an owner, runbook and description
but no severity / tactics / alert volume / FP handling. They must parse
with the full (lighter) model instead of falling into the loose-parse
branch, which would silently drop owner + description.
"""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from contentops.core.asset import NON_DETECTION_ASSETS, Asset
from contentops.core.envelope import parse_envelope
from contentops.core.metadata import RuleMetadata, SupportAssetMetadata


def test_support_metadata_accepts_owner_runbook_description_only() -> None:
    md = SupportAssetMetadata(
        owner="soc@example.com", runbookUrl="https://wiki/x", description="d",
    )
    assert md.severity is None
    assert md.tactics == []
    assert md.techniques == []
    assert md.expectedAlertsPerDay is None
    assert md.fpHandling is None


def test_support_metadata_rejects_unknown_keys_and_bad_owner() -> None:
    with pytest.raises(ValidationError):
        SupportAssetMetadata(owner="soc@example.com", runbookUrl="https://wiki/x", bogus=1)
    with pytest.raises(ValidationError, match="email"):
        SupportAssetMetadata(owner="not-an-email", runbookUrl="https://wiki/x")


def test_rule_metadata_contract_unchanged() -> None:
    """The four detection fields are still required on RuleMetadata."""
    with pytest.raises(ValidationError):
        RuleMetadata(owner="soc@example.com", runbookUrl="https://wiki/x")


@pytest.mark.parametrize("asset", sorted(a.value for a in NON_DETECTION_ASSETS))
def test_parse_envelope_uses_support_model_without_loose_fallback(asset: str, caplog) -> None:
    raw = {
        "id": "x-y", "version": "1.0.0", "asset": asset, "status": "production",
        "metadata": {
            "owner": "soc@example.com", "runbookUrl": "https://wiki/x",
            "description": "what it does", "arm_name": "abc",
        },
        "payload": {},
    }
    with caplog.at_level(logging.WARNING, logger="contentops.core.envelope"):
        env, _ = parse_envelope(raw)
    assert isinstance(env.metadata, SupportAssetMetadata)
    assert env.metadata.owner == "soc@example.com"
    assert env.metadata.description == "what it does"
    assert env.arm_name == "abc"
    assert not any("loose parse" in r.message for r in caplog.records)


def test_parse_envelope_detection_kind_still_uses_rule_metadata() -> None:
    raw = {
        "id": "x-y", "version": "1.0.0", "asset": Asset.SENTINEL_ANALYTIC.value,
        "status": "production",
        "metadata": {
            "owner": "soc@example.com", "runbookUrl": "https://wiki/x",
            "severity": "low", "tactics": ["Execution"], "techniques": [],
            "expectedAlertsPerDay": 1, "fpHandling": "x",
        },
        "payload": {},
    }
    env, _ = parse_envelope(raw)
    assert isinstance(env.metadata, RuleMetadata)


def test_support_kind_with_only_arm_name_still_parses_loose() -> None:
    env, _ = parse_envelope({
        "id": "x-y", "version": "1.0.0", "asset": "sentinel_playbook",
        "status": "production", "metadata": {"arm_name": "wf"}, "payload": {},
    })
    assert env.metadata is None
    assert env.arm_name == "wf"
