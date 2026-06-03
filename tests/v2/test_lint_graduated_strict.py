# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Phase 2.2b graduated ``scaffoldStrict`` policy.

Once an operator has started authoring T.3 fields (``description`` /
``attackDescription`` / ``references`` / ``falsePositives``) on a rule,
the lint runner escalates META002-005 to error severity so the
remaining T.3 fields must be filled too — even when the tenant-wide
``scaffoldStrict`` is lenient. Collected envelopes carrying no T.3
content stay lenient until the tenant flips ``scaffoldStrict``
globally. This back-pressure lets the G24 backlog drain without
making every collected-content PR go red.

The escalation lives in ``contentops/lint/runner.py``'s
``_has_partial_authoring`` helper; ``lint_metadata`` itself is
unchanged so direct callers keep their existing semantics.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.metadata import RuleMetadata
from contentops.lint.runner import _has_partial_authoring, lint_assets


def _meta(**overrides) -> RuleMetadata:
    base = dict(
        owner="secops@example.com",
        runbookUrl="https://runbooks.example.com/x",
        severity="low",
        tactics=["Execution"],
        techniques=["T1059"],
        expectedAlertsPerDay=1,
        fpHandling="Triage manually.",
        lastValidatedAt="2026-05-14",
    )
    base.update(overrides)
    return RuleMetadata(**base)


# ---------------------------------------------------------------------------
# _has_partial_authoring (pure helper, unit-level)
# ---------------------------------------------------------------------------


def test_partial_authoring_false_when_metadata_none() -> None:
    """Collected envelope (no metadata block) → not partially authored.

    These are the bulk of the G24 backlog; they stay lenient under
    scaffoldStrict=false."""
    assert _has_partial_authoring(None) is False


def test_partial_authoring_false_when_all_t3_empty() -> None:
    """M1-complete metadata with no T.3 content → not partially authored.

    The envelope was collected (or test-built) with the seven M1 fields
    but none of the four T.3 fields. Same lenient treatment as the
    metadata=None case."""
    assert _has_partial_authoring(_meta()) is False


def test_partial_authoring_false_when_all_t3_populated() -> None:
    """Every T.3 field non-empty → fully authored, not partial.

    Lint runner has nothing to escalate (no META002-005 will fire)."""
    metadata = _meta(
        description="A detection paragraph.",
        attackDescription="What attackers do.",
        references=["https://attack.mitre.org/techniques/T1059/"],
        falsePositives=["Legitimate admin scripts."],
    )
    assert _has_partial_authoring(metadata) is False


def test_partial_authoring_true_when_only_description_set() -> None:
    """Operator started authoring (description filled) but stopped
    before attackDescription / references / falsePositives.

    The graduated policy fires here: escalate the remaining META002-005
    findings to error so the operator has to finish."""
    metadata = _meta(description="A detection paragraph.")
    assert _has_partial_authoring(metadata) is True


def test_partial_authoring_true_when_only_references_set() -> None:
    """Symmetric: references list non-empty but description /
    attackDescription / falsePositives still missing."""
    metadata = _meta(references=["https://example.com/cve-x"])
    assert _has_partial_authoring(metadata) is True


def test_partial_authoring_treats_whitespace_only_as_empty() -> None:
    """A description that's only spaces is not "authored" — operator
    started typing then deleted everything."""
    metadata = _meta(description="   ")
    assert _has_partial_authoring(metadata) is False


# ---------------------------------------------------------------------------
# Runner-level integration: partial authoring escalates METAs to error
# ---------------------------------------------------------------------------


def _write_envelope(detections: Path, rule_id: str, metadata_block: dict) -> Path:
    detections.mkdir(parents=True, exist_ok=True)
    asset_dir = detections / "sentinel_analytic"
    asset_dir.mkdir(parents=True, exist_ok=True)
    p = asset_dir / f"{rule_id}.yml"
    body: dict = {
        "id": rule_id,
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "metadata": {
            "owner": "secops@example.com",
            "runbookUrl": "https://runbooks.example.com/x",
            "severity": "low",
            "tactics": ["Execution"],
            "techniques": ["T1059"],
            "expectedAlertsPerDay": 1,
            "fpHandling": "Triage manually.",
            "lastValidatedAt": "2026-05-14",
            **metadata_block,
        },
        "payload": {"kind": "Scheduled", "displayName": rule_id},
    }
    p.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return p


def test_runner_partial_authoring_escalates_meta_to_error(tmp_path: Path) -> None:
    """Partial T.3 authoring on a single envelope → the missing T.3
    fields surface as ERROR even when strict_policy=False at the
    tenant level."""
    detections = tmp_path / "detections"
    # description filled, the other three T.3 fields missing.
    _write_envelope(detections, "rule-partial", {
        "description": "What this rule detects.",
    })
    linted = lint_assets(detections, strict_policy=False)
    # Find the partial-rule entry.
    [lf] = [x for x in linted if "rule-partial" in str(x.path)]
    severities = {f.rule_id: f.severity for f in lf.findings}
    # The three missing T.3 fields should fire as ERROR (graduated escalation).
    assert severities.get("META003") == "error"
    assert severities.get("META004") == "error"
    assert severities.get("META005") == "error"
    # META002 doesn't fire (description was filled).
    assert "META002" not in severities


def test_runner_no_t3_authoring_stays_lenient(tmp_path: Path) -> None:
    """A collected-style envelope (no T.3 content) keeps lenient
    severity under strict_policy=False — the backlog meter stays
    non-blocking until the tenant flips scaffoldStrict globally."""
    detections = tmp_path / "detections"
    _write_envelope(detections, "rule-collected", {})  # no T.3 fields
    linted = lint_assets(detections, strict_policy=False)
    [lf] = [x for x in linted if "rule-collected" in str(x.path)]
    severities = {f.rule_id: f.severity for f in lf.findings}
    # All four T.3 fields fire as warning (lenient mode), not error.
    for rule_id in ("META002", "META003", "META004", "META005"):
        assert severities.get(rule_id) == "warning", (
            f"{rule_id} should be warning under lenient mode + no T.3 content, "
            f"got {severities.get(rule_id)}"
        )


def test_runner_full_authoring_no_findings(tmp_path: Path) -> None:
    """Fully-authored T.3 envelope produces zero META002-005 findings,
    regardless of mode."""
    detections = tmp_path / "detections"
    _write_envelope(detections, "rule-full", {
        "description": "What this rule detects.",
        "attackDescription": "What attackers do.",
        "references": ["https://attack.mitre.org/techniques/T1059/"],
        "falsePositives": ["Legitimate admin scripts."],
    })
    linted = lint_assets(detections, strict_policy=False)
    [lf] = [x for x in linted if "rule-full" in str(x.path)]
    severities = {f.rule_id: f.severity for f in lf.findings}
    for rule_id in ("META002", "META003", "META004", "META005"):
        assert rule_id not in severities


def test_runner_strict_policy_true_still_escalates_collected(tmp_path: Path) -> None:
    """When the tenant flips ``scaffoldStrict: true`` globally, even
    collected envelopes (no T.3 content) surface META002-005 as error.

    Sanity: graduated escalation is additive, not a replacement for
    the tenant-wide knob."""
    detections = tmp_path / "detections"
    _write_envelope(detections, "rule-collected-strict", {})  # no T.3 fields
    linted = lint_assets(detections, strict_policy=True)
    [lf] = [x for x in linted if "rule-collected-strict" in str(x.path)]
    severities = {f.rule_id: f.severity for f in lf.findings}
    for rule_id in ("META002", "META003", "META004", "META005"):
        assert severities.get(rule_id) == "error"
