# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for PAYLOAD003, PAYLOAD004, META008, META009 lint rules.

Background — these four rules were added together to address gaps the
100-engineer review surfaced:

* **PAYLOAD003** — MITRE ATT&CK mapping fields empty on a detection.
  Warning, not error: a tenant may legitimately ship a rule that
  isn't ATT&CK-mapped yet, but the linter is loud about it at commit.
* **PAYLOAD004** — Defender custom detection ``recommendedActions``
  is null. SOC analysts see "no triage guidance" in the portal;
  warning to nudge authors.
* **META008** — Template-TODO placeholders (``TODO (METAxxx): ...``)
  surviving past ``status: experimental``. Error severity once the
  rule is promoted — production envelopes must not ship with the
  literal scaffold prompt visible to analysts.
* **META009** — Self-declared FP-rate ``fpExpectedPerWeek=high``
  paired with ``severity=high`` is the classic noise-generator
  shape. Info severity (we don't block), but the lint message points
  at the rule before it gets promoted into the triage backlog.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from types import SimpleNamespace

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.metadata import RuleMetadata
from contentops.lint.metadata_rules import lint_metadata
from contentops.lint.payload import lint_payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _full_metadata(**overrides) -> RuleMetadata:
    """Build a fully-populated RuleMetadata so META002-007 stay quiet
    and only the rule under test fires."""
    defaults: dict = {
        "owner": "secops@example.com",
        "runbookUrl": "https://runbooks.example.com/x",
        "severity": "medium",
        "tactics": ["Execution"],
        "techniques": ["T1059"],
        "expectedAlertsPerDay": 1,
        "fpHandling": "Tune threshold; check known service accounts.",
        "description": "Real authored description, not a placeholder.",
        "attackDescription": "Real attack context, not a placeholder.",
        "references": ["https://attack.mitre.org/techniques/T1059/"],
        "falsePositives": ["Admin scripts running scheduled tasks."],
        "lastValidatedAt": date.today().isoformat(),
    }
    defaults.update(overrides)
    return RuleMetadata(**defaults)


def _loaded(envelope: EnvelopeV2, payload: dict | None = None) -> SimpleNamespace:
    """Shape that satisfies ``LoadedAsset`` for the lint functions.

    The lint_metadata function reads ``.envelope`` and ``.payload``; a
    SimpleNamespace with those two attributes is sufficient — no need
    to construct a real LoadedAsset (which couples to the discovery
    machinery)."""
    return SimpleNamespace(envelope=envelope, payload=payload or {})


# ---------------------------------------------------------------------------
# PAYLOAD003 — empty MITRE
# ---------------------------------------------------------------------------


def test_payload003_sentinel_empty_tactics_warns() -> None:
    payload = {"tactics": [], "techniques": ["T1059"]}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    p003 = [f for f in findings if f.rule_id == "PAYLOAD003"]
    assert len(p003) == 1
    assert p003[0].severity == "warning"
    assert "tactics" in p003[0].message


def test_payload003_sentinel_empty_techniques_warns() -> None:
    payload = {"tactics": ["Execution"], "techniques": []}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    p003 = [f for f in findings if f.rule_id == "PAYLOAD003"]
    assert len(p003) == 1
    assert "techniques" in p003[0].message


def test_payload003_sentinel_both_populated_silent() -> None:
    payload = {"tactics": ["Execution"], "techniques": ["T1059"]}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    assert [f for f in findings if f.rule_id == "PAYLOAD003"] == []


def test_payload003_sentinel_both_empty_two_findings() -> None:
    payload = {"tactics": [], "techniques": []}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    p003 = [f for f in findings if f.rule_id == "PAYLOAD003"]
    assert len(p003) == 2


def test_payload003_defender_empty_mitre_techniques_warns() -> None:
    payload = {
        "detectionAction": {
            "alertTemplate": {"mitreTechniques": []},
        },
    }
    findings = lint_payload(payload, asset=Asset.DEFENDER_CUSTOM_DETECTION)
    p003 = [f for f in findings if f.rule_id == "PAYLOAD003"]
    assert len(p003) == 1
    assert "mitreTechniques" in p003[0].message


def test_payload003_defender_with_mitre_silent() -> None:
    payload = {
        "detectionAction": {
            "alertTemplate": {"mitreTechniques": ["T1059.001"]},
        },
    }
    findings = lint_payload(payload, asset=Asset.DEFENDER_CUSTOM_DETECTION)
    assert [f for f in findings if f.rule_id == "PAYLOAD003"] == []


def test_payload003_handles_missing_alert_template() -> None:
    """Defender envelope with no detectionAction block — degrades
    gracefully, doesn't crash."""
    payload = {"displayName": "minimal"}
    findings = lint_payload(payload, asset=Asset.DEFENDER_CUSTOM_DETECTION)
    p003 = [f for f in findings if f.rule_id == "PAYLOAD003"]
    # No alertTemplate -> mitreTechniques is missing -> warning
    assert len(p003) == 1


# ---------------------------------------------------------------------------
# PAYLOAD004 — null recommendedActions
# ---------------------------------------------------------------------------


def test_payload004_defender_null_actions_warns() -> None:
    payload = {
        "detectionAction": {
            "alertTemplate": {"recommendedActions": None},
        },
    }
    findings = lint_payload(payload, asset=Asset.DEFENDER_CUSTOM_DETECTION)
    p004 = [f for f in findings if f.rule_id == "PAYLOAD004"]
    assert len(p004) == 1
    assert p004[0].severity == "warning"


def test_payload004_defender_empty_string_warns() -> None:
    payload = {
        "detectionAction": {
            "alertTemplate": {"recommendedActions": "   "},
        },
    }
    findings = lint_payload(payload, asset=Asset.DEFENDER_CUSTOM_DETECTION)
    p004 = [f for f in findings if f.rule_id == "PAYLOAD004"]
    assert len(p004) == 1


def test_payload004_defender_filled_silent() -> None:
    payload = {
        "detectionAction": {
            "alertTemplate": {
                "recommendedActions": "Investigate the process tree.",
            },
        },
    }
    findings = lint_payload(payload, asset=Asset.DEFENDER_CUSTOM_DETECTION)
    assert [f for f in findings if f.rule_id == "PAYLOAD004"] == []


def test_payload004_does_not_apply_to_sentinel() -> None:
    """PAYLOAD004 is Defender-specific (the field doesn't exist on
    Sentinel envelopes)."""
    payload = {"recommendedActions": None}  # nonsensical on Sentinel
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    assert [f for f in findings if f.rule_id == "PAYLOAD004"] == []


def test_payload004_missing_field_no_finding() -> None:
    """If recommendedActions key isn't present at all, no finding —
    the rule warns about explicit nulls / empties, not absences."""
    payload = {"detectionAction": {"alertTemplate": {}}}
    findings = lint_payload(payload, asset=Asset.DEFENDER_CUSTOM_DETECTION)
    assert [f for f in findings if f.rule_id == "PAYLOAD004"] == []


# ---------------------------------------------------------------------------
# META008 — template-TODO surviving past experimental
# ---------------------------------------------------------------------------


def test_meta008_silent_when_experimental() -> None:
    """A freshly-scaffolded envelope (status=experimental) with TODO
    placeholders in T.3 fields is fine — that's the scaffolding
    purpose."""
    metadata = _full_metadata(
        description="TODO (META002): describe what this rule detects",
        attackDescription="TODO (META003): describe the threat context",
    )
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="experimental", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    assert [f for f in findings if f.rule_id == "META008"] == []


def test_meta008_fires_on_production_with_todo() -> None:
    metadata = _full_metadata(
        description="TODO (META002): describe what this rule detects",
    )
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="production", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    m008 = [f for f in findings if f.rule_id == "META008"]
    assert len(m008) == 1
    assert m008[0].severity == "error"
    assert "description" in m008[0].message


def test_meta008_fires_on_test_status_too() -> None:
    metadata = _full_metadata(
        attackDescription="TODO (META003): describe the threat context",
    )
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="test", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    m008 = [f for f in findings if f.rule_id == "META008"]
    assert len(m008) == 1


def test_meta008_silent_on_real_content() -> None:
    """Production envelope with real T.3 content — no finding."""
    metadata = _full_metadata()
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="production", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    assert [f for f in findings if f.rule_id == "META008"] == []


def test_meta008_does_not_fire_on_word_todo_midtext() -> None:
    """The check is prefix-anchored; a sentence containing the word
    'todo' mid-text isn't a scaffold placeholder."""
    metadata = _full_metadata(
        description="Detects users adding a todo item in admin tooling.",
    )
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="production", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    assert [f for f in findings if f.rule_id == "META008"] == []


# ---------------------------------------------------------------------------
# META009 — severity / FP-rate mismatch
# ---------------------------------------------------------------------------


def test_meta009_fires_on_high_severity_high_fp() -> None:
    metadata = _full_metadata(severity="high", fpExpectedPerWeek="high")
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="experimental", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    m009 = [f for f in findings if f.rule_id == "META009"]
    assert len(m009) == 1
    assert m009[0].severity == "info"


def test_meta009_silent_when_severity_medium() -> None:
    metadata = _full_metadata(severity="medium", fpExpectedPerWeek="high")
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="experimental", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    assert [f for f in findings if f.rule_id == "META009"] == []


def test_meta009_silent_when_fp_low() -> None:
    metadata = _full_metadata(severity="high", fpExpectedPerWeek="low")
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="experimental", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    assert [f for f in findings if f.rule_id == "META009"] == []


def test_meta009_silent_when_fp_not_set() -> None:
    """fpExpectedPerWeek is optional; absent means "no opinion" and
    the rule can't fire."""
    metadata = _full_metadata(severity="high")  # no fpExpectedPerWeek
    env = EnvelopeV2(
        id="example-rule", version="0.1.0", asset=Asset.SENTINEL_ANALYTIC,
        status="experimental", metadata=metadata,
    )
    findings = list(lint_metadata(_loaded(env)))
    assert [f for f in findings if f.rule_id == "META009"] == []
