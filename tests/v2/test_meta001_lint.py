# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the META001 lint rule (lastValidatedAt freshness, S.2 / G19).

The rule mirrors the existing
``contentops.lifecycle.gate_recent_validation`` check but surfaces it at
lint time so operators see the warning during PR review instead of
when they hit the promote-to-production gate.

Four cases pinned:

* missing field on a full metadata block → ``warning``
* well-formed but stale field → ``warning`` with the age in the message
* well-formed and fresh field → no finding (clean)
* malformed value (not ISO 8601) → ``error``

Plus one regression: an envelope with no ``metadata`` block at all
(common for freshly-collected rules) emits the same "not set" warning
rather than crashing the rule.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.metadata import RuleMetadata
from contentops.lint.metadata_rules import lint_metadata


def _load(metadata: RuleMetadata | None, *, status: str = "test") -> LoadedAsset:
    """Build a minimal LoadedAsset with the given metadata for lint.

    Default status is ``"test"``. Severity for META002-005 is driven
    solely by ``strict_policy`` now — the production-status auto-
    escalation was removed (see ``CHANGELOG.md`` and the
    metadata-backlog entry in ``docs/reference/gap-assessment.md``).
    """
    envelope = EnvelopeV2(
        id="test-rule",
        version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC,
        status=status,
        metadata=metadata,
    )
    return LoadedAsset(path=Path("test.yml"), envelope=envelope, payload={})


def _full_metadata(**overrides) -> RuleMetadata:
    """Build a RuleMetadata with sensible authoring defaults; overrides
    let each test inject a different ``lastValidatedAt``."""
    base = dict(
        owner="secops@example.com",
        runbookUrl="https://runbooks.example.com/x",
        severity="low",
        tactics=["Execution"],
        techniques=["T1059"],
        expectedAlertsPerDay=1,
        fpHandling="Triage manually.",
    )
    base.update(overrides)
    return RuleMetadata(**base)


def _findings_for(findings, rule_id: str):
    """Scope assertions to a single rule_id. The lint_metadata function
    now emits META001 PLUS META002-007 for any envelope missing
    authoring fields; this helper keeps the per-rule tests focused on
    their target without coupling to the other rules' behaviour."""
    return [f for f in findings if f.rule_id == rule_id]


def test_lastvalidatedat_missing_warns() -> None:
    """Authored envelope with all required metadata but no
    ``lastValidatedAt`` → META001 warning. Operator action: validate
    the rule, add the field."""
    findings = list(lint_metadata(_load(_full_metadata())))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert f[0].severity == "warning"
    assert "lastValidatedAt is not set" in f[0].message


def test_lastvalidatedat_fresh_clean() -> None:
    """A recent ``lastValidatedAt`` (within the 180-day default) yields
    no META001 finding (other META rules may still fire)."""
    today = date(2026, 5, 15)
    fresh = "2026-04-01"  # ~44 days back
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt=fresh)),
        today=today,
    ))
    assert _findings_for(findings, "META001") == []


def test_lastvalidatedat_stale_warns_with_age() -> None:
    """A ``lastValidatedAt`` older than 180 days → warning. The age
    and threshold are both surfaced in the message so the operator
    knows exactly how stale and what the bar is."""
    today = date(2026, 5, 15)
    stale = "2025-01-01"  # ~500 days back
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt=stale)),
        today=today,
    ))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert f[0].severity == "warning"
    assert "2025-01-01" in f[0].message
    assert "180d" in f[0].message or "180 d" in f[0].message


def test_lastvalidatedat_malformed_errors() -> None:
    """A non-ISO value (e.g. ``'last Tuesday'``) → error severity.
    Stricter than the missing case because a bogus value would
    silently bypass the freshness check unless we trip on it."""
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="last Tuesday")),
        today=date(2026, 5, 15),
    ))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert f[0].severity == "error"
    assert "not ISO 8601" in f[0].message


def test_no_metadata_block_warns_not_crashes() -> None:
    """A freshly-collected envelope with ``metadata is None`` should
    surface the same "not set" warning as a full-metadata envelope
    missing the field. The lint runner walks collected envelopes too;
    crashing here would break the whole lint run."""
    findings = list(lint_metadata(_load(None)))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert f[0].severity == "warning"
    assert "not set" in f[0].message


def test_custom_max_age_threshold() -> None:
    """The threshold is configurable so a future caller (e.g. a
    project-specific compliance gate) can tighten it. With a 30-day
    threshold, a 44-day-old value is now stale."""
    today = date(2026, 5, 15)
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-04-01")),
        today=today,
        max_age_days=30,
    ))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert "30d" in f[0].message or "30 d" in f[0].message


def test_production_uses_stricter_90day_threshold() -> None:
    """Production rules carry alert volume; their freshness bar is
    tighter (90 days) than non-production envelopes (180 days)."""
    today = date(2026, 5, 15)
    # 100 days back — past production's 90-day bar, within test's 180.
    stamp = "2026-02-04"
    # Non-production: clean.
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt=stamp), status="test"),
        today=today,
    ))
    assert _findings_for(findings, "META001") == [], (
        "100-day-old test envelope should NOT trip META001 (180-day bar)"
    )
    # Production: stale.
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt=stamp), status="production"),
        today=today,
    ))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert "90d" in f[0].message or "90 d" in f[0].message
    assert "production" in f[0].message


def test_stale_lastvalidatedat_lenient_mode_stays_warning() -> None:
    """Under lenient mode, staleness is a warning regardless of status —
    the backlog meter, non-blocking. (Closes G19 lenient half.)"""
    today = date(2026, 5, 15)
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2025-01-01"), status="production"),
        today=today,
        strict_policy=False,
    ))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert f[0].severity == "warning"


def test_stale_lastvalidatedat_strict_mode_escalates_to_error() -> None:
    """Under strict mode, staleness escalates to error so CI blocks at
    PR time, not at promote time. Closes G19 strict half."""
    today = date(2026, 5, 15)
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2025-01-01"), status="production"),
        today=today,
        strict_policy=True,
    ))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert f[0].severity == "error"
    # The message names the status and the threshold the operator just hit.
    assert "production" in f[0].message
    assert "90d" in f[0].message or "90 d" in f[0].message


def test_strict_mode_does_not_escalate_clean_lastvalidatedat() -> None:
    """Strict mode only escalates META001 when the field IS stale. A
    recently-validated envelope produces zero META001 findings even
    under strict mode."""
    today = date(2026, 5, 15)
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-05-14"), status="production"),
        today=today,
        strict_policy=True,
    ))
    assert _findings_for(findings, "META001") == []


def test_production_max_age_is_overridable() -> None:
    """The production threshold is a parameter, so a tighter compliance
    gate can pass e.g. ``production_max_age_days=30`` without touching
    the default for other callers."""
    today = date(2026, 5, 15)
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-04-01"), status="production"),
        today=today,
        production_max_age_days=30,
    ))
    f = _findings_for(findings, "META001")
    assert len(f) == 1
    assert "30d" in f[0].message or "30 d" in f[0].message


def test_iso_timestamp_form_accepted() -> None:
    """ARM-style ISO timestamps (with time + Z) should parse fine —
    the underlying ``_parse_iso_date`` accepts both YYYY-MM-DD and
    full ISO timestamps. This pins backwards-compat with whatever
    collect happens to write today."""
    today = date(2026, 5, 15)
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-04-01T00:00:00Z")),
        today=today,
    ))
    # META001 clean; META002-007 still fire because we didn't fill them.
    meta_001 = [f for f in findings if f.rule_id == "META001"]
    assert meta_001 == []


# ---------------------------------------------------------------------------
# META002-META007 — T.3 authoring-metadata rules
# ---------------------------------------------------------------------------


def _meta_findings(findings, rule_id: str):
    return [f for f in findings if f.rule_id == rule_id]


def test_meta002_description_missing_warns_in_lenient_mode() -> None:
    """Default lenient mode: META002 fires as a warning when
    metadata.description is empty/missing."""
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-05-14")),
        today=date(2026, 5, 15),
        strict_policy=False,
    ))
    f = _meta_findings(findings, "META002")
    assert len(f) == 1
    assert f[0].severity == "warning"


def test_meta002_description_missing_errors_in_strict_mode() -> None:
    """Strict mode (tenant.policy.scaffoldStrict=true) escalates
    META002 to error severity so CI blocks."""
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-05-14")),
        today=date(2026, 5, 15),
        strict_policy=True,
    ))
    f = _meta_findings(findings, "META002")
    assert len(f) == 1
    assert f[0].severity == "error"


def test_meta002_description_present_clean() -> None:
    findings = list(lint_metadata(
        _load(_full_metadata(
            lastValidatedAt="2026-05-14",
            description="Detects LSASS access patterns.",
        )),
        today=date(2026, 5, 15),
        strict_policy=True,
    ))
    assert _meta_findings(findings, "META002") == []


def test_meta003_attack_description_strict_vs_lenient() -> None:
    for strict, expected_severity in [(True, "error"), (False, "warning")]:
        findings = list(lint_metadata(
            _load(_full_metadata(lastValidatedAt="2026-05-14")),
            today=date(2026, 5, 15),
            strict_policy=strict,
        ))
        f = _meta_findings(findings, "META003")
        assert len(f) == 1
        assert f[0].severity == expected_severity


def test_meta004_references_empty_strict_vs_lenient() -> None:
    for strict, expected_severity in [(True, "error"), (False, "warning")]:
        findings = list(lint_metadata(
            _load(_full_metadata(lastValidatedAt="2026-05-14")),
            today=date(2026, 5, 15),
            strict_policy=strict,
        ))
        f = _meta_findings(findings, "META004")
        assert len(f) == 1
        assert f[0].severity == expected_severity


def test_meta004_references_present_clean() -> None:
    findings = list(lint_metadata(
        _load(_full_metadata(
            lastValidatedAt="2026-05-14",
            references=["https://attack.mitre.org/techniques/T1059/"],
        )),
        today=date(2026, 5, 15),
        strict_policy=True,
    ))
    assert _meta_findings(findings, "META004") == []


def test_meta005_false_positives_strict_vs_lenient() -> None:
    for strict, expected_severity in [(True, "error"), (False, "warning")]:
        findings = list(lint_metadata(
            _load(_full_metadata(lastValidatedAt="2026-05-14")),
            today=date(2026, 5, 15),
            strict_policy=strict,
        ))
        f = _meta_findings(findings, "META005")
        assert len(f) == 1
        assert f[0].severity == expected_severity


def test_meta006_blind_spots_always_info() -> None:
    """META006 (blindSpots) is INFO regardless of strict mode —
    'known evasions' is genuinely best-effort and shouldn't gate CI."""
    for strict in [True, False]:
        findings = list(lint_metadata(
            _load(_full_metadata(lastValidatedAt="2026-05-14")),
            today=date(2026, 5, 15),
            strict_policy=strict,
        ))
        f = _meta_findings(findings, "META006")
        assert len(f) == 1
        assert f[0].severity == "info", (
            f"META006 must be info in {strict=} mode; got {f[0].severity}"
        )


def test_meta007_response_actions_always_info() -> None:
    """META007 (responseActions) is INFO regardless of strict mode —
    runbookUrl can still carry the full playbook."""
    for strict in [True, False]:
        findings = list(lint_metadata(
            _load(_full_metadata(lastValidatedAt="2026-05-14")),
            today=date(2026, 5, 15),
            strict_policy=strict,
        ))
        f = _meta_findings(findings, "META007")
        assert len(f) == 1
        assert f[0].severity == "info"


def test_no_metadata_block_yields_all_rules() -> None:
    """A freshly-collected envelope with no metadata block at all
    yields META001 + META002-007 (one per rule). Severities follow
    the same strict-vs-lenient rules. Pins that the 'present_metadata=
    False' fast path emits a complete set of findings."""
    findings = list(lint_metadata(
        _load(None),  # no metadata block
        today=date(2026, 5, 15),
        strict_policy=True,
    ))
    rule_ids = sorted(set(f.rule_id for f in findings))
    assert rule_ids == [
        "META001", "META002", "META003", "META004",
        "META005", "META006", "META007",
    ]
    # META002-005 strict -> error; META001 + META006-007 stay warning/info.
    severities_by_id = {f.rule_id: f.severity for f in findings}
    assert severities_by_id["META002"] == "error"
    assert severities_by_id["META005"] == "error"
    assert severities_by_id["META001"] == "warning"
    assert severities_by_id["META006"] == "info"
    assert severities_by_id["META007"] == "info"


def test_fully_authored_envelope_has_no_meta_findings() -> None:
    """The happy path: every Section T field filled, lastValidatedAt
    fresh. Zero META findings in either strict or lenient mode."""
    fresh = _full_metadata(
        lastValidatedAt="2026-05-14",
        description="Detects suspicious LSASS access.",
        attackDescription="Attackers dump NTLM hashes from LSASS for "
                          "pass-the-hash lateral movement.",
        references=[
            "https://attack.mitre.org/techniques/T1003/001/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        ],
        falsePositives=["Vulnerability scanners during scheduled sweeps."],
        blindSpots=["Misses in-memory reflection (T1620)."],
        responseActions=["Isolate the affected host.", "Force user logout."],
    )
    for strict in [True, False]:
        findings = list(lint_metadata(
            _load(fresh),
            today=date(2026, 5, 15),
            strict_policy=strict,
        ))
        # No META findings at all — fully authored.
        meta_ids = {f.rule_id for f in findings}
        assert not meta_ids, f"unexpected findings in {strict=} mode: {findings}"


# ---------------------------------------------------------------------------
# Severity is driven only by strict_policy (no per-status auto-escalation)
# ---------------------------------------------------------------------------


def test_production_status_in_lenient_mode_stays_warning() -> None:
    """``status: production`` does NOT auto-escalate META002-005.

    An earlier revision escalated production envelopes regardless of
    ``strict_policy``. That override was removed so the tenant can
    drain a collected-but-not-yet-enriched production-rules backlog
    without every PR going red. Strictness is now a single explicit
    knob: ``tenant.policy.scaffoldStrict``.
    """
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-05-14"), status="production"),
        today=date(2026, 5, 15),
        strict_policy=False,  # explicitly lenient at the tenant level
    ))
    severities = {f.rule_id: f.severity for f in findings}
    # Policy revision: production no longer auto-escalates META002-005.
    # Full metadata means none fire here; if any did they'd be warning.
    for rule_id in ("META002", "META003", "META004", "META005"):
        if rule_id in severities:
            assert severities[rule_id] == "warning"
    assert severities.get("META006") == "info"
    assert severities.get("META007") == "info"


def test_non_production_status_keeps_lenient_severity() -> None:
    """``status: test`` (the analyst's working state) keeps META002-005
    at warning severity when ``strict_policy=False``. Otherwise the
    enrichment backlog drain experience for a forker would be 'every
    PR fails until every rule is fully enriched' — too rigid."""
    findings = list(lint_metadata(
        _load(_full_metadata(lastValidatedAt="2026-05-14"), status="test"),
        today=date(2026, 5, 15),
        strict_policy=False,
    ))
    severities = {f.rule_id: f.severity for f in findings}
    assert severities.get("META002") == "warning"
    assert severities.get("META003") == "warning"
    assert severities.get("META004") == "warning"
    assert severities.get("META005") == "warning"


def test_collected_envelope_with_production_status_stays_warning() -> None:
    """A collected envelope (no metadata block beyond arm_name) marked
    ``status: production`` reports META002-005 at WARNING under
    ``strict_policy=False`` — the lenient backlog-drain mode.

    Operators who want this to fail CI set
    ``tenant.policy.scaffoldStrict: true`` in ``config/tenant.yml``.
    """
    findings = list(lint_metadata(
        _load(None, status="production"),
        today=date(2026, 5, 15),
        strict_policy=False,
    ))
    # Policy revision: production no longer auto-escalates META002-005.
    # Under strict_policy=False they fire at warning so the backlog is
    # visible without gating CI. Operators opt in via
    # tenant.policy.scaffoldStrict: true to make these blocking.
    by_rule = {f.rule_id: f for f in findings}
    for rule_id in ("META002", "META003", "META004", "META005"):
        assert rule_id in by_rule, f"{rule_id} should still fire as a finding"
        assert by_rule[rule_id].severity == "warning"
