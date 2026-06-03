# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for PAYLOAD002 — displayName produces a slug that gets truncated.

Background: ``contentops.utils.slug.displayname_slug`` caps slugs at 80
chars. A longer displayName silently truncates, so the canonical
envelope id no longer matches a literal "slugify the displayName".
Hand-authored references (compliance/mappings/*.yml, audit notes,
SOAR playbook lookup keys) that quote the un-truncated form then
silently diverge.

The compliance fix earlier this session uncovered exactly this
shape: the displayName "Detection of Malicious Process Injection
Events with Untrusted or Rare Initiating Processes" slugs to 104
chars, gets truncated to ``...with-untrusted-or-rare-initiatin``,
and the mapping file referenced the full form.

PAYLOAD002 catches this at PR time. Legacy envelopes (collected
content from the upstream tenant) are exempt — the displayName
came from outside the repo, so a lint rule shouldn't gate it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from contentops.core.asset import Asset
from contentops.lint.payload import lint_payload
from contentops.lint.runner import lint_assets
from contentops.utils.slug import _SLUG_MAX_LEN, displayname_slug


# ---------------------------------------------------------------------------
# Boundary / scope (pure unit tests against lint_payload)
# ---------------------------------------------------------------------------


def _long_display_name(slug_chars: int) -> str:
    """Return a displayName whose slugified form will be exactly ``slug_chars``.

    Slug rules: lowercase + replace runs of non-[a-z0-9] with ``-``,
    strip leading/trailing ``-``. Spaces collapse to single ``-``;
    pure-alpha words pass through. So "word " repeated N times slugs
    to "word-word-word..." — chars = N*4 + (N-1) = 5N - 1. We just
    grow a single token to the required length.
    """
    assert slug_chars >= 1
    return "x" * slug_chars  # single alpha token, slug == name (lowercased).


def test_short_display_name_passes() -> None:
    """A displayName comfortably under the cap produces no PAYLOAD002.

    PAYLOAD003 will fire here because the minimal test payload omits
    `tactics` / `techniques`; that's expected and unrelated to this
    test, so filter to PAYLOAD002 explicitly."""
    payload = {"displayName": "Suspicious LDAP Queries"}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    assert [f.rule_id for f in findings if f.rule_id == "PAYLOAD002"] == []


def test_display_name_at_cap_passes() -> None:
    """Boundary: slug length == cap is fine; only strictly greater
    triggers truncation."""
    payload = {"displayName": _long_display_name(_SLUG_MAX_LEN)}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    assert "PAYLOAD002" not in [f.rule_id for f in findings]


def test_display_name_one_over_cap_triggers_payload002() -> None:
    """Boundary: slug length == cap + 1 emits PAYLOAD002 as warning.

    PAYLOAD002 is informational — the slug truncation is a hand-author
    cross-reference concern, not an ARM-contract failure. Severity
    'warning' rather than 'error' so the build stays green when
    collected content already accepted the truncation by pinning an
    explicit ``id:``.
    """
    payload = {"displayName": _long_display_name(_SLUG_MAX_LEN + 1)}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    p002 = [f for f in findings if f.rule_id == "PAYLOAD002"]
    assert len(p002) == 1
    assert p002[0].severity == "warning"
    # The message points at the cap so the author can see the limit.
    assert str(_SLUG_MAX_LEN) in p002[0].message


def test_payload002_message_is_actionable() -> None:
    """The remediation message should suggest two concrete fixes:
    shorten the displayName, or pin an explicit ``id:``."""
    payload = {"displayName": _long_display_name(_SLUG_MAX_LEN + 50)}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    msg = findings[0].message.lower()
    assert "shorten" in msg
    assert "id:" in msg


def test_missing_display_name_no_finding() -> None:
    """No displayName key in the payload — silent (it's another
    rule's job to require the field)."""
    payload = {"kind": "Scheduled", "query": "T | take 1"}
    findings = lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    assert [f.rule_id for f in findings if f.rule_id == "PAYLOAD002"] == []


def test_non_string_display_name_no_finding() -> None:
    """A pathological displayName value (e.g. None / dict) doesn't crash
    the rule — it just falls through with no finding."""
    for bad in (None, 12345, {"nested": "dict"}, ["a", "b"]):
        payload = {"displayName": bad}
        findings = lint_payload(
            payload, asset=Asset.SENTINEL_ANALYTIC,
        )
        assert [f.rule_id for f in findings if f.rule_id == "PAYLOAD002"] == []


def test_payload002_applies_to_defender_custom_detection() -> None:
    """Defender envelopes derive their canonical id from displayName
    the same way Sentinel does — they're subject to PAYLOAD002 too."""
    payload = {"displayName": _long_display_name(_SLUG_MAX_LEN + 10)}
    findings = lint_payload(
        payload, asset=Asset.DEFENDER_CUSTOM_DETECTION,
    )
    assert any(f.rule_id == "PAYLOAD002" for f in findings)


def test_payload002_applies_to_sentinel_hunting() -> None:
    """Hunting queries share the slug-from-displayName convention."""
    payload = {"displayName": _long_display_name(_SLUG_MAX_LEN + 10)}
    findings = lint_payload(
        payload, asset=Asset.SENTINEL_HUNTING,
    )
    assert any(f.rule_id == "PAYLOAD002" for f in findings)


def test_payload002_does_not_apply_to_non_slug_assets() -> None:
    """Asset kinds whose envelope id is NOT slug-derived (watchlist,
    workbook, parser, ...) shouldn't get the rule applied — their
    canonical ids are stable regardless of any displayName."""
    payload = {"displayName": _long_display_name(_SLUG_MAX_LEN + 10)}
    # Sample a non-detection asset kind.
    findings = lint_payload(
        payload, asset=Asset.SENTINEL_WATCHLIST,
    )
    assert [f.rule_id for f in findings if f.rule_id == "PAYLOAD002"] == []


# ---------------------------------------------------------------------------
# Production reproducer
# ---------------------------------------------------------------------------


def test_payload002_catches_the_historical_compliance_incident() -> None:
    """The displayName that escaped the compliance reconcile in the
    `defender-` prefix incident:

      "Detection of Malicious Process Injection Events with
       Untrusted or Rare Initiating Processes"

    Its slug is 104 chars; the production helper truncates to
    ``...with-untrusted-or-rare-initiatin``. The lint rule must
    fire on this displayName so a future PR introducing a
    similarly-long title gets caught at gate time."""
    historical = (
        "Detection of Malicious Process Injection Events with "
        "Untrusted or Rare Initiating Processes"
    )
    # Sanity: the production slug helper does truncate.
    assert len(displayname_slug(historical)) == _SLUG_MAX_LEN
    findings = lint_payload(
        {"displayName": historical},
        asset=Asset.DEFENDER_CUSTOM_DETECTION,
    )
    assert any(f.rule_id == "PAYLOAD002" for f in findings), (
        f"PAYLOAD002 must fire on the historical incident displayName; "
        f"got {[f.rule_id for f in findings]}"
    )


# ---------------------------------------------------------------------------
# End-to-end through lint_assets (the runner integration)
# ---------------------------------------------------------------------------


def _write_envelope(
    detections: Path, *,
    envelope_id: str,
    asset_value: str,
    display_name: str,
) -> Path:
    asset_dir = detections / asset_value
    asset_dir.mkdir(parents=True, exist_ok=True)
    doc: dict = {
        "id": envelope_id,
        "version": "0.1.0",
        "asset": asset_value,
        "status": "production",
        "metadata": {
            "owner": "secops@example.com",
            "runbookUrl": "https://runbooks.example.com/x",
            "severity": "medium",
            "tactics": ["Execution"],
            "expectedAlertsPerDay": 1,
            "fpHandling": "Tune the threshold.",
        },
        "payload": {
            "kind": "Scheduled",
            "displayName": display_name,
            "severity": "Medium",
            "query": "SecurityEvent | take 1",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": [],
            "enabled": True,
        },
    }
    path = asset_dir / f"{envelope_id}.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def test_lint_runner_emits_payload002_for_long_name(tmp_path):
    """End-to-end: an envelope with a too-long displayName surfaces
    PAYLOAD002 via the runner."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="too-long-rule",
        asset_value="sentinel_analytic",
        display_name=_long_display_name(_SLUG_MAX_LEN + 10),
    )
    results = lint_assets(detections, asset_filter=Asset.SENTINEL_ANALYTIC)
    rule_ids = [
        f.rule_id for r in results for f in r.findings
    ]
    assert "PAYLOAD002" in rule_ids, rule_ids


def test_lint_runner_short_name_no_finding(tmp_path):
    """End-to-end happy path — a normal displayName produces no
    PAYLOAD002 finding."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="ok-rule",
        asset_value="sentinel_analytic",
        display_name="Suspicious LDAP Queries",
    )
    results = lint_assets(detections, asset_filter=Asset.SENTINEL_ANALYTIC)
    rule_ids = [
        f.rule_id for r in results for f in r.findings
    ]
    assert "PAYLOAD002" not in rule_ids, rule_ids


# ---------------------------------------------------------------------------
# Sync check between rule + helper
# ---------------------------------------------------------------------------


def test_rule_slug_logic_mirrors_production_helper() -> None:
    """The rule synthesises the un-capped slug to measure
    truncation; that synthesis must match what
    ``contentops.utils.slug.displayname_slug`` would have produced
    in the absence of the cap.

    If the production helper's slug-character rules ever change
    (e.g. a new charset, a different separator), this test will
    fail and the rule's local regex needs to follow.
    """
    samples = [
        "Suspicious LDAP Queries",
        "Detection of attempts to disable Microsoft Defender",
        # Punctuation and unicode-ish edge cases.
        "AAD: a user used PIM to request permisisons (outside office hours!)",
        "rule with    multiple   spaces",
        "trailing punctuation!!!",
    ]
    from contentops.lint.payload import _NON_SLUG as RULE_NON_SLUG

    for s in samples:
        # Production helper truncates at the cap. We want to compare
        # the *uncapped* slug shape only, so reach into the helper's
        # building blocks.
        production_uncapped = RULE_NON_SLUG.sub(
            "-", s.strip().lower(),
        ).strip("-")
        # And confirm the helper's capped output is a prefix of the
        # uncapped form (up to the trailing-hyphen rstrip).
        capped = displayname_slug(s)
        assert production_uncapped.startswith(capped.rstrip("-")), (
            f"helper output drifted from the rule's uncapped synthesis: "
            f"helper={capped!r}, uncapped={production_uncapped!r}"
        )
