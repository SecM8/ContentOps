# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``contentops collect --enrich`` (L11 — forker bulk import).

The enrichment helper mutates a DriftReport in place so freshly-collected
envelopes carry placeholder metadata + ``status: test`` instead of the
remote's ``status: production``. This makes the day-1 fork experience
"one PR with TODOs to clean up" instead of "159 hand rewrites".

The tests pin three contracts:

* status: production is demoted to status: test (so the L4 escalation
  doesn't fail CI on the freshly-collected rule)
* missing metadata block is replaced with a placeholder that ALSO passes
  RuleMetadata pydantic validation (so the envelope round-trips through
  the parser without errors)
* arm_name on existing minimal metadata is preserved (load-bearing for
  apply / prune idempotency)
* a fully-authored envelope (operator-curated) is LEFT ALONE
"""

from __future__ import annotations

from contentops.cli.commands.collect_support import _enrich_drift_entries
from contentops.core.asset import Asset
from contentops.core.drift import DriftEntry, DriftReport
from contentops.core.envelope import parse_envelope
from contentops.core.metadata import RuleMetadata


def _entry(envelope: dict, *, kind: str = "new") -> DriftEntry:
    return DriftEntry(
        asset=Asset.SENTINEL_ANALYTIC,
        asset_id=envelope.get("id", "x"),
        kind=kind,
        envelope=envelope,
    )


def test_demotes_status_production_to_test() -> None:
    """Production-status rules collected from a tenant get demoted so
    the L4 META escalation doesn't trip on day-1."""
    report = DriftReport()
    report.entries.append(_entry({
        "id": "rule-a", "version": "0.1.0",
        "asset": "sentinel_analytic", "status": "production",
        "metadata": {"arm_name": "abc-123"},
        "payload": {},
    }))
    touched = _enrich_drift_entries(report)
    assert touched == 1
    assert report.entries[0].envelope["status"] == "test"


def test_stubs_placeholder_metadata_when_missing() -> None:
    """A collected envelope with metadata=None gets a full placeholder
    block so the envelope parses through RuleMetadata validation."""
    report = DriftReport()
    report.entries.append(_entry({
        "id": "rule-b", "version": "0.1.0",
        "asset": "sentinel_analytic", "status": "production",
        "payload": {},
    }))
    _enrich_drift_entries(report)
    meta = report.entries[0].envelope["metadata"]
    # Required RuleMetadata fields all present.
    assert set(meta.keys()) >= {
        "owner", "runbookUrl", "severity", "tactics", "techniques",
        "expectedAlertsPerDay", "fpHandling",
    }
    # And the placeholder actually validates as a real RuleMetadata —
    # otherwise the round-trip through parse_envelope would crash on
    # the next lint run.
    RuleMetadata(**meta)


def test_preserves_arm_name_on_minimal_metadata() -> None:
    """The arm_name is load-bearing (apply/prune resolve the remote
    resource by arm_name first). Enrichment must keep it."""
    report = DriftReport()
    report.entries.append(_entry({
        "id": "rule-c", "version": "0.1.0",
        "asset": "sentinel_analytic", "status": "production",
        "metadata": {"arm_name": "deadbeef-1234"},
        "payload": {},
    }))
    _enrich_drift_entries(report)
    assert report.entries[0].envelope["metadata"]["arm_name"] == "deadbeef-1234"


def test_leaves_fully_authored_metadata_alone() -> None:
    """An operator-authored envelope with full metadata isn't touched
    (other than the status demotion, if status was production). We
    don't want enrich to silently regress hand-curated owner / fpHandling
    on a re-collect."""
    authored = {
        "owner": "soc@example.com",
        "runbookUrl": "https://runbooks.example.com/x",
        "severity": "medium",
        "tactics": ["DefenseEvasion"],
        "techniques": ["T1562.001"],
        "expectedAlertsPerDay": 2,
        "fpHandling": "Triage manually.",
        "arm_name": "real-arm",
        "description": "Detects X.",
    }
    report = DriftReport()
    report.entries.append(_entry({
        "id": "rule-d", "version": "0.1.0",
        "asset": "sentinel_analytic", "status": "test",  # not production
        "metadata": authored,
        "payload": {},
    }))
    touched = _enrich_drift_entries(report)
    # Nothing to do: status already non-production, metadata already full.
    assert touched == 0
    # And the metadata is byte-identical.
    assert report.entries[0].envelope["metadata"] == authored


def test_round_trips_through_parse_envelope() -> None:
    """The enriched envelope must parse cleanly through the canonical
    envelope parser — otherwise the very next lint run would crash on
    the freshly-enriched output."""
    report = DriftReport()
    report.entries.append(_entry({
        "id": "rule-e", "version": "0.1.0",
        "asset": "sentinel_analytic", "status": "production",
        "metadata": {"arm_name": "x"},
        "payload": {"queryFrequency": "PT5M"},
    }))
    _enrich_drift_entries(report)
    enriched = report.entries[0].envelope
    envelope, payload = parse_envelope(enriched)
    assert envelope.status == "test"
    assert envelope.metadata is not None
    assert envelope.metadata.owner == "unknown@example.invalid"
