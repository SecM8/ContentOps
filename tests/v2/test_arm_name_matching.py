# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for ``arm_name`` vs envelope-id matching in drift/prune.

These pin the Phase 1 fix to the high-risk slug-collision bug. Before
the fix, ``contentops drift`` and ``contentops prune`` matched remote ARM
rules to local envelopes purely by the slug-derived envelope id. On
tenants where two rules shared a ``displayName``, the slug collided —
collect-time disambiguation produced local ids like
``aad-failed-mfa-6babf568`` while the live tenant only had one rule
with ARM name ``6babf568-...`` and a re-derived slug of
``aad-failed-mfa``. The strings didn't match, so:

  * drift incorrectly flagged surviving rules as ``NEW``.
  * prune incorrectly flagged surviving rules as orphans and would
    have tried to delete them — saved only by the
    ``--max-deletes`` fail-closed cap.

The fix indexes local envelopes under BOTH their envelope id AND
their ``metadata.arm_name`` (when set), and the drift / prune match
path looks up by the authoritative remote name first, falling back
to envelope id only for legacy envelopes that pre-date arm_name
capture.

The tests below exercise the lookup contract directly
(``_local_index``, ``detect_drift``) and through the prune CLI, so
both layers stay locked down.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.drift import _local_index, detect_drift
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


# ---------------------------------------------------------------------------
# YAML helpers — write legacy-flagged envelopes (collected-content shape)
# ---------------------------------------------------------------------------


def _payload(display_name: str, *, query: str = "SecurityEvent | take 1") -> dict:
    return {
        "kind": "Scheduled",
        "displayName": display_name,
        "severity": "Medium",
        "query": query,
        "queryFrequency": "PT5M",
        "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "tactics": [],
        "enabled": True,
    }


def _write_envelope(
    detections: Path,
    *,
    envelope_id: str,
    display_name: str,
    arm_name: str | None = None,
    query: str = "SecurityEvent | take 1",
) -> Path:
    """Write a legacy-flagged sentinel_analytic envelope.

    ``arm_name`` (when given) lands under ``metadata.arm_name`` —
    parse_envelope mirrors it onto ``envelope.arm_name``. Without
    ``arm_name`` the envelope models a legacy v1 file that pre-dates
    collect-time metadata capture.
    """
    asset_dir = detections / "sentinel_analytic"
    asset_dir.mkdir(parents=True, exist_ok=True)
    doc: dict = {
        "id": envelope_id,
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "legacy": True,
        "payload": _payload(display_name, query=query),
    }
    if arm_name is not None:
        doc["metadata"] = {"arm_name": arm_name}
    path = asset_dir / f"{envelope_id}.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def _remote(name: str, display_name: str, *,
            query: str = "SecurityEvent | take 1") -> dict:
    """Shape of one entry returned by an ARM ``alertRules`` list."""
    return {
        "name": name,
        "kind": "Scheduled",
        "etag": 'W/"e"',
        "properties": {
            "displayName": display_name,
            "severity": "Medium",
            "query": query,
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": [],
            "enabled": True,
        },
    }


class _DriftableHandler:
    """Drift-capable analytic handler that replays the production
    ``to_envelope`` logic against a list of canned remote items.

    Pinned to the post-Phase-1 envelope shape: every remote becomes
    an envelope whose ``metadata.arm_name`` is the remote's
    ``name``, and whose envelope ``id`` is the slugified
    ``displayName`` (collisions resolved by
    ``disambiguate_envelope_ids`` inside ``detect_drift``).
    """

    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self, remote_items: Iterable[dict]) -> None:
        self.remote_items = list(remote_items)

    def list_remote(self):
        return list(self.remote_items)

    def to_envelope(self, remote: dict) -> dict | None:
        from contentops.utils.slug import displayname_slug
        rid = remote.get("name")
        if not rid:
            return None
        properties = dict(remote.get("properties") or {})
        display_name = properties.get("displayName") or ""
        envelope_id = displayname_slug(display_name, fallback_id=rid)
        if not envelope_id:
            return None
        properties.pop("lastModifiedUtc", None)
        for k in ("alertRuleTemplateName", "templateVersion"):
            properties.pop(k, None)
        properties["kind"] = remote.get("kind", "Scheduled")
        return {
            "id": envelope_id,
            "version": "0.1.0",
            "asset": Asset.SENTINEL_ANALYTIC.value,
            "status": "production" if properties.get("enabled", True) else "deprecated",
            "legacy": True,
            "metadata": {"arm_name": rid},
            "payload": properties,
        }

    def validate(self, loaded):
        return None

    def plan(self, loaded):
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.NOOP, status="planned",
        )

    def apply(self, loaded, *, dry_run=False):
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.NOOP, status="success",
        )

    def delete(self, remote_id: str) -> ActionResult:
        return ActionResult(
            asset_id=remote_id, asset_kind=self.asset.value,
            action=PlanAction.DELETE, status="success", detail="deleted",
        )

    def close(self):
        return None


# ===========================================================================
# _local_index — the lookup table both drift + prune use
# ===========================================================================


def test_local_index_registers_envelope_under_both_arm_name_and_id(tmp_path):
    """A modern collect-shaped envelope is reachable via BOTH its
    ``metadata.arm_name`` AND its slug-based envelope id, so a
    remote rule looked up by ARM name matches even when the
    slug-derived id differs."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="aad-failed-mfa-6babf568",
        display_name="AAD failed MFA",
        arm_name="6babf568-a01d-44c7-a2ba-6fbb748c7b12",
    )

    idx = _local_index(detections, Asset.SENTINEL_ANALYTIC)

    # Both keys point at the same on-disk entry.
    assert "aad-failed-mfa-6babf568" in idx, sorted(idx)
    assert "6babf568-a01d-44c7-a2ba-6fbb748c7b12" in idx, sorted(idx)
    assert idx["aad-failed-mfa-6babf568"] == idx[
        "6babf568-a01d-44c7-a2ba-6fbb748c7b12"
    ]


def test_local_index_legacy_envelope_registered_by_id_only(tmp_path):
    """A pre-Phase-1 envelope with no ``metadata.arm_name`` is keyed
    by envelope id only — there's no arm_name to register under."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="legacy-rule",
        display_name="Legacy Rule",
        arm_name=None,
    )

    idx = _local_index(detections, Asset.SENTINEL_ANALYTIC)

    assert "legacy-rule" in idx
    # No arm_name to register under, so the only key is the env id.
    assert len(idx) == 1


# ===========================================================================
# detect_drift — match priority is arm_name first, then envelope id
# ===========================================================================


def test_drift_matches_by_arm_name_when_envelope_id_differs(tmp_path):
    """The classic slug-collision recovery scenario.

    Local envelope id is ``aad-failed-mfa-6babf568`` (slug
    disambiguated at collect time when the displayName collided
    with another rule). After the colliding twin was deleted from
    the tenant, the live tenant has just one remote rule whose ARM
    name is ``6babf568-...`` and whose displayName re-slugs to the
    un-suffixed form ``aad-failed-mfa``. Without arm_name matching
    this remote would be flagged NEW; with it, the rule is
    recognised as in-sync."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="aad-failed-mfa-6babf568",
        display_name="AAD failed MFA",
        arm_name="6babf568-a01d-44c7-a2ba-6fbb748c7b12",
    )

    handler = _DriftableHandler([
        _remote("6babf568-a01d-44c7-a2ba-6fbb748c7b12", "AAD failed MFA"),
    ])

    report = detect_drift([handler], detections)

    assert [e.kind for e in report.entries] == ["in-sync"], (
        f"expected in-sync via arm_name match; got {[(e.kind, e.asset_id) for e in report.entries]}"
    )
    assert report.entries[0].asset_id == "aad-failed-mfa"
    assert report.entries[0].local_path is not None
    assert not report.has_drift()


def test_drift_falls_back_to_envelope_id_for_legacy_envelopes(tmp_path):
    """When the local envelope has no ``metadata.arm_name`` (true
    v1-era files), drift still matches by the envelope id —
    backward-compat with content that pre-dates the arm_name
    capture in collect."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="legacy-rule",
        display_name="Legacy Rule",
        arm_name=None,
    )

    # Remote rule's ARM name is the SAME as the envelope id (matches
    # the v1 convention where the envelope id was the ARM name).
    handler = _DriftableHandler([_remote("legacy-rule", "Legacy Rule")])

    report = detect_drift([handler], detections)

    assert [e.kind for e in report.entries] == ["in-sync"]
    assert report.entries[0].asset_id == "legacy-rule"


def test_drift_slug_collision_does_not_flag_surviving_rule_as_new(tmp_path):
    """End-to-end repro of the historical bug.

    Two displayName-colliding rules existed; one was deleted from the
    tenant. Local still has the survivor's disambiguated YAML. Drift
    against the live tenant (now showing one rule) must NOT report
    NEW — it should match the survivor by ARM name and report
    in-sync."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="user-added-to-priv-role-1840b991",
        display_name="User added to priv role",
        arm_name="1840b991-a12b-4e67-a685-d0cad73863fc",
    )

    handler = _DriftableHandler([
        _remote(
            "1840b991-a12b-4e67-a685-d0cad73863fc",
            "User added to priv role",
        ),
    ])

    report = detect_drift([handler], detections)

    new_entries = [e for e in report.entries if e.kind == "new"]
    assert new_entries == [], (
        "surviving rule must not be reported NEW after slug-collision "
        f"cleanup; report: {[(e.kind, e.asset_id) for e in report.entries]}"
    )
    in_sync = [e for e in report.entries if e.kind == "in-sync"]
    assert len(in_sync) == 1


def test_drift_does_not_misroute_remote_to_wrong_local(tmp_path):
    """Two local envelopes, two remote rules — each remote must match
    its OWN local, not the wrong one. This pins the arm_name lookup
    against the case where two un-suffixed slugs accidentally happen
    to be substrings of each other or otherwise lookalike."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="rule-a-abcd1234",
        display_name="Rule A",
        arm_name="abcd1234-0000-0000-0000-000000000000",
    )
    _write_envelope(
        detections,
        envelope_id="rule-b-efgh5678",
        display_name="Rule B",
        arm_name="efgh5678-0000-0000-0000-000000000000",
        query="SecurityEvent | where EventID == 4625",
    )

    handler = _DriftableHandler([
        _remote("abcd1234-0000-0000-0000-000000000000", "Rule A"),
        _remote(
            "efgh5678-0000-0000-0000-000000000000", "Rule B",
            query="SecurityEvent | where EventID == 4625",
        ),
    ])

    report = detect_drift([handler], detections)

    # Both remotes match a local envelope (in-sync), and the
    # local_path on each entry points at the correct YAML.
    in_sync_pairs = {
        e.asset_id: e.local_path.name for e in report.entries
        if e.kind == "in-sync" and e.local_path is not None
    }
    assert in_sync_pairs == {
        "rule-a": "rule-a-abcd1234.yml",
        "rule-b": "rule-b-efgh5678.yml",
    }, in_sync_pairs


# ===========================================================================
# prune CLI — arm_name match prevents false orphan flags
# ===========================================================================


def _register_only(asset: Asset, handler) -> None:
    """Same helper pattern test_prune.py uses — start from an empty
    registry so the fake is the only handler considered."""
    default_registry.reset_all()
    default_registry.register(asset, lambda: handler)


def test_prune_does_not_flag_remote_orphan_when_arm_name_matches(tmp_path):
    """Local envelope has ``metadata.arm_name=<guid>``; remote has a
    rule with that same ARM ``name``. Even though the envelope id
    (``aad-failed-mfa-6babf568``) and the remote-derived slug
    (``aad-failed-mfa``) differ, the rule MUST match — prune
    reports zero orphans."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="aad-failed-mfa-6babf568",
        display_name="AAD failed MFA",
        arm_name="6babf568-a01d-44c7-a2ba-6fbb748c7b12",
    )

    handler = _DriftableHandler([
        _remote("6babf568-a01d-44c7-a2ba-6fbb748c7b12", "AAD failed MFA"),
    ])
    _register_only(Asset.SENTINEL_ANALYTIC, handler)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic"],
    )
    assert result.exit_code == 0, result.output
    assert "Nothing to prune." in result.output
    assert "ORPHAN" not in result.output


def test_prune_falls_back_to_envelope_id_for_legacy(tmp_path):
    """A legacy envelope (no ``metadata.arm_name``) whose envelope
    id matches the remote ARM name is correctly matched —
    backward-compat path."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="legacy-rule",
        display_name="Legacy Rule",
        arm_name=None,
    )

    handler = _DriftableHandler([_remote("legacy-rule", "Legacy Rule")])
    _register_only(Asset.SENTINEL_ANALYTIC, handler)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic"],
    )
    assert result.exit_code == 0, result.output
    assert "Nothing to prune." in result.output


def test_prune_slug_collision_does_not_delete_surviving_rule(tmp_path):
    """Re-runs the historical-bug scenario through the prune CLI.

    Local has the disambiguated survivor; remote has one rule with
    the matching ARM name. The PRIMARY safety mechanism — arm_name
    matching — must hold: 0 orphans, not ``--max-deletes`` saving
    us at the last second."""
    detections = tmp_path / "detections"
    _write_envelope(
        detections,
        envelope_id="user-added-to-priv-role-1840b991",
        display_name="User added to priv role",
        arm_name="1840b991-a12b-4e67-a685-d0cad73863fc",
    )

    handler = _DriftableHandler([
        _remote(
            "1840b991-a12b-4e67-a685-d0cad73863fc",
            "User added to priv role",
        ),
    ])
    _register_only(Asset.SENTINEL_ANALYTIC, handler)

    # Run with --no-dry-run --yes — if the bug regressed, this would
    # attempt a delete; max-deletes default of 25 wouldn't even
    # fire (single orphan).
    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.output
    assert "Nothing to prune." in result.output
    assert "DELETED" not in result.output
    assert "ORPHAN" not in result.output


def test_prune_max_deletes_remains_guardrail_not_primary_safety(tmp_path):
    """``--max-deletes`` still fires on genuine multi-orphan deletes
    (the cap was the only thing standing between the historical bug
    and unintended prod deletes). This test pins it as a backstop:
    when there ARE actual orphans, the cap still applies — but with
    the arm_name fix in place, well-formed local content never trips
    the cap accidentally.

    Prove both ends in one test: 3 real orphans, cap=2, expect exit 1
    with "exceeds --max-deletes"."""
    detections = tmp_path / "detections"
    detections.mkdir()  # no local envelopes — every remote is an orphan

    handler = _DriftableHandler([
        _remote("orphan-1", "Orphan 1"),
        _remote("orphan-2", "Orphan 2"),
        _remote("orphan-3", "Orphan 3"),
    ])
    _register_only(Asset.SENTINEL_ANALYTIC, handler)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes",
              "--max-deletes", "2"],
    )
    assert result.exit_code == 1, result.output
    assert "exceeds --max-deletes=2" in result.output
