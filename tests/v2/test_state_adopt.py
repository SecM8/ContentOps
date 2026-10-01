# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``contentops state adopt``.

``state adopt`` runs the read-only drift comparison and records every
IN-SYNC asset in the per-env state file with ``status="adopted"``. It
must never adopt an asset that differs from the tenant, never touch
state when the comparison could not complete, key state by the LOCAL
envelope id (not the remote-derived slug), and leave
``last_apply_sha`` / ``last_apply_at`` alone because adoption is not
an apply.

Stub drift handlers replay canned ARM ``alertRules`` items, the same
shape ``tests/v2/test_arm_name_matching.py`` uses. The v2 conftest
already chdirs every test into its own ``tmp_path``, so the state file
lands in ``tmp_path/state/<env>/state.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.registry import default_registry
from contentops.state import EnvState, load_state, save_state, state_path

ENV = "adopt-test"


def _payload(display_name: str, *, query: str) -> dict:
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
    return {
        "name": name,
        "kind": "Scheduled",
        "etag": 'W/"e"',
        "properties": _payload(display_name, query=query),
    }


class _StubDriftHandler:
    """Drift-capable analytic handler over canned remote items.

    Mirrors the production ``to_envelope`` shape: envelope id is the
    displayName slug, ``metadata.arm_name`` is the ARM name. Any write
    method raises, so a test fails loudly if adopt ever tries to touch
    the tenant.
    """

    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self, remote_items: Iterable[dict] = (), *,
                 list_error: Exception | None = None) -> None:
        self.remote_items = list(remote_items)
        self.list_error = list_error

    def list_remote(self):
        if self.list_error is not None:
            raise self.list_error
        return list(self.remote_items)

    def to_envelope(self, remote: dict) -> dict | None:
        from contentops.utils.slug import displayname_slug
        rid = remote.get("name")
        properties = dict(remote.get("properties") or {})
        envelope_id = displayname_slug(
            properties.get("displayName") or "", fallback_id=rid,
        )
        properties["kind"] = remote.get("kind", "Scheduled")
        return {
            "id": envelope_id,
            "version": "0.1.0",
            "asset": Asset.SENTINEL_ANALYTIC.value,
            "status": "production",
            "legacy": True,
            "metadata": {"arm_name": rid},
            "payload": properties,
        }

    def validate(self, loaded):
        return None

    def plan(self, loaded):  # pragma: no cover - never called by adopt
        raise AssertionError("adopt must not plan")

    def apply(self, loaded, *, dry_run=False):  # pragma: no cover
        raise AssertionError("adopt must not write to the tenant")

    def delete(self, remote_id: str):  # pragma: no cover
        raise AssertionError("adopt must not delete from the tenant")

    def close(self):
        return None


def _register(handler) -> None:
    default_registry.reset_all()
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: handler)


def _adopt(*extra: str):
    return CliRunner().invoke(
        cli,
        ["state", "adopt", "--path", "detections",
         "--asset", "sentinel_analytic", "--env", ENV, *extra],
    )


def _managed() -> dict:
    return load_state(env=ENV).managed_assets.get("sentinel_analytic", {})


# ---------------------------------------------------------------------------


def test_in_sync_asset_is_adopted_with_status_adopted(tmp_path: Path) -> None:
    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    _register(_StubDriftHandler([_remote("guid-a", "Rule A")]))

    result = _adopt()

    assert result.exit_code == 0, result.output
    managed = _managed()
    assert set(managed) == {"rule-a"}
    assert managed["rule-a"].status == "adopted"
    assert managed["rule-a"].remote_id == "guid-a"
    assert state_path(env=ENV).is_file()
    assert "adopted: 1" in result.output


def test_changed_and_new_entries_are_never_adopted(tmp_path: Path) -> None:
    detections = Path("detections")
    _write_envelope(detections, envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    _write_envelope(detections, envelope_id="rule-b",
                    display_name="Rule B", arm_name="guid-b",
                    query="SecurityEvent | take 1")
    _register(_StubDriftHandler([
        _remote("guid-a", "Rule A"),
        # Query edited in the portal -> CHANGED.
        _remote("guid-b", "Rule B", query="SecurityEvent | take 99"),
        # Only in the tenant -> NEW.
        _remote("guid-c", "Rule C"),
    ]))

    result = _adopt()

    assert result.exit_code == 0, result.output
    assert set(_managed()) == {"rule-a"}
    assert "not adopted (differs): 2" in result.output
    assert "changed: 1, new: 1" in result.output
    assert "not adopted (differs from tenant: CHANGED)" in result.output
    assert "not adopted (differs from tenant: NEW)" in result.output


def test_error_entry_exits_non_zero_and_leaves_state_untouched(tmp_path: Path) -> None:
    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    existing = EnvState(env=ENV, last_apply_sha="abc", last_apply_at="t0")
    existing.remember("sentinel_analytic", "old-rule", sha="abc")
    path = save_state(existing)
    before = path.read_bytes()
    _register(_StubDriftHandler(list_error=RuntimeError("ARM 500")))

    result = _adopt()

    assert result.exit_code != 0, result.output
    assert "could not list remote: ARM 500" in result.output
    assert "state was not changed" in result.output
    assert path.read_bytes() == before


def test_error_entry_does_not_create_state_file(tmp_path: Path) -> None:
    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    _register(_StubDriftHandler(list_error=RuntimeError("401")))

    result = _adopt()

    assert result.exit_code != 0
    assert not state_path(env=ENV).exists()


def test_renamed_rule_is_keyed_by_local_envelope_id(tmp_path: Path) -> None:
    """Local id is slug-disambiguated (``aad-failed-mfa-6babf568``); the
    remote re-slugs to ``aad-failed-mfa``. Drift matches by arm_name and
    reports the remote-derived id -- state must use the LOCAL id, which
    is what apply / prune / the status page look up."""
    _write_envelope(
        Path("detections"),
        envelope_id="aad-failed-mfa-6babf568",
        display_name="AAD failed MFA",
        arm_name="6babf568-a01d-44c7-a2ba-6fbb748c7b12",
    )
    _register(_StubDriftHandler([
        _remote("6babf568-a01d-44c7-a2ba-6fbb748c7b12", "AAD failed MFA"),
    ]))

    result = _adopt()

    assert result.exit_code == 0, result.output
    managed = _managed()
    assert set(managed) == {"aad-failed-mfa-6babf568"}, set(managed)
    assert managed["aad-failed-mfa-6babf568"].remote_id == (
        "6babf568-a01d-44c7-a2ba-6fbb748c7b12"
    )


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    _register(_StubDriftHandler([_remote("guid-a", "Rule A")]))

    result = _adopt("--dry-run")

    assert result.exit_code == 0, result.output
    assert "would adopt: 1" in result.output
    assert "[dry-run]" in result.output
    assert not state_path(env=ENV).exists()
    assert not Path("state").exists()


def test_last_apply_fields_unchanged_after_adopt(tmp_path: Path) -> None:
    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    existing = EnvState(env=ENV, last_apply_sha="deadbeef",
                        last_apply_at="2026-01-01T00:00:00.000000Z")
    save_state(existing)
    _register(_StubDriftHandler([_remote("guid-a", "Rule A")]))

    result = _adopt()

    assert result.exit_code == 0, result.output
    state = load_state(env=ENV)
    assert state.last_apply_sha == "deadbeef"
    assert state.last_apply_at == "2026-01-01T00:00:00.000000Z"
    assert state.is_managed("sentinel_analytic", "rule-a")


def test_already_managed_is_skipped_without_refresh(tmp_path: Path) -> None:
    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    existing = EnvState(env=ENV)
    existing.remember("sentinel_analytic", "rule-a", sha="cafe", status="success")
    save_state(existing)
    _register(_StubDriftHandler([_remote("guid-a", "Rule A")]))

    result = _adopt()

    assert result.exit_code == 0, result.output
    entry = _managed()["rule-a"]
    assert entry.status == "success"
    assert entry.last_applied_sha == "cafe"
    assert "already managed: 1" in result.output
    assert "adopted: 0" in result.output

    _register(_StubDriftHandler([_remote("guid-a", "Rule A")]))
    refreshed = _adopt("--refresh")

    assert refreshed.exit_code == 0, refreshed.output
    assert _managed()["rule-a"].status == "adopted"
    assert "adopted: 1" in refreshed.output


def test_state_file_stays_loadable_by_schema(tmp_path: Path) -> None:
    """Adopt adds no new fields to AssetStateEntry -- older clients build
    it with ``AssetStateEntry(**entry)`` and would crash on extras."""
    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    _register(_StubDriftHandler([_remote("guid-a", "Rule A")]))

    assert _adopt().exit_code == 0
    raw = json.loads(state_path(env=ENV).read_text(encoding="utf-8"))
    entry = raw["managed_assets"]["sentinel_analytic"]["rule-a"]
    assert set(entry) == {"remote_id", "last_applied_at",
                          "last_applied_sha", "status"}


def test_adopted_asset_renders_managed_on_status_page(tmp_path: Path) -> None:
    from contentops.status import render_deployments

    _write_envelope(Path("detections"), envelope_id="rule-a",
                    display_name="Rule A", arm_name="guid-a")
    _register(_StubDriftHandler([_remote("guid-a", "Rule A")]))
    assert _adopt().exit_code == 0

    rendered = render_deployments(
        detections_root=Path("detections"),
        state=load_state(env=ENV),
        audit_dir=Path("audit"),
    )
    assert "in-sync (adopted)" in rendered
    assert "0 unmanaged" in rendered
