# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Round-trip drift tests for automation rules and playbooks.

collect -> write -> load -> drift must come back in-sync, including the
playbook definition sidecar and the ``playbook:`` sugar on automation
rules.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import yaml

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.discovery import load_asset
from contentops.core.drift import detect_drift, write_drift
from contentops.handlers.sentinel_automation_rule import SentinelAutomationRuleHandler
from contentops.handlers.sentinel_playbook import SentinelPlaybookHandler
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


def _definition() -> dict:
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {"manual": {"type": "Request", "kind": "Http"}},
        "actions": {},
    }


def _provider() -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws",
                         playbooksResourceGroup="rg-pb")
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(base_url=sentinel_arm.ARM_BASE_URL,
                             transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    return p


class _StubAutomation(SentinelAutomationRuleHandler):
    def __init__(self, items: list[dict]) -> None:
        super().__init__(_provider, tenant_id="tenant-guid")
        self._items = items

    def list_remote(self) -> list[dict]:
        return self._items


class _StubPlaybook(SentinelPlaybookHandler):
    def __init__(self, items: list[dict]) -> None:
        super().__init__(_provider)
        self._items = items

    def list_remote(self) -> list[dict]:
        return self._items


def _automation_remote() -> dict:
    return {
        "name": "00000000-0000-0000-0000-000000000001",
        "properties": {
            "displayName": "Run Notify SOC",
            "order": 1,
            "triggeringLogic": {"isEnabled": True, "triggersOn": "Incidents",
                                "triggersWhen": "Created", "conditions": []},
            "actions": [{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {
                "logicAppResourceId": "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/notify-soc",
                "tenantId": "tenant-guid"}}],
        },
    }


def _playbook_remote() -> dict:
    return {
        "name": "notify-soc", "location": "westeurope",
        "tags": {"contentops-managed": "true"},
        "identity": {"type": "SystemAssigned", "principalId": "p"},
        "properties": {"definition": _definition(), "state": "Enabled"},
    }


def test_drift_writes_envelopes_and_sidecars_that_reload_and_come_back_in_sync(tmp_path: Path) -> None:
    handlers = [_StubAutomation([_automation_remote()]), _StubPlaybook([_playbook_remote()])]

    report = detect_drift(handlers, tmp_path)
    new_ids = {(e.asset, e.asset_id) for e in report.new}
    assert (Asset.SENTINEL_AUTOMATION_RULE, "run-notify-soc") in new_ids
    assert (Asset.SENTINEL_PLAYBOOK, "notify-soc") in new_ids

    written = write_drift(report, tmp_path)
    names = sorted(p.name for p in written)
    assert names == ["notify-soc.workflow.json", "notify-soc.yml", "run-notify-soc.yml"]

    pb_yaml = yaml.safe_load((tmp_path / "sentinel_playbook" / "notify-soc.yml").read_text(encoding="utf-8"))
    assert pb_yaml["payload"]["definitionFile"] == "notify-soc.workflow.json"
    assert "definition" not in pb_yaml["payload"]
    sidecar = json.loads((tmp_path / "sentinel_playbook" / "notify-soc.workflow.json").read_text(encoding="utf-8"))
    assert sidecar == _definition()

    ar_yaml = yaml.safe_load((tmp_path / "sentinel_automation_rule" / "run-notify-soc.yml").read_text(encoding="utf-8"))
    cfg = ar_yaml["payload"]["actions"][0]["actionConfiguration"]
    assert cfg == {"playbook": "notify-soc"}  # no GUIDs on disk
    assert ar_yaml["metadata"]["arm_name"] == "00000000-0000-0000-0000-000000000001"

    # Every written envelope loads (sidecar inlined) and validates.
    for path in (p for p in written if p.suffix == ".yml"):
        la = load_asset(path)
        assert la.envelope.asset in (Asset.SENTINEL_AUTOMATION_RULE, Asset.SENTINEL_PLAYBOOK)
        assert la.payload
        if la.envelope.asset is Asset.SENTINEL_PLAYBOOK:
            assert la.payload["definition"] == _definition()
            assert "definitionFile" not in la.payload

    # Second pass: everything is in-sync, nothing to write, no version bump.
    report2 = detect_drift(handlers, tmp_path)
    assert not report2.has_drift(), [(e.asset.value, e.asset_id, e.kind) for e in report2.entries]
    assert len(report2.in_sync) == 2


def test_drift_detects_changed_playbook_definition(tmp_path: Path) -> None:
    handlers = [_StubPlaybook([_playbook_remote()])]
    write_drift(detect_drift(handlers, tmp_path), tmp_path)

    changed = _playbook_remote()
    changed["properties"]["definition"]["actions"]["Notify"] = {"type": "Http", "inputs": {}}
    report = detect_drift([_StubPlaybook([changed])], tmp_path)
    assert [e.kind for e in report.entries] == ["changed"]
    written = write_drift(report, tmp_path)
    assert any(p.name == "notify-soc.workflow.json" for p in written)
    sidecar = json.loads((tmp_path / "sentinel_playbook" / "notify-soc.workflow.json").read_text(encoding="utf-8"))
    assert "Notify" in sidecar["actions"]
    # version bumped exactly once for the real change
    pb_yaml = yaml.safe_load((tmp_path / "sentinel_playbook" / "notify-soc.yml").read_text(encoding="utf-8"))
    assert pb_yaml["version"] == "1.0.1"


def test_drift_matches_collected_automation_rule_by_arm_name_after_rename(tmp_path: Path) -> None:
    handlers = [_StubAutomation([_automation_remote()])]
    write_drift(detect_drift(handlers, tmp_path), tmp_path)
    renamed = _automation_remote()
    renamed["properties"]["displayName"] = "Run Notify SOC (renamed)"
    report = detect_drift([_StubAutomation([renamed])], tmp_path)
    assert [e.kind for e in report.entries] == ["changed"]
    assert report.changed[0].local_path.name == "run-notify-soc.yml"
