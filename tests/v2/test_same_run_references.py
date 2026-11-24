# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""An automation rule collected in the same run as the analytic and the
playbook it references names them by envelope id.

On a first full collect (or a drift run that finds a new portal rule and
its new automation rule together) the analytic and playbook files are not
on disk yet. The reverse mapping looked only at disk, so the rule kept the
raw analytic resource id, subscription GUID included, which gitleaks
blocks in ``detections/``, and ``logicApp:`` instead of ``playbook:``.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from contentops.cli.commands.collect_support import _classify_collected_drift
from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.drift import detect_drift
from contentops.handlers.sentinel_automation_rule import SentinelAutomationRuleHandler
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider

WS_PATH = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
ANALYTIC_ARM = "1840b991-a12b-4e67-a685-000000000001"


def _provider() -> SentinelArmProvider:
    cfg = SentinelConfig(
        subscriptionId="sub", resourceGroup="rg", workspaceName="ws",
        playbooksResourceGroup="rg-pb",
    )
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(
        base_url=sentinel_arm.ARM_BASE_URL,
        transport=httpx.MockTransport(lambda r: httpx.Response(404)),
    )
    return p


_RULE_REMOTE = {
    "name": "rule-guid",
    "properties": {
        "displayName": "Close test incidents",
        "order": 1,
        "triggeringLogic": {
            "isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
            "conditions": [{
                "conditionType": "Property",
                "conditionProperties": {
                    "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains",
                    "propertyValues": [
                        f"{WS_PATH}/providers/Microsoft.SecurityInsights/alertRules/{ANALYTIC_ARM}",
                    ],
                },
            }],
        },
        "actions": [{
            "order": 1, "actionType": "RunPlaybook",
            "actionConfiguration": {
                "logicAppResourceId": "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/Notify_SOC",
                "tenantId": "tenant",
            },
        }],
    },
}


class _Fake:
    """A drift-capable handler that returns fixed remotes and envelopes."""

    def __init__(self, asset: Asset, remotes: list[dict], envelopes: dict[str, dict]) -> None:
        self.asset = asset
        self._remotes = remotes
        self._envelopes = envelopes

    def list_remote(self) -> list[dict]:
        return self._remotes

    def to_envelope(self, remote: dict) -> dict | None:
        return self._envelopes.get(remote["name"])


def _handlers(root: Path):
    rule = SentinelAutomationRuleHandler(_provider, tenant_id="tenant", detections_root=root)
    rule.list_remote = lambda: [_RULE_REMOTE]  # type: ignore[method-assign]
    analytic = _Fake(Asset.SENTINEL_ANALYTIC, [{"name": ANALYTIC_ARM}], {ANALYTIC_ARM: {
        "id": "suspicious-login", "version": "0.0.0", "asset": "sentinel_analytic",
        "status": "production", "metadata": {"arm_name": ANALYTIC_ARM},
        "payload": {"displayName": "Suspicious login", "kind": "Scheduled", "query": "T"},
    }})
    playbook = _Fake(Asset.SENTINEL_PLAYBOOK, [{"name": "Notify_SOC"}], {"Notify_SOC": {
        "id": "notify-soc", "version": "0.0.0", "asset": "sentinel_playbook",
        "status": "production", "metadata": {"arm_name": "Notify_SOC"},
        "payload": {"definition": {"triggers": {}, "actions": {}}},
    }})
    # The rule handler first on purpose: the order must not matter.
    return [rule, analytic, playbook]


def _rule_payload(report) -> dict:
    [entry] = [e for e in report.entries if e.asset is Asset.SENTINEL_AUTOMATION_RULE]
    assert entry.kind == "new"
    return entry.envelope["payload"]


def _assert_named_by_envelope_id(payload: dict) -> None:
    cond = payload["triggeringLogic"]["conditions"][0]["conditionProperties"]
    assert cond["propertyValues"] == ["analytic:suspicious-login"]
    assert payload["actions"][0]["actionConfiguration"] == {"playbook": "notify-soc"}


def test_drift_names_same_run_analytic_and_playbook_by_id(tmp_path: Path) -> None:
    report = detect_drift(_handlers(tmp_path), tmp_path)
    _assert_named_by_envelope_id(_rule_payload(report))


def test_collect_names_same_run_analytic_and_playbook_by_id(tmp_path: Path) -> None:
    handlers = _handlers(tmp_path)
    results = {h.asset.value: h.list_remote() for h in handlers}
    report = _classify_collected_drift(handlers, results, tmp_path)
    _assert_named_by_envelope_id(_rule_payload(report))


def test_a_file_on_disk_wins_over_a_same_run_id(tmp_path: Path) -> None:
    """An analytic already on disk keeps the id its file has."""
    import yaml

    (tmp_path / "sentinel_analytic").mkdir()
    (tmp_path / "sentinel_analytic" / "old-name.yml").write_text(yaml.safe_dump({
        "id": "old-name", "version": "1.0.0", "asset": "sentinel_analytic", "status": "production",
        "metadata": {"arm_name": ANALYTIC_ARM},
        "payload": {"displayName": "Suspicious login", "kind": "Scheduled", "query": "T"},
    }), encoding="utf-8")
    report = detect_drift(_handlers(tmp_path), tmp_path)
    cond = _rule_payload(report)["triggeringLogic"]["conditions"][0]["conditionProperties"]
    assert cond["propertyValues"] == ["analytic:old-name"]
