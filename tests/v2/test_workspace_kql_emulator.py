# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""The telemetry KQL, executed in the Kusto emulator against synthetic rows.

``test_workspace_kql_strict.py`` proves the queries *bind*; this proves what
they *return*. Opt-in: start Microsoft's emulator and point the tests at it::

    docker run -d --network host -e ACCEPT_EULA=Y \\
        mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
    CONTENTOPS_KUSTO_EMULATOR_URL=http://localhost:8080 \\
        pytest tests/v2/test_workspace_kql_emulator.py

Each scenario is one finding from the review of #395: a rule's alert whose
``AlertType`` doesn't parse to the rule id but sits in a single-rule
incident; an incident closed as FalsePositive, then reopened; an incident
without ``RelatedAnalyticRuleIds`` titled like the rule; a Defender alert in
an incident related to one Sentinel rule; repeated status rows.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

EMULATOR = os.environ.get("CONTENTOPS_KUSTO_EMULATOR_URL", "").rstrip("/")
if not EMULATOR:
    pytest.skip(
        reason="set CONTENTOPS_KUSTO_EMULATOR_URL to a running Kusto emulator",
        allow_module_level=True,
    )

import httpx  # noqa: E402

from contentops.rule_keys import RuleKeys, TelemetryIndex  # noqa: E402
from contentops.workspace_kql import silent_rules_query, suppression_impact_query  # noqa: E402

WS = "0b3c1f2e-1111-4a2b-9c3d-abcdefabcdef"
RULE_ID = (
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights"
    "/workspaces/w/providers/Microsoft.SecurityInsights/alertRules/"
)
NOW = datetime.now(timezone.utc).replace(microsecond=0)

# (hours ago, SystemAlertId, AlertName, AlertType, ProductName)
ALERTS = [
    (3, "a1", "Rule One", f"{WS}_rule-one", "Azure Sentinel"),       # status row 1
    (2, "a1", "Rule One", f"{WS}_rule-one", "Azure Sentinel"),       # status row 2
    (5, "a2", "Rule One from 10.0.0.1", "UnexpectedType", "Microsoft Sentinel"),  # in I1
    (4, "a3", "Rule One from 10.0.0.2", "UnexpectedType2", "Azure Sentinel"),     # no incident
    (1, "a4", "Credential dumping via LSASS", "WindowsDefenderAv", "Microsoft 365 Defender"),
    (1, "a5", "Rule Two", f"{WS}_rule-two", "Azure Sentinel"),
]
# (hours ago, IncidentNumber, Title, Status, Classification, related rules, AlertIds)
INCIDENTS = [
    (5, 1, "Rule One", "New", "", ["rule-one"], ["a2"]),
    (4, 1, "Rule One", "Closed", "TruePositive", ["rule-one"], ["a2"]),
    (3, 2, "Rule One", "Closed", "FalsePositive", ["rule-one"], ["a1"]),
    (2, 2, "Rule One", "Active", "FalsePositive", ["rule-one"], ["a1"]),  # reopened
    (1, 3, "Multi-stage incident", "Closed", "BenignPositive", ["rule-two"], ["a4", "a5"]),
    (1, 4, "Rule One", "Closed", "TruePositive", [], []),
]


def _ts(hours: float) -> str:
    stamp = (NOW - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    return f"datetime({stamp})"


class _Kusto:
    def __init__(self, url: str, db: str) -> None:
        # The emulator is local: never route it through an HTTP(S) proxy.
        self.client = httpx.Client(base_url=url, timeout=120, trust_env=False)
        self.db = db

    def mgmt(self, csl: str, db: str | None = None) -> None:
        r = self.client.post("/v1/rest/mgmt", json={"db": db or self.db, "csl": csl})
        assert r.status_code < 400, r.text[:500]

    def query(self, csl: str) -> list[dict]:
        r = self.client.post("/v1/rest/query", json={"db": self.db, "csl": csl})
        assert r.status_code < 400, r.text[:800]
        table = r.json()["Tables"][0]
        cols = [c["ColumnName"] for c in table["Columns"]]
        return [dict(zip(cols, row)) for row in table["Rows"]]


@pytest.fixture(scope="module")
def kusto():
    k = _Kusto(EMULATOR, f"telemetry_{uuid.uuid4().hex[:8]}")
    k.mgmt(f".create database {k.db} volatile", db="NetDefaultDB")
    alert_rows = ",\n".join(
        f'{_ts(h)}, "{sid}", "{name}", "{atype}", "{product}"'
        for h, sid, name, atype, product in ALERTS
    )
    k.mgmt(
        ".set-or-append SecurityAlert <| datatable(TimeGenerated:datetime, "
        "SystemAlertId:string, AlertName:string, AlertType:string, "
        f"ProductName:string)[\n{alert_rows}\n]"
    )
    incident_rows = ",\n".join(
        f'{_ts(h)}, {number}, "{title}", "{status}", "{cls}", '
        f"dynamic({json.dumps([RULE_ID + r for r in rules])}), dynamic({json.dumps(ids)})"
        for h, number, title, status, cls, rules, ids in INCIDENTS
    )
    k.mgmt(
        ".set-or-append SecurityIncident <| datatable(TimeGenerated:datetime, "
        "IncidentNumber:int, Title:string, Status:string, Classification:string, "
        f"RelatedAnalyticRuleIds:dynamic, AlertIds:dynamic)[\n{incident_rows}\n]"
    )
    yield k
    k.mgmt(f".drop database {k.db} ifexists", db="NetDefaultDB")
    k.client.close()


def _counts(row: dict) -> tuple[int, ...]:
    return tuple(int(row.get(c) or 0) for c in (
        "alerts_30d", "incidents_30d", "closed_tp_30d", "closed_fp_30d", "closed_bp_30d",
    ))


def test_silent_rules_query_rows(kusto) -> None:
    rows = {r["rule_key"]: r for r in kusto.query(silent_rules_query())}
    # a1 counted once; a2 joins its single-rule incident's rule despite its
    # AlertType; the reopened incident (I2) is not a closed FP.
    assert _counts(rows["id:rule-one"]) == (2, 2, 1, 0, 0)
    # Incident without RelatedAnalyticRuleIds, keyed by its title.
    assert _counts(rows["name:rule one"]) == (0, 1, 1, 0, 0)
    # The Defender alert in rule-two's incident keeps its own name key.
    assert _counts(rows["id:rule-two"]) == (1, 1, 0, 0, 1)
    assert _counts(rows["name:credential dumping via lsass"]) == (1, 0, 0, 0, 0)
    # Documented residual: unexpected AlertType and no incident.
    assert _counts(rows["id:unexpectedtype2"]) == (1, 0, 0, 0, 0)
    assert set(rows) == {
        "id:rule-one", "name:rule one", "id:rule-two",
        "name:credential dumping via lsass", "id:unexpectedtype2",
    }


def test_a_rules_rows_are_summed(kusto) -> None:
    index = TelemetryIndex(kusto.query(silent_rules_query()))
    rule_one = index.lookup(RuleKeys(ids=("rule-one",), names=("rule one",)))
    assert _counts(rule_one) == (2, 3, 2, 0, 0)
    rule_two = index.lookup(RuleKeys(ids=("rule-two",), names=("rule two",)))
    assert _counts(rule_two) == (1, 1, 0, 0, 1)


def test_suppression_impact_query(kusto) -> None:
    rows = {
        r["match_key"]: (r["alerts_count"], r["incidents_count"])
        for r in kusto.query(suppression_impact_query(rule_keys=["id:rule-one", "name:rule one"]))
    }
    assert rows == {"id:rule-one": (2, 2), "name:rule one": (0, 1)}
