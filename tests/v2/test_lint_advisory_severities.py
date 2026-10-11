# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""KQL010 (cross-scope) and KQL101 (take/limit) are advisories.

Both rules used to emit ``error`` and therefore blocked the default
``contentops lint`` gate. A deployment fork's first collect snapshot
showed that both shapes exist in healthy production tenants: Sentinel
supports cross-workspace analytics rules (central SOC / MSSP), and a
bounded result set is a tuning choice rather than a defect. They now
emit ``warning`` so ``validate`` reports them without failing, while
``--fail-on-warn`` still turns them into a gate on demand.
"""

from __future__ import annotations

from contentops.lint.kql import at_or_above, lint_kql
from contentops.lint.strict_rules import run_python_rules


def _by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def test_kql010_workspace_is_a_warning_with_caveats() -> None:
    query = 'workspace("abc").SecurityAlert\n| where Status == "New"'
    findings = lint_kql(query, kind="sentinel_analytic")
    k010 = _by_id(findings, "KQL010")
    assert len(k010) == 1
    assert k010[0].severity == "warning"
    assert k010[0].line == 1
    assert "workspace()" in k010[0].message
    assert "20 workspaces" in k010[0].message
    assert "multi-workspace" in k010[0].message
    assert at_or_above(findings, "error") == []


def test_kql010_cluster_is_a_warning() -> None:
    findings = lint_kql('cluster("x").database("y").T | count', kind="sentinel_hunting")
    k010 = _by_id(findings, "KQL010")
    assert len(k010) == 1
    assert k010[0].severity == "warning"
    assert "cluster()" in k010[0].message


def test_kql010_silent_without_cross_scope() -> None:
    findings = lint_kql("SecurityAlert | where Status == 'New'", kind="sentinel_analytic")
    assert _by_id(findings, "KQL010") == []


def test_kql101_is_a_warning_everywhere() -> None:
    findings = list(run_python_rules("T | take 10"))
    assert [f.rule_id for f in findings] == ["KQL101"]
    assert findings[0].severity == "warning"
    assert "top N by <field>" in findings[0].message
    assert at_or_above(findings, "error") == []
