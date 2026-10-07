# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Every KQL query the tool builds binds against the cached workspace schema.

Runs each query builder through the Kusto.Language wrapper
(``tools/kql_strict``, ``schemas.json``): the telemetry queries behind
portfolio, the report, the lifecycle gate, silent-rules and the tuning
preview (``telemetry_query`` is ``silent_rules_query``); auto-disabled
rules; the alert-ledger and reconciliation queries; the Navigator
firings query; the report's table-health probe. Skips without the
wrapper, like ``test_lint_strict_dotnet.py``; build it with
``scripts/build_kql_strict.sh``. The ``kql-strict`` CI job (not a
required check) sets ``CONTENTOPS_REQUIRE_KQL_STRICT`` so a missing
wrapper fails there instead of skipping.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from contentops.lint.strict import _resolve_dotnet, _resolve_wrapper, is_available
from contentops.navigator.extract import firing_techniques_query
from contentops.report.enrich import health_query
from contentops.workspace_kql import (
    auto_disabled_query,
    reconciliation_query,
    security_alerts_for_date_query,
    security_alerts_joined_for_date_query,
    security_alerts_joined_query,
    security_alerts_query,
    silent_rules_query,
    suppression_impact_query,
)

# The v2 conftest chdirs every test into a tmp dir: resolve from the repo.
REPO_ROOT = Path(__file__).resolve().parents[2]

if not is_available(repo_root=REPO_ROOT):
    if os.environ.get("CONTENTOPS_REQUIRE_KQL_STRICT"):
        pytest.fail(
            "CONTENTOPS_REQUIRE_KQL_STRICT is set but the Kusto.Language "
            "wrapper is not available (scripts/build_kql_strict.sh).",
            pytrace=False,
        )
    pytest.skip(
        reason="Kusto.Language wrapper not installed; build via "
               "scripts/build_kql_strict.sh to exercise these tests.",
        allow_module_level=True,
    )


def _diagnostics(kql: str, tmp_path: Path) -> list[str]:
    path = tmp_path / "query.kql"
    path.write_text(kql, encoding="utf-8")
    env = {**os.environ, "KQL_STRICT_PROMOTE_SEVERITY": "1"}
    result = subprocess.run(  # noqa: S603 -- fixed dotnet + wrapper paths
        [_resolve_dotnet(), str(_resolve_wrapper(REPO_ROOT)), str(path)],
        input=kql, capture_output=True, text=True, timeout=120, check=False, env=env,
    )
    return [line for line in result.stdout.splitlines() if line.startswith("KS")]


@pytest.mark.parametrize("kql", [
    pytest.param(silent_rules_query(since_days=30), id="silent_rules"),
    pytest.param(suppression_impact_query(
        rule_keys=["id:brute-force", "name:brute force"], since_days=30,
    ), id="suppression_impact"),
    pytest.param(auto_disabled_query(since_days=7), id="auto_disabled"),
    pytest.param(security_alerts_query(since_days=30), id="security_alerts"),
    pytest.param(
        security_alerts_for_date_query(target_date="2026-01-15"),
        id="security_alerts_for_date",
    ),
    pytest.param(security_alerts_joined_query(since_days=30), id="security_alerts_joined"),
    pytest.param(
        security_alerts_joined_for_date_query(target_date="2026-01-15"),
        id="security_alerts_joined_for_date",
    ),
    pytest.param(reconciliation_query(), id="reconciliation"),
    pytest.param(firing_techniques_query(since_days=365), id="navigator_firing_techniques"),
    pytest.param(health_query("SecurityEvent", since_hours=24), id="report_health"),
])
def test_query_binds_cleanly(kql: str, tmp_path: Path) -> None:
    assert _diagnostics(kql, tmp_path) == []


def test_wrapper_checks_inside_let_bodies(tmp_path: Path) -> None:
    """Control: a typo inside a ``let`` body is reported, so the clean
    result above means the query really bound."""
    broken = silent_rules_query().replace("RelatedAnalyticRuleIds", "RelatedAnalyticRuleIdz", 1)
    assert _diagnostics(broken, tmp_path)
