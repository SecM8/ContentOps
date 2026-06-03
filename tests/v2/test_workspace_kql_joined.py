# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the joined SecurityAlert+SecurityIncident KQL queries."""

from __future__ import annotations

from contentops.workspace_kql import (
    _security_alerts_base,
    _security_alerts_joined_base,
    reconciliation_query,
    security_alerts_for_date_query,
    security_alerts_joined_for_date_query,
    security_alerts_joined_query,
    security_alerts_query,
)


class TestJoinedQueryShape:
    def test_contains_mv_expand(self) -> None:
        kql = security_alerts_joined_query(since_days=30)
        assert "mv-expand AlertIds" in kql

    def test_contains_leftouter_join(self) -> None:
        kql = security_alerts_joined_query(since_days=30)
        assert "join kind=leftouter" in kql

    def test_contains_arg_max_on_incidents(self) -> None:
        kql = security_alerts_joined_query(since_days=30)
        assert "arg_max(TimeGenerated, *) by IncidentNumber" in kql

    def test_contains_project_away_alertid(self) -> None:
        kql = security_alerts_joined_query(since_days=30)
        assert "project-away AlertId" in kql

    def test_incident_columns_prefixed(self) -> None:
        kql = security_alerts_joined_query(since_days=30)
        assert "IncidentStatus = Status" in kql
        assert "IncidentClassification = Classification" in kql
        assert "IncidentClosedTime = ClosedTime" in kql
        assert "IncidentOwner = Owner" in kql
        assert "IncidentNumber" in kql

    def test_alert_columns_aliased(self) -> None:
        kql = security_alerts_joined_query(since_days=30)
        assert "AlertStatus = Status" in kql
        assert "AlertClassification" in kql

    def test_90d_incident_lookback(self) -> None:
        kql = security_alerts_joined_query(since_days=30)
        assert "ago(90d)" in kql

    def test_since_days_in_alert_filter(self) -> None:
        kql = security_alerts_joined_query(since_days=14)
        assert "ago(14d)" in kql


class TestJoinedForDateQuery:
    def test_uses_time_generated(self) -> None:
        kql = security_alerts_joined_for_date_query(target_date="2026-05-25")
        assert "TimeGenerated >=" in kql
        assert "ingestion_time()" not in kql

    def test_contains_date_boundaries(self) -> None:
        kql = security_alerts_joined_for_date_query(target_date="2026-05-25")
        assert "datetime(2026-05-25)" in kql

    def test_contains_join(self) -> None:
        kql = security_alerts_joined_for_date_query(target_date="2026-05-25")
        assert "join kind=leftouter" in kql


class TestOldQueryUnchanged:
    def test_security_alerts_query_no_join(self) -> None:
        kql = security_alerts_query(since_days=30)
        assert "join" not in kql
        assert "SecurityIncident" not in kql
        assert "mv-expand" not in kql

    def test_security_alerts_for_date_query_no_join(self) -> None:
        kql = security_alerts_for_date_query(target_date="2026-05-25")
        assert "join" not in kql
        assert "SecurityIncident" not in kql

    def test_old_query_still_uses_time_generated(self) -> None:
        kql = security_alerts_for_date_query(target_date="2026-05-25")
        assert "TimeGenerated >=" in kql
        assert "ingestion_time" not in kql


class TestReconciliationQuery:
    def test_contains_mv_expand(self) -> None:
        kql = reconciliation_query()
        assert "mv-expand AlertIds" in kql

    def test_projects_current_state(self) -> None:
        kql = reconciliation_query()
        assert "CurrentStatus = Status" in kql
        assert "CurrentClassification = Classification" in kql
        assert "ClosedTime" in kql
