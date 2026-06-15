# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ReportsConfig (committed-report retention) in tenant config."""

from __future__ import annotations

import pytest

from contentops.config import ReportsConfig, TenantConfig


def _build_config(reports_block: dict | None = None) -> TenantConfig:
    raw: dict = {
        "name": "test-tenant",
        "tenantId": "00000000-0000-0000-0000-000000000000",
    }
    if reports_block is not None:
        raw["reports"] = reports_block
    return TenantConfig.model_validate(raw)


class TestReportsConfig:
    def test_reports_absent(self) -> None:
        """Opt-in: a missing reports: block means no retention configured
        (the report command keeps every dated snapshot)."""
        cfg = _build_config(None)
        assert cfg.reports is None

    def test_reports_present_default(self) -> None:
        cfg = _build_config({})
        assert cfg.reports is not None
        assert cfg.reports.retentionDays == 365

    def test_custom_retention(self) -> None:
        cfg = _build_config({"retentionDays": 90})
        assert cfg.reports is not None
        assert cfg.reports.retentionDays == 90

    def test_zero_retention_allowed(self) -> None:
        """0 is a valid value — disables pruning (keep everything)."""
        cfg = _build_config({"retentionDays": 0})
        assert cfg.reports is not None
        assert cfg.reports.retentionDays == 0

    def test_retention_upper_bound(self) -> None:
        ReportsConfig(retentionDays=3650)
        with pytest.raises(Exception):
            ReportsConfig(retentionDays=3651)

    def test_retention_negative_rejected(self) -> None:
        with pytest.raises(Exception):
            ReportsConfig(retentionDays=-1)

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(Exception):
            _build_config({"retentionDays": 365, "unknownField": "nope"})
