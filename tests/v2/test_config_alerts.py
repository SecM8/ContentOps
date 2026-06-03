# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for AlertsConfig in tenant configuration."""

from __future__ import annotations

import pytest
import yaml

from contentops.config import AlertsConfig, TenantConfig


def _build_config(alerts_block: dict | None = None) -> TenantConfig:
    raw: dict = {
        "name": "test-tenant",
        "tenantId": "00000000-0000-0000-0000-000000000000",
    }
    if alerts_block is not None:
        raw["alerts"] = alerts_block
    return TenantConfig.model_validate(raw)


class TestAlertsConfig:
    def test_alerts_present(self) -> None:
        cfg = _build_config({"enabled": True})
        assert cfg.alerts is not None
        assert cfg.is_alerts_enabled()

    def test_alerts_absent(self) -> None:
        cfg = _build_config(None)
        assert cfg.alerts is None
        assert not cfg.is_alerts_enabled()

    def test_alerts_disabled(self) -> None:
        cfg = _build_config({"enabled": False})
        assert cfg.alerts is not None
        assert not cfg.is_alerts_enabled()

    def test_custom_lookback(self) -> None:
        cfg = _build_config({
            "enabled": True,
            "defenderLookbackDays": 14,
            "sentinelLookbackDays": 180,
        })
        assert cfg.alerts is not None
        assert cfg.alerts.defenderLookbackDays == 14
        assert cfg.alerts.sentinelLookbackDays == 180

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(Exception):
            _build_config({
                "enabled": True,
                "unknownField": "should fail",
            })

    def test_defaults(self) -> None:
        cfg = _build_config({})
        assert cfg.alerts is not None
        assert cfg.alerts.enabled is True
        assert cfg.alerts.defenderLookbackDays == 30
        assert cfg.alerts.sentinelLookbackDays == 90
        assert cfg.alerts.ledgerRetentionDays == 90
        assert cfg.alerts.rollupRetentionDays == 365

    def test_custom_retention(self) -> None:
        cfg = _build_config({
            "ledgerRetentionDays": 60,
            "rollupRetentionDays": 180,
        })
        assert cfg.alerts is not None
        assert cfg.alerts.ledgerRetentionDays == 60
        assert cfg.alerts.rollupRetentionDays == 180

    def test_ledger_retention_validation(self) -> None:
        with pytest.raises(Exception):
            _build_config({"ledgerRetentionDays": 3})

    def test_rollup_retention_validation(self) -> None:
        with pytest.raises(Exception):
            _build_config({"rollupRetentionDays": 10})
