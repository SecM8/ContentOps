# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the conformance L2 auth_env smart check (task #34).

Previously auth_env hard-failed with "missing env vars: AZURE_CLIENT_ID,
AZURE_TENANT_ID" whenever those env vars were unset — even when the
operator was on Path A (az login as user, no .env). This actively
misled adopters on Path A into thinking they needed to set env vars
they shouldn't need.

Fix: detect `az account show` success, downgrade auth_env to INFO when
active. FAIL only when both az is missing AND env vars are unset.
"""

from __future__ import annotations

from unittest.mock import patch


def _l2_check(monkeypatch, *, az_signed_in: bool) -> list:
    """Drive just the L2 portion of conformance and return its checks."""
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)

    from contentops.devex.conformance import (
        ConformanceReport,
        check_l2_tenant_config,
    )

    report = ConformanceReport()
    with patch(
        "contentops.devex.conformance._az_signed_in",
        return_value=az_signed_in,
    ):
        # Patch the tenant config loader so we don't depend on a real
        # config/tenant.yml on disk during the test run.
        with patch("contentops.config.load_tenant_config") as ld:
            ld.return_value = type("Cfg", (), {
                "name": "production",
                "tenantId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "sentinelWorkspaces": [],
                "defender": type("D", (), {"enabled": False})(),
            })()
            check_l2_tenant_config(report)

    return [c for c in report.checks if c.name == "auth_env"]


def test_auth_env_info_when_az_signed_in(monkeypatch) -> None:
    """Path A: az login is active and env vars are absent → INFO, not FAIL."""
    checks = _l2_check(monkeypatch, az_signed_in=True)
    assert len(checks) == 1
    auth_env = checks[0]
    assert auth_env.status == "INFO"
    assert "az login" in auth_env.detail or "Path A" in auth_env.detail
    # The historical (wrong) remediation said "set env vars"; we must
    # not emit that when az login is doing the work.
    assert "set" not in auth_env.remediation.lower() or auth_env.remediation == ""


def test_auth_env_fail_when_no_az_and_no_env(monkeypatch) -> None:
    """No env vars AND no az login → FAIL with both remediation options
    spelled out."""
    checks = _l2_check(monkeypatch, az_signed_in=False)
    assert len(checks) == 1
    auth_env = checks[0]
    assert auth_env.status == "FAIL"
    assert "az login" in auth_env.remediation
    assert "AZURE_CLIENT_ID" in auth_env.remediation


def test_auth_env_pass_when_env_vars_set(monkeypatch) -> None:
    """Path B: env vars set → PASS regardless of az login status."""
    monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")

    from contentops.devex.conformance import (
        ConformanceReport,
        check_l2_tenant_config,
    )

    report = ConformanceReport()
    with patch("contentops.config.load_tenant_config") as ld:
        ld.return_value = type("Cfg", (), {
            "name": "production",
            "tenantId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "sentinelWorkspaces": [],
            "defender": type("D", (), {"enabled": False})(),
        })()
        check_l2_tenant_config(report)

    auth_env = [c for c in report.checks if c.name == "auth_env"]
    assert len(auth_env) == 1
    assert auth_env[0].status == "PASS"
    assert "Path B" in auth_env[0].detail
