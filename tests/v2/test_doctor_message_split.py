# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the doctor 401 vs 403 message split (task #31).

Adopter test on 2026-05-18 surfaced that doctor conflated both auth
failure modes into a single misleading "credentials missing role"
message. 401 means the token itself was rejected (chain ordering,
wrong tenant, expired); 403 means authenticated but lacks RBAC. The
remediation paths differ — adopters chased RBAC for ~30 minutes on a
chain-ordering bug because the message said "missing role."

This test pins both messages so a future refactor can't silently
re-conflate them.
"""

from __future__ import annotations

from contentops.devex.doctor import _classify_handler_matrix_failure


def test_handler_403_reports_lacks_rbac() -> None:
    """403 → WARN with explicit "lacks RBAC" framing."""
    result = _classify_handler_matrix_failure(
        "handler:sentinel_analytic",
        "Client error '403 Forbidden' for url 'https://...'",
    )
    assert result.status == "WARN"
    assert "lacks RBAC" in result.detail
    # Must NOT confuse the operator with a missing-role hint when it's
    # really a chain-ordering or stale-token issue.
    assert "missing role" not in result.detail.lower()


def test_handler_401_reports_token_rejected() -> None:
    """401 → FAIL with explicit "token rejected" framing and the
    AZURE_TOKEN_CREDENTIALS=dev workaround pointer."""
    result = _classify_handler_matrix_failure(
        "handler:sentinel_analytic",
        "Client error '401 Unauthorized' for url 'https://...'",
    )
    assert result.status == "FAIL"
    assert "token rejected" in result.detail
    # Workaround hint so adopters hit by the chain-ordering bug get
    # an actionable suggestion without having to read the source.
    assert "AZURE_TOKEN_CREDENTIALS" in result.detail


def test_handler_workspace_manager_400_unchanged() -> None:
    """Regression: workspace_manager 400 → WARN with the existing
    "endpoint unavailable" message stays in place. Splits for 401/403
    should not have affected this branch."""
    result = _classify_handler_matrix_failure(
        "handler:sentinel_workspace_manager_assignment",
        "Client error '400 Bad Request' for url 'https://...'",
    )
    assert result.status == "WARN"
    assert "Workspace Manager endpoint" in result.detail


def test_handler_other_error_is_fail() -> None:
    """A non-401/403/400 error still maps to FAIL."""
    result = _classify_handler_matrix_failure(
        "handler:sentinel_analytic",
        "Client error '500 Internal Server Error' for url 'https://...'",
    )
    assert result.status == "FAIL"
