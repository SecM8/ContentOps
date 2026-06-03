# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``contentops.devex.doctor._classify_handler_matrix_failure``.

The doctor matrix check (``contentops doctor --matrix``) calls
``list_remote()`` on every registered drift-capable handler. Exceptions
are routed through a small classifier that decides whether the error
should be reported as ``FAIL`` (real breakage), ``WARN`` (an expected
"feature unavailable / unauthorised" signal), or — for clean responses
— ``PASS``.

These tests pin the classifier rules. They don't touch live Azure; the
classifier consumes exception strings the way the real call site
extracts them via ``str(exc)``.
"""

from __future__ import annotations

from contentops.devex.doctor import _classify_handler_matrix_failure


def test_forbidden_anywhere_is_warn() -> None:
    """The Defender Graph case: 403 / Forbidden anywhere in the
    exception string → WARN. Pre-existing behaviour, regression pin."""
    result = _classify_handler_matrix_failure(
        "handler:defender_custom_detection",
        "Client error '403 Forbidden' for url 'https://graph.microsoft.com/...'",
    )
    assert result.status == "WARN"
    assert "403" in result.detail


def test_workspace_manager_400_is_warn() -> None:
    """Workspace Manager is an opt-in Sentinel feature. Tenants that
    have not provisioned a manager workspace get 400 from the
    ``workspaceManagerAssignments`` / ``…Groups`` / ``…Members`` /
    ``…Configurations`` collections. Classify as WARN — same
    "feature unavailable" semantics as the Defender 403 case above."""
    result = _classify_handler_matrix_failure(
        "handler:sentinel_workspace_manager_assignment",
        "Client error '400 Bad Request' for url '...workspaceManagerAssignments...'",
    )
    assert result.status == "WARN"
    assert "Workspace Manager" in result.detail
    assert "400" in result.detail


def test_workspace_manager_400_warn_covers_all_four_subkinds() -> None:
    """The rule applies to every Workspace Manager handler, not just
    one. Each sub-resource hits the same Workspace Manager gating."""
    for asset_name in (
        "sentinel_workspace_manager_assignment",
        "sentinel_workspace_manager_configuration",
        "sentinel_workspace_manager_group",
        "sentinel_workspace_manager_member",
    ):
        result = _classify_handler_matrix_failure(
            f"handler:{asset_name}",
            "Client error '400 Bad Request' for url '...'",
        )
        assert result.status == "WARN", asset_name


def test_workspace_manager_non_400_still_fails() -> None:
    """Narrowed to 400 specifically. A 500 on Workspace Manager is
    real server-side breakage and should surface as FAIL — operators
    need to know if a Microsoft-side outage is masking handler health."""
    result = _classify_handler_matrix_failure(
        "handler:sentinel_workspace_manager_assignment",
        "Server error '500 Internal Server Error' for url '...'",
    )
    assert result.status == "FAIL"


def test_generic_400_on_core_handler_is_still_fail() -> None:
    """The Workspace Manager carve-out is not a global 400-as-WARN
    policy. A 400 on the analytic handler is a real bug — most
    likely a malformed query body or scaffold drift — and must FAIL
    so the operator notices."""
    result = _classify_handler_matrix_failure(
        "handler:sentinel_analytic",
        "Client error '400 Bad Request' for url '...alertRules...'",
    )
    assert result.status == "FAIL"


def test_long_exception_string_is_truncated() -> None:
    """The detail field truncates at 160 chars so the doctor report
    stays readable. Pre-existing behaviour; regression pin."""
    long_msg = "Client error '500 Internal Server Error' " + ("x" * 500)
    result = _classify_handler_matrix_failure(
        "handler:sentinel_analytic", long_msg,
    )
    assert len(result.detail) <= 200
