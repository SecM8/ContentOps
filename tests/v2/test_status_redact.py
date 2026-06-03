# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tenant-ID redactor used by the status dashboard."""

from __future__ import annotations

import pytest

from contentops.status.redact import redact


# ---------------------------------------------------------------------------
# Full GUIDs
# ---------------------------------------------------------------------------


def test_redacts_full_guid_lowercase() -> None:
    assert redact("tenantId=550e8400-e29b-41d4-a716-446655440000") == (
        "tenantId=<redacted-guid>"
    )


def test_redacts_full_guid_uppercase() -> None:
    assert redact("appId=550E8400-E29B-41D4-A716-446655440000 ok") == (
        "appId=<redacted-guid> ok"
    )


def test_redacts_multiple_guids_in_one_string() -> None:
    text = (
        "tenant=550e8400-e29b-41d4-a716-446655440000 "
        "sub=11111111-2222-3333-4444-555555555555"
    )
    assert redact(text) == "tenant=<redacted-guid> sub=<redacted-guid>"


# ---------------------------------------------------------------------------
# Truncated GUID prefixes
# ---------------------------------------------------------------------------


def test_redacts_truncated_guid_with_ascii_ellipsis() -> None:
    assert redact("tenantId=550e8400...") == "tenantId=<redacted>"


def test_redacts_truncated_guid_with_unicode_ellipsis() -> None:
    # contentops conformance uses U+2026 in some detail strings.
    assert redact("tenantId=550e8400…") == "tenantId=<redacted>"


def test_redacts_truncated_guid_in_prose() -> None:
    assert redact("objectId=abc12345... displayName=ContentOps") == (
        "objectId=<redacted> displayName=ContentOps"
    )


# ---------------------------------------------------------------------------
# Azure resource paths
# ---------------------------------------------------------------------------


def test_redacts_resource_path_in_error_prose() -> None:
    text = (
        "403 lacks Reader on "
        "/subscriptions/550e8400-e29b-41d4-a716-446655440000/"
        "resourceGroups/rg-prod/providers/Microsoft.OperationalInsights/"
        "workspaces/law-sentinel-prod (RBAC role assignment missing)"
    )
    out = redact(text)
    assert "550e8400" not in out
    assert "rg-prod" not in out
    assert "<redacted-resource-path>" in out
    # The trailing prose after the closing paren is preserved.
    assert "(RBAC role assignment missing)" in out


def test_resource_path_redaction_short_circuits_inner_guid() -> None:
    """The path-level rule runs first; the inner GUID is gone with the path."""
    text = "/subscriptions/550e8400-e29b-41d4-a716-446655440000/resourceGroups/rg/providers/x"
    assert redact(text) == "<redacted-resource-path>"


# ---------------------------------------------------------------------------
# Preserved content (operator-readable, not sensitive on private repo)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "preserved",
    [
        "law-sentinel-prod",                     # workspace name alone
        "sentinel_analytic",                     # asset kind
        "AADSTS7000215",                         # AAD error code
        "ContentOps",                            # app display name
        "200, 5 rule(s)",                        # HTTP status + count
        "CustomDetection.ReadWrite.All",         # Graph permission
        "GET https://graph.microsoft.com/beta",  # API URL without resource path
    ],
)
def test_preserves_operator_readable_content(preserved: str) -> None:
    assert redact(preserved) == preserved


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_string_is_no_op() -> None:
    assert redact("") == ""


def test_already_redacted_text_is_idempotent() -> None:
    once = redact("tenantId=550e8400-e29b-41d4-a716-446655440000")
    twice = redact(once)
    assert once == twice == "tenantId=<redacted-guid>"


def test_does_not_match_partial_guid_without_dashes() -> None:
    """A 32-char hex string without dashes is not a GUID; leave it alone."""
    assert redact("hash=550e8400e29b41d4a716446655440000") == (
        "hash=550e8400e29b41d4a716446655440000"
    )


def test_does_not_match_sha256_starting_with_guid_like_prefix() -> None:
    """A SHA256 prefix that starts with 8 hex chars must not look like a truncated GUID."""
    # SHA256 hex doesn't contain '...' or U+2026, so this should pass through.
    sha = "abc12345def67890abc12345def67890abc12345def67890abc12345def67890"
    assert redact(f"sha={sha}") == f"sha={sha}"
