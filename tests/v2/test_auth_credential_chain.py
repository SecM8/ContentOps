# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for get_credential() and the opt-in .env → OIDC/az-login fallback.

The credential factory returns a _FallbackCredential when .env
credentials are present (AZURE_CLIENT_SECRET set), and a plain
DefaultAzureCredential otherwise. On auth failure (expired secret,
wrong value) _FallbackCredential raises CredentialFallbackRefused by
default: switching to OIDC or the operator's ``az login`` would change
the acting identity (and the actor in audit records). Falling back
requires CONTENTOPS_AUTH_FALLBACK=1 and is never allowed in GitHub
Actions.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import CredentialUnavailableError


def test_get_credential_returns_fallback_when_secret_set(monkeypatch) -> None:
    """When all three env vars are set, returns _FallbackCredential."""
    from contentops.utils.auth import _reset_credential_cache
    _reset_credential_cache()
    monkeypatch.setenv("AZURE_CLIENT_ID", "fake-id")
    monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")

    with patch("contentops.utils.auth.ClientSecretCredential"), \
         patch("contentops.utils.auth.DefaultAzureCredential"):
        from contentops.utils.auth import _FallbackCredential, get_credential
        cred = get_credential()
        assert isinstance(cred, _FallbackCredential)
    _reset_credential_cache()


def test_get_credential_returns_default_when_no_secret(monkeypatch) -> None:
    """Without AZURE_CLIENT_SECRET, returns DefaultAzureCredential directly."""
    from contentops.utils.auth import _reset_credential_cache
    _reset_credential_cache()
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)

    with patch(
        "contentops.utils.auth.DefaultAzureCredential"
    ) as mock_dac:
        from contentops.utils.auth import get_credential
        cred = get_credential()
    _reset_credential_cache()

    mock_dac.assert_called_once_with(
        exclude_shared_token_cache_credential=True,
        exclude_visual_studio_code_credential=True,
        exclude_environment_credential=True,
    )
    assert cred is mock_dac.return_value


def test_fallback_credential_uses_primary_on_success() -> None:
    """When primary credential succeeds, returns its token."""
    from contentops.utils.auth import _FallbackCredential

    expected = AccessToken("primary-token", 9999999999)
    primary = MagicMock()
    primary.get_token.return_value = expected
    fallback = MagicMock()

    cred = _FallbackCredential(primary, fallback)
    token = cred.get_token("https://management.azure.com/.default")

    assert token.token == "primary-token"
    primary.get_token.assert_called_once()
    fallback.get_token.assert_not_called()


def test_fallback_credential_falls_back_on_auth_error() -> None:
    """When primary raises ClientAuthenticationError, falls back."""
    from contentops.utils.auth import _FallbackCredential

    primary = MagicMock()
    primary.get_token.side_effect = ClientAuthenticationError(message="expired secret")
    fallback_token = AccessToken("fallback-token", 9999999999)
    fallback = MagicMock()
    fallback.get_token.return_value = fallback_token

    cred = _FallbackCredential(primary, fallback, allow_fallback=True)
    token = cred.get_token("https://management.azure.com/.default")

    assert token.token == "fallback-token"
    fallback.get_token.assert_called_once()


def test_fallback_credential_falls_back_on_unavailable() -> None:
    """When primary raises CredentialUnavailableError, falls back."""
    from contentops.utils.auth import _FallbackCredential

    primary = MagicMock()
    primary.get_token.side_effect = CredentialUnavailableError(message="not configured")
    fallback_token = AccessToken("fallback-token", 9999999999)
    fallback = MagicMock()
    fallback.get_token.return_value = fallback_token

    cred = _FallbackCredential(primary, fallback, allow_fallback=True)
    token = cred.get_token("https://management.azure.com/.default")

    assert token.token == "fallback-token"


def test_fallback_credential_does_not_retry_primary_after_failure() -> None:
    """Once primary fails, subsequent calls go straight to fallback."""
    from contentops.utils.auth import _FallbackCredential

    primary = MagicMock()
    primary.get_token.side_effect = ClientAuthenticationError(message="bad secret")
    fallback_token = AccessToken("fallback-token", 9999999999)
    fallback = MagicMock()
    fallback.get_token.return_value = fallback_token

    cred = _FallbackCredential(primary, fallback, allow_fallback=True)
    cred.get_token("scope1")
    cred.get_token("scope2")
    cred.get_token("scope3")

    # Primary tried once (first call), then never again
    assert primary.get_token.call_count == 1
    assert fallback.get_token.call_count == 3


def test_get_credential_returns_object_with_get_token(monkeypatch) -> None:
    """Sanity: the factory always returns something with .get_token()."""
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    from contentops.utils.auth import get_credential
    cred = get_credential()
    assert cred is not None
    assert hasattr(cred, "get_token")


# ---------------------------------------------------------------------------
# Fallback is opt-in and never allowed in CI (review finding: silent
# identity switch).
# ---------------------------------------------------------------------------


def _failing_primary(message: str = "AADSTS7000222: secret expired for fake-secret") -> MagicMock:
    primary = MagicMock()
    primary.get_token.side_effect = ClientAuthenticationError(message=message)
    return primary


def test_fallback_refused_by_default(monkeypatch) -> None:
    from contentops.utils.auth import CredentialFallbackRefused, _FallbackCredential

    monkeypatch.delenv("CONTENTOPS_AUTH_FALLBACK", raising=False)
    fallback = MagicMock()
    cred = _FallbackCredential(_failing_primary(), fallback)
    with pytest.raises(CredentialFallbackRefused) as excinfo:
        cred.get_token("https://management.azure.com/.default")
    fallback.get_token.assert_not_called()
    message = str(excinfo.value)
    assert "AADSTS7000222" in message
    assert "CONTENTOPS_AUTH_FALLBACK" in message
    # The upstream message (which can echo identifiers) is not repeated.
    assert "fake-secret" not in message


def test_refusal_is_a_client_authentication_error(monkeypatch) -> None:
    """Callers that already catch ClientAuthenticationError keep working."""
    from contentops.utils.auth import _FallbackCredential

    monkeypatch.delenv("CONTENTOPS_AUTH_FALLBACK", raising=False)
    cred = _FallbackCredential(_failing_primary(), MagicMock())
    with pytest.raises(ClientAuthenticationError):
        cred.get_token("scope")


def test_fallback_opt_in_locally(monkeypatch) -> None:
    from contentops.utils.auth import _FallbackCredential

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("CONTENTOPS_AUTH_FALLBACK", "1")
    fallback = MagicMock()
    fallback.get_token.return_value = AccessToken("fallback-token", 9999999999)
    cred = _FallbackCredential(_failing_primary(), fallback)
    assert cred.get_token("scope").token == "fallback-token"


def test_fallback_opt_in_ignored_in_github_actions(monkeypatch) -> None:
    from contentops.utils.auth import CredentialFallbackRefused, _FallbackCredential

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CONTENTOPS_AUTH_FALLBACK", "1")
    fallback = MagicMock()
    cred = _FallbackCredential(_failing_primary(), fallback)
    with pytest.raises(CredentialFallbackRefused):
        cred.get_token("scope")
    fallback.get_token.assert_not_called()


def test_unavailable_primary_follows_the_same_policy(monkeypatch) -> None:
    from contentops.utils.auth import CredentialFallbackRefused, _FallbackCredential

    monkeypatch.delenv("CONTENTOPS_AUTH_FALLBACK", raising=False)
    primary = MagicMock()
    primary.get_token.side_effect = CredentialUnavailableError(message="not configured")
    cred = _FallbackCredential(primary, MagicMock())
    with pytest.raises(CredentialFallbackRefused):
        cred.get_token("scope")
