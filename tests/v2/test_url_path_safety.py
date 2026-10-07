# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Resource names from YAML can never escape their URL path segment.

``metadata.arm_name`` (and the envelope id, watchlist alias, Graph rule id)
is interpolated into ARM / Graph request paths. httpx normalises ``..``
segments before sending, so an unchecked ``../../automationRules/x`` would
make apply GET/PUT a different resource with the deploy identity. These
tests pin the central check in :mod:`contentops.utils.url_path` and every
URL builder that uses it.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.providers.sentinel_arm import SentinelArmProvider
from contentops.utils.url_path import UnsafePathSegment, safe_path_segment


@pytest.mark.parametrize(
    "name",
    [
        "1840b991-a12b-4e67-a685-d0cad73863fc",
        "BuiltInFusion",
        "18210",
        "my-rule_1",
        "a-user-added-an-account",
    ],
)
def test_real_resource_names_pass_unchanged(name: str) -> None:
    assert safe_path_segment(name) == name


def test_other_characters_are_percent_encoded() -> None:
    assert safe_path_segment("My Watchlist") == "My%20Watchlist"
    assert safe_path_segment("a:b@c") == "a%3Ab%40c"


@pytest.mark.parametrize(
    "name",
    ["", "   ", ".", "..", "../x", "../../automationRules/x", "a/b", "a\\b",
     "a?b", "a#b", "%2e%2e", "..%2f", "a\x00b", "a\nb", "a\x7fb", None],
)
def test_unsafe_names_are_rejected(name) -> None:
    with pytest.raises(UnsafePathSegment):
        safe_path_segment(name)


def test_error_names_the_kind() -> None:
    with pytest.raises(UnsafePathSegment, match="alert rule name"):
        safe_path_segment("../x", kind="alert rule name")


def _provider() -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws")
    return SentinelArmProvider(cfg, token="t")


@pytest.mark.parametrize(
    "build",
    [
        lambda p: p.resource_url("alertRules", "../../automationRules/x"),
        lambda p: p.la_resource_url("savedSearches", "../x"),
        lambda p: p.subscription_resource_url(
            "Microsoft.Logic", "workflows", "a/b", api_version="2019-05-01",
        ),
        lambda p: p.resource_url("watchlists", "..", child="watchlistItems"),
    ],
)
def test_arm_url_builders_reject_traversal(build) -> None:
    provider = _provider()
    try:
        with pytest.raises(UnsafePathSegment):
            build(provider)
    finally:
        provider.close()


def test_arm_url_builders_encode_names_and_keep_children() -> None:
    provider = _provider()
    try:
        url = provider.resource_url("watchlists", "High Value", child="watchlistItems")
        assert url.endswith(
            "/providers/Microsoft.SecurityInsights/watchlists/High%20Value/"
            "watchlistItems?api-version=2025-07-01-preview"
        )
        assert provider.resource_url("alertRules").endswith(
            "/Microsoft.SecurityInsights/alertRules?api-version=2025-07-01-preview"
        )
    finally:
        provider.close()


def test_defender_client_rejects_unsafe_ids_before_any_request() -> None:
    from contentops.defender.client import DefenderClient

    def _never(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    client = DefenderClient(token="t")
    client._client.close()
    client._client = httpx.Client(
        base_url="https://graph.microsoft.com/beta/security/rules",
        transport=httpx.MockTransport(_never),
    )
    try:
        for call in (
            lambda: client.get_rule("../../incidents"),
            lambda: client.update_rule("1/../2", {}),
            lambda: client.delete_rule(".."),
        ):
            with pytest.raises(UnsafePathSegment):
                call()
    finally:
        client.close()


def test_analytic_apply_with_traversal_arm_name_sends_no_request(monkeypatch) -> None:
    """A crafted ``metadata.arm_name`` fails before ARM is contacted."""
    from contentops.core.asset import Asset
    from contentops.core.envelope import EnvelopeV2
    from contentops.core.handler import LoadedAsset
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
    from contentops.providers import sentinel_arm

    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)
    sent: list[str] = []

    def _record(request: httpx.Request) -> httpx.Response:
        sent.append(f"{request.method} {request.url.path}")
        return httpx.Response(404)

    provider = _provider()
    provider._client.close()
    provider._client = httpx.Client(
        base_url="https://management.azure.com",
        transport=httpx.MockTransport(_record),
    )
    handler = SentinelAnalyticHandler(lambda: provider)
    env = EnvelopeV2(
        id="crafted-rule",
        version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC,
        status="production",
        arm_name="../../automationRules/takeover",
    )
    payload = {
        "kind": "Scheduled", "displayName": "Crafted", "severity": "Medium",
        "query": "SecurityEvent | take 1", "queryFrequency": "PT5M",
        "queryPeriod": "PT5M", "triggerOperator": "GreaterThan",
        "triggerThreshold": 0, "tactics": [], "enabled": True,
    }
    loaded = LoadedAsset(path=Path("crafted.yml"), envelope=env, payload=payload)
    with pytest.raises(UnsafePathSegment):
        handler.apply(loaded)
    assert sent == []
