# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Post-apply verification tests for SentinelWatchlistHandler."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.handlers.sentinel_watchlist import (
    SentinelWatchlistHandler,
    _expected_item_count,
)
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _provider_with(transport: httpx.MockTransport) -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws")
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(
        base_url=sentinel_arm.ARM_BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return p


_PAYLOAD = {
    "displayName": "High Value Assets",
    "provider": "Custom",
    "source": "Local file",
    "contentType": "text/csv",
    "itemsSearchKey": "AssetName",
    # 2 data rows after the header.
    "rawContent": "AssetName,Tier\na,0\nb,1\n",
}


def _loaded(payload: dict | None = None) -> LoadedAsset:
    env = EnvelopeV2(
        id="hva", version="0.1.0",
        asset=Asset.SENTINEL_WATCHLIST, status="production",
    )
    return LoadedAsset(
        path=Path("w.yml"), envelope=env,
        payload=dict(payload or _PAYLOAD),
    )


def _matching_remote(display: str = _PAYLOAD["displayName"]) -> dict:
    return {
        "name": "hva",
        "etag": 'W/"wl-etag"',
        "properties": {
            "displayName": display,
            "provider": _PAYLOAD["provider"],
            "contentType": _PAYLOAD["contentType"],
            "itemsSearchKey": _PAYLOAD["itemsSearchKey"],
        },
    }


def _items(count: int) -> dict:
    return {
        "value": [
            {"name": f"item-{i}", "properties": {"itemsKeyValue": {}}}
            for i in range(count)
        ]
    }


def _make_handler(routes: list[httpx.Response | dict], items_count: int | None = 2):
    """Default request handler:

    * GET .../watchlists/hva                        → envelope (pre + post)
    * PUT .../watchlists/hva                        → 200 envelope
    * GET .../watchlists/hva/watchlistItems         → ``items_count`` items

    Pass ``items_count=None`` to suppress the items endpoint (returns 404)
    so callers can simulate fetch failure.
    """
    state: dict = {"get_envelope_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "GET" and "/watchlistItems" in url:
            if items_count is None:
                return httpx.Response(500, text="boom")
            return httpx.Response(200, json=_items(items_count))
        if request.method == "GET":
            state["get_envelope_calls"] += 1
            return httpx.Response(200, json=_matching_remote())
        # PUT
        return httpx.Response(200, json=_matching_remote())

    return handler, state


def test_apply_happy_path_verifies_items_and_sends_ifmatch() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "GET" and "/watchlistItems" in url:
            return httpx.Response(200, json=_items(2))
        if request.method == "GET":
            return httpx.Response(200, json=_matching_remote())
        seen.update(request.headers)
        return httpx.Response(200, json=_matching_remote())

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.status == "success"
    assert result.verified is True
    assert seen.get("if-match") == 'W/"wl-etag"'


def test_apply_hash_mismatch() -> None:
    state = {"phase": "pre"}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "GET" and "/watchlistItems" in url:
            return httpx.Response(200, json=_items(2))
        if request.method == "GET":
            if state["phase"] == "pre":
                state["phase"] = "post"
                return httpx.Response(200, json=_matching_remote())
            return httpx.Response(200, json=_matching_remote(display="Tampered"))
        return httpx.Response(200, json=_matching_remote())

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.verified is False
    assert "post-apply hash mismatch" in (result.error or "")


def test_apply_412_etag_conflict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=_matching_remote())
        return httpx.Response(412, text="Precondition Failed")

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.status == "error-412"
    assert result.verified is False
    assert "rerun contentops plan" in (result.error or "")


# ---------------------------------------------------------------------------
# W4.5-B: item-count verification
# ---------------------------------------------------------------------------

def test_apply_item_count_mismatch() -> None:
    handler, _ = _make_handler([], items_count=1)  # expected 2, actual 1
    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.verified is False
    assert "post-apply item-count mismatch" in (result.error or "")
    assert "expected=2" in (result.error or "")
    assert "actual=1" in (result.error or "")


def test_apply_items_get_failure() -> None:
    handler, _ = _make_handler([], items_count=None)
    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.verified is False
    assert "watchlistItems GET failed" in (result.error or "")


def test_apply_respects_number_of_lines_to_skip() -> None:
    payload = dict(_PAYLOAD)
    payload["rawContent"] = "# preamble\nAssetName,Tier\nx,0\ny,1\nz,2\n"
    payload["numberOfLinesToSkip"] = 1
    handler, _ = _make_handler([], items_count=3)
    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded(payload))

    assert result.verified is True


def test_apply_blank_lines_ignored() -> None:
    payload = dict(_PAYLOAD)
    payload["rawContent"] = "AssetName,Tier\na,0\n\n   \nb,1\n"
    handler, _ = _make_handler([], items_count=2)
    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded(payload))

    assert result.verified is True


def test_apply_no_raw_content_skips_item_verification() -> None:
    """When a watchlist is sourced via sasUri (no inline rawContent),
    item-count verification is not applicable and must not fail apply.
    Envelope verification still runs."""
    payload = {
        "displayName": "High Value Assets",
        "provider": "Custom",
        "source": "Remote storage",
        "contentType": "text/csv",
        "itemsSearchKey": "AssetName",
        # rawContent intentionally omitted because sasUri provides the
        # CSV body. The handler must still apply + verify the envelope
        # without trying to count rows from a missing rawContent.
        "sasUri": "https://example.blob.core.windows.net/c/x.csv?sv=1&sig=z",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "GET" and "/watchlistItems" in url:
            # If we reach here, the implementation incorrectly called the
            # items endpoint despite no rawContent.
            raise AssertionError("watchlistItems must not be fetched without rawContent")
        if request.method == "GET":
            return httpx.Response(200, json=_matching_remote())
        return httpx.Response(200, json=_matching_remote())

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded(payload))

    assert result.verified is True


def test_apply_collected_watchlist_skips_with_clear_error() -> None:
    """A watchlist envelope as produced by `contentops collect` carries no
    rawContent (the API doesn't echo the CSV body) and no sasUri. Apply
    must skip such envelopes with a clear "no-content" message rather
    than PUTting an empty watchlist."""
    # This is the shape `contentops collect` writes to disk: source is the
    # original CSV filename, sourceType is the type, sasUri is "" (empty).
    payload = {
        "displayName": "AutoClose",
        "provider": "Microsoft",
        "source": "AutoClose.csv",
        "sourceType": "Local",
        "itemsSearchKey": "Title",
        "sasUri": "",  # collected as empty string
        # No rawContent — the API doesn't return CSV bodies on GET.
    }
    from contentops.handlers.sentinel_watchlist_models import (
        SentinelWatchlistPayload,
    )
    # Schema must accept this shape (test the relaxed model first).
    SentinelWatchlistPayload(**payload)

    # Apply must skip — no API calls.
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(
            f"apply must not call the API for a content-less watchlist; "
            f"got {request.method} {request.url}"
        )

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    result = h.apply(_loaded(payload))
    from contentops.core.result import PlanAction
    assert result.action is PlanAction.SKIP
    assert result.status == "skipped"
    assert "rawContent" in (result.detail or "")


# ---------------------------------------------------------------------------
# Pure-helper tests for the count algorithm (no network).
# ---------------------------------------------------------------------------

def test_expected_item_count_header_only() -> None:
    assert _expected_item_count("AssetName,Tier\n") == 0


def test_expected_item_count_blank_lines_ignored() -> None:
    assert _expected_item_count("h,a\nx,1\n\n  \ny,2\n") == 2


def test_expected_item_count_skips_preamble() -> None:
    raw = "# comment\n# another\nh,a\nx,1\ny,2\n"
    assert _expected_item_count(raw, number_of_lines_to_skip=2) == 2


def test_expected_item_count_empty_string() -> None:
    assert _expected_item_count("") == 0
    assert _expected_item_count("", 3) == 0

