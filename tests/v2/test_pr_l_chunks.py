# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops new --from-template` and watchlist SAS-URI ingestion.

(Earlier the file also covered the Sentinel TI indicator handler, removed
in the asset-taxonomy reduction; those tests went with it.)
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from contentops.config import SentinelConfig
from contentops.devex.templates_remote import (
    TemplateError,
    envelope_from_template,
    fetch_template,
    scaffold_from_template,
    search_templates,
)
from contentops.handlers.sentinel_watchlist_models import (
    SentinelWatchlistPayload,
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


# ===========================================================================
# contentops new --from-template
# ===========================================================================


def _scheduled_template(name: str = "tpl-1") -> dict:
    return {
        "name": name,
        "kind": "Scheduled",
        "properties": {
            "displayName": "Brute force attack against user credentials",
            "description": "Identifies brute force activity.",
            "severity": "Medium",
            "query": "SigninLogs | take 1",
            "queryFrequency": "P1D",
            "queryPeriod": "P1D",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": ["CredentialAccess"],
            "techniques": ["T1110"],
            "version": "2.0.0",
        },
    }


def test_envelope_from_scheduled_template_projects_required_fields() -> None:
    env = envelope_from_template(_scheduled_template("tpl-1"))
    assert env["asset"] == "sentinel_analytic"
    assert env["status"] == "experimental"
    assert env["payload"]["kind"] == "Scheduled"
    assert env["payload"]["alertRuleTemplateName"] == "tpl-1"
    assert env["payload"]["templateVersion"] == "2.0.0"
    assert env["payload"]["queryFrequency"] == "P1D"
    # MITRE tactic mapped, technique preserved.
    assert env["metadata"]["tactics"] == ["CredentialAccess"]
    assert env["metadata"]["techniques"] == ["T1110"]
    # Severity normalised to lowercase per metadata schema.
    assert env["metadata"]["severity"] == "medium"


def test_envelope_from_template_id_override_validated() -> None:
    with pytest.raises(TemplateError):
        envelope_from_template(_scheduled_template(), override_id="Bad ID")


def test_envelope_from_fusion_template_is_toggle_only() -> None:
    fusion = {
        "name": "fusion-tpl",
        "kind": "Fusion",
        "properties": {
            "displayName": "Fusion catch-all",
            "severity": "High",
            "tactics": [],
        },
    }
    env = envelope_from_template(fusion)
    # Toggle-only kinds carry only kind + alertRuleTemplateName + enabled.
    assert env["payload"] == {
        "kind": "Fusion",
        "alertRuleTemplateName": "fusion-tpl",
        "enabled": True,
    }


def test_search_templates_substring_case_insensitive() -> None:
    items = [
        {"name": "guid-1", "kind": "Scheduled",
         "properties": {"displayName": "Brute force attack against AAD"}},
        {"name": "guid-2", "kind": "Scheduled",
         "properties": {"displayName": "DNS exfiltration"}},
        {"name": "BRUTE-3", "kind": "NRT",
         "properties": {"displayName": "Other"}},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": items})

    p = _provider_with(httpx.MockTransport(handler))
    matches = search_templates(p, "brute")
    # Two matches: one by displayName, one by ARM name.
    assert {m["name"] for m in matches} == {"guid-1", "BRUTE-3"}


def test_fetch_template_404_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    p = _provider_with(httpx.MockTransport(handler))
    with pytest.raises(TemplateError, match="not found"):
        fetch_template(p, "absent-tpl")


def test_scaffold_from_template_writes_envelope(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_scheduled_template())

    p = _provider_with(httpx.MockTransport(handler))
    out = tmp_path / "scaffolded.yml"
    written = scaffold_from_template(
        p, "tpl-1", override_id="brute-force-001",
        out_path=out, force=False,
    )
    assert written == out
    assert out.exists()
    assert "alertRuleTemplateName" in out.read_text(encoding="utf-8")


def test_scaffold_refuses_overwrite_without_force(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_scheduled_template())

    p = _provider_with(httpx.MockTransport(handler))
    out = tmp_path / "scaffolded.yml"
    out.write_text("# pre-existing")
    with pytest.raises(TemplateError, match="overwrite"):
        scaffold_from_template(
            p, "tpl-1", override_id="brute-force-001",
            out_path=out, force=False,
        )



# ===========================================================================
# Watchlist SAS-URI ingestion
# ===========================================================================


_FAKE_SAS = (
    "https://stwl.blob.core.windows.net/lists/big.csv"
    "?sv=2021-06-08&ss=b&srt=o&sp=r&se=2030-01-01T00:00:00Z"
    "&sig=Z2YxNzU3M2JiMmI5NDE5OWE3MzE3OTA5NTcwMmEwYjU%3D"
)


def test_watchlist_sas_path_valid() -> None:
    p = SentinelWatchlistPayload(
        displayName="HVA",
        provider="Custom",
        contentType="text/csv",
        itemsSearchKey="AssetName",
        sasUri=_FAKE_SAS,
    )
    # Source coerced to "Remote storage" when sasUri is set.
    assert p.source == "Remote storage"
    assert p.sasUri == _FAKE_SAS
    assert p.rawContent is None


def test_watchlist_sas_requires_https() -> None:
    with pytest.raises(ValidationError, match="https://"):
        SentinelWatchlistPayload(
            displayName="x",
            itemsSearchKey="k",
            sasUri="http://insecure.example/file.csv?sig=abc",
        )


def test_watchlist_sas_requires_sig_token() -> None:
    with pytest.raises(ValidationError, match="sig="):
        SentinelWatchlistPayload(
            displayName="x",
            itemsSearchKey="k",
            sasUri="https://stwl.blob.core.windows.net/lists/big.csv",
        )


def test_watchlist_rawcontent_and_sasuri_mutually_exclusive() -> None:
    with pytest.raises(ValidationError, match="not both"):
        SentinelWatchlistPayload(
            displayName="x",
            itemsSearchKey="AssetName",
            rawContent="AssetName,Tier\ndc01,0\n",
            sasUri=_FAKE_SAS,
        )


def test_watchlist_neither_path_accepted_at_schema() -> None:
    """Schema no longer requires rawContent OR sasUri at load time —
    collected watchlist envelopes lack both (the API doesn't echo CSV
    bodies on GET). The apply handler rejects content-less watchlists
    just before PUT; the schema stays permissive so envelopes load."""
    # Must NOT raise.
    p = SentinelWatchlistPayload(
        displayName="x",
        itemsSearchKey="AssetName",
    )
    assert p.rawContent is None
    assert p.sasUri is None
