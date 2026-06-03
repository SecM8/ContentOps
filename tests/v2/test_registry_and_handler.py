# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the handler registry and the watchlist handler in dry-run."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from contentops.core.asset import Asset
from contentops.core.discovery import load_asset
from contentops.core.handler import LoadedAsset
from contentops.core.registry import HandlerRegistry
from contentops.core.result import PlanAction
from contentops.handlers.sentinel_watchlist import SentinelWatchlistHandler


SAMPLE_WATCHLIST = """\
id: hva
version: 0.1.0
asset: sentinel_watchlist
status: production
payload:
  displayName: High Value Assets
  provider: Custom
  source: Local file
  contentType: text/csv
  itemsSearchKey: AssetName
  rawContent: |
    AssetName,Tier
    dc01,0
    ceo-laptop,1
"""


@pytest.fixture
def watchlist_yaml(tmp_path: Path) -> Path:
    p = tmp_path / "hva.yml"
    p.write_text(SAMPLE_WATCHLIST, encoding="utf-8")
    return p


def test_registry_register_get_lazy() -> None:
    reg = HandlerRegistry()
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        return SentinelWatchlistHandler(provider_factory=lambda: None)

    reg.register(Asset.SENTINEL_WATCHLIST, factory)
    assert calls["n"] == 0  # not constructed yet
    h1 = reg.get(Asset.SENTINEL_WATCHLIST)
    h2 = reg.get(Asset.SENTINEL_WATCHLIST)
    assert h1 is h2
    assert calls["n"] == 1  # cached


def test_registry_unknown_asset_raises() -> None:
    reg = HandlerRegistry()
    with pytest.raises(KeyError, match="No handler"):
        reg.get(Asset.SENTINEL_HUNTING)


def test_watchlist_handler_validate_and_plan(watchlist_yaml: Path) -> None:
    h = SentinelWatchlistHandler(provider_factory=lambda: None)
    loaded = load_asset(watchlist_yaml)
    h.validate(loaded)
    plan = h.plan(loaded)
    assert plan.action is PlanAction.UPDATE
    assert plan.status == "planned"


def test_watchlist_handler_dry_run_apply(watchlist_yaml: Path) -> None:
    """dry_run must NOT call the provider factory."""
    calls = {"n": 0}

    def boom():
        calls["n"] += 1
        raise AssertionError("provider must not be created on dry-run")

    h = SentinelWatchlistHandler(provider_factory=boom)
    loaded = load_asset(watchlist_yaml)
    result = h.apply(loaded, dry_run=True)
    assert result.status == "dry-run"
    assert result.action is PlanAction.UPDATE
    assert calls["n"] == 0


def test_watchlist_handler_skips_experimental(tmp_path: Path) -> None:
    raw = yaml.safe_load(SAMPLE_WATCHLIST)
    raw["status"] = "experimental"
    p = tmp_path / "x.yml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")

    h = SentinelWatchlistHandler(provider_factory=lambda: None)
    loaded = load_asset(p)
    plan = h.plan(loaded)
    assert plan.action is PlanAction.SKIP


def test_watchlist_handler_skips_deprecated(tmp_path: Path) -> None:
    raw = yaml.safe_load(SAMPLE_WATCHLIST)
    raw["status"] = "deprecated"
    p = tmp_path / "d.yml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")

    h = SentinelWatchlistHandler(provider_factory=lambda: None)
    loaded = load_asset(p)
    plan = h.plan(loaded)
    assert plan.action is PlanAction.SKIP
    assert "prune" in plan.detail
