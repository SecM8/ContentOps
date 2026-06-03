# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the declarative dependency graph + pre-flight validator."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from contentops.core.asset import Asset
from contentops.core.dependencies import (
    DependencyGraph,
    load_graph,
    validate,
)
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset


def _loaded(asset_id: str, kind: Asset, *, path: Path | None = None) -> LoadedAsset:
    """Build a minimal LoadedAsset for tests, bypassing YAML parsing.

    Metadata is omitted: the dependency validator only inspects
    ``envelope.id`` and ``envelope.asset`` so RuleMetadata is unnecessary.
    """
    env = EnvelopeV2(
        id=asset_id,
        version="1.0.0",
        asset=kind,
        status="test",
    )
    return LoadedAsset(path=path or Path(f"{asset_id}.yml"), envelope=env, payload={})


def test_load_missing_file_returns_empty_graph(tmp_path: Path) -> None:
    g = load_graph(tmp_path / "nope.yml")
    assert isinstance(g, DependencyGraph)
    assert g.assets == {}


def test_load_parses_yaml(tmp_path: Path) -> None:
    p = tmp_path / "deps.yml"
    p.write_text(dedent("""
        version: 1
        assets:
          rule-a:
            tables: [SecurityEvent]
            watchlists: [highvalue]
            external: ["Microsoft.Insights/workbooks"]
    """).lstrip())
    g = load_graph(p)
    assert g.for_asset("rule-a").tables == ["SecurityEvent"]
    assert g.for_asset("rule-a").watchlists == ["highvalue"]
    assert g.for_asset("missing").tables == []


def test_validate_clean_when_prereqs_present() -> None:
    """R5: parsers resolve against SENTINEL_PARSER envelopes (not
    SENTINEL_HUNTING, which is a separate asset kind). A
    declared `parsers: [parser-x]` prerequisite must find a
    matching `asset: sentinel_parser` envelope in the load set."""
    loaded = [
        _loaded("rule-a", Asset.SENTINEL_ANALYTIC),
        _loaded("highvalue", Asset.SENTINEL_WATCHLIST),
        _loaded("parser-x", Asset.SENTINEL_PARSER),
    ]
    g = DependencyGraph.model_validate({
        "version": 1,
        "assets": {
            "rule-a": {"watchlists": ["highvalue"], "parsers": ["parser-x"]},
        },
    })
    report = validate(loaded, g)
    assert report.ok
    assert report.violations == ()


def test_validate_hunting_query_does_not_satisfy_parser_prereq() -> None:
    """R5 regression: previously a `sentinel_hunting` envelope with the
    same id as a declared parser would silently satisfy the prereq.
    Hunting queries and parsers are different asset kinds — a rule
    that depends on a parser function (`sentinel_parser`) should NOT
    resolve against a hunting query that happens to share the slug."""
    loaded = [
        _loaded("rule-a", Asset.SENTINEL_ANALYTIC),
        _loaded("parser-x", Asset.SENTINEL_HUNTING),  # NOT a parser
    ]
    g = DependencyGraph.model_validate({
        "version": 1,
        "assets": {"rule-a": {"parsers": ["parser-x"]}},
    })
    report = validate(loaded, g)
    assert not report.ok
    assert any(
        v.missing_kind == "parser" and v.missing_name == "parser-x"
        for v in report.violations
    )


def test_validate_flags_missing_watchlist_and_parser() -> None:
    loaded = [_loaded("rule-a", Asset.SENTINEL_ANALYTIC)]
    g = DependencyGraph.model_validate({
        "version": 1,
        "assets": {
            "rule-a": {"watchlists": ["nope"], "parsers": ["also-nope"]},
        },
    })
    report = validate(loaded, g)
    assert not report.ok
    kinds = {(v.missing_kind, v.missing_name) for v in report.violations}
    assert ("watchlist", "nope") in kinds
    assert ("parser", "also-nope") in kinds


def test_validate_flags_missing_detection_dependency() -> None:
    loaded = [_loaded("rule-a", Asset.SENTINEL_ANALYTIC)]
    g = DependencyGraph.model_validate({
        "version": 1,
        "assets": {"rule-a": {"detections": ["rule-b"]}},
    })
    report = validate(loaded, g)
    assert {v.missing_name for v in report.violations} == {"rule-b"}


def test_tables_and_external_are_informational_only() -> None:
    loaded = [_loaded("rule-a", Asset.SENTINEL_ANALYTIC)]
    g = DependencyGraph.model_validate({
        "version": 1,
        "assets": {
            "rule-a": {
                "tables": ["SecurityEvent", "SigninLogs"],
                "external": ["Microsoft.Insights/workbooks"],
            },
        },
    })
    report = validate(loaded, g)
    assert report.ok
    assert report.info_tables["rule-a"] == ("SecurityEvent", "SigninLogs")
    assert report.info_external["rule-a"] == ("Microsoft.Insights/workbooks",)
