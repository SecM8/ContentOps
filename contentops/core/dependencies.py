# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Declarative prerequisites between assets.

Inspired by the ``dependencies.json`` pattern used in the Sentinel-As-Code
project: a single document at ``detections/dependencies.yml`` declares
prerequisites (Log Analytics tables, watchlists, parser functions, other
detections) for assets in the repo. ``plan`` runs the validator before
dispatching to handlers so a missing prerequisite surfaces as one clean
error instead of a cascade of API failures.

YAML schema::

    version: 1
    assets:
      <asset-id>:
        tables:     [SecurityEvent, SigninLogs]      # workspace tables
        watchlists: [HighValueUsers]                 # asset_ids in repo
        parsers:    [CommonSecurityLog_Enriched]     # parser function names
        detections: [<other-asset-id>]               # other asset_ids in repo
        external:   ["Microsoft.Insights/workbooks"] # free-form, never validated

The validator is repo-local: it can confirm that watchlist/parser/detection
prerequisites exist as files in the repo. Tables and ``external`` entries
are documentation only — they are reported in `plan` output but never fail
validation, because we cannot know what tables a workspace has without an
API call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, Field

from contentops.core.handler import LoadedAsset
from contentops.utils.yaml_io import load_yaml


class AssetDependencies(BaseModel):
    tables: list[str] = Field(default_factory=list)
    watchlists: list[str] = Field(default_factory=list)
    parsers: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    external: list[str] = Field(default_factory=list)


class DependencyGraph(BaseModel):
    version: int = 1
    assets: dict[str, AssetDependencies] = Field(default_factory=dict)

    def for_asset(self, asset_id: str) -> AssetDependencies:
        return self.assets.get(asset_id) or AssetDependencies()


@dataclass(frozen=True)
class DependencyViolation:
    asset_id: str
    missing_kind: str  # "watchlist" | "parser" | "detection"
    missing_name: str

    def as_row(self) -> str:
        return f"  MISSING {self.missing_kind:10s} {self.missing_name!r:40s} required by {self.asset_id}"


@dataclass(frozen=True)
class DependencyReport:
    violations: tuple[DependencyViolation, ...] = ()
    info_tables: dict[str, tuple[str, ...]] = field(default_factory=dict)
    info_external: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.violations


DEFAULT_PATH = Path("detections") / "dependencies.yml"


def load_graph(path: Path | None = None) -> DependencyGraph:
    """Load the graph file. Missing file == empty graph (not an error)."""
    target = path or DEFAULT_PATH
    if not target.is_file():
        return DependencyGraph()
    raw = load_yaml(target) or {}
    return DependencyGraph(**raw)


def _index_by_asset(
    loaded: Iterable[LoadedAsset],
) -> tuple[set[str], set[str], set[str]]:
    """Single O(n) pass over ``loaded`` that builds:

    1. ``watchlists`` — every envelope.id where ``asset == SENTINEL_WATCHLIST``.
    2. ``parsers``   — every envelope.id where ``asset == SENTINEL_PARSER``.
    3. ``all_ids``   — every envelope.id in the load set (used for the
       cross-detection prerequisite check).

    Previously each of these three views was computed by its own
    ``for la in loaded`` loop, and ``validate`` walked the load set a
    fourth time to surface dependencies — making the validator O(n)
    per rule for a total of O(n²) per run. With the upcoming
    larger-corpus tenants this would scale badly.

    Also fixes R5: ``parsers`` used to be built from
    ``SENTINEL_HUNTING`` envelopes, conflating two distinct asset
    kinds. Hunting queries and parsers are separate concepts in
    Sentinel — parsers materialise as ``sentinel_parser``-asset
    envelopes (saved KQL functions); hunting queries are alerts you
    can pivot on. A rule declaring ``parsers: [foo]`` should
    resolve against a ``sentinel_parser`` envelope, not a hunting
    query that happens to share the slug.
    """
    from contentops.core.asset import Asset
    watchlists: set[str] = set()
    parsers: set[str] = set()
    all_ids: set[str] = set()
    for la in loaded:
        env_id = la.envelope.id
        all_ids.add(env_id)
        kind = la.envelope.asset
        if kind == Asset.SENTINEL_WATCHLIST:
            watchlists.add(env_id)
        elif kind == Asset.SENTINEL_PARSER:
            parsers.add(env_id)
    return watchlists, parsers, all_ids


def validate(
    loaded: list[LoadedAsset],
    graph: DependencyGraph | None = None,
) -> DependencyReport:
    """Validate prerequisites for the supplied assets against ``graph``.

    Watchlists, parsers, and detections must resolve to ids present in
    ``loaded``. Tables and ``external`` are reported but never fail.

    The watchlist/parser/all-ids indexes are built once per validation
    run (single O(n) pass over ``loaded``), then reused for every
    rule's lookups — see Q4.
    """
    g = graph if graph is not None else load_graph()
    watchlists, parsers, asset_ids = _index_by_asset(loaded)

    violations: list[DependencyViolation] = []
    info_tables: dict[str, tuple[str, ...]] = {}
    info_external: dict[str, tuple[str, ...]] = {}

    for la in loaded:
        deps = g.for_asset(la.envelope.id)
        for w in deps.watchlists:
            if w not in watchlists:
                violations.append(DependencyViolation(la.envelope.id, "watchlist", w))
        for p in deps.parsers:
            if p not in parsers:
                violations.append(DependencyViolation(la.envelope.id, "parser", p))
        for d in deps.detections:
            if d not in asset_ids:
                violations.append(DependencyViolation(la.envelope.id, "detection", d))
        if deps.tables:
            info_tables[la.envelope.id] = tuple(deps.tables)
        if deps.external:
            info_external[la.envelope.id] = tuple(deps.external)

    return DependencyReport(
        violations=tuple(violations),
        info_tables=info_tables,
        info_external=info_external,
    )


__all__ = [
    "AssetDependencies",
    "DependencyGraph",
    "DependencyReport",
    "DependencyViolation",
    "load_graph",
    "validate",
    "DEFAULT_PATH",
]
