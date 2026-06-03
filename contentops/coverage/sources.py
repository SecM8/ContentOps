# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-log-source coverage rollup.

Groups detections by the data source (KQL table) they read from, so a
SOC lead can see distribution across log sources — and which sources the
corpus leans on — rather than only the MITRE tactic view.

A source table is recognised only at the syntactic positions where a real
table is READ FROM:

* the start of a line (the source table, or a subquery's table after ``(``),
* immediately after a ``join`` (``join kind=inner T``, ``join (T | ...)``),
* in a ``union`` (``union (T | ...)``, ``union T1, T2``).

Every candidate is then VALIDATED against the committed table surface
(``tools/kql_strict/schemas*.json`` — the same schema the kql_strict
check uses), so column names, operators (``where``/``extend``), function
calls, and typos never bucket as sources. Status-aware: each source
carries a production count alongside the total (mirrors the heatmap).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from contentops.core.asset import kql_body_from_payload
from contentops.core.discovery import iter_loaded_assets
from contentops.coverage.report import DETECTION_ASSETS
from contentops.report.enrich import _load_schema_tables

# Repo-root-anchored schema files (committed; also mirrored to adopters).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_FILES = (
    _REPO_ROOT / "tools" / "kql_strict" / "schemas.json",
    _REPO_ROOT / "tools" / "kql_strict" / "schemas_defender.json",
)

_COMMENT_RE = re.compile(r"^\s*//")
_LET_RE = re.compile(r"^\s*let\b", re.IGNORECASE)
# Line-start table: an identifier at column 0, optionally inside a "(" that
# opens a subquery. Pipe-operator lines ("| where ...") don't match.
_LINE_START_RE = re.compile(r"^\s*\(?\s*([A-Za-z_][A-Za-z0-9_]*)\b")
# After `join` (skip kind=/hint. options), optionally an opening "(".
_JOIN_RE = re.compile(
    r"\bjoin\b\s*(?:kind\s*=\s*[\w-]+\s+)?(?:hint\.\w+\s*=\s*\S+\s+)*\(?\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
# After `union` (skip kind=/withsource=/isfuzzy= options); the tail may list
# several comma- or paren-separated tables — grab every identifier and let
# the known-table validation drop the non-tables.
_UNION_RE = re.compile(
    r"\bunion\b\s*((?:(?:kind|withsource|isfuzzy)\s*=\s*\S+\s+)*.*)",
    re.IGNORECASE,
)
_IDENT_RE = re.compile(r"\(?\s*([A-Za-z_][A-Za-z0-9_]*)\b")


@lru_cache(maxsize=1)
def load_known_tables() -> frozenset[str]:
    """Union of table names across the committed Sentinel + Defender schemas.

    Empty when the schema files are absent (the rollup then reports every
    source as unrecognised, with a clear note, rather than crashing)."""
    names: set[str] = set()
    for path in _SCHEMA_FILES:
        names |= _load_schema_tables(path)
    return frozenset(names)


def extract_source_tables(query: str, known_tables: frozenset[str]) -> set[str]:
    """Return the validated source tables a KQL query reads from.

    Candidates are taken at line-start / after ``join`` / in ``union`` and
    kept only if they are real tables in ``known_tables``."""
    if not query:
        return set()
    found: set[str] = set()
    for raw in query.splitlines():
        line = raw.strip()
        if not line or _COMMENT_RE.match(line) or _LET_RE.match(line):
            continue
        candidates: list[str] = []
        m = _LINE_START_RE.match(line)
        if m:
            candidates.append(m.group(1))
        candidates += _JOIN_RE.findall(line)
        um = _UNION_RE.search(line)
        if um:
            candidates += _IDENT_RE.findall(um.group(1))
        found.update(c for c in candidates if c in known_tables)
    return found


@dataclass
class SourceCoverage:
    table: str
    detection_count: int = 0
    production_detection_count: int = 0


@dataclass
class SourceCoverageReport:
    sources: list[SourceCoverage]            # sorted desc by detection_count
    total_detections: int
    detections_with_a_known_source: int
    detections_without_known_source: int     # no recognised table (custom/parser/typo)
    unrecognised_tables: tuple[str, ...]     # extracted but not in the schema surface
    known_tables_available: bool


def compute_source_coverage(detections_root: Path) -> SourceCoverageReport:
    """Bucket detection-class envelopes by the data source(s) they read."""
    known = load_known_tables()
    per_source: dict[str, SourceCoverage] = {}
    unrecognised: set[str] = set()
    total = 0
    with_known = 0

    if detections_root.is_dir():
        for la in iter_loaded_assets(detections_root):
            if la.envelope.asset not in DETECTION_ASSETS:
                continue
            query = kql_body_from_payload(la.envelope.asset, la.payload)
            if not query:
                continue
            total += 1
            is_prod = (
                str(getattr(la.envelope, "status", "") or "").strip().lower()
                == "production"
            )
            tables = extract_source_tables(query, known)
            if tables:
                with_known += 1
            else:
                # Surface raw line-start candidates that weren't recognised so
                # the operator can tell "custom table / parser" from "typo".
                unrecognised.update(_raw_line_start_idents(query))
            for table in tables:
                sc = per_source.setdefault(table, SourceCoverage(table=table))
                sc.detection_count += 1
                if is_prod:
                    sc.production_detection_count += 1

    sources = sorted(
        per_source.values(), key=lambda s: (-s.detection_count, s.table),
    )
    return SourceCoverageReport(
        sources=sources,
        total_detections=total,
        detections_with_a_known_source=with_known,
        detections_without_known_source=total - with_known,
        unrecognised_tables=tuple(sorted(unrecognised)),
        known_tables_available=bool(known),
    )


# KQL tabular operators / keywords that can appear at a wrapped line-start
# (a continuation of a `|`-piped statement) — never a data source.
_KQL_KEYWORDS: frozenset[str] = frozenset({
    "union", "print", "range", "datatable", "find", "search", "where",
    "project", "extend", "summarize", "by", "join", "on", "parse", "sort",
    "order", "take", "top", "limit", "distinct", "count", "render", "lookup",
    "invoke", "evaluate", "mv", "make", "getschema", "sample", "serialize",
    "scan", "partition", "fork", "facet", "consume", "as", "and", "or", "let",
})


def _raw_line_start_idents(query: str) -> set[str]:
    """Line-start identifiers (pre-validation) that look like a source but
    aren't a known table — reported so the operator can tell a custom table
    / parser from a typo. KQL operators are filtered out."""
    out: set[str] = set()
    for raw in query.splitlines():
        line = raw.strip()
        if not line or _COMMENT_RE.match(line) or _LET_RE.match(line):
            continue
        m = _LINE_START_RE.match(line)
        if m and m.group(1).lower() not in _KQL_KEYWORDS:
            out.add(m.group(1))
    return out


def render_markdown(report: SourceCoverageReport) -> str:
    lines = ["# Coverage by data source", ""]
    if not report.known_tables_available:
        lines.append(
            "> **Schema surface unavailable** (`tools/kql_strict/schemas*.json` "
            "missing) — cannot validate table names, so the rollup is empty. "
            "Refresh via `contentops upstream check-schemas --write`."
        )
        lines.append("")
        return "\n".join(lines)

    lines.append(
        f"**{report.total_detections}** detection(s); "
        f"**{report.detections_with_a_known_source}** map to a known data "
        f"source, **{report.detections_without_known_source}** to none "
        "(custom table, parser, or cross-workspace function)."
    )
    lines.append("")
    lines.append("| Data source (table) | # Detections | # Production |")
    lines.append("|---|---:|---:|")
    for s in report.sources:
        prod = s.production_detection_count
        prod_cell = (
            f"⚠️ {prod}" if (s.detection_count > 0 and prod == 0) else str(prod)
        )
        lines.append(f"| `{s.table}` | {s.detection_count} | {prod_cell} |")
    lines.append("")
    if report.unrecognised_tables:
        shown = ", ".join(f"`{t}`" for t in report.unrecognised_tables[:15])
        more = (
            "" if len(report.unrecognised_tables) <= 15
            else f" (+{len(report.unrecognised_tables) - 15} more)"
        )
        lines.append(
            f"_Unrecognised source identifiers (not in the schema surface — "
            f"custom tables, parsers, or typos): {shown}{more}._"
        )
        lines.append("")
    return "\n".join(lines)


def render_json(report: SourceCoverageReport) -> str:
    import json
    payload = {
        "total_detections": report.total_detections,
        "detections_with_a_known_source": report.detections_with_a_known_source,
        "detections_without_known_source": report.detections_without_known_source,
        "known_tables_available": report.known_tables_available,
        "sources": [
            {
                "table": s.table,
                "detection_count": s.detection_count,
                "production_detection_count": s.production_detection_count,
            }
            for s in report.sources
        ],
        "unrecognised_tables": list(report.unrecognised_tables),
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


__all__ = [
    "SourceCoverage",
    "SourceCoverageReport",
    "load_known_tables",
    "extract_source_tables",
    "compute_source_coverage",
    "render_markdown",
    "render_json",
]
