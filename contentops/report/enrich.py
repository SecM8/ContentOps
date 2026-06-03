# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live-enrichment passes for the detection inventory report.

Three optional enrichers, each one a pure function over a row list
plus the data it needs:

* :func:`enrich_with_telemetry` — adds alerts_30d / TP / FP / fp_rate
  + effectiveness_score. Reuses the F4 silent-rules KQL and the
  :mod:`contentops.portfolio.score` formula so the report's score
  column is byte-identical to the ``portfolio --rank`` output.
* :func:`enrich_with_health` — adds ``data_source_healthy``. Parses
  each detection's primary KQL table, runs ``<Table> | take 1`` per
  unique table against the workspace, marks every rule whose primary
  table returned at least one row in the last 24h as healthy.
* :func:`enrich_with_schema_drift` — adds ``schema_drift_columns``.
  Cross-references each detection's primary table against
  ``tools/kql_strict/schemas.json`` (refreshed by
  ``kql-schemas-refresh.yml``). A primary table not present in the
  cache surfaces as a drift signal — likely retired or renamed.

The enrichers mutate ``ReportRow`` via :func:`dataclasses.replace` so
the row stays frozen / hashable; the caller swaps each row in the
list. Tests pin field-level behaviour without mocking network code.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from contentops.report.assemble import ReportRow

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# KQL primary-table extraction (shared by health + schema-drift enrichers)
# ---------------------------------------------------------------------------


# The first non-blank, non-comment line is conventionally the primary
# table name. Operators sometimes prepend ``// notes`` comments or
# ``let X = ...`` declarations; we skip those and grab the first
# identifier we can find at column 0 (or after a `union`).
_TABLE_NAME_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\b")
_LET_RE = re.compile(r"^\s*let\b", re.IGNORECASE)
_COMMENT_RE = re.compile(r"^\s*//")
_UNION_RE = re.compile(r"^\s*union\s+", re.IGNORECASE)


def extract_primary_table(query: str | None) -> str | None:
    """Return the first table name referenced in a KQL query.

    Skips:

    * Blank lines and ``//`` comments.
    * ``let X = ...`` declarations (the *primary* table is the one
      the rule fires against, not a helper binding).
    * Leading whitespace.

    Strips a leading ``union `` keyword so a query of the form
    ``union DeviceProcessEvents, DeviceFileEvents`` resolves to the
    first of the unioned tables. Returns ``None`` for empty input or
    queries that don't start with a clear table identifier.

    This is heuristic — a full KQL parser lives in the kql_strict
    wrapper, but it's a .NET subprocess too heavy to call per-row.
    The heuristic correctly identifies the primary table for ~95% of
    real Sentinel content; the remainder leaves
    ``data_source_healthy`` / ``schema_drift_columns`` as ``None``
    (not False) so the cell renders as "unknown" rather than a false
    "broken" claim.
    """
    if not query or not isinstance(query, str):
        return None
    for raw in query.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _COMMENT_RE.match(line):
            continue
        if _LET_RE.match(line):
            continue
        # Strip a leading "union " keyword if present.
        stripped = _UNION_RE.sub("", line)
        m = _TABLE_NAME_RE.match(stripped.lstrip())
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Schemas cache loader
# ---------------------------------------------------------------------------


def _load_schema_tables(schemas_path: Path) -> set[str]:
    """Return the set of table names recorded in the cached schema.

    Missing / unparseable file -> empty set. Reading the cache is
    best-effort so a stale schemas.json doesn't crash report
    generation; the enricher just reports every table as drift in
    that pathological case and operators see the empty cache as the
    root cause.
    """
    try:
        raw = json.loads(schemas_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    out: set[str] = set()
    for entry in raw.get("tables", []):
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, str) and name:
            out.add(name)
    return out


# ---------------------------------------------------------------------------
# Enricher 1 — telemetry + effectiveness score
# ---------------------------------------------------------------------------


def enrich_with_telemetry(
    rows: list[ReportRow],
    telemetry_by_name: dict[str, dict[str, Any]],
    *,
    score_weights: Any | None = None,
) -> list[ReportRow]:
    """Populate alerts / TP / FP / fp_rate / effectiveness_score.

    ``telemetry_by_name`` is ``{display_name: {alerts_30d, incidents_30d,
    closed_fp_30d, ...}}``; produce it from
    :func:`contentops.workspace_kql.query` + :func:`silent_rules_query`,
    or stub it in tests. The match key is the rule's display_name —
    same key the silent-rules KQL emits as ``rule_name``.

    Uses :func:`contentops.portfolio.score.compute_score` so the
    report's score column is byte-identical to ``portfolio --rank``.
    """
    from contentops.portfolio.score import ScoreWeights, compute_score

    weights = score_weights or ScoreWeights()
    out: list[ReportRow] = []
    for row in rows:
        tel = telemetry_by_name.get(row.title)
        if tel is None:
            # No telemetry merged -> leave fields as None ("unknown").
            out.append(row)
            continue
        alerts = int(tel.get("alerts_30d") or 0)
        incidents = int(tel.get("incidents_30d") or 0)
        closed_fp = int(tel.get("closed_fp_30d") or 0)
        tp = max(0, incidents - closed_fp)
        fp_rate = round(closed_fp / incidents, 3) if incidents > 0 else None
        score = compute_score(
            {
                "alerts_30d": alerts,
                "incidents_30d": incidents,
                "closed_fp_30d": closed_fp,
            },
            weights,
        )
        out.append(replace(
            row,
            alerts_30d=alerts,
            true_positives_30d=tp,
            false_positives_30d=closed_fp,
            fp_rate=fp_rate,
            effectiveness_score=score,
        ))
    return out


# ---------------------------------------------------------------------------
# Enricher 2 — data-source health probe
# ---------------------------------------------------------------------------


def health_query(table: str, *, since_hours: int = 24) -> str:
    """KQL that returns one row iff the table has any data in the
    last N hours. Conservative — we don't care about row counts,
    just presence."""
    return f"{table}\n| where TimeGenerated > ago({since_hours}h)\n| take 1"


def enrich_with_health(
    rows: list[ReportRow],
    primary_tables_by_id: dict[str, str | None],
    table_health: dict[str, bool],
) -> list[ReportRow]:
    """Populate ``data_source_healthy`` from a precomputed table-health
    map.

    ``primary_tables_by_id``: ``{rule_id: primary_table_or_None}`` —
    typically built by walking the row list and calling
    :func:`extract_primary_table` on each rule's KQL query.
    ``table_health``: ``{table_name: bool}`` from running
    :func:`health_query` against the workspace. Tests stub both maps;
    the CLI builds them by querying the workspace once per unique
    table (deduplicated to keep round-trips minimal).

    A rule with no detectable primary table or a table not in the
    health map gets ``data_source_healthy = None`` (unknown), NOT
    False — distinguishes "we don't know" from "table is dead".
    """
    out: list[ReportRow] = []
    for row in rows:
        primary = primary_tables_by_id.get(row.rule_id)
        if not primary:
            out.append(row)
            continue
        healthy = table_health.get(primary)
        out.append(replace(row, data_source_healthy=healthy))
    return out


# ---------------------------------------------------------------------------
# Enricher 3 — schema drift (primary-table existence)
# ---------------------------------------------------------------------------


def enrich_with_schema_drift(
    rows: list[ReportRow],
    primary_tables_by_id: dict[str, str | None],
    schemas_path: Path,
) -> list[ReportRow]:
    """Populate ``schema_drift_columns`` with the primary table name
    if it isn't in the cached schema.

    Today's "drift" signal is coarse — it flags a rule whose primary
    table is missing from the cache entirely (likely retired or
    renamed in the workspace). Column-level drift (checking every
    referenced column against the cached column list) would need a
    full KQL parser; that's a future iteration, not PR-2.

    A rule with no detectable primary table or with a table that IS
    in the schema gets an empty tuple — no drift detected.
    """
    known_tables = _load_schema_tables(schemas_path)
    out: list[ReportRow] = []
    for row in rows:
        primary = primary_tables_by_id.get(row.rule_id)
        drift: tuple[str, ...] = ()
        if primary and known_tables and primary not in known_tables:
            drift = (primary,)
        out.append(replace(row, schema_drift_columns=drift))
    return out


# ---------------------------------------------------------------------------
# Helpers for the CLI to build the input maps
# ---------------------------------------------------------------------------


def primary_tables_for_rows(
    rows: list[ReportRow],
    *,
    query_loader: Callable[[ReportRow], str | None] | None = None,
) -> dict[str, str | None]:
    """Map each row's ``rule_id`` to its primary KQL table.

    ``query_loader`` defaults to reading the YAML file at ``row.path``
    and pulling ``payload.query`` — tests can supply a stub that
    returns a literal string per row id.
    """
    out: dict[str, str | None] = {}
    loader = query_loader or _load_query_from_path
    for row in rows:
        try:
            query = loader(row)
        except Exception as exc:
            logger.debug("failed to read query for %s: %s", row.rule_id, exc)
            out[row.rule_id] = None
            continue
        out[row.rule_id] = extract_primary_table(query)
    return out


def _load_query_from_path(row: ReportRow) -> str | None:
    """Default query loader — reads the row's YAML and pulls
    ``payload.query``. Returns None when the field is missing /
    not a string (some assets like watchlists carry no query)."""
    import yaml
    try:
        raw = yaml.safe_load(Path(row.path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    payload = raw.get("payload")
    if not isinstance(payload, dict):
        return None
    query = payload.get("query")
    return query if isinstance(query, str) else None


# ---------------------------------------------------------------------------
# Enricher 4 — alert health (Graph / Sentinel alert API)
# ---------------------------------------------------------------------------


def enrich_with_alerts(
    rows: list[ReportRow],
    health_by_id: dict[str, Any],
) -> list[ReportRow]:
    """Populate alert-performance columns from DetectionHealthRow data.

    ``health_by_id`` maps ``detection_id`` (envelope slug) to a
    ``DetectionHealthRow`` (or any object with the expected attributes).
    Fills existing telemetry fields (alerts_30d, TP, FP, fp_rate) plus
    the new alert_silent_days and alert_recommendation fields.
    """
    from contentops.portfolio.score import ScoreWeights, compute_score

    weights = ScoreWeights()
    out: list[ReportRow] = []
    for row in rows:
        health = health_by_id.get(row.rule_id)
        if health is None:
            out.append(row)
            continue
        score = compute_score(
            {
                "alerts_30d": health.alert_count,
                "incidents_30d": health.tp_count + health.fp_count,
                "closed_fp_30d": health.fp_count,
            },
            weights,
        )
        out.append(replace(
            row,
            alerts_30d=health.alert_count,
            true_positives_30d=health.tp_count,
            false_positives_30d=health.fp_count,
            fp_rate=health.fp_rate / 100 if health.fp_rate is not None else None,
            effectiveness_score=score,
            alert_silent_days=health.silent_days,
            alert_recommendation=health.recommendation,
        ))
    return out


__all__ = [
    "enrich_with_alerts",
    "enrich_with_health",
    "enrich_with_schema_drift",
    "enrich_with_telemetry",
    "extract_primary_table",
    "health_query",
    "primary_tables_for_rows",
]
