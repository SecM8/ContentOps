# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Portfolio CSV/JSON renderer.

Builds one row per detection-class asset (sentinel_analytic,
sentinel_hunting, defender_custom_detection) from the shared coverage
corpus (:func:`contentops.coverage.corpus.load_corpus`): ATT&CK tactics
and techniques come from the same extractor as every coverage number
(metadata + payload, normalised), so a collected rule's row is not empty.
Files that cannot be parsed at all are skipped with a warning --
`contentops lint` is the channel for parse failures.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from pathlib import Path
from typing import Any

from contentops.core.asset import DETECTION_ASSETS, Asset
from contentops.coverage.corpus import Corpus, CorpusEntry, load_corpus

logger = logging.getLogger(__name__)


COLUMNS: tuple[str, ...] = (
    "id",
    "asset",
    "path",
    "display_name",
    "severity",
    "tactics",
    "techniques",
    "enabled",
    "expected_alerts_per_day",
    "last_validated_at",
    "cohort",
    "query_period_minutes",
    "query_lines",
)

_DETECTION_ASSETS = DETECTION_ASSETS  # historical alias

# PT5M / PT1H / PT1D / P1D — anything else returns None.
_ISO_DURATION_RE = re.compile(
    r"^P(?:T(?P<thours>\d+)H|T(?P<tminutes>\d+)M|T(?P<tdays>\d+)D|(?P<pdays>\d+)D)$"
)


def iso8601_duration_to_minutes(value: str | None) -> int | None:
    """Convert a narrow subset of ISO 8601 durations to whole minutes.

    Supports PT<n>M, PT<n>H, PT<n>D, P<n>D. Returns None for anything
    else (including None / empty input). Deliberately strict — we'd
    rather render an empty cell than a wrong number.
    """
    if not value or not isinstance(value, str):
        return None
    m = _ISO_DURATION_RE.match(value.strip())
    if not m:
        return None
    if m.group("tminutes"):
        return int(m.group("tminutes"))
    if m.group("thours"):
        return int(m.group("thours")) * 60
    if m.group("tdays"):
        return int(m.group("tdays")) * 24 * 60
    if m.group("pdays"):
        return int(m.group("pdays")) * 24 * 60
    return None


def _query_line_count(query: Any) -> int | None:
    if not isinstance(query, str) or not query.strip():
        return None
    return len([ln for ln in query.splitlines() if ln.strip()])


def _display_name(asset: Asset, payload: dict[str, Any]) -> str | None:
    return (
        payload.get("DisplayName")
        or payload.get("displayName")
        or None
    )


def _enabled(asset: Asset, payload: dict[str, Any]) -> bool | None:
    if asset is Asset.SENTINEL_ANALYTIC:
        v = payload.get("enabled")
        return bool(v) if v is not None else None
    if asset is Asset.DEFENDER_CUSTOM_DETECTION:
        if payload.get("status") is None and payload.get("isEnabled") is None:
            return None
        from contentops.defender.rule_status import is_enabled

        return is_enabled(payload)
    return None


def _query_text(asset: Asset, payload: dict[str, Any]) -> str | None:
    if asset is Asset.DEFENDER_CUSTOM_DETECTION:
        qc = payload.get("queryCondition") or {}
        if isinstance(qc, dict):
            q = qc.get("queryText")
            if isinstance(q, str):
                return q
        return None
    q = payload.get("query")
    return q if isinstance(q, str) else None


def _query_period(asset: Asset, payload: dict[str, Any]) -> str | None:
    if asset is not Asset.SENTINEL_ANALYTIC:
        return None
    qp = payload.get("queryPeriod")
    return qp if isinstance(qp, str) else None


def _row_for(entry: CorpusEntry, repo_root: Path) -> dict[str, Any]:
    env = entry.envelope
    md = env.metadata
    payload = dict(entry.payload or {})

    try:
        rel_path = entry.path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        rel_path = entry.path.as_posix()

    severity = md.severity if md is not None else None
    tactics = list(entry.mitre.tactics)
    techniques = list(entry.mitre.techniques)
    expected = md.expectedAlertsPerDay if md is not None else None
    last_validated = md.lastValidatedAt if md is not None else None
    cohort = entry.cohort

    query_text = _query_text(env.asset, payload)
    query_period_minutes = iso8601_duration_to_minutes(_query_period(env.asset, payload))

    return {
        "id": env.id,
        "asset": env.asset.value,
        "path": rel_path,
        "display_name": _display_name(env.asset, payload),
        "severity": severity,
        "tactics": tactics,
        "techniques": techniques,
        "enabled": _enabled(env.asset, payload),
        "expected_alerts_per_day": expected,
        "last_validated_at": last_validated,
        "cohort": cohort,
        "query_period_minutes": query_period_minutes,
        "query_lines": _query_line_count(query_text),
    }


def build_rows(
    base: Path,
    *,
    cohort: str | None = None,
    corpus: Corpus | None = None,
) -> list[dict[str, Any]]:
    """Walk `base/`, return one row per detection envelope.

    Every detection gets a row (the coverage scope only affects coverage
    numbers). Files that cannot be parsed are skipped with a warning —
    `contentops lint` is the channel for surfacing parse errors.
    Non-detection assets (watchlist/workbook/etc.) are filtered out.
    Pass ``corpus`` to reuse an existing walk.
    """
    repo_root = Path.cwd()
    corpus = corpus or load_corpus(base)
    for path, error in corpus.load_errors:
        logger.warning("portfolio: skipping %s: %s", path, error)
    rows: list[dict[str, Any]] = []
    for entry in corpus.entries:
        row = _row_for(entry, repo_root)
        if cohort is not None and row["cohort"] != cohort:
            continue
        rows.append(row)

    rows.sort(key=lambda r: (r["asset"], r["id"]))
    return rows


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ";".join(str(v) for v in value)
    return str(value)


def write_csv(
    rows: list[dict[str, Any]], out,
    *,
    extra_columns: tuple[str, ...] = (),
) -> None:
    """Write rows as CSV. `out` may be a Path or an open text stream.

    ``extra_columns`` appends extra column names (e.g. F20 telemetry
    fields) after the default COLUMNS list.
    """
    if isinstance(out, (str, Path)):
        with open(out, "w", encoding="utf-8", newline="") as fh:
            _write_csv_stream(rows, fh, extra_columns)
    else:
        _write_csv_stream(rows, out, extra_columns)


def _write_csv_stream(
    rows: list[dict[str, Any]], stream,
    extra_columns: tuple[str, ...] = (),
) -> None:
    writer = csv.writer(stream, lineterminator="\n")
    columns = COLUMNS + tuple(extra_columns)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_csv_cell(row.get(col)) for col in columns])


def write_json(rows: list[dict[str, Any]], out) -> None:
    """Write rows as JSON (a list of objects). `out` is a Path or stream."""
    payload = json.dumps(rows, indent=2, sort_keys=False)
    if isinstance(out, (str, Path)):
        Path(out).write_text(payload + "\n", encoding="utf-8")
    else:
        out.write(payload + "\n")


def render_csv_string(
    rows: list[dict[str, Any]],
    *,
    extra_columns: tuple[str, ...] = (),
) -> str:
    buf = io.StringIO()
    _write_csv_stream(rows, buf, extra_columns)
    return buf.getvalue()
