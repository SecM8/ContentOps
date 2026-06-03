# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Audit-record filtering helpers — shared by `retry-failed` and the
upcoming `audit query` command.

Pure functions; no Click, no global state. The CLI commands compose
these to filter ``audit/*.jsonl`` records by time window, run-id,
status, asset, or actor before extracting whatever they need.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator


class AuditFilterError(ValueError):
    """Raised on malformed --since values."""


_DURATION_RE = re.compile(r"^(\d+)([smhd])$")
_DURATION_UNITS = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
}


def parse_since(value: str, *, now: datetime | None = None) -> datetime:
    """Parse a --since value into a UTC datetime.

    Accepts either a relative duration (``"1h"``, ``"30m"``, ``"7d"``)
    or an ISO 8601 timestamp (``"2026-05-07T08:00Z"`` etc.).

    Returns a tz-aware UTC datetime that filters should compare
    record timestamps against (records >= this datetime are in
    scope).
    """
    if not value:
        raise AuditFilterError("empty --since value")
    s = value.strip()
    now = now or datetime.now(timezone.utc)

    # Duration form first (cheaper, common case).
    m = _DURATION_RE.match(s)
    if m:
        n = int(m.group(1))
        unit = _DURATION_UNITS[m.group(2)]
        delta = timedelta(**{unit: n})
        return now - delta

    # ISO form.
    try:
        normalised = s.replace("Z", "+00:00") if s.endswith("Z") else s
        dt = datetime.fromisoformat(normalised)
    except ValueError as exc:
        raise AuditFilterError(
            f"--since={value!r} is not a duration (e.g. '1h') "
            f"or ISO 8601 timestamp"
        ) from exc

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_record_timestamp(rec: dict) -> datetime | None:
    """Extract the audit record's UTC timestamp.

    Audit records carry ``timestamp`` like ``"2026-05-07T09:14:32.481213Z"``
    (writer.py:475). Returns None if the field is missing or
    unparseable — those records are *excluded* from time-windowed
    scopes (better than silently including them with a default).
    """
    raw = rec.get("timestamp")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        normalised = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iter_records(files: Iterable[Path]) -> Iterator[dict]:
    """Yield each parsed JSON object across ``files``, skipping bad lines."""
    for f in files:
        try:
            content = f.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _matches(rec: dict, predicate: tuple[str, object | None]) -> bool:
    """Apply a predicate tuple to one record."""
    kind, value = predicate
    if kind == "none":
        return True
    if kind == "since":
        # value is a datetime
        ts = _parse_record_timestamp(rec)
        if ts is None:
            return False
        return ts >= value  # type: ignore[operator]
    if kind == "run_id":
        return str(rec.get("workflow_run") or "") == str(value)
    raise ValueError(f"unknown predicate kind: {kind!r}")


def collect_failed_pairs(
    files: Iterable[Path],
    predicate: tuple[str, object | None] = ("none", None),
) -> set[tuple[str, str]]:
    """Walk ``files``, return ``{(asset, id)}`` for records with status=failed.

    The predicate is applied *before* the failed-status check, so a
    --since=1h that excludes a record's timestamp also excludes it
    even if it was failed.
    """
    out: set[tuple[str, str]] = set()
    for rec in iter_records(files):
        if not _matches(rec, predicate):
            continue
        if rec.get("status") != "failed":
            continue
        asset_value = str(rec.get("asset") or "")
        rule_id = str(rec.get("id") or "")
        if asset_value and rule_id:
            out.add((asset_value, rule_id))
    return out


__all__ = [
    "AuditFilterError",
    "parse_since",
    "iter_records",
    "collect_failed_pairs",
]
