# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Drift-suppressions — opt-out for known-good portal-side tweaks.

A suppression names a (asset, id) pair as "expected to differ from
git for now" plus an expiry date. ``contentops drift`` reads
``detections/drift_suppressions.yml`` and:

* Suppressed entries are *omitted* from the changed list (still
  counted in the summary).
* Entries past ``expires`` are *not* suppressed — they re-surface
  in the changed list with a ``[suppression-expired]`` tag.
* Suppressions that match no actual change get flagged
  ``[suppression-unused]`` so dead entries can be cleaned up.

The opt-out is `contentops drift --suppressions=ignore`.

Closes the operational risk behind the "drift fatigue" failure
mode: every legitimate portal-side tweak shows as CHANGED forever
until either the YAML is updated or the tweak is reverted, and
analysts learn to ignore the wall of CHANGED entries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date as _date
from pathlib import Path
from typing import Iterable

import yaml

from contentops.core.asset import Asset
from contentops.core.drift import DriftEntry, DriftReport


SUPPRESSIONS_FILENAME = "drift_suppressions.yml"
SCHEMA_VERSION = "1.0"


class SuppressionsError(ValueError):
    """Raised when the suppressions YAML is malformed."""


@dataclass(frozen=True)
class Suppression:
    asset: str
    id: str
    reason: str
    expires: _date

    def expired(self, today: _date | None = None) -> bool:
        return self.expires < (today or _date.today())

    def matches(self, entry: DriftEntry) -> bool:
        return self.asset == entry.asset.value and self.id == entry.asset_id


@dataclass
class FilterResult:
    """Output of ``apply_suppressions``.

    The filtered report has suppressed-and-not-expired entries
    removed from its ``changed`` list (still present in the raw
    entries list with kind="suppressed" so totals can show the
    count). Use ``filtered`` for downstream rendering and
    ``expired`` / ``unused`` for the UX flags.
    """
    filtered: DriftReport
    suppressed: list[DriftEntry] = field(default_factory=list)
    expired: list[Suppression] = field(default_factory=list)
    unused: list[Suppression] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Loading + validation
# ---------------------------------------------------------------------------


def _coerce_date(raw: object, *, where: str) -> _date:
    """Accept a YAML-native ``date`` (PyYAML decodes ``2026-06-01``) or
    an ISO 8601 ``YYYY-MM-DD`` string. Anything else → SuppressionsError."""
    if isinstance(raw, _date):
        return raw
    if isinstance(raw, str):
        try:
            return _date.fromisoformat(raw)
        except ValueError as exc:
            raise SuppressionsError(
                f"{where}: 'expires' is not a YYYY-MM-DD date: {raw!r}"
            ) from exc
    raise SuppressionsError(
        f"{where}: 'expires' must be a YYYY-MM-DD date (got {type(raw).__name__})"
    )


def load_suppressions(detections_root: Path) -> list[Suppression]:
    """Load ``detections/drift_suppressions.yml``.

    Missing file → empty list (no error). Malformed file →
    SuppressionsError so the CLI can surface a clear message; the
    drift run does NOT silently swallow malformed YAML.
    """
    path = detections_root / SUPPRESSIONS_FILENAME
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SuppressionsError(f"{path}: parse error: {exc}") from exc

    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise SuppressionsError(f"{path}: top-level must be a mapping")

    schema = str(raw.get("schema_version") or "")
    if schema and schema != SCHEMA_VERSION:
        raise SuppressionsError(
            f"{path}: schema_version {schema!r} is not supported "
            f"(expected {SCHEMA_VERSION!r})"
        )

    items = raw.get("suppressions") or []
    if not isinstance(items, list):
        raise SuppressionsError(f"{path}: 'suppressions' must be a list")

    asset_values = {a.value for a in Asset}
    out: list[Suppression] = []
    for i, entry in enumerate(items):
        where = f"{path}[{i}]"
        if not isinstance(entry, dict):
            raise SuppressionsError(f"{where}: entry must be a mapping")
        asset = str(entry.get("asset") or "")
        if asset not in asset_values:
            raise SuppressionsError(
                f"{where}: 'asset' is not a known kind: {asset!r}"
            )
        id_ = str(entry.get("id") or "")
        if not id_:
            raise SuppressionsError(f"{where}: 'id' is empty")
        reason = str(entry.get("reason") or "")
        if not reason:
            raise SuppressionsError(
                f"{where}: 'reason' is empty (every suppression must "
                "carry an explanation an analyst can read later)"
            )
        expires = _coerce_date(entry.get("expires"), where=where)
        out.append(Suppression(asset=asset, id=id_, reason=reason, expires=expires))
    return out


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def apply_suppressions(
    report: DriftReport,
    suppressions: Iterable[Suppression],
    *,
    today: _date | None = None,
) -> FilterResult:
    """Filter ``report`` by ``suppressions``.

    Returns a FilterResult with:
      * ``filtered`` — the report minus active (non-expired)
        suppressed entries.
      * ``suppressed`` — the entries that were removed.
      * ``expired`` — suppressions whose `expires` date has passed
        AND that matched a real changed entry (those entries
        remain in the filtered report but the caller can flag
        them with `[suppression-expired]`).
      * ``unused`` — suppressions that didn't match any changed
        entry (active OR expired); cleanup signal.
    """
    today = today or _date.today()
    suppressions = list(suppressions)

    # Index suppressions by (asset, id) for quick lookup.
    by_key: dict[tuple[str, str], Suppression] = {
        (s.asset, s.id): s for s in suppressions
    }
    matched_keys: set[tuple[str, str]] = set()

    suppressed: list[DriftEntry] = []
    expired: list[Suppression] = []
    new_entries: list[DriftEntry] = []
    for entry in report.entries:
        key = (entry.asset.value, entry.asset_id)
        s = by_key.get(key)
        if s is None:
            new_entries.append(entry)
            continue
        matched_keys.add(key)
        if s.expired(today):
            # Expired suppression — entry passes through but caller
            # can flag it via the `expired` list.
            expired.append(s)
            new_entries.append(entry)
            continue
        # Active suppression — entry is filtered out.
        suppressed.append(entry)

    unused = [
        s for s in suppressions
        if (s.asset, s.id) not in matched_keys
    ]

    filtered = DriftReport(entries=new_entries)
    return FilterResult(
        filtered=filtered, suppressed=suppressed,
        expired=expired, unused=unused,
    )


__all__ = [
    "SUPPRESSIONS_FILENAME",
    "SCHEMA_VERSION",
    "SuppressionsError",
    "Suppression",
    "FilterResult",
    "load_suppressions",
    "apply_suppressions",
]
