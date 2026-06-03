# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Manifest load / diff / write — pure JSON I/O, no network."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ManifestDiff:
    """Result of comparing two upstream catalog snapshots.

    ``added`` is entries present in ``new`` but not in ``old``.
    ``removed`` is the inverse.
    ``changed`` is entries whose key exists in both but whose normalised
    record differs (compared field-by-field on the stable dict shape the
    fetcher returns).
    """
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[tuple[dict[str, Any], dict[str, Any]]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)


def load_manifest(path: Path) -> list[dict[str, Any]]:
    """Read a manifest file; return its ``entries`` list.

    Missing or empty files return an empty list so the first run treats
    the entire upstream catalog as ``added``. Malformed JSON raises so
    we never silently lose a baseline.
    """
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return []
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON is not an object")
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'entries' is not a list")
    return entries


def write_manifest(path: Path, entries: list[dict[str, Any]]) -> None:
    """Serialise entries to ``path`` with stable ordering + trailing newline.

    Entries are sorted by their ``name`` field so reviewers see clean
    diffs on every run. Top-level wrapper carries ``schema_version`` so
    future field additions don't break stale CI.
    """
    sorted_entries = sorted(entries, key=lambda e: str(e.get("name") or ""))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "entries": sorted_entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def compute_diff(
    old: list[dict[str, Any]],
    new: list[dict[str, Any]],
) -> ManifestDiff:
    """Return added / removed / changed between two entry lists.

    Keyed on the ``name`` field (the ARM resource name, which is stable
    across versions). ``changed`` carries ``(old_entry, new_entry)``
    pairs so the markdown renderer can show the version delta.
    """
    by_name_old = {str(e.get("name") or ""): e for e in old}
    by_name_new = {str(e.get("name") or ""): e for e in new}

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[tuple[dict[str, Any], dict[str, Any]]] = []

    for name, entry in by_name_new.items():
        if name not in by_name_old:
            added.append(entry)
            continue
        prior = by_name_old[name]
        if prior != entry:
            changed.append((prior, entry))

    for name, entry in by_name_old.items():
        if name not in by_name_new:
            removed.append(entry)

    added.sort(key=lambda e: str(e.get("name") or ""))
    removed.sort(key=lambda e: str(e.get("name") or ""))
    changed.sort(key=lambda pair: str(pair[1].get("name") or ""))
    return ManifestDiff(added=added, removed=removed, changed=changed)


__all__ = [
    "SCHEMA_VERSION",
    "ManifestDiff",
    "compute_diff",
    "load_manifest",
    "write_manifest",
]
