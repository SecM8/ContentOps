# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Read table names from the cached KQL schema manifests.

``tools/kql_strict/schemas.json`` (Sentinel) and ``schemas_defender.json``
(Defender XDR) are refreshed by ``kql-schemas-refresh.yml``. Shared by the
coverage-by-source rollup and the report's schema-drift enricher; kept in
``utils`` so neither package has to import the other.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_schema_tables(schemas_path: Path) -> set[str]:
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


__all__ = ["load_schema_tables"]
