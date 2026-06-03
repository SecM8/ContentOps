# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Detection ownership mapping.

Provides a YAML-based ownership file (``config/owners.yml``) that maps
detection IDs to owner email addresses. The file is committed to the
repo so ownership is version-controlled. New detections are auto-
appended by ``contentops portfolio --sync-owners``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from contentops.core.handler import LoadedAsset

logger = logging.getLogger(__name__)

# Repo-root-anchored (mirrors contentops.config.CONFIG_DIR) so ownership
# resolves config/owners.yml regardless of the process CWD — the previous
# CWD-relative path silently returned an empty owner map when `contentops
# alerts report` ran from a subdirectory.
DEFAULT_OWNERS_PATH = Path(__file__).resolve().parent.parent / "config" / "owners.yml"


def load_owner_map(path: Path | None = None) -> dict[str, str]:
    """Load detection_id → owner email mapping from owners.yml."""
    p = path or DEFAULT_OWNERS_PATH
    if not p.is_file():
        return {}
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        logger.debug("failed to load owners: %s", exc)
        return {}
    if not isinstance(raw, dict):
        return {}
    owners = raw.get("owners")
    if not isinstance(owners, dict):
        return {}
    return {str(k): str(v) for k, v in owners.items()}


def sync_owner_file(
    path: Path | None,
    detections: list[LoadedAsset],
) -> int:
    """Append missing detections to the owners file with 'unassigned'.

    Returns count of newly added detections.
    """
    p = path or DEFAULT_OWNERS_PATH
    existing = load_owner_map(p)
    new_count = 0

    for d in sorted(detections, key=lambda x: x.envelope.id):
        det_id = d.envelope.id
        if det_id not in existing:
            existing[det_id] = "unassigned"
            new_count += 1

    if new_count > 0 or not p.is_file():
        p.parent.mkdir(parents=True, exist_ok=True)
        content = yaml.dump(
            {"owners": existing},
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )
        p.write_text(content, encoding="utf-8")

    return new_count


def resolve_owner(
    detection_id: str,
    owner_map: dict[str, str] | None,
    metadata_owner: str | None,
) -> str:
    """Resolve the owner for a detection. Owner map wins."""
    if owner_map:
        mapped = owner_map.get(detection_id)
        if mapped and mapped != "unassigned":
            return mapped
    if metadata_owner:
        return metadata_owner
    return "unassigned"


__all__ = [
    "DEFAULT_OWNERS_PATH",
    "load_owner_map",
    "resolve_owner",
    "sync_owner_file",
]
