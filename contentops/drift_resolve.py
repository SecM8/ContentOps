# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-rule drift reconciliation — `contentops drift-resolve <id>`.

The default `contentops drift --write` is all-or-nothing: it
overwrites every changed envelope with the remote's version. This
module adds per-rule resolution so a Detection Engineer can keep
some rules' git version (typical case) and accept the remote for
others (intentional portal tunes), one at a time.

Strategies:

- ``git`` — local YAML wins. No file mutation; the next `pipeline
  apply` will push git's version to the tenant. Useful when the
  drift PR caught a portal-side change you want to revert.
- ``remote`` — tenant version wins. Writes the remote envelope to
  the local YAML path. Equivalent to `contentops drift --write`
  scoped to one rule.
- ``merge`` — was reserved for an editor-driven 3-way diff. Not
  implemented; ``resolve_merge`` raises ``NotImplementedStrategy``
  by design. Operators should pick ``git`` or ``remote`` per rule;
  if a real 3-way-merge use case ever surfaces, the design needs
  editor-integration + conflict markers + validation round-trip.

Pure functions; CLI command is in commands.py.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from contentops.core.drift import DriftCapable, DriftEntry
from contentops.core.drift import _local_index  # type: ignore[attr-defined]
from contentops.utils.yaml_io import dump_envelope_yaml


class DriftResolveError(RuntimeError):
    """Raised when resolution can't proceed (no remote, bad YAML, etc.)."""


class NotImplementedStrategy(DriftResolveError):
    """Raised when the operator requested 'merge' (deferred)."""


@dataclass
class ResolveOutcome:
    asset_id: str
    strategy: str
    action: str         # "no-change-needed" | "wrote" | "would-write"
    path: Path | None = None  # path written (or would-write) or None
    detail: str = ""


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------


def resolve_git(asset_id: str) -> ResolveOutcome:
    """`git` strategy: local YAML wins. No mutation; documentation only."""
    return ResolveOutcome(
        asset_id=asset_id, strategy="git",
        action="no-change-needed",
        detail=(
            "git is the source of truth for this rule; nothing written. "
            "Run `contentops apply --asset <kind> --changed-since main` "
            "to push git's version back to the tenant."
        ),
    )


def resolve_remote(
    *, entry: DriftEntry, dry_run: bool = False,
) -> ResolveOutcome:
    """`remote` strategy: write the remote envelope to disk."""
    if entry.envelope is None:
        raise DriftResolveError(
            f"no remote envelope captured for {entry.asset_id} "
            "(drift entry kind must be 'new' or 'changed')"
        )
    target = entry.local_path
    if target is None:
        # New entry — pick the canonical path.
        target = (
            Path("detections") / entry.asset.value
            / f"{entry.asset_id}.yml"
        )
    if dry_run:
        return ResolveOutcome(
            asset_id=entry.asset_id, strategy="remote",
            action="would-write", path=target,
            detail=f"would overwrite {target} with remote payload",
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dump_envelope_yaml(entry.envelope), encoding="utf-8")
    return ResolveOutcome(
        asset_id=entry.asset_id, strategy="remote",
        action="wrote", path=target,
        detail=f"wrote remote payload to {target}",
    )


def resolve_merge(*, entry: DriftEntry) -> ResolveOutcome:
    """`merge` strategy: open $EDITOR with the remote contents.

    Deferred by design -- a real 3-way merge needs editor
    integration, conflict markers, and a validation round-trip;
    operators should pick ``git`` or ``remote`` per rule instead.
    Raises ``NotImplementedStrategy`` so the CLI surfaces a clear
    message rather than half-implementing. Revisit only if a
    concrete operational use case for merge surfaces.
    """
    raise NotImplementedStrategy(
        "merge strategy is not implemented by design; "
        "use --strategy git or --strategy remote, or hand-edit the "
        "YAML directly."
    )


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def find_entry_for(
    handlers: list[DriftCapable],
    detections_root: Path,
    asset_id: str,
) -> DriftEntry | None:
    """Walk the live tenant for ``asset_id`` and return the matching DriftEntry.

    Imports from contentops.core.drift to avoid duplicating the
    new/changed/in-sync classification logic. Returns None if the
    rule isn't found anywhere (neither remote nor local).
    """
    from contentops.core.drift import (
        _payloads_match, disambiguate_envelope_ids,
    )
    for handler in handlers:
        local = _local_index(detections_root, handler.asset)
        try:
            remote_items = handler.list_remote()
        except Exception:
            continue
        envelopes: list[dict] = []
        for remote in remote_items:
            env = handler.to_envelope(remote)
            if env is not None:
                envelopes.append(env)
        envelopes = disambiguate_envelope_ids(envelopes)
        for envelope in envelopes:
            if envelope.get("id") != asset_id:
                continue
            new_payload = envelope.get("payload", {})
            if asset_id not in local:
                return DriftEntry(
                    asset=handler.asset, asset_id=asset_id, kind="new",
                    envelope=envelope,
                )
            local_path, local_payload = local[asset_id]
            if _payloads_match(local_payload, new_payload):
                return DriftEntry(
                    asset=handler.asset, asset_id=asset_id, kind="in-sync",
                    local_path=local_path,
                )
            return DriftEntry(
                asset=handler.asset, asset_id=asset_id, kind="changed",
                envelope=envelope, local_path=local_path,
            )
    return None


__all__ = [
    "DriftResolveError",
    "NotImplementedStrategy",
    "ResolveOutcome",
    "resolve_git",
    "resolve_remote",
    "resolve_merge",
    "find_entry_for",
]
