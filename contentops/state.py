# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-env state file for ``apply`` / ``prune`` / ``drift``.

DESIGN §13. The state file records which assets the pipeline has
last successfully applied so that:

* ``drift`` can distinguish "remote-only & never managed" (leave alone)
  from "remote-only & previously managed" (orphan — flag for prune).
* ``prune`` can default to deleting only orphans that the state file
  says we owned, keeping ``--include-unmanaged`` for the wider sweep.
* ``apply`` knows the last successful commit per env, useful for
  ``--changed-since`` defaulting and audit traceability.

Storage: a JSON file. Locally lives at ``state/state.json``;
in CI it's checked out from an orphan branch ``state/<env>`` so
the history of the state itself is auditable but it doesn't
pollute main's commit log. Absent state file = git-history
fallback; the pipeline never *requires* state to function.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = "1.0"


@dataclass
class AssetStateEntry:
    """One asset's last-applied record."""

    remote_id: str = ""
    last_applied_at: str = ""
    last_applied_sha: str = ""
    status: str = "success"


@dataclass
class EnvState:
    """Per-env state.

    ``managed_assets`` maps ``asset_kind -> envelope_id -> AssetStateEntry``.
    """

    schema_version: str = SCHEMA_VERSION
    env: str = ""
    last_apply_sha: str = ""
    last_apply_at: str = ""
    managed_assets: dict[str, dict[str, AssetStateEntry]] = field(default_factory=dict)

    def is_managed(self, asset_kind: str, envelope_id: str) -> bool:
        return envelope_id in (self.managed_assets.get(asset_kind) or {})

    def remember(
        self,
        asset_kind: str,
        envelope_id: str,
        *,
        remote_id: str = "",
        sha: str = "",
        status: str = "success",
    ) -> None:
        bucket = self.managed_assets.setdefault(asset_kind, {})
        bucket[envelope_id] = AssetStateEntry(
            remote_id=remote_id,
            last_applied_at=_now_iso(),
            last_applied_sha=sha,
            status=status,
        )

    def forget(self, asset_kind: str, envelope_id: str) -> None:
        bucket = self.managed_assets.get(asset_kind)
        if bucket is not None:
            bucket.pop(envelope_id, None)
            if not bucket:
                self.managed_assets.pop(asset_kind, None)

    def asset_count(self) -> int:
        return sum(len(b) for b in self.managed_assets.values())


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def state_path(env: str | None = None, *, root: Path | None = None) -> Path:
    """Resolve the state file path.

    ``env``-specific suffix is appended only when env is set. Local
    development uses ``state/state.json``; multi-env workflows can
    point at ``state/<env>/state.json`` via this helper.
    """
    base = (root or Path.cwd()) / "state"
    if env:
        return base / env / "state.json"
    return base / "state.json"


def load_state(env: str | None = None, *, root: Path | None = None) -> EnvState:
    """Load state for ``env``. Returns an empty EnvState when absent."""
    path = state_path(env, root=root)
    if not path.is_file():
        return EnvState(env=env or "")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        # Corrupt state — never crash the pipeline; treat as absent.
        return EnvState(env=env or "")
    managed_raw = raw.get("managed_assets") or {}
    managed: dict[str, dict[str, AssetStateEntry]] = {}
    for asset_kind, entries in managed_raw.items():
        managed[asset_kind] = {
            envelope_id: AssetStateEntry(**entry)
            for envelope_id, entry in (entries or {}).items()
            if isinstance(entry, dict)
        }
    return EnvState(
        schema_version=raw.get("schema_version", SCHEMA_VERSION),
        env=raw.get("env", env or ""),
        last_apply_sha=raw.get("last_apply_sha", ""),
        last_apply_at=raw.get("last_apply_at", ""),
        managed_assets=managed,
    )


def save_state(state: EnvState, *, root: Path | None = None) -> Path:
    """Write the state file. Creates parent dir if missing."""
    path = state_path(state.env or None, root=root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": state.schema_version,
        "env": state.env,
        "last_apply_sha": state.last_apply_sha,
        "last_apply_at": state.last_apply_at,
        "managed_assets": {
            asset_kind: {
                envelope_id: asdict(entry)
                for envelope_id, entry in entries.items()
            }
            for asset_kind, entries in state.managed_assets.items()
        },
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    import os as _os
    _os.replace(str(tmp), str(path))
    return path


def merge_apply_results(
    state: EnvState,
    results: Iterable[tuple[str, str, str, str]],
    *,
    sha: str = "",
) -> EnvState:
    """Merge a batch of apply results into the state file.

    ``results`` is an iterable of ``(asset_kind, envelope_id,
    remote_id, status)`` tuples. ``status`` is one of ``success``,
    ``failed``, ``skipped``. Skipped entries are not recorded.
    """
    if sha:
        state.last_apply_sha = sha
    state.last_apply_at = _now_iso()
    for asset_kind, envelope_id, remote_id, status in results:
        if status == "skipped":
            continue
        state.remember(
            asset_kind, envelope_id, remote_id=remote_id, sha=sha, status=status,
        )
    return state


def classify_remote(
    state: EnvState,
    asset_kind: str,
    envelope_id: str,
    *,
    in_local: bool,
) -> str:
    """Classify a remote item against state + local presence.

    Returns one of:
      * ``in-sync``    — local + in state.
      * ``new-local``  — local exists but state doesn't (first apply).
      * ``orphan``     — state has it but local doesn't (delete candidate).
      * ``unmanaged``  — state doesn't have it AND local doesn't (third
                          party feed; leave alone).
    """
    in_state = state.is_managed(asset_kind, envelope_id)
    if in_local and in_state:
        return "in-sync"
    if in_local and not in_state:
        return "new-local"
    if not in_local and in_state:
        return "orphan"
    return "unmanaged"


__all__ = [
    "SCHEMA_VERSION",
    "AssetStateEntry",
    "EnvState",
    "state_path",
    "load_state",
    "save_state",
    "merge_apply_results",
    "classify_remote",
]
