# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-env state file: which assets the pipeline last applied.

DESIGN §13. ``apply`` records each applied asset and the commit it
came from; ``state adopt`` records rules already in sync with the
tenant. The file is read by the ``state`` commands, the status pages,
``explain`` and the undeployed-rules report. No deploy, drift or prune
decision reads it: those compare the repository with the tenant.

Storage: a JSON file, ``state/<env>/state.json`` (``state/state.json``
without an env). In CI it travels on the branch ``state/<env>``
(see ``contentops.state_sync``): each push replaces that branch's single
commit, so the branch keeps no history. The pipeline never *requires*
state to function, and state can be rebuilt with ``state adopt``.

An unreadable file (invalid JSON, or JSON of the wrong shape) is
reported and read as empty; the next save keeps a copy of it next to
the new file (``state.json.corrupt-<time>``) instead of replacing it
silently.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, asdict, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"

logger = logging.getLogger(__name__)


class UnreadableState(ValueError):
    """The state file exists but is not a state document."""


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


_ENTRY_FIELDS = frozenset(f.name for f in fields(AssetStateEntry))


def _read_state(path: Path, env: str | None) -> EnvState:
    """Parse the state file at ``path``; raise ``UnreadableState`` if it is not one."""
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise UnreadableState(f"not valid JSON ({exc.__class__.__name__})") from exc
    if not isinstance(raw, dict):
        raise UnreadableState("the document is not a JSON object")
    # A missing value or null means "none"; anything else must be an object.
    managed_raw = raw.get("managed_assets")
    if managed_raw is None:
        managed_raw = {}
    if not isinstance(managed_raw, dict):
        raise UnreadableState("managed_assets is not an object")
    managed: dict[str, dict[str, AssetStateEntry]] = {}
    for asset_kind, entries in managed_raw.items():
        if entries is None:
            entries = {}
        if not isinstance(entries, dict):
            raise UnreadableState(f"managed_assets.{asset_kind} is not an object")
        bucket: dict[str, AssetStateEntry] = {}
        for envelope_id, entry in entries.items():
            if not isinstance(entry, dict):
                raise UnreadableState(f"managed_assets.{asset_kind}.{envelope_id} is not an object")
            # Unknown fields are skipped: a newer tool may have added one.
            bucket[envelope_id] = AssetStateEntry(
                **{k: v for k, v in entry.items() if k in _ENTRY_FIELDS}
            )
        managed[asset_kind] = bucket
    return EnvState(
        schema_version=raw.get("schema_version", SCHEMA_VERSION),
        env=raw.get("env", env or ""),
        last_apply_sha=raw.get("last_apply_sha", ""),
        last_apply_at=raw.get("last_apply_at", ""),
        managed_assets=managed,
    )


def load_state(env: str | None = None, *, root: Path | None = None) -> EnvState:
    """Load state for ``env``. Returns an empty EnvState when absent.

    An unreadable file never crashes the pipeline: it is reported and read
    as empty, and ``save_state`` keeps a copy of it before writing.
    """
    path = state_path(env, root=root)
    if not path.is_file():
        return EnvState(env=env or "")
    try:
        return _read_state(path, env)
    except UnreadableState as exc:
        logger.warning(
            "state file %s cannot be read (%s); reading it as empty. The next "
            "save keeps a copy next to it. Rebuild the managed inventory with "
            "`contentops state adopt` (state-adopt.yml).",
            path, exc,
        )
        return EnvState(env=env or "")


def _keep_unreadable_copy(path: Path) -> None:
    """Copy an existing, unreadable state file aside before it is replaced."""
    if not path.is_file():
        return
    try:
        _read_state(path, None)
        return
    except UnreadableState:
        pass
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    copy = path.with_name(f"{path.name}.corrupt-{stamp}")
    n = 1
    while copy.exists():
        n += 1
        copy = path.with_name(f"{path.name}.corrupt-{stamp}-{n}")
    shutil.copy2(path, copy)
    logger.warning("kept the unreadable state file as %s before writing a new one", copy)


def save_state(state: EnvState, *, root: Path | None = None) -> Path:
    """Write the state file. Creates parent dir if missing.

    An existing file that cannot be read is copied aside first. The write
    goes through a temporary file of its own, then an atomic rename.
    """
    path = state_path(state.env or None, root=root)
    path.parent.mkdir(parents=True, exist_ok=True)
    _keep_unreadable_copy(path)
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
    # A temporary file of this writer's own: a shared name let two writers
    # rename each other's half-written file into place.
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True))
        # mkstemp creates the file owner-only; keep the mode a plain write gave.
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
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
