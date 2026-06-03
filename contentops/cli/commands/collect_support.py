# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Helpers for ``collect`` (and ``clean``) used by the command module.

Extracted from ``collect.py`` so the command file reads as orchestration
("what happens") while this module holds the implementation details
("how it happens") — mirrors ``apply_support.py`` / ``lifecycle_support.py``.
"""

from __future__ import annotations

import concurrent.futures
import sys
from pathlib import Path

import click
import yaml

from contentops.cli.commands._shared import _resolve_single_workspace_or_exit
from contentops.core.asset import Asset
from contentops.core.drift import disambiguate_envelope_ids
from contentops.core.registry import default_registry


# ---------------------------------------------------------------------------
# Workspace resolution
# ---------------------------------------------------------------------------


def _resolve_collect_workspace_or_exit(
    role: str | None, workspace_name: str | None,
) -> None:
    """Resolve ``--role`` / ``--workspace`` for ``collect``.

    collect targets one Sentinel workspace per run; when the tenant has
    more than one and neither selector is passed it defaults to ``prod``
    (the overwhelmingly common cron case). Defender (tenant-level) is
    collected regardless. Delegates to the shared single-workspace
    resolver so the selection/exit semantics stay in one place.
    """
    _resolve_single_workspace_or_exit(
        role, workspace_name, default_role_for_multi="prod",
    )


# ---------------------------------------------------------------------------
# --since parsing
# ---------------------------------------------------------------------------


def _parse_since_or_exit(since_iso: str | None):
    """Parse ``--since`` (ISO 8601), exiting 2 on an invalid value.

    Returns a tz-aware datetime, or ``None`` when ``--since`` is unset.
    """
    if not since_iso:
        return None
    since_dt = _parse_since(since_iso)
    if since_dt is None:
        click.echo(
            f"error: --since={since_iso!r} is not a valid ISO 8601 timestamp",
            err=True,
        )
        sys.exit(2)
    return since_dt


# ---------------------------------------------------------------------------
# Parallel list_remote fan-out
# ---------------------------------------------------------------------------


def _list_remote_parallel(
    drift_handlers: list, *, workers: int,
) -> tuple[dict[str, list[dict]], dict[str, str]]:
    """Run ``list_remote()`` across handlers in a thread pool.

    Returns ``(handler_results, failed_kinds)``: a kind -> items map and a
    kind -> error-string map for handlers whose ``list_remote`` raised
    (those land in ``handler_results`` as an empty list and emit a warning).
    """
    handler_results: dict[str, list[dict]] = {}
    failed_kinds: dict[str, str] = {}

    def _list_one(handler) -> tuple[str, list[dict] | Exception]:
        try:
            return handler.asset.value, handler.list_remote()
        except Exception as exc:  # noqa: BLE001 — surfaced below
            return handler.asset.value, exc

    workers = max(1, workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for asset_value, result in pool.map(_list_one, drift_handlers):
            if isinstance(result, Exception):
                click.echo(
                    f"  [warn] list_remote failed for {asset_value}: {result}",
                    err=True,
                )
                handler_results[asset_value] = []
                failed_kinds[asset_value] = str(result)
            else:
                handler_results[asset_value] = result
    return handler_results, failed_kinds


# ---------------------------------------------------------------------------
# Drift classification
# ---------------------------------------------------------------------------


def _classify_collected_drift(
    drift_handlers: list,
    handler_results: dict[str, list[dict]],
    detections_path: Path,
    *,
    since_dt=None,
):
    """Classify collected remote items into a ``DriftReport``.

    For each handler: index local YAML, convert remote items to envelopes
    (applying the ``--since`` timestamp filter), disambiguate ids, then
    bucket each into new / changed / in-sync.

    NOTE: matches local envelopes by the disambiguated ``asset_id`` ONLY —
    it does not consult ``remote.name`` / arm_name the way
    :func:`contentops.core.drift.detect_drift` does. On the documented
    slug-vs-GUID divergence this can re-flag an item as NEW that ``drift``
    calls in-sync. This is a faithful move of the pre-refactor behaviour;
    unifying the two matching paths is a deliberate follow-up (see the
    refactor plan / ``contentops.core.drift``).
    """
    from contentops.core.drift import (
        DriftEntry, DriftReport, _local_index, _payloads_match,
    )

    report = DriftReport()
    try:
        for handler in drift_handlers:
            asset_value = handler.asset.value
            local = _local_index(detections_path, handler.asset)
            envelopes: list[dict] = []
            for remote in handler_results.get(asset_value, []):
                if since_dt is not None:
                    ts = _remote_timestamp(remote)
                    if ts is not None and ts < since_dt:
                        continue
                env = handler.to_envelope(remote)
                if env is None:
                    continue
                envelopes.append(env)
            envelopes = disambiguate_envelope_ids(envelopes)
            for envelope in envelopes:
                asset_id = envelope.get("id")
                if not asset_id:
                    continue
                new_payload = envelope.get("payload", {})
                if asset_id not in local:
                    report.entries.append(DriftEntry(
                        asset=handler.asset, asset_id=asset_id, kind="new",
                        envelope=envelope,
                    ))
                    continue
                local_path, local_payload = local[asset_id]
                if _payloads_match(local_payload, new_payload):
                    report.entries.append(DriftEntry(
                        asset=handler.asset, asset_id=asset_id, kind="in-sync",
                        local_path=local_path,
                    ))
                else:
                    report.entries.append(DriftEntry(
                        asset=handler.asset, asset_id=asset_id, kind="changed",
                        envelope=envelope, local_path=local_path,
                    ))
    finally:
        default_registry.close_all()
    return report


def _summarize_collect(
    drift_handlers: list, report, failed_kinds: dict[str, str],
) -> dict[str, dict[str, int]]:
    """Build the per-asset new/changed/in-sync/failed bucket table.

    Seeds a zeroed bucket for every handler that ran (so failed and
    quiet-but-empty kinds still show), then tallies report entries and
    failed kinds.
    """
    by_asset: dict[str, dict[str, int]] = {}
    for handler in drift_handlers:
        by_asset.setdefault(
            handler.asset.value,
            {"new": 0, "changed": 0, "in-sync": 0, "failed": 0},
        )
    for entry in report.entries:
        bucket = by_asset.setdefault(
            entry.asset.value,
            {"new": 0, "changed": 0, "in-sync": 0, "failed": 0},
        )
        bucket[entry.kind] = bucket.get(entry.kind, 0) + 1
    for kind in failed_kinds:
        bucket = by_asset.setdefault(
            kind, {"new": 0, "changed": 0, "in-sync": 0, "failed": 0},
        )
        bucket["failed"] = bucket.get("failed", 0) + 1
    return by_asset


# ---------------------------------------------------------------------------
# --enrich (bulk-import day-1 placeholders)
# ---------------------------------------------------------------------------


_ENRICH_TODO_METADATA = {
    # Required RuleMetadata fields, populated with values that pass
    # Pydantic validation but are obviously TODOs. The operator walks
    # these down per-rule during enrichment; META rule warnings surface
    # the remaining gaps.
    "owner": "unknown@example.invalid",
    "runbookUrl": "https://example.invalid/runbook-todo",
    "severity": "low",
    "tactics": ["Execution"],
    "techniques": [],
    "expectedAlertsPerDay": 0,
    "fpHandling": "TODO: describe FP handling and tuning approach.",
}


def _enrich_drift_entries(report) -> int:
    """Apply --enrich placeholders to every new + changed entry.

    Mutates each entry's ``envelope`` dict in place:

    * If ``status == "production"``, demote to ``"test"`` so the
      L4 production-status META escalation does NOT fire on the
      freshly-collected rule. The forker promotes back to production
      rule-by-rule after enrichment.
    * If the metadata block is missing or carries only ``arm_name``,
      merge in the placeholder fields from ``_ENRICH_TODO_METADATA``.
      Existing arm_name (the load-bearing ARM resource name for
      apply / prune idempotency) is preserved. Envelopes that already
      have a full metadata block are left alone.

    Returns the number of envelopes touched (for the CLI summary).
    """
    touched = 0
    for entry in report.new + report.changed:
        env = entry.envelope
        if not isinstance(env, dict):
            continue
        changed = False
        if env.get("status") == "production":
            env["status"] = "test"
            changed = True
        existing = env.get("metadata") if isinstance(env.get("metadata"), dict) else None
        # Determine whether the existing metadata is "minimal" (only
        # arm_name) and therefore worth enriching. A full metadata block
        # (operator-authored) is left alone.
        is_minimal = (
            existing is None
            or set(existing.keys()) <= {"arm_name"}
        )
        if is_minimal:
            arm_name = (existing or {}).get("arm_name")
            new_meta = dict(_ENRICH_TODO_METADATA)
            if arm_name:
                new_meta["arm_name"] = arm_name
            env["metadata"] = new_meta
            changed = True
        if changed:
            touched += 1
    return touched


# ---------------------------------------------------------------------------
# --rename-existing (slug-normalise filenames)
# ---------------------------------------------------------------------------


def _rename_existing_to_slug(detections_root: Path) -> list[tuple[Path, Path]]:
    """Rename envelope files whose name doesn't match displayname_slug(displayName).

    Walks ``detections_root/<asset_kind>/`` and, for every YAML file
    whose envelope payload carries a usable displayName / title, moves
    it onto ``<displayname_slug>.yml`` if that differs from the current
    filename. Idempotent — files already on their slug name are
    untouched. Files whose displayName slugs to nothing usable are
    skipped (no harm done).

    Returns the list of (old_path, new_path) tuples for caller logging.
    """
    from contentops.utils.slug import displayname_slug

    moves: list[tuple[Path, Path]] = []
    if not detections_root.is_dir():
        return moves

    for kind_dir in sorted(detections_root.iterdir()):
        if not kind_dir.is_dir():
            continue
        for yml in sorted(kind_dir.glob("*.yml")):
            try:
                raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(raw, dict):
                continue
            payload = raw.get("payload") or {}
            display_name = ""
            if isinstance(payload, dict):
                display_name = (
                    payload.get("displayName")
                    or payload.get("title")
                    or ""
                )
            if not display_name:
                continue
            existing_id = raw.get("id") or ""
            target_slug = displayname_slug(display_name, fallback_id=existing_id)
            if not target_slug:
                continue
            if yml.stem == target_slug:
                continue
            new_path = yml.with_name(f"{target_slug}.yml")
            if new_path.exists():
                continue
            yml.rename(new_path)
            moves.append((yml, new_path))
            click.echo(f"  renamed: {yml.name} -> {new_path.name}")
    return moves


# ---------------------------------------------------------------------------
# --since timestamp helpers
# ---------------------------------------------------------------------------


_TIMESTAMP_FIELDS = (
    "lastUpdatedTimeUtc", "lastModifiedTimeUtc", "lastModifiedUtc",
    "lastUpdatedDateTime", "lastUpdated", "createdDateTime",
    "createdTimeUtc", "ingestedDateTime",
)


def _parse_since(value: str):
    """Parse an ISO 8601 timestamp, returning a tz-aware datetime or None."""
    from datetime import datetime as _dt
    try:
        # Python's fromisoformat handles "2026-05-06T00:00:00+00:00" and
        # the `Z` suffix as of 3.11+. Defensive normalise of trailing `Z`.
        normalised = value.replace("Z", "+00:00") if value.endswith("Z") else value
        return _dt.fromisoformat(normalised)
    except Exception:
        return None


def _remote_timestamp(remote: dict):
    """Best-effort timestamp extractor for --since filtering."""
    from datetime import datetime as _dt

    def _coerce(text: str | None):
        if not text:
            return None
        try:
            normalised = text.replace("Z", "+00:00") if text.endswith("Z") else text
            return _dt.fromisoformat(normalised)
        except Exception:
            return None

    if not isinstance(remote, dict):
        return None
    properties = remote.get("properties") or {}
    for source in (properties, remote):
        if not isinstance(source, dict):
            continue
        for field in _TIMESTAMP_FIELDS:
            value = source.get(field)
            if isinstance(value, str):
                ts = _coerce(value)
                if ts is not None:
                    return ts
    return None


# ---------------------------------------------------------------------------
# `clean` / `collect --clear` — shared disk-cleanup helper
# ---------------------------------------------------------------------------


def _clean_local_detections(
    detections_path: Path,
    *,
    asset_kinds: set[Asset] | None = None,
) -> tuple[int, list[str]]:
    """Delete local detection YAMLs. Returns (files_deleted, dirs_removed).

    Removes every YAML under ``detections/<asset_kind>/`` for the
    given asset kinds (or every asset-kind directory present if
    ``asset_kinds`` is None). Preserves ``detections/templates/`` and
    ``detections/samples/`` always — those carry stable scaffolding.

    Shared between ``contentops clean`` and ``contentops collect --clear``.
    """
    files_deleted = 0
    dirs_removed: list[str] = []

    skip_dirs = {"templates", "samples"}
    candidates: list[Path] = []
    for entry in detections_path.iterdir():
        if not entry.is_dir() or entry.name in skip_dirs:
            continue
        try:
            kind = Asset(entry.name)
        except ValueError:
            continue  # unknown directory; leave it
        if asset_kinds is None or kind in asset_kinds:
            candidates.append(entry)

    for d in candidates:
        for f in list(d.glob("*.yml")) + list(d.glob("*.yaml")):
            f.unlink()
            files_deleted += 1
        # Remove the now-empty directory so collect can recreate it.
        try:
            d.rmdir()
            dirs_removed.append(d.name)
        except OSError:
            pass  # not empty (unexpected non-YAML files), leave it

    return files_deleted, dirs_removed
