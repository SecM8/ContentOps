# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops prune`` — delete remote assets that have no local YAML."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from contentops.audit import write_records
from contentops.cli.handler_factories import register_default_handlers
from contentops.cli.commands._shared import (
    _apply_log_levels,
    _collect_drift_handlers,
    _is_locked,
    _print_run_banner,
    _resolve_single_workspace_or_exit,
    _skip_if_integration_role_absent,
)
from contentops.cli.commands.apply_support import _build_audit_record
from contentops.core.asset import Asset
from contentops.core.discovery import iter_loaded_assets
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


@click.command("prune")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict prune to one asset kind.",
)
@click.option(
    "--dry-run/--no-dry-run", default=True,
    help="Default true. Set --no-dry-run plus --yes to actually delete.",
)
@click.option(
    "--yes", is_flag=True, default=False,
    help="Required to actually delete (alongside --no-dry-run).",
)
@click.option(
    "--max-deletes", type=int, default=25,
    help="Fail-closed if more than this many orphans are detected. Default 25.",
)
@click.option(
    "--include-locked", is_flag=True, default=False,
    help="By default locked assets (localCustomization=true) are NEVER pruned. Pass to override.",
)
@click.option(
    "--json", "as_json", is_flag=True, default=False,
    help="Emit a structured JSON summary on stdout instead of the human-readable table.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role. Mutex with --workspace. "
         "Multi-workspace tenants must pass one of --role / --workspace; "
         "prune operates on one workspace per run.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName``. "
         "Mutex with --role.",
)
def prune_cmd(
    detections_path: Path,
    asset: str | None,
    dry_run: bool,
    yes: bool,
    max_deletes: int,
    include_locked: bool,
    as_json: bool,
    role: str | None,
    workspace_name: str | None,
) -> None:
    """Delete remote assets that are not in local YAML.

    Each registered drift-capable handler is asked for its remote
    inventory; anything in the remote that doesn't have a matching
    local envelope id is flagged as an orphan and (with --no-dry-run
    --yes) deleted via the handler's ``delete()`` method.

    Safety rails:
      * --dry-run defaults to true.
      * --yes is required even with --no-dry-run.
      * --max-deletes caps the orphan list (fail-closed).
      * --include-locked is required to touch any envelope on disk
        carrying ``localCustomization: true``.
      * Read-only / collect-only handlers' delete() raises
        NotSupportedError; the prune loop catches that and emits
        SKIP, never failing the batch.
      * Applies across the six-kind taxonomy: sentinel_analytic,
        sentinel_hunting, sentinel_watchlist, sentinel_parser,
        sentinel_data_connector, defender_custom_detection.
      * Every actual deletion writes an AuditRecord onto the same
        JSONL chain ``apply`` uses.
    """
    import json as _json
    from contentops.core.drift import DriftCapable, _local_index
    from contentops.core.result import NotSupportedError

    _apply_log_levels()
    # Resolve --role / --workspace before handler registration so the
    # Sentinel ARM provider factories in contentops/cli/handler_factories.py
    # target the right LA workspace.
    if _skip_if_integration_role_absent(role, workspace_name, command="prune"):
        return
    _resolve_single_workspace_or_exit(role, workspace_name)

    # Per-workspace safeguard check (tenant.yml `purgeAllowed` +
    # `maxDelete`). Loaded BEFORE handler registration so a denied
    # workspace short-circuits without opening any Azure connections.
    # Failures are loud (stderr + exit 2) — the safeguard is the
    # fourth physical brake on destructive ops and refusing must look
    # different from a "nothing to prune" success.
    #
    # Dry-run bypasses the purgeAllowed gate so operators can preview
    # "what would prune do" against a locked workspace — matches the
    # equivalent dry-run bypass in apply.py and matches operator
    # expectations (preview is non-destructive). The maxDelete clamp
    # stays in effect either way so a dry-run preview still reflects
    # the cap the eventual real run would hit.
    safeguards = _resolve_safeguards_for_target(asset)
    will_actually_delete = (not dry_run) and yes
    effective_max_deletes = max_deletes
    for source_label, sg in safeguards:
        if will_actually_delete and not sg.purgeAllowed:
            click.echo(
                f"error: tenant.yml safeguard refuses prune for {source_label}: "
                f"purgeAllowed={sg.purgeAllowed!r}. Edit the workspace's "
                f"`purgeAllowed: true` in config/tenant.yml (or the "
                f"TENANT_CONFIG_YAML secret in CI) to enable. Re-run with "
                f"--dry-run to preview without the gate.",
                err=True,
            )
            sys.exit(2)
        effective_max_deletes = min(effective_max_deletes, sg.maxDelete)
    if effective_max_deletes != max_deletes and not as_json:
        click.echo(
            f"info: --max-deletes clamped {max_deletes} -> "
            f"{effective_max_deletes} by tenant.yml safeguards."
        )
    max_deletes = effective_max_deletes

    register_default_handlers()
    if not as_json:
        _print_run_banner(
            "prune",
            detections_path,
            extra={
                "dry_run": str(dry_run).lower(),
                "yes": str(yes).lower(),
                "max_deletes": str(max_deletes),
            },
        )
    target_asset = Asset(asset) if asset else None

    # Build the locked-set from disk so locked envelopes can never be
    # pruned even by a misuse of --include-locked.
    locked_ids: set[tuple[str, str]] = set()
    for la in iter_loaded_assets(detections_path):
        try:
            la_locked = _is_locked(la)
        except Exception:
            la_locked = False
        if la_locked:
            locked_ids.add((la.envelope.asset.value, la.envelope.id))

    drift_handlers = _collect_drift_handlers(target_asset)

    if not drift_handlers:
        click.echo("No drift-capable handlers registered.")
        return

    # Plan phase: walk every drift-capable handler, list_remote(),
    # compare envelope ids against local, collect orphans.
    orphans: list[dict] = []  # {asset, envelope_id, remote_id, path?}
    skipped_locked: list[dict] = []
    # Assets whose remote inventory could not be enumerated. Prune decides
    # what to DELETE by subtracting the local YAML set from the remote set,
    # so a failed listing is NOT "zero remote items" — it's an unknown. We
    # collect these and fail-closed below rather than silently under-report
    # orphans (or, in the fully-blind case, claim "nothing to prune").
    list_errors: list[dict] = []
    listed_ok = 0  # handlers that enumerated their remote without error
    try:
        for handler in drift_handlers:
            asset_value = handler.asset.value
            local = _local_index(detections_path, handler.asset)
            try:
                remote_items = handler.list_remote()
            except Exception as exc:
                click.echo(f"  [warn] list_remote failed for {asset_value}: {exc}", err=True)
                list_errors.append({"asset": asset_value, "error": str(exc)[:300]})
                continue
            listed_ok += 1
            for remote in remote_items:
                envelope = handler.to_envelope(remote)
                if envelope is None:
                    continue
                env_id = envelope.get("id")
                if not env_id:
                    continue
                remote_id = remote.get("name") or remote.get("id") or ""
                if not remote_id:
                    continue
                # Orphan = exists remote, no local YAML. Match on the
                # authoritative remote name FIRST (the local index
                # registers each envelope under its metadata.arm_name
                # when set) and fall back to the slug-based envelope
                # id for legacy envelopes that pre-date arm_name
                # capture. Without the arm_name match, prune
                # incorrectly flagged every legacy v1 rule as an
                # orphan whenever displayName slugs collided — the
                # ``--max-deletes=25`` fail-closed cap was the only
                # thing standing between that bug and unintended
                # production deletes.
                if str(remote_id) in local or env_id in local:
                    continue
                key = (asset_value, env_id)
                if key in locked_ids and not include_locked:
                    skipped_locked.append({
                        "asset": asset_value, "envelope_id": env_id,
                        "remote_id": remote_id,
                    })
                    continue
                orphans.append({
                    "asset": asset_value, "envelope_id": env_id,
                    "remote_id": remote_id,
                })
    finally:
        # Don't close the registry yet — we may still need it to delete.
        pass

    # Fail-closed ONLY when fully blind — every drift handler failed to list,
    # so prune has zero remote visibility and "0 orphans / nothing to prune"
    # would be the false-green this guard exists to prevent (e.g. tenant
    # config unreadable -> every list_remote() raised). A PARTIAL failure
    # (some kinds listed, one hiccuped) is NOT blind: prune only ever deletes
    # orphans of kinds it fully listed, so it proceeds and just reports the
    # un-listable kinds. Without this distinction a single Defender / transient
    # listing error would block an otherwise-fine Sentinel prune. Applies to
    # dry-run too — a fully-blind preview is worse than none.
    if list_errors and listed_ok == 0:
        failed = ", ".join(e["asset"] for e in list_errors)
        click.echo(
            f"\nerror: could not list the remote inventory for ANY asset kind "
            f"({failed}). Refusing to prune blind — fix the listing error(s) "
            "above (often an unreadable / auth-failed tenant config) and re-run.",
            err=True,
        )
        if as_json:
            click.echo(_json.dumps({
                "dry_run": dry_run or not yes,
                "max_deletes": max_deletes,
                "orphans": orphans,
                "skipped_locked": skipped_locked,
                "deleted": [],
                "errors": [],
                "list_errors": list_errors,
                "error": "remote_inventory_incomplete",
            }, indent=2))
        default_registry.close_all()
        sys.exit(2)

    if list_errors and not as_json:
        # Partial visibility: proceed, but make the un-listable kinds loud so
        # the operator knows prune did NOT consider them (their orphans, if
        # any, are left untouched).
        failed = ", ".join(e["asset"] for e in list_errors)
        click.echo(
            f"\nwarning: could not list {failed} — pruning only the kinds that "
            "listed cleanly; rules under the above are untouched.",
            err=True,
        )

    if as_json:
        summary = {
            "dry_run": dry_run or not yes,
            "max_deletes": max_deletes,
            "orphans": orphans,
            "skipped_locked": skipped_locked,
            "deleted": [],
            "errors": [],
            "list_errors": list_errors,
        }
    else:
        click.echo(
            f"\nPrune plan — {len(orphans)} orphan(s) found"
            + (f" (+{len(skipped_locked)} skipped because locked)" if skipped_locked else "")
            + ":"
        )
        for o in orphans:
            click.echo(f"  ORPHAN  {o['asset']:35} {o['envelope_id']:40} remote_id={o['remote_id']}")
        for s in skipped_locked:
            click.echo(f"  LOCKED  {s['asset']:35} {s['envelope_id']:40} (skipped)")

    if not orphans:
        if as_json:
            click.echo(_json.dumps(summary, indent=2))
        else:
            click.echo("\nNothing to prune.")
        default_registry.close_all()
        return

    if len(orphans) > max_deletes:
        msg = (
            f"\n{len(orphans)} orphans exceeds --max-deletes={max_deletes}; "
            "refusing to proceed. Pass a higher cap explicitly if intended."
        )
        click.echo(msg, err=True)
        if as_json:
            summary["error"] = "max_deletes_exceeded"
            click.echo(_json.dumps(summary, indent=2))
        default_registry.close_all()
        sys.exit(1)

    will_delete = (not dry_run) and yes
    if not will_delete:
        msg = (
            "\n[dry-run] No deletions performed. "
            "Pass --no-dry-run --yes to actually delete."
        )
        click.echo(msg)
        if as_json:
            click.echo(_json.dumps(summary, indent=2))
        default_registry.close_all()
        return

    # Apply phase: delete each orphan via the handler.
    deleted: list[dict] = []
    errors: list[dict] = []
    audit_pairs: list[tuple[str, str, ActionResult]] = []
    try:
        for orphan in orphans:
            handler = default_registry.get(Asset(orphan["asset"]))
            try:
                result = handler.delete(orphan["remote_id"])
            except NotSupportedError as exc:
                result = ActionResult(
                    asset_id=orphan["envelope_id"],
                    asset_kind=orphan["asset"],
                    action=PlanAction.SKIP,
                    status="skipped",
                    detail=str(exc)[:200],
                )
            except Exception as exc:
                result = ActionResult(
                    asset_id=orphan["envelope_id"],
                    asset_kind=orphan["asset"],
                    action=PlanAction.DELETE,
                    status="error-exception",
                    detail=str(exc)[:200],
                    error=str(exc)[:200],
                )
            audit_pairs.append((orphan["envelope_id"], orphan["asset"], result))

            if result.is_failure:
                errors.append({**orphan, "error": result.error or result.detail})
                if not as_json:
                    click.echo(
                        f"  ERROR   {orphan['asset']:35} "
                        f"{orphan['envelope_id']:40} {result.status}: {result.detail}",
                        err=True,
                    )
            elif result.action is PlanAction.SKIP:
                if not as_json:
                    click.echo(
                        f"  SKIP    {orphan['asset']:35} "
                        f"{orphan['envelope_id']:40} ({result.detail})"
                    )
            else:
                deleted.append(orphan)
                if not as_json:
                    click.echo(
                        f"  DELETED {orphan['asset']:35} {orphan['envelope_id']:40}"
                    )
    finally:
        default_registry.close_all()

    # Audit chain — one record per attempted delete. Resolve the
    # active workspace so the per-record ``workspace`` field
    # Attributes the prune to the right LA
    # workspace -- ``_resolve_single_workspace_or_exit`` set
    # PIPELINE_WORKSPACE_NAME for handler dispatch; we read it back
    # here for the audit record.
    if audit_pairs:
        active_ws = os.environ.get("PIPELINE_WORKSPACE_NAME")
        records = [
            _build_audit_record(
                res, envelope_id=env_id, asset_value=asset_value,
                workspace=active_ws, success_detail="pruned",
            )
            for env_id, asset_value, res in audit_pairs
        ]
        path = write_records(Path.cwd(), records)
        if not as_json:
            click.echo(f"[audit] wrote {len(records)} prune records to {path}")

    if as_json:
        summary["deleted"] = deleted
        summary["errors"] = errors
        click.echo(_json.dumps(summary, indent=2))
    else:
        click.echo(
            f"\nPrune summary: {len(deleted)} deleted, "
            f"{len(errors)} error(s), {len(skipped_locked)} skipped (locked)."
        )

    if errors:
        sys.exit(1)


def _resolve_safeguards_for_target(
    asset: str | None,
) -> list[tuple[str, "object"]]:
    """Return the safeguard objects that apply to this prune run.

    Each entry is ``(source_label, safeguards)`` for clear error
    messages. The active Sentinel workspace's safeguards apply to
    Sentinel handlers; the tenant-level Defender block applies to
    the Defender handler. When ``--asset`` filters to one kind, only
    its source is consulted; otherwise both apply and *both* must
    allow purge (fail-closed on the most conservative).

    Returns ``[]`` if no tenant config is loadable — e.g. unit tests
    operating against a synthetic tree with no ``config/tenant.yml``.
    The caller treats an empty list as "no safeguard configured;
    fall through to the legacy CLI behaviour" so existing test
    suites that pre-date the safeguard model keep passing.
    """
    from contentops.config import load_tenant_config
    from contentops.core.asset import Asset

    try:
        cfg = load_tenant_config()
    except FileNotFoundError:
        return []

    sentinel_assets = {
        Asset.SENTINEL_ANALYTIC.value,
        Asset.SENTINEL_HUNTING.value,
        Asset.SENTINEL_PARSER.value,
        Asset.SENTINEL_WATCHLIST.value,
        Asset.SENTINEL_DATA_CONNECTOR.value,
    }
    defender_assets = {Asset.DEFENDER_CUSTOM_DETECTION.value}

    want_sentinel = asset is None or asset in sentinel_assets
    want_defender = asset is None or asset in defender_assets

    out: list[tuple[str, object]] = []

    if want_sentinel and cfg.sentinelWorkspaces:
        active = os.environ.get("PIPELINE_WORKSPACE_NAME")
        if active:
            try:
                ws = cfg.workspace_by_name(active)
            except KeyError:
                ws = None
        else:
            # Implicit single-workspace case — _resolve_single_workspace_or_exit
            # leaves PIPELINE_WORKSPACE_NAME unset when only one Sentinel
            # workspace exists. The handler factories pick it implicitly;
            # mirror that behaviour for the safeguard lookup.
            ws = cfg.sentinelWorkspaces[0] if len(cfg.sentinelWorkspaces) == 1 else None
        if ws is not None:
            out.append((f"sentinel workspace {ws.workspaceName!r} ({ws.role})", ws))

    if want_defender and cfg.defender is not None:
        out.append(("Defender XDR (tenant-level)", cfg.defender))

    return out


