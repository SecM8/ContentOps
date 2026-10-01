# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops rollback`` command."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from contentops.audit import write_records
from contentops.cli.handler_factories import register_default_handlers
from contentops.cli.commands._shared import (
    _apply_log_levels,
    _filter_disabled_engines,
    _is_locked,
    _is_locked_path,
    _load_all,
    _print_run_banner,
    _resolve_single_workspace_or_exit,
    _skip_if_integration_role_absent,
)
from contentops.cli.commands.apply_support import (
    WorkspaceRunContext,
    _build_audit_record,
    _check_apply_write_allowed_or_exit,
    _filter_loaded_by_env_status,
    _process_apply_asset,
    _process_plan_asset,
)
import contentops.config as _config
from contentops.config import SentinelWorkspaceConfig, TenantConfig
from contentops.core.asset import Asset
from contentops.core.discovery import iter_loaded_assets
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult

# Rollback replays the materialised tree but resolves locks and snippet
# overrides against the CURRENT checkout (the same roots apply uses).
_CURRENT_DETECTIONS = Path("detections")


def _rollback_target() -> tuple[TenantConfig | None, list[SentinelWorkspaceConfig]]:
    """Return (tenant config, workspaces this rollback writes to).

    Runs after ``_resolve_single_workspace_or_exit``, so an explicit
    selector has already landed in ``PIPELINE_WORKSPACE_NAME`` (the env
    var the handler factories read). Without one, every configured
    workspace is in scope — conservative for the writeAllowed gate.
    Missing tenant.yml -> ``(None, [])``, as for apply.
    """
    try:
        cfg = _config.load_tenant_config()
    except FileNotFoundError:
        return None, []
    name = os.environ.get("PIPELINE_WORKSPACE_NAME")
    if name:
        match = [w for w in cfg.sentinelWorkspaces if w.workspaceName == name]
        if match:
            return cfg, match
    return cfg, list(cfg.sentinelWorkspaces)


def _locked_in_current_tree(
    la: LoadedAsset,
    rollback_root: Path,
    current: dict[tuple[Asset, str], LoadedAsset],
) -> bool:
    """True when TODAY's file for this asset carries the lock.

    The copy materialised from the target SHA predates any lock added
    since, so it cannot be trusted. Match by (asset, id) so a file moved
    since the SHA is still found; fall back to the same relative path
    when today's file does not load.
    """
    today = current.get((la.envelope.asset, la.envelope.id))
    if today is not None:
        return _is_locked(today)
    return _is_locked_path(_CURRENT_DETECTIONS / la.path.relative_to(rollback_root))


@click.command("rollback")
@click.argument("sha")
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict rollback to one asset kind. Strongly recommended.",
)
@click.option(
    "--rule-id", "rule_id",
    default=None,
    help="Restrict rollback to a single envelope by its id (post-incident "
         "narrow rollback: one bad rule, one apply). Combine with --asset "
         "to disambiguate if the same id exists across asset kinds.",
)
@click.option(
    "--dry-run/--no-dry-run", default=True,
    help="Default true. Set --no-dry-run plus --yes to actually apply.",
)
@click.option(
    "--yes", is_flag=True, default=False,
    help="Required to actually apply (alongside --no-dry-run).",
)
@click.option(
    "--no-audit", is_flag=True, default=False,
    help="Skip writing audit records (local debugging only).",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role (sets "
         "PIPELINE_WORKSPACE_NAME). Mutex with --workspace. "
         "Single-workspace tenants pick implicitly when both omitted.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName`` "
         "(must match config/tenant.yml). Mutex with --role.",
)
@click.option(
    "--max-apply", "max_apply", type=int, default=25, show_default=True,
    help="Fail-closed if the (post-filter) rollback scope exceeds this "
         "many assets. The blast-radius brake analogous to prune's "
         "--max-deletes: an untargeted rollback to an old SHA could "
         "otherwise replay hundreds of rules. Narrow with --asset/"
         "--rule-id, or raise this cap when a large batch is intended.",
)
def rollback_cmd(
    sha: str, asset: str | None, rule_id: str | None, dry_run: bool,
    yes: bool, no_audit: bool,
    role: str | None, workspace_name: str | None,
    max_apply: int,
) -> None:
    """Replay the YAML at SHA against the tenant.

    Materialises ``detections/`` at SHA into a temp tree, then runs
    every handler's validate + apply against that tree. Audit
    records carry ``message="rollback to <full-sha>"`` so the trail
    is searchable post-incident.

    \b
    Behaviour:
      * Defaults to dry-run; pass --no-dry-run --yes to actually push.
      * Non-destructive: a rule that exists today but didn't at SHA
        is LEFT ALONE. Run ``contentops prune`` afterwards if you want
        full reset semantics.
      * Honours ``localCustomization: true`` locks as they stand in the
        current checkout (same as apply). Unlock the rule first if you
        want rollback to overwrite it.
      * Same gates as apply: tenant.yml ``writeAllowed``, the env-status
        filter, and snippet substitution from the current overrides/.
      * Skips dependency check - the SHA was valid at its merge time;
        re-validating against today's dependency graph is the wrong
        contract for an incident-response replay.
      * Audit records: ``action`` stays as the actual API verb
        (``update``/``disable``); ``message`` is prefixed
        ``rollback to <sha>`` so audit queries can find them.
    """
    from contentops.rollback import (
        RollbackError, materialize_at_sha, resolve_sha, rollback_audit_message,
    )
    import tempfile

    _apply_log_levels()
    if _skip_if_integration_role_absent(role, workspace_name, command="rollback"):
        return
    _resolve_single_workspace_or_exit(role, workspace_name)
    cfg, workspaces = _rollback_target()
    will_apply = (not dry_run) and yes
    # Same writeAllowed safeguard as apply, before any handler exists; a
    # preview (dry-run, or --no-dry-run without --yes) bypasses it.
    _check_apply_write_allowed_or_exit(cfg, workspaces, asset, not will_apply)
    ws_name = (
        workspaces[0].workspaceName if len(workspaces) == 1
        else os.environ.get("PIPELINE_WORKSPACE_NAME")
    )
    register_default_handlers()

    try:
        full_sha = resolve_sha(sha)
    except RollbackError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    _print_run_banner(
        "rollback",
        Path("detections"),
        extra={
            "target_sha": full_sha[:12],
            "dry_run": str(dry_run).lower(),
            "yes": str(yes).lower(),
        },
    )

    with tempfile.TemporaryDirectory(prefix="rollback-") as tmp:
        tmp_root = Path(tmp)
        try:
            n_files = materialize_at_sha(full_sha, "detections", tmp_root)
        except RollbackError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(1)
        click.echo(f"Materialized {n_files} file(s) from {full_sha[:12]}")

        rollback_root = tmp_root / "detections"
        if not rollback_root.is_dir():
            click.echo(
                f"error: SHA {full_sha[:12]} has no detections/ directory",
                err=True,
            )
            sys.exit(1)

        loaded = _load_all(rollback_root)
        if asset:
            target = Asset(asset)
            loaded = [la for la in loaded if la.envelope.asset == target]
        if rule_id:
            loaded = [la for la in loaded if la.envelope.id == rule_id]
            if not loaded:
                click.echo(
                    f"error: rule_id {rule_id!r} not found at SHA "
                    f"{full_sha[:12]}"
                    + (f" (asset={asset})" if asset else ""),
                    err=True,
                )
                sys.exit(1)

        loaded = _filter_disabled_engines(loaded)
        loaded = _filter_loaded_by_env_status(loaded, cfg, workspaces)
        if not loaded:
            click.echo("No assets to rollback.")
            return

        # Filter locked envelopes — rollback honours the lock by default,
        # read from the current checkout (a lock added after SHA counts).
        current: dict[tuple[Asset, str], LoadedAsset] = {}
        if _CURRENT_DETECTIONS.is_dir():
            for today in iter_loaded_assets(_CURRENT_DETECTIONS):
                current[(today.envelope.asset, today.envelope.id)] = today
        kept: list[LoadedAsset] = []
        for la in loaded:
            if _locked_in_current_tree(la, rollback_root, current):
                click.echo(
                    f"  skipped (locked): {la.envelope.id} "
                    "— contentops unlock then re-run rollback to override"
                )
                continue
            kept.append(la)
        loaded = kept

        # Blast-radius brake (mirrors prune's --max-deletes). Checked on the
        # final post-filter set, before plan/apply, so even a dry-run of an
        # over-broad scope fails fast and tells the operator to narrow it —
        # an untargeted rollback to an old SHA could otherwise replay
        # hundreds of rules in one CONFIRM.
        if len(loaded) > max_apply:
            click.echo(
                f"error: rollback scope is {len(loaded)} asset(s), exceeding "
                f"--max-apply={max_apply}. Narrow with --asset / --rule-id, "
                f"or raise --max-apply if a batch this large is intended.",
                err=True,
            )
            default_registry.close_all()
            sys.exit(1)

        # Plan phase — snippet substitution + validate + plan against the
        # materialised tree, through apply's per-asset helper.
        plan_ctx = WorkspaceRunContext(
            command="plan", detections_path=_CURRENT_DETECTIONS,
        )
        for la in loaded:
            _process_plan_asset(la, ws_name, plan_ctx)
        plan_results: list[ActionResult] = plan_ctx.results

        click.echo(f"\nRollback plan ({len(plan_results)} assets):")
        for r in plan_results:
            click.echo(r.as_row())

        plan_errors = [r for r in plan_results if r.is_error]
        if plan_errors:
            click.echo(
                f"\n{len(plan_errors)} validation error(s) — refusing to apply.",
                err=True,
            )
            default_registry.close_all()
            sys.exit(1)

        if not will_apply:
            click.echo(
                "\n[dry-run] No API calls. "
                "Pass --no-dry-run --yes to actually apply this rollback."
            )
            default_registry.close_all()
            return

        # Apply phase — apply's per-asset helper, so the PUT carries the
        # snippet-substituted payload exactly as `apply` would send it.
        ctx = WorkspaceRunContext(
            command="apply", detections_path=_CURRENT_DETECTIONS,
            dry_run=False, audit_pairs=[],
        )
        try:
            for la in loaded:
                _process_apply_asset(la, ws_name, ctx)
        finally:
            default_registry.close_all()
        results = ctx.results
        assert ctx.audit_pairs is not None
        audit_pairs = ctx.audit_pairs

        click.echo(f"\nRollback summary ({len(results)} assets):")
        for r in results:
            click.echo(r.as_row())

        # Audit — same chain as `apply`, with the rollback marker on every record.
        # Thread the active workspace through the audit-record schema
        # through so multi-workspace rollbacks are attributable.
        if not no_audit and audit_pairs:
            records = []
            marker = rollback_audit_message(full_sha)
            for la, r, pair_ws, snippet_digest in audit_pairs:
                base = _build_audit_record(
                    r, la, workspace=pair_ws, snippet_digest=snippet_digest,
                )
                # Prefix the message; preserve any pre-existing detail.
                existing = base.message or ""
                new_message = (
                    f"{marker}: {existing}" if existing else marker
                )
                from dataclasses import replace
                records.append(replace(base, message=new_message))
            path = write_records(Path.cwd(), records)
            click.echo(f"[audit] wrote {len(records)} rollback records to {path}")

        failed = [r for r in results if r.is_failure]
        if failed:
            click.echo(f"\n{len(failed)} error(s).", err=True)
            sys.exit(1)
