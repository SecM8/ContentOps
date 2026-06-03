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
    _is_locked,
    _load_all,
    _print_run_banner,
    _resolve_single_workspace_or_exit,
    _skip_if_integration_role_absent,
)
from contentops.cli.commands.apply_support import _build_audit_record
from contentops.core.asset import Asset
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


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
      * Honours ``localCustomization: true`` locks (same as apply).
        Unlock the rule first if you want rollback to overwrite it.
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

        if not loaded:
            click.echo("No assets to rollback.")
            return

        # Filter locked envelopes — rollback honours the lock by default.
        kept: list[LoadedAsset] = []
        for la in loaded:
            if _is_locked(la):
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

        # Plan phase — validate + plan against the materialised tree.
        plan_results: list[ActionResult] = []
        for la in loaded:
            if not default_registry.has(la.envelope.asset):
                click.echo(f"  no handler for {la.envelope.asset.value}: {la.path}")
                continue
            handler = default_registry.get(la.envelope.asset)
            try:
                handler.validate(la)
                plan_results.append(handler.plan(la))
            except Exception as exc:
                plan_results.append(ActionResult(
                    asset_id=la.envelope.id, asset_kind=la.envelope.asset.value,
                    action=PlanAction.NOOP,
                    status="error-validate", detail=str(exc),
                ))

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

        will_apply = (not dry_run) and yes
        if not will_apply:
            click.echo(
                "\n[dry-run] No API calls. "
                "Pass --no-dry-run --yes to actually apply this rollback."
            )
            default_registry.close_all()
            return

        # Apply phase.
        results: list[ActionResult] = []
        audit_pairs: list[tuple[LoadedAsset, ActionResult]] = []
        try:
            for la in loaded:
                handler = default_registry.get(la.envelope.asset)
                try:
                    handler.validate(la)
                    result = handler.apply(la, dry_run=False)
                except Exception as exc:
                    result = ActionResult(
                        asset_id=la.envelope.id, asset_kind=la.envelope.asset.value,
                        action=PlanAction.NOOP, status="error-apply", detail=str(exc),
                    )
                    click.echo(f"  error: {la.envelope.id}: {exc}", err=True)
                results.append(result)
                audit_pairs.append((la, result))
        finally:
            default_registry.close_all()

        click.echo(f"\nRollback summary ({len(results)} assets):")
        for r in results:
            click.echo(r.as_row())

        # Audit — same chain as `apply`, with the rollback marker on every record.
        # Thread the active workspace through the audit-record schema
        # through so multi-workspace rollbacks are attributable.
        if not no_audit and audit_pairs:
            records = []
            marker = rollback_audit_message(full_sha)
            active_ws = os.environ.get("PIPELINE_WORKSPACE_NAME")
            for la, r in audit_pairs:
                base = _build_audit_record(r, la, workspace=active_ws)
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
