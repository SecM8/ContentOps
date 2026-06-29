# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""V2 ``plan`` and ``apply`` Click commands."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from contentops.audit import (
    AuditConcurrentWriteError,
    _resolve_actor,
    _resolve_sha,
    write_orphan_records,
    write_records_with_retry,
)
from contentops.cli.handler_factories import register_default_handlers
from contentops.cli.commands._shared import (
    _apply_log_levels,
    _emit_dependency_report,
    _print_run_banner,
    _resolve_single_workspace_or_exit,
    _skip_if_integration_role_absent,
)
from contentops.cli.commands.apply_support import (
    WorkspaceLoopEntry,
    WorkspaceRunContext,
    _apply_dependency_violations_or_exit,
    _apply_integration_no_workspace_skip,
    _apply_no_loaded_assets_or_return,
    _build_audit_record,
    _check_apply_write_allowed_or_exit,
    _filter_loaded_by_env_status,
    _filter_locked_loaded_assets,
    _load_assets_for_run,
    _print_against_tenant_summary,
    _resolve_workspaces_for_run,
    _run_workspace_iteration,
)
from contentops.core.asset import Asset
from contentops.core.result import ActionResult, PlanAction


@click.command("plan")
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
    help="Restrict to one asset kind.",
)
@click.option(
    "--changed-since",
    "changed_since",
    default=None,
    help="Restrict to assets whose YAML changed vs this git ref "
         "(e.g. origin/main). Includes untracked files.",
)
@click.option(
    "--skip-deps-check",
    is_flag=True,
    help="Don't validate detections/dependencies.yml prerequisites.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role (sets PIPELINE_WORKSPACE_NAME). "
         "Mutex with --workspace. Tenant with exactly one Sentinel workspace "
         "picks it implicitly when both flags are omitted; multi-workspace "
         "tenants without a flag raise from _active_workspace().",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName`` "
         "(must match config/tenant.yml). Mutex with --role.",
)
@click.option(
    "--against-tenant/--no-against-tenant", default=False,
    help="Closes G17. After the normal plan, ALSO call list_remote() on "
         "each handler and overlay the predicted CREATE / UPDATE / "
         "DELETE counts vs the live tenant. Read-only; requires the same "
         "tenant credentials as `contentops drift`. Off by default so "
         "fork PRs and offline unit tests keep working.",
)
def plan_cmd(
    detections_path: Path,
    asset: str | None,
    changed_since: str | None,
    skip_deps_check: bool,
    role: str | None,
    workspace_name: str | None,
    against_tenant: bool,
) -> None:
    """Show what `apply` would do - no API calls (or --against-tenant for live diff).

    When ``--role`` matches multiple Sentinel workspaces, ``plan``
    iterates per workspace (mirroring ``apply``) so the operator can
    see per-workspace snippet substitution before deploying. Defender
    envelopes plan once (tenant-scoped).

    Note: by default ``plan`` does not call ``list_remote()``, so the
    per-asset action shows UPDATE even for rules that do not yet exist
    in the tenant -- the real CREATE vs UPDATE classification happens
    at ``apply`` time when the handler GETs the resource. Treat this
    as "would touch" rather than "would create". Pass ``--against-tenant``
    to swap to a tenant-aware classification (closes G17 -- PR-time
    pre-flight diff).
    """
    if _skip_if_integration_role_absent(role, workspace_name, command="plan"):
        return
    _resolve_single_workspace_or_exit(role, workspace_name)

    # Same workspace resolution as apply (helper below); keeps plan/apply
    # multi-workspace iteration in sync.
    cfg, workspaces = _resolve_workspaces_for_run(role, workspace_name)

    if cfg is not None and workspaces:
        os.environ["PIPELINE_WORKSPACE_NAME"] = workspaces[0].workspaceName

    register_default_handlers()
    loaded = _load_assets_for_run(
        detections_path,
        asset=asset,
        changed_since=changed_since,
    )

    deps_violations = False if skip_deps_check else _emit_dependency_report(loaded)

    iter_workspaces: list[WorkspaceLoopEntry] = (
        list(workspaces) if (cfg is not None and workspaces) else [None]
    )

    ctx = WorkspaceRunContext(command="plan", detections_path=detections_path)
    _run_workspace_iteration(
        loaded,
        iter_workspaces,
        role=role,
        ctx=ctx,
    )
    results = ctx.results

    click.echo(f"\nPlan ({len(results)} assets):")
    for r in results:
        click.echo(r.as_row())

    if against_tenant:
        _print_against_tenant_summary(loaded, detections_path)

    errors = [r for r in results if r.is_error]
    if errors or deps_violations:
        # The plan table (as_row) shows status but not the reason: its
        # last column is the verify state, not detail. Without this block
        # an `error-validate` row is a dead end: the operator sees that a
        # rule failed but not why. Print each errored asset's detail next
        # to the exit so the cause is actionable from the CI log alone.
        # (The apply path already echoes detail inline per asset.)
        if errors:
            click.echo("\nValidation errors:")
            for r in errors:
                detail = r.detail or "(no detail recorded)"
                click.echo(f"  {r.asset_id} ({r.asset_kind}): {detail}")
        click.echo(
            f"\n{len(errors)} validation error(s)"
            + (f", {sum(1 for _ in [deps_violations] if _)} dependency violation block(s)" if deps_violations else "")
            + "."
        )
        sys.exit(1)


@click.command("apply")
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
    help="Restrict to one asset kind.",
)
@click.option("--dry-run", is_flag=True, help="No API calls; print intended actions.")
@click.option("--no-audit", is_flag=True, help="Skip writing the JSONL audit record (local debugging).")
@click.option(
    "--changed-since",
    "changed_since",
    default=None,
    help="Restrict to assets whose YAML changed vs this git ref "
         "(e.g. origin/main). Includes untracked files.",
)
@click.option(
    "--skip-deps-check",
    is_flag=True,
    help="Don't validate detections/dependencies.yml prerequisites.",
)
@click.option(
    "--force-overwrite",
    is_flag=True,
    help="Push assets even when their envelope sets metadata.localCustomization=true. "
         "Without this flag those assets are skipped (Sentinel-as-Code Wave 2 customization protection).",
)
@click.option(
    "--json-report",
    "json_report_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write a structured JSON outcome report to this path. Pass '-' to write "
         "to stdout (after the human summary). The report mirrors the audit chain "
         "with per-asset audit_pointer references for scripted post-apply triage.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target every Sentinel workspace with this role. See "
         "DESIGN section 6 - multi-workspace selection. Mutex with --workspace. "
         "When the tenant has exactly one Sentinel workspace, omitting "
         "both flags picks it implicitly.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName`` "
         "(must match config/tenant.yml). Mutex with --role.",
)
@click.option(
    "--continue-on-error", "continue_on_error", is_flag=True, default=False,
    help=(
        "Treat per-rule failures as warnings, not failures. Exit code 0 "
        "even if N rules fail to deploy (the failures are still printed, "
        "audited, and counted in the summary). Pipeline-level errors "
        "(auth, network, missing config, dependency violations) still "
        "exit non-zero. Intended for integration deploys where a "
        "broken rule should not block PR merges - see "
        "`integration-deploy.yml`. Default off (prod deploy fails loud)."
    ),
)
@click.option(
    "--push-state", "push_state", is_flag=True, default=False,
    help=(
        "After a successful apply, push the local state file to "
        "refs/heads/state/<env> (orphan branch) so other operators see "
        "the managed-by snapshot. Equivalent to running `contentops "
        "state sync push` immediately after apply. Off by default: the "
        "CI deploy workflow already does this for prod; only useful for "
        "CLI-driven operators. If the push itself fails (e.g. branch "
        "rejected by a hook), the apply is still considered successful "
        "- the rules are live - and the operator is told to run `state "
        "sync push` manually."
    ),
)
def apply_cmd(
    detections_path: Path,
    asset: str | None,
    dry_run: bool,
    no_audit: bool,
    changed_since: str | None,
    skip_deps_check: bool,
    force_overwrite: bool,
    json_report_path: Path | None,
    role: str | None,
    workspace_name: str | None,
    continue_on_error: bool,
    push_state: bool,
) -> None:
    """Apply all assets via their registered handlers."""
    # Apply pipeline (high level — read top to bottom):
    # 1. Pick workspace(s) from config/tenant.yml + --role / --workspace
    # 2. Safety checks (write allowed, env status, dependencies, locked assets)
    # 3. Load detection YAML from disk (--asset / --changed-since filters apply here)
    # 4. Deploy each rule per workspace (shared loop in apply_support.py)
    # 5. Print summary, write audit trail, update state file, optional JSON report
    #
    # Steps 1–3 and 5 live in this file. Step 4 is _run_workspace_iteration().
    _apply_log_levels()

    # Resolve workspace(s) from --role / --workspace (see
    # apply_support._resolve_workspaces_for_run). Must run before handler
    # registration — factories read PIPELINE_WORKSPACE_NAME.
    cfg, workspaces = _resolve_workspaces_for_run(role, workspace_name)

    # Pre-dispatch apply gates (writeAllowed, integration skip, env-status,
    # deps, locks) — see apply_support helpers. Order matters.
    _check_apply_write_allowed_or_exit(cfg, workspaces, asset, dry_run)

    if cfg is not None and workspaces:
        # We'll iterate every matched workspace below. Seed
        # PIPELINE_WORKSPACE_NAME with the first one so initial
        # handler registration (and Defender, which is tenant-scoped
        # and applies once) sees a valid value.
        os.environ["PIPELINE_WORKSPACE_NAME"] = workspaces[0].workspaceName
    elif _apply_integration_no_workspace_skip(role):
        return

    register_default_handlers()
    _print_run_banner(
        "apply",
        detections_path,
        extra={"dry_run": str(dry_run).lower()},
    )
    started_at = datetime.now(timezone.utc)
    loaded = _load_assets_for_run(
        detections_path,
        asset=asset,
        changed_since=changed_since,
    )

    loaded = _filter_loaded_by_env_status(loaded, cfg, workspaces)
    if _apply_no_loaded_assets_or_return(loaded):
        return

    _apply_dependency_violations_or_exit(loaded, skip_deps_check)
    loaded = _filter_locked_loaded_assets(loaded, force_overwrite)

    # Multi-workspace iteration — see apply_support._run_workspace_iteration.
    iter_workspaces: list[WorkspaceLoopEntry] = (
        list(workspaces) if (cfg is not None and workspaces) else [None]
    )

    ctx = WorkspaceRunContext(
        command="apply",
        detections_path=detections_path,
        dry_run=dry_run,
        audit_pairs=[],
    )
    _run_workspace_iteration(
        loaded,
        iter_workspaces,
        role=role,
        ctx=ctx,
    )
    results = ctx.results
    # apply always builds ctx with audit_pairs=[] (and _process_apply_asset
    # raises if it were None), so this can't be None here — assert the
    # invariant for the type-narrow + readers, rather than carry an
    # unreachable runtime guard.
    assert ctx.audit_pairs is not None
    audit_pairs = ctx.audit_pairs

    click.echo(f"\nApply summary ({len(results)} assets):")
    click.echo(
        f"  {'asset_id':40s} {'kind':30s} {'action':8s} {'status':18s} verified"
    )
    for r in results:
        click.echo(r.as_row())

    audit_path: Path | None = None
    audit_first_line: int | None = None
    if not dry_run and not no_audit and audit_pairs:
        records = [
            _build_audit_record(r, la, workspace=ws_name, snippet_digest=snippet_digest)
            for la, r, ws_name, snippet_digest in audit_pairs
        ]
        # Count existing lines before append so the json-report knows the
        # 1-indexed line number of this batch's first record.
        from datetime import date as _date
        target_path = Path.cwd() / "audit" / f"{_date.today():%Y-%m-%d}.jsonl"
        if target_path.exists():
            existing_lines = sum(
                1 for line in target_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        else:
            existing_lines = 0
        try:
            audit_path = write_records_with_retry(Path.cwd(), records)
            audit_first_line = existing_lines + 1
            click.echo(f"[audit] wrote {len(records)} records to {audit_path}")
        except AuditConcurrentWriteError as exc:
            # The ARM PUTs already succeeded — a persistent audit-tail race
            # must NOT false-fail the deploy. Surface loudly and persist the
            # batch to a recovery sidecar so the records are not silently
            # dropped (data completeness), then continue.
            orphan_path = write_orphan_records(Path.cwd(), records)
            click.echo(
                f"[audit] WARNING: concurrent-write race persisted after "
                f"retries ({exc}). Apply itself SUCCEEDED; wrote "
                f"{len(records)} unchained record(s) to {orphan_path} for "
                f"manual reconciliation. Re-run `contentops audit verify` "
                f"and fold the orphan batch into the chain.",
                err=True,
            )

        # State file: record what we just applied so drift / prune can
        # distinguish "intentionally deleted" from "never managed".
        # See DESIGN §13.
        try:
            from contentops.config import load_tenant_config
            from contentops.state import load_state, merge_apply_results, save_state
            cfg = load_tenant_config()
            env_name = cfg.name
            state = load_state(env=env_name)
            sha = _resolve_sha(Path.cwd())
            state_inputs = []
            for la, r, _ws_name, _digest in audit_pairs:
                if r.is_failure:
                    status = "failed"
                elif r.action is PlanAction.SKIP:
                    status = "skipped"
                else:
                    status = "success"
                state_inputs.append(
                    (la.envelope.asset.value, la.envelope.id, "", status)
                )
            merge_apply_results(state, state_inputs, sha=sha)
            save_state(state)
        except Exception as exc:
            # State file is best-effort; never fail apply because of it.
            click.echo(f"[warn] state file update skipped: {exc}", err=True)

        # --push-state (P3-2): after a successful apply + state-file save,
        # optionally push the per-env state ref. Off by default; CI's
        # `deploy.yml` already does this for prod, so this flag is for
        # CLI-driven operators who want the same behaviour.
        if push_state:
            try:
                from contentops.config import load_tenant_config as _ltc
                from contentops.state import state_path as _state_path
                from contentops.state_sync import push as _state_push
                push_env = _ltc().name
                push_result = _state_push(
                    push_env, _state_path(env=push_env),
                    repo=Path.cwd(), remote="origin", push_remote=True,
                )
                click.echo(
                    f"[state push] env={push_env} ref={push_result.ref} "
                    f"commit={push_result.commit_sha[:12]} "
                    f"pushed_remote={push_result.pushed_remote}"
                )
            except Exception as exc:
                # Apply already succeeded; the rules are live. State push
                # is a post-apply convenience — warn loudly so the operator
                # runs `contentops state sync push` manually, but don't
                # crash. Mirrors the state-file save block above which is
                # also best-effort by design. Catch the broad Exception
                # because the underlying push path can raise
                # StateSyncError, FileNotFoundError (no tenant.yml),
                # CalledProcessError (git op failed), etc.
                click.echo(
                    f"[error] --push-state failed: {exc}\n"
                    f"  Apply succeeded; the rules are deployed. Run "
                    f"`contentops state sync push` manually to recover.",
                    err=True,
                )

    finished_at = datetime.now(timezone.utc)

    # JSON report — opt-in, decoupled from audit so it works for dry-run too.
    if json_report_path is not None:
        from contentops.apply_report import build_report, to_json, write_report
        try:
            from contentops.config import load_tenant_config
            tenant_name = load_tenant_config().name
        except Exception:
            tenant_name = ""
        report = build_report(
            tenant=tenant_name,
            started_at=started_at,
            finished_at=finished_at,
            sha=_resolve_sha(Path.cwd()),
            actor=_resolve_actor(),
            workflow_run=os.getenv("GITHUB_RUN_ID") or None,
            dry_run=dry_run,
            pairs=audit_pairs,
            audit_path=audit_path,
            audit_first_line=audit_first_line,
        )
        if str(json_report_path) == "-":
            click.echo("")  # blank line between summary and JSON
            click.echo(to_json(report).rstrip())
        else:
            written = write_report(report, json_report_path)
            click.echo(f"[json-report] wrote {written}")

    failed = [r for r in results if r.is_failure]
    if failed:
        if continue_on_error:
            click.echo(
                f"\n{len(failed)} per-rule error(s) — exit code suppressed "
                f"by --continue-on-error."
            )
        else:
            click.echo(f"\n{len(failed)} error(s).")
            sys.exit(1)

