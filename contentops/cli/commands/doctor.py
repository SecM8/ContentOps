# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops doctor`` command."""

from __future__ import annotations

import sys

import click

from contentops.devex.doctor import (
    aggregate_exit_code,
    format_results,
    run_checks,
)


@click.command("doctor")
@click.option(
    "--auth/--no-auth", default=False,
    help="Also test Azure token acquisition (default: skipped).",
)
@click.option(
    "--matrix/--no-matrix", default=False,
    help=(
        "Also produce a per-handler PASS/FAIL matrix (one row per drift-"
        "capable handler, listing remote items). Implies --auth. On a "
        "multi-Sentinel-workspace tenant, auto-picks the prod-role "
        "workspace (or the first listed) and emits a single info note; "
        "pass --role or --workspace to target a specific one."
    ),
)
@click.option(
    "--role", "role", default=None,
    help=(
        "Scope the handler matrix to one workspace role (e.g. prod, "
        "integration). Mutually exclusive with --workspace."
    ),
)
@click.option(
    "--workspace", "workspace_name", default=None,
    help=(
        "Scope the handler matrix to one named workspace. Mutually "
        "exclusive with --role."
    ),
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--fix", "fix_mode", is_flag=True, default=False,
    help=(
        "Apply safe autofixes for failed checks. Whitelisted to "
        "non-credential, non-rule-content fixes (currently: copy "
        ".env.example -> .env, mkdir detections/ subdirs). "
        "Re-runs the checks after fixing so the operator sees "
        "the post-fix state."
    ),
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="With --fix, print which fixes would run without mutating disk.",
)
def doctor_cmd(
    auth: bool, matrix: bool,
    role: str | None, workspace_name: str | None,
    output_format: str,
    fix_mode: bool, dry_run: bool,
) -> None:
    """Run environment & configuration sanity checks (`--fix` to autofix)."""
    import os

    from contentops.config import load_tenant_config, select_workspaces

    saved_ws_env = os.environ.get("PIPELINE_WORKSPACE_NAME")
    if role or workspace_name:
        try:
            cfg = load_tenant_config()
        except Exception as exc:
            raise click.UsageError(
                f"--role/--workspace requires a readable tenant.yml: {exc}"
            )
        try:
            selected = select_workspaces(
                cfg, role=role, workspace=workspace_name,
            )
        except (ValueError, KeyError) as exc:
            raise click.UsageError(str(exc))
        if len(selected) != 1:
            raise click.UsageError(
                f"--role/--workspace must resolve to exactly one workspace; "
                f"got {len(selected)}"
            )
        os.environ["PIPELINE_WORKSPACE_NAME"] = selected[0].workspaceName

    try:
        results = run_checks(with_auth=auth, with_matrix=matrix)
        _render_and_maybe_fix(
            results, auth, matrix, output_format, fix_mode, dry_run,
        )
    finally:
        if saved_ws_env is None:
            os.environ.pop("PIPELINE_WORKSPACE_NAME", None)
        else:
            os.environ["PIPELINE_WORKSPACE_NAME"] = saved_ws_env


def _render_and_maybe_fix(
    results, auth, matrix, output_format, fix_mode, dry_run,
):
    """Render results, optionally apply autofixes + re-render. Extracted so
    the env-var restoration finally-block in ``doctor_cmd`` stays focused
    on the single concern of leaking PIPELINE_WORKSPACE_NAME state."""
    from contentops.devex.doctor import apply_safe_fixes

    if fix_mode:
        fixes = apply_safe_fixes(results, dry_run=dry_run)
        if not fixes:
            click.echo("No safe fixes applicable.", err=True)
        else:
            verb = "[dry-run]" if dry_run else "[fix]"
            for f in fixes:
                tag = "[OK]" if f.applied else ("[would]" if dry_run else "[skip]")
                click.echo(f"  {verb} {tag} {f.name}: {f.action}", err=True)
                if f.detail:
                    click.echo(f"        {f.detail}", err=True)
        # Re-run checks if we actually mutated something so the operator
        # sees the post-fix state.
        if not dry_run and any(f.applied for f in fixes):
            click.echo("\nRe-running checks after fixes:", err=True)
            results = run_checks(with_auth=auth, with_matrix=matrix)

    click.echo(format_results(results, json_out=(output_format == "json")))
    code = aggregate_exit_code(results)
    if code != 0:
        sys.exit(code)
