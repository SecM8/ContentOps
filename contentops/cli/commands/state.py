# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops state ...`` commands (DESIGN section 13)."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.core.asset import Asset


@click.group("state")
def state_group() -> None:
    """Inspect and manage the per-env state file (DESIGN section 13)."""


@state_group.command("show")
@click.option(
    "--env", "env_name", default=None,
    help="Tenant env slug. Defaults to the current tenant.yml's name.",
)
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict to one asset kind.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]), default="text",
)
def state_show_cmd(env_name: str | None, asset: str | None, output_format: str) -> None:
    """Print the per-env state file."""
    import json as _json

    from contentops.config import load_tenant_config
    from contentops.state import load_state

    if env_name is None:
        try:
            env_name = load_tenant_config().name
        except Exception:
            env_name = ""
    state = load_state(env=env_name)

    if output_format == "json":
        click.echo(_json.dumps({
            "schema_version": state.schema_version,
            "env": state.env,
            "last_apply_sha": state.last_apply_sha,
            "last_apply_at": state.last_apply_at,
            "asset_count": state.asset_count(),
            "managed_assets": {
                k: list(v.keys()) for k, v in state.managed_assets.items()
            } if not asset else {
                asset: list((state.managed_assets.get(asset) or {}).keys()),
            },
        }, indent=2))
        return

    click.echo(f"State for env={state.env or '(unset)'}")
    click.echo(f"  schema_version: {state.schema_version}")
    click.echo(f"  last_apply_sha: {state.last_apply_sha or '(none)'}")
    click.echo(f"  last_apply_at:  {state.last_apply_at or '(none)'}")
    click.echo(f"  asset_count:    {state.asset_count()}")
    asset_kinds = (
        [asset] if asset else sorted(state.managed_assets.keys())
    )
    for kind in asset_kinds:
        entries = state.managed_assets.get(kind) or {}
        if not entries:
            continue
        click.echo(f"\n  {kind}: {len(entries)} managed asset(s)")
        for envelope_id, entry in sorted(entries.items()):
            click.echo(f"    {envelope_id:50s} status={entry.status} sha={entry.last_applied_sha[:8] if entry.last_applied_sha else '-'}")


@state_group.command("forget")
@click.argument("envelope_id")
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    required=True,
    help="Asset kind to forget the entry from.",
)
@click.option("--env", "env_name", default=None, help="Tenant env slug.")
def state_forget_cmd(envelope_id: str, asset: str, env_name: str | None) -> None:
    """Drop one envelope id from state (e.g. after a manual portal cleanup)."""
    from contentops.config import load_tenant_config
    from contentops.state import load_state, save_state

    if env_name is None:
        try:
            env_name = load_tenant_config().name
        except Exception:
            env_name = ""
    state = load_state(env=env_name)
    state.forget(asset, envelope_id)
    save_state(state)
    click.echo(f"forgot {asset}/{envelope_id} from state (env={state.env})")


@state_group.command("adopt")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory compared against the live tenant.",
)
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict adoption to one asset kind.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role. Mutex with "
         "--workspace. Multi-workspace tenants must pass one of --role / "
         "--workspace; adopt reads one workspace per run.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact workspaceName. "
         "Mutex with --role.",
)
@click.option(
    "--env", "env_name", default=None,
    help="Tenant env slug for the state file. Defaults to tenant.yml's name.",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="Print what would be adopted; write nothing.",
)
@click.option(
    "--refresh", is_flag=True, default=False,
    help="Re-record assets that are already managed (default: skip them).",
)
@click.option(
    "--push", "push_state", is_flag=True, default=False,
    help="After saving, push the state file like `state sync push`.",
)
def state_adopt_cmd(
    detections_path: Path,
    asset: str | None,
    role: str | None,
    workspace_name: str | None,
    env_name: str | None,
    dry_run: bool,
    refresh: bool,
    push_state: bool,
) -> None:
    """Mark assets already in sync with the live tenant as managed.

    Runs the same read-only comparison as `contentops drift`, then
    records every IN-SYNC asset in the per-env state file with
    status=adopted. Use it on a tenant whose content was deployed
    before ContentOps tracked state, instead of a full redeploy.

    Never writes to Azure. Writes only state/<env>/state.json (and,
    with --push, the state/<env> branch). Assets that differ from the
    tenant (changed / new) are listed but never adopted. Any remote
    listing error aborts before state is touched.
    """
    from contentops.audit import _resolve_sha
    from contentops.cli.commands._shared import (
        _apply_log_levels,
        _collect_drift_handlers,
        _resolve_single_workspace_or_exit,
        _skip_if_integration_role_absent,
    )
    from contentops.cli.handler_factories import register_default_handlers
    from contentops.core.discovery import load_asset
    from contentops.core.drift import detect_drift
    from contentops.core.registry import default_registry
    from contentops.state import load_state, save_state

    _apply_log_levels()
    env_name = env_name or _state_env_default()
    if not env_name:
        click.echo("error: no env (pass --env or set tenant.yml's name)", err=True)
        sys.exit(2)
    if _skip_if_integration_role_absent(role, workspace_name, command="state adopt"):
        return
    _resolve_single_workspace_or_exit(role, workspace_name)
    register_default_handlers()
    target_asset = Asset(asset) if asset else None

    handlers = _collect_drift_handlers(target_asset)
    if not handlers:
        click.echo("No drift-capable handlers registered; nothing to adopt.")
        return

    try:
        report = detect_drift(handlers, detections_path)
    finally:
        default_registry.close_all()

    if report.has_errors():
        for entry in report.errors:
            click.echo(
                f"  ERROR    {entry.asset.value:30} (could not list remote: {entry.error})",
                err=True,
            )
        click.echo(
            f"error: {len(report.errors)} asset kind(s) could not be compared "
            "with the tenant; state was not changed.",
            err=True,
        )
        sys.exit(1)

    # Resolve every IN-SYNC entry to its LOCAL envelope. DriftEntry.asset_id
    # is derived from the remote (displayName slug), which differs from the
    # local id after a rename or slug disambiguation; state is keyed by the
    # local id because that is what apply / prune / status look up.
    candidates: dict[tuple[str, str], str] = {}
    load_errors: list[str] = []
    for entry in report.in_sync:
        if entry.local_path is None:
            load_errors.append(f"{entry.asset.value}/{entry.asset_id}: no local path")
            continue
        try:
            envelope = load_asset(entry.local_path).envelope
        except Exception as exc:  # noqa: BLE001 - reported, aborts below
            load_errors.append(f"{entry.local_path}: {exc}")
            continue
        key = (envelope.asset.value, envelope.id)
        candidates[key] = str(envelope.arm_name or "")
    if load_errors:
        for line in load_errors:
            click.echo(f"  ERROR    could not reload {line}", err=True)
        click.echo(
            f"error: {len(load_errors)} in-sync asset(s) could not be "
            "reloaded; state was not changed.",
            err=True,
        )
        sys.exit(1)

    state = load_state(env=env_name)
    # save_state() derives the path from state.env; pin it to the env we
    # loaded from so the write lands in the same state/<env>/state.json.
    state.env = env_name
    sha = _resolve_sha(Path.cwd())
    adopted: list[tuple[str, str]] = []
    already: list[tuple[str, str]] = []
    for (kind, envelope_id), remote_id in sorted(candidates.items()):
        if state.is_managed(kind, envelope_id) and not refresh:
            already.append((kind, envelope_id))
            continue
        adopted.append((kind, envelope_id))
        if not dry_run:
            # remember() only -- NOT merge_apply_results(): adoption is not
            # an apply, so last_apply_sha / last_apply_at stay truthful.
            state.remember(
                kind, envelope_id,
                remote_id=remote_id, sha=sha, status="adopted",
            )

    differs = report.changed + report.new
    verb = "would adopt" if dry_run else "adopted"
    for kind, envelope_id in adopted:
        click.echo(f"  ADOPT    {kind:30} {envelope_id}")
    for kind, envelope_id in already:
        click.echo(f"  MANAGED  {kind:30} {envelope_id}  (already managed; --refresh to re-record)")
    for entry in differs:
        label = "CHANGED" if entry.kind == "changed" else "NEW"
        where = f"  ({entry.local_path})" if entry.local_path else ""
        click.echo(
            f"  SKIP     {entry.asset.value:30} {entry.asset_id}  "
            f"not adopted (differs from tenant: {label}){where}"
        )

    click.echo(
        f"\nAdopt summary (env={env_name}) - {verb}: {len(adopted)}, "
        f"already managed: {len(already)}, "
        f"not adopted (differs): {len(differs)} "
        f"(changed: {len(report.changed)}, new: {len(report.new)}), "
        f"errors: 0"
    )

    if dry_run:
        click.echo("[dry-run] state file not written.")
        return
    path = save_state(state)
    click.echo(f"wrote {path}")
    if push_state:
        _push_state_or_exit(env_name, remote="origin", no_push=False)


@state_group.group("sync")
def state_sync_group() -> None:
    """Push / pull / status against the orphan-branch state convention.

    Wires DESIGN section 13's "state lives on refs/heads/state/<env>"
    promise. Closes G15. See contentops/state_sync.py for plumbing.
    """


def _state_env_default() -> str:
    try:
        from contentops.config import load_tenant_config
        return load_tenant_config().name
    except Exception:
        return ""


def _push_state_or_exit(env_name: str, *, remote: str, no_push: bool) -> None:
    """Push state/<env>/state.json onto refs/heads/state/<env>.

    Shared by ``state sync push`` and ``state adopt --push`` so both
    take the same code path. Exits 1 when the push fails -- including
    a failed network push, which used to print ``pushed_remote=False``
    and exit 0, so a CI step reported success while the durable state
    never moved.
    """
    from contentops.state import state_path
    from contentops.state_sync import StateSyncError, push as _push

    state_file = state_path(env=env_name)
    try:
        result = _push(
            env_name, state_file, repo=Path.cwd(),
            remote=remote, push_remote=not no_push,
        )
    except StateSyncError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    click.echo(
        f"[state push] env={env_name} ref={result.ref} "
        f"commit={result.commit_sha[:12]} pushed_remote={result.pushed_remote}"
    )
    if result.detail:
        click.echo(f"  {result.detail}")
    if not no_push and not result.pushed_remote:
        click.echo(
            "error: the remote push failed; the local ref was updated but "
            f"{remote} still has the previous state.",
            err=True,
        )
        sys.exit(1)


@state_sync_group.command("push")
@click.option("--env", "env_name", default=None,
              help="Tenant env slug (defaults to tenant.yml's name).")
@click.option("--remote", default="origin",
              help="Git remote (default: origin).")
@click.option("--no-push", is_flag=True, default=False,
              help="Update the local ref but skip the network push (CI debugging).")
def state_sync_push(env_name: str | None, remote: str, no_push: bool) -> None:
    """Push state/<env>/state.json onto refs/heads/state/<env> (orphan)."""
    env_name = env_name or _state_env_default()
    if not env_name:
        click.echo("error: no env (pass --env or set tenant.yml's name)", err=True)
        sys.exit(2)
    _push_state_or_exit(env_name, remote=remote, no_push=no_push)


@state_sync_group.command("pull")
@click.option("--env", "env_name", default=None,
              help="Tenant env slug (defaults to tenant.yml's name).")
@click.option("--remote", default="origin",
              help="Git remote (default: origin).")
@click.option("--no-fetch", is_flag=True, default=False,
              help="Don't run `git fetch` first (rely on existing local ref).")
def state_sync_pull(env_name: str | None, remote: str, no_fetch: bool) -> None:
    """Pull refs/heads/state/<env> into state/<env>/state.json."""
    from contentops.state import state_path
    from contentops.state_sync import StateSyncError, pull as _pull

    env_name = env_name or _state_env_default()
    if not env_name:
        click.echo("error: no env (pass --env or set tenant.yml's name)", err=True)
        sys.exit(2)
    state_file = state_path(env=env_name)
    try:
        result = _pull(
            env_name, state_file, repo=Path.cwd(),
            remote=remote, fetch_remote=not no_fetch,
        )
    except StateSyncError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    if result.written_path:
        click.echo(f"[state pull] wrote {result.written_path}")
    else:
        click.echo(f"[state pull] {result.detail}")


@state_sync_group.command("status")
@click.option("--env", "env_name", default=None,
              help="Tenant env slug (defaults to tenant.yml's name).")
def state_sync_status(env_name: str | None) -> None:
    """Show divergence between local state and the state/<env> ref."""
    from contentops.state import state_path
    from contentops.state_sync import StateSyncError, status as _status

    env_name = env_name or _state_env_default()
    if not env_name:
        click.echo("error: no env (pass --env or set tenant.yml's name)", err=True)
        sys.exit(2)
    state_file = state_path(env=env_name)
    try:
        result = _status(env_name, state_file, repo=Path.cwd())
    except StateSyncError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"env={env_name}  ref={result.ref}")
    click.echo(
        f"  local:  {'present' if result.local_present else 'missing'}"
        f"  sha={(result.local_sha or '-')[:12]}"
    )
    click.echo(
        f"  remote: {'present' if result.remote_present else 'missing'}"
        f"  sha={(result.remote_sha or '-')[:12]}"
    )
    click.echo(f"  in_sync: {result.in_sync}")
    if not result.in_sync:
        sys.exit(1)
