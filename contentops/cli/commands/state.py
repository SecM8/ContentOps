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


@state_sync_group.command("push")
@click.option("--env", "env_name", default=None,
              help="Tenant env slug (defaults to tenant.yml's name).")
@click.option("--remote", default="origin",
              help="Git remote (default: origin).")
@click.option("--no-push", is_flag=True, default=False,
              help="Update the local ref but skip the network push (CI debugging).")
def state_sync_push(env_name: str | None, remote: str, no_push: bool) -> None:
    """Push state/state.json onto refs/heads/state/<env> (orphan)."""
    from contentops.state import state_path
    from contentops.state_sync import StateSyncError, push as _push

    env_name = env_name or _state_env_default()
    if not env_name:
        click.echo("error: no env (pass --env or set tenant.yml's name)", err=True)
        sys.exit(2)
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


@state_sync_group.command("pull")
@click.option("--env", "env_name", default=None,
              help="Tenant env slug (defaults to tenant.yml's name).")
@click.option("--remote", default="origin",
              help="Git remote (default: origin).")
@click.option("--no-fetch", is_flag=True, default=False,
              help="Don't run `git fetch` first (rely on existing local ref).")
def state_sync_pull(env_name: str | None, remote: str, no_fetch: bool) -> None:
    """Pull refs/heads/state/<env> into state/state.json."""
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
