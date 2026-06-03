# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops config`` group — validate and inspect tenant configuration.

Two read-only subcommands:

* ``config validate`` — load + parse ``config/tenant.yml`` (or the
  env-aware path) and report whether it's structurally valid. Surfaces
  Pydantic / loader errors verbatim and exits 1 on failure. Optionally
  ``--strict`` also exits 1 on (a) the "no deployment targets" warning
  and (b) deployment targets configured but ``AZURE_CLIENT_ID`` /
  ``AZURE_TENANT_ID`` env vars unset.
* ``config list-workspaces`` — print the configured Sentinel workspaces
  in table / JSON / CSV format. Empty list is informational, not an
  error (Defender-only tenants are valid).
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from pathlib import Path

import click
from pydantic import ValidationError

from contentops.config import TenantConfig, load_tenant_config


_REQUIRED_AUTH_ENV_VARS = ("AZURE_CLIENT_ID", "AZURE_TENANT_ID")


@click.group("config")
def config_group() -> None:
    """Inspect and validate tenant configuration."""


def _engine_summary(cfg: TenantConfig) -> str:
    """One-line engine summary used by `config validate`."""
    if cfg.defender is None:
        defender_state = "absent"
    elif cfg.defender.enabled:
        defender_state = "enabled"
    else:
        defender_state = "disabled"

    if cfg.sentinelWorkspaces:
        ws_summary = ", ".join(
            f"{w.role}:{w.workspaceName}" for w in cfg.sentinelWorkspaces
        )
        ws_str = f"sentinel_workspaces={len(cfg.sentinelWorkspaces)} [{ws_summary}]"
    else:
        ws_str = "sentinel_workspaces=0"
    return f"tenant={cfg.name}, {ws_str}, defender={defender_state}"


def _has_deployment_targets(cfg: TenantConfig) -> bool:
    """True if at least one engine is deployable.

    Empty tenant (zero workspaces + Defender disabled/absent) → False. Used
    to decide whether ``config validate`` emits a WARN line and whether
    ``--strict`` should exit non-zero.
    """
    has_sentinel = bool(cfg.sentinelWorkspaces)
    has_defender = cfg.defender is not None and cfg.defender.enabled
    return has_sentinel or has_defender


@config_group.command("validate")
@click.option(
    "--path",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Tenant config file to validate. Defaults to the PIPELINE_ENV-aware "
         "path (config/tenant.<env>.yml or config/tenant.yml).",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Fail-fast (exit 1) on either: (a) the 'no deployment targets' "
         "WARN (empty tenant), or (b) deployment targets present but "
         "AZURE_CLIENT_ID / AZURE_TENANT_ID env vars unset. Use in CI "
         "before deploy steps.",
)
def config_validate_cmd(config_path: Path | None, strict: bool) -> None:
    """Load and validate the tenant configuration."""
    try:
        cfg = load_tenant_config(config_path)
    except FileNotFoundError as exc:
        click.echo(f"error: tenant config not found: {exc}", err=True)
        sys.exit(1)
    except (ValidationError, KeyError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    click.echo(_engine_summary(cfg))

    strict_failed = False

    if not _has_deployment_targets(cfg):
        click.echo(
            "WARN: tenant has no deployment targets - 0 Sentinel workspaces "
            "and Defender disabled. Add a sentinelWorkspaces entry, enable "
            "Defender, or both.",
            err=True,
        )
        if strict:
            strict_failed = True
    elif strict:
        # Tenant has at least one deployment target. The auth env vars
        # must therefore be set, or `apply` / `collect` / `drift` will
        # fail at the first Azure call. CI calls `config validate
        # --strict` to fail-fast on this case before any deploy step.
        missing = [name for name in _REQUIRED_AUTH_ENV_VARS if not os.environ.get(name)]
        if missing:
            click.echo(
                f"error: --strict: tenant has deployment targets but the "
                f"following auth environment variables are unset: "
                f"{', '.join(missing)}. Set them in CI Variables (not "
                f"Secrets) before running deploy commands.",
                err=True,
            )
            strict_failed = True

    if strict_failed:
        sys.exit(1)


@config_group.command("list-workspaces")
@click.option(
    "--path",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Tenant config file. Defaults to the PIPELINE_ENV-aware path.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format. JSON / CSV are stable shapes for scripting.",
)
def config_list_workspaces_cmd(
    config_path: Path | None, output_format: str,
) -> None:
    """Print the configured Sentinel workspaces.

    A Defender-only tenant has zero workspaces; the command prints
    "no Sentinel workspaces configured" and exits 0.
    """
    try:
        cfg = load_tenant_config(config_path)
    except FileNotFoundError as exc:
        click.echo(f"error: tenant config not found: {exc}", err=True)
        sys.exit(1)
    except (ValidationError, KeyError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    if not cfg.sentinelWorkspaces:
        if output_format == "json":
            click.echo("[]")
        elif output_format == "csv":
            click.echo("name,role,subscription_id_suffix,resource_group,location")
        else:
            click.echo(
                "no Sentinel workspaces configured "
                "(this is a valid Defender-only tenant)",
            )
        return

    rows = [
        {
            "name": w.workspaceName,
            "role": w.role,
            "subscription_id_suffix": w.subscriptionId[-8:],
            "resource_group": w.resourceGroup,
            "location": w.location,
        }
        for w in cfg.sentinelWorkspaces
    ]

    if output_format == "json":
        click.echo(json.dumps(rows, indent=2))
        return
    if output_format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=list(rows[0].keys()), lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        sys.stdout.write(buf.getvalue())
        return

    # table
    headers = ("name", "role", "sub-id (last 8)", "resource group", "location")
    width = [
        max(len(headers[0]), max(len(r["name"]) for r in rows)),
        max(len(headers[1]), max(len(r["role"]) for r in rows)),
        max(len(headers[2]), 8),
        max(len(headers[3]), max(len(r["resource_group"]) for r in rows)),
        max(len(headers[4]), max(len(r["location"]) for r in rows)),
    ]
    click.echo(
        f"{headers[0]:<{width[0]}}  {headers[1]:<{width[1]}}  "
        f"{headers[2]:<{width[2]}}  {headers[3]:<{width[3]}}  {headers[4]:<{width[4]}}"
    )
    click.echo("  ".join("-" * w for w in width))
    for row in rows:
        click.echo(
            f"{row['name']:<{width[0]}}  {row['role']:<{width[1]}}  "
            f"{row['subscription_id_suffix']:<{width[2]}}  "
            f"{row['resource_group']:<{width[3]}}  {row['location']:<{width[4]}}"
        )


__all__ = ["config_group"]
