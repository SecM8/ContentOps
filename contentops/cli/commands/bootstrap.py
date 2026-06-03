# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops bootstrap`` command.

First-run setup for a new tenant: creates the resource group +
Log Analytics workspace and onboards Sentinel. Handler factory
registration (the unrelated "wire up which class handles which
asset kind" responsibility) lives in
``contentops/cli/handler_factories.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
import yaml


@click.command("bootstrap")
@click.option("--subscription", "subscription_id", required=True,
              help="Azure subscription ID.")
@click.option("--resource-group", "resource_group", required=True,
              help="Resource group name (created if missing).")
@click.option("--workspace", "workspace_name", required=True,
              help="Log Analytics workspace name (created if missing).")
@click.option("--location", default="westeurope",
              help="Azure region for the resource group + workspace (default: westeurope).")
@click.option("--env", "env_slug", default=None,
              help="Tenant env slug. If set, writes config/tenant.<env>.yml; "
                   "otherwise writes config/tenant.yml.")
@click.option("--dry-run", is_flag=True,
              help="Print what would be created without calling any API.")
def bootstrap_cmd(
    subscription_id: str, resource_group: str, workspace_name: str,
    location: str, env_slug: str | None, dry_run: bool,
) -> None:
    """Idempotent first-run setup for a new Sentinel workspace.

    Creates (if missing) the resource group + Log Analytics workspace,
    onboards Microsoft Sentinel via PUT onboardingStates/default, and
    writes a tenant config file the rest of the CLI can load.

    Each step is idempotent: an existing resource is left untouched.
    Failures fail the whole command - partial bootstrap is worse than
    no bootstrap.
    """
    import json as _json

    from contentops.providers.sentinel_arm import SentinelArmProvider
    from contentops.utils.auth import get_arm_token, get_credential

    if dry_run:
        click.echo(f"[DRY-RUN] Would bootstrap:")
        click.echo(f"  subscription:    {subscription_id}")
        click.echo(f"  resource group:  {resource_group} (location {location})")
        click.echo(f"  workspace:       {workspace_name}")
        click.echo(f"  Sentinel:        onboardingStates/default PUT")
        click.echo(f"  config file:     config/tenant{'.' + env_slug if env_slug else ''}.yml")
        return

    token = get_arm_token(get_credential())

    # Step 1: ensure resource group exists.
    rg_url = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"?api-version=2021-04-01"
    )
    import httpx as _httpx
    arm = _httpx.Client(
        base_url="https://management.azure.com",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        # Explicit per-phase timeout. Bootstrap can do longer RG / Sentinel
        # onboarding PUTs that occasionally run 30-45s, so keep read=60.
        # Connect/pool stay short so DNS / TCP-unreachable failures don't
        # hide for the full read budget.
        timeout=_httpx.Timeout(connect=10.0, read=60.0, write=60.0, pool=10.0),
    )
    try:
        rg_resp = arm.get(rg_url)
        if rg_resp.status_code == 404:
            click.echo(f"[bootstrap] Creating resource group {resource_group} in {location}")
            create_resp = arm.put(rg_url, json={"location": location})
            if create_resp.status_code not in (200, 201):
                click.echo(
                    f"error: failed to create RG {resource_group}: "
                    f"{create_resp.status_code} {create_resp.text}",
                    err=True,
                )
                sys.exit(1)
        elif rg_resp.status_code == 200:
            click.echo(f"[bootstrap] Resource group {resource_group} already exists")
        else:
            click.echo(
                f"error: GET RG {resource_group} returned {rg_resp.status_code}: "
                f"{rg_resp.text}",
                err=True,
            )
            sys.exit(1)

        # Step 2: ensure Log Analytics workspace exists.
        ws_url = (
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
            f"?api-version=2022-10-01"
        )
        ws_resp = arm.get(ws_url)
        if ws_resp.status_code == 404:
            click.echo(f"[bootstrap] Creating Log Analytics workspace {workspace_name}")
            ws_create = arm.put(ws_url, json={
                "location": location,
                "properties": {
                    "sku": {"name": "PerGB2018"},
                    "retentionInDays": 90,
                },
            })
            if ws_create.status_code not in (200, 201):
                click.echo(
                    f"error: failed to create workspace: "
                    f"{ws_create.status_code} {ws_create.text}",
                    err=True,
                )
                sys.exit(1)
        elif ws_resp.status_code == 200:
            click.echo(f"[bootstrap] Workspace {workspace_name} already exists")
        else:
            click.echo(
                f"error: GET workspace returned {ws_resp.status_code}: {ws_resp.text}",
                err=True,
            )
            sys.exit(1)
    finally:
        arm.close()

    # Step 3: onboard Sentinel via SentinelArmProvider.
    from contentops.config import SentinelConfig
    cfg = SentinelConfig(
        subscriptionId=subscription_id,
        resourceGroup=resource_group,
        workspaceName=workspace_name,
        location=location,
    )
    provider = SentinelArmProvider(cfg, token)
    try:
        existing = provider.get_resource("onboardingStates", "default")
        if existing is None:
            click.echo("[bootstrap] PUT onboardingStates/default")
            onboarding_resp = provider.request(
                "PUT",
                provider.resource_url("onboardingStates", "default"),
                json={"properties": {}},
            )
            if onboarding_resp.status_code not in (200, 201):
                click.echo(
                    f"error: Sentinel onboarding failed: "
                    f"{onboarding_resp.status_code} {onboarding_resp.text}",
                    err=True,
                )
                sys.exit(1)
        else:
            click.echo("[bootstrap] Sentinel already onboarded on this workspace")
    finally:
        provider.close()

    # Step 4: write tenant config file.
    config_dir = Path("config")
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / (f"tenant.{env_slug}.yml" if env_slug else "tenant.yml")
    tenant_doc = {
        "tenant": {
            "name": env_slug or "production",
            "tenantId": os.getenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000"),
            "sentinelWorkspaces": [
                {
                    "role": "prod",
                    "subscriptionId": subscription_id,
                    "resourceGroup": resource_group,
                    "workspaceName": workspace_name,
                    "location": location,
                },
            ],
            "defender": {"enabled": True},
        }
    }
    config_path.write_text(
        yaml.safe_dump(tenant_doc, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    click.echo(f"[bootstrap] Wrote {config_path}")
