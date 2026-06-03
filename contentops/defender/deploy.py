# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Defender deployment logic — POST/PATCH rules via Graph Security Beta API."""

from __future__ import annotations

import logging
from typing import Any

import click

from contentops.defender.client import DefenderClient
from contentops.utils.yaml_io import to_defender_body

logger = logging.getLogger(__name__)


def build_display_name_map(client: DefenderClient) -> dict[str, str]:
    """GET all rules and build a displayName → Graph ID map.

    Fails fast if duplicate displayNames are found.
    """
    rules = client.list_rules()
    name_map: dict[str, str] = {}
    duplicates: list[str] = []

    for rule in rules:
        display_name = rule.get("displayName", "")
        graph_id = str(rule.get("id", ""))
        if display_name in name_map:
            duplicates.append(display_name)
        else:
            name_map[display_name] = graph_id

    if duplicates:
        raise click.ClickException(
            f"Duplicate displayNames found in Defender API: {duplicates}. "
            f"Cannot safely deploy — resolve duplicates first."
        )

    return name_map


def deploy_defender_rule(
    client: DefenderClient,
    rule_id: str,
    payload: dict[str, Any],
    status: str,
    name_map: dict[str, str],
    dry_run: bool = False,
) -> dict[str, str]:
    """Deploy a single Defender rule via POST or PATCH.

    Returns a result dict with keys: id, platform, action, result.
    """
    body = to_defender_body(payload)
    display_name = body.get("displayName", "")

    # Deprecated rules get disabled remotely
    if status == "deprecated":
        body["isEnabled"] = False

    if dry_run:
        action = "update" if display_name in name_map else "create"
        click.echo(f"  [DRY-RUN] Would {action} defender rule: {rule_id} ({display_name})")
        return {"id": rule_id, "platform": "defender", "action": action, "result": "dry-run"}

    graph_id = name_map.get(display_name)

    if graph_id:
        # Existing rule — PATCH
        response = client.update_rule(graph_id, body)
        if response.status_code == 200:
            action = "disabled" if status == "deprecated" else "updated"
            click.echo(f"  {action}: {rule_id} (graph:{graph_id})")
            return {"id": rule_id, "platform": "defender", "action": action, "result": "success"}
        logger.error(
            f"Failed to update defender rule {rule_id}: "
            f"{response.status_code} {response.text}"
        )
        return {"id": rule_id, "platform": "defender", "action": "update", "result": f"error-{response.status_code}"}

    # New rule — POST
    response = client.create_rule(body)
    if response.status_code == 201:
        click.echo(f"  created: {rule_id}")
        return {"id": rule_id, "platform": "defender", "action": "created", "result": "success"}

    logger.error(
        f"Failed to create defender rule {rule_id}: "
        f"{response.status_code} {response.text}"
    )
    return {"id": rule_id, "platform": "defender", "action": "create", "result": f"error-{response.status_code}"}
