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


def build_rule_index(client: DefenderClient) -> tuple[dict[str, str], set[str]]:
    """GET all rules once; return (displayName -> Graph ID map, set of Graph IDs).

    The id set lets apply match a YAML by its ``metadata.arm_name`` (the
    Graph id collect records) before falling back to displayName, so a
    rule renamed in YAML is PATCHed in place instead of re-created.

    Fails fast if duplicate displayNames are found.
    """
    rules = client.list_rules()
    name_map: dict[str, str] = {}
    graph_ids: set[str] = set()
    duplicates: list[str] = []

    for rule in rules:
        display_name = rule.get("displayName", "")
        graph_id = str(rule.get("id", ""))
        if graph_id:
            graph_ids.add(graph_id)
        if display_name in name_map:
            duplicates.append(display_name)
        else:
            name_map[display_name] = graph_id

    if duplicates:
        raise click.ClickException(
            f"Duplicate displayNames found in Defender API: {duplicates}. "
            f"Cannot safely deploy — resolve duplicates first."
        )

    return name_map, graph_ids


def build_display_name_map(client: DefenderClient) -> dict[str, str]:
    """GET all rules and build a displayName → Graph ID map.

    Fails fast if duplicate displayNames are found.
    """
    return build_rule_index(client)[0]


def resolve_graph_id(
    display_name: str,
    name_map: dict[str, str],
    *,
    arm_name: str | None = None,
    graph_ids: set[str] | None = None,
) -> str | None:
    """Return the Graph id an apply should PATCH, or None to create.

    ``arm_name`` (the Graph id collect stored in ``metadata.arm_name``)
    wins when that rule still exists, so a displayName edit renames the
    rule in place. Without it — or when the recorded rule is gone — fall
    back to the displayName match.
    """
    if arm_name and graph_ids is not None and arm_name in graph_ids:
        return arm_name
    return name_map.get(display_name) or None


def record_graph_id(
    display_name: str,
    graph_id: str,
    name_map: dict[str, str],
    graph_ids: set[str] | None = None,
) -> None:
    """Point ``display_name`` at ``graph_id`` for the rest of the run.

    Called after a create or rename so a later YAML in the same run with
    the same displayName PATCHes this rule instead of POSTing a second.
    """
    for name, gid in list(name_map.items()):
        if gid == graph_id and name != display_name:
            del name_map[name]
    name_map[display_name] = graph_id
    if graph_ids is not None:
        graph_ids.add(graph_id)


def deploy_defender_rule(
    client: DefenderClient,
    rule_id: str,
    payload: dict[str, Any],
    status: str,
    name_map: dict[str, str],
    dry_run: bool = False,
    *,
    arm_name: str | None = None,
    graph_ids: set[str] | None = None,
) -> dict[str, str]:
    """Deploy a single Defender rule via POST or PATCH.

    Returns a result dict with keys: id, platform, action, result.
    """
    # Deprecated rules get disabled remotely (``status: disabled``).
    body = to_defender_body(payload, deprecated=status == "deprecated")
    display_name = body.get("displayName", "")

    graph_id = resolve_graph_id(
        display_name, name_map, arm_name=arm_name, graph_ids=graph_ids,
    )

    if dry_run:
        action = "update" if graph_id else "create"
        click.echo(f"  [DRY-RUN] Would {action} defender rule: {rule_id} ({display_name})")
        return {"id": rule_id, "platform": "defender", "action": action, "result": "dry-run"}

    if graph_id:
        # Existing rule — PATCH
        response = client.update_rule(graph_id, body)
        if response.status_code == 200:
            action = "disabled" if status == "deprecated" else "updated"
            record_graph_id(display_name, graph_id, name_map, graph_ids)
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
        try:
            new_id = str((response.json() or {}).get("id") or "")
        except ValueError:
            new_id = ""
        if new_id:
            record_graph_id(display_name, new_id, name_map, graph_ids)
        click.echo(f"  created: {rule_id}")
        return {"id": rule_id, "platform": "defender", "action": "created", "result": "success"}

    logger.error(
        f"Failed to create defender rule {rule_id}: "
        f"{response.status_code} {response.text}"
    )
    return {"id": rule_id, "platform": "defender", "action": "create", "result": f"error-{response.status_code}"}
