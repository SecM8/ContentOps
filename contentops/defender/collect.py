# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Collect Defender rules from live environment → YAML files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import click

from contentops.defender.client import DefenderClient
from contentops.utils.yaml_io import _sanitize_filename, dump_rule

READ_ONLY_FIELDS = {
    "createdBy", "createdDateTime", "lastModifiedDateTime", "lastModifiedBy",
    "detectorId", "lastRunDetails", "id",
}

READ_ONLY_NESTED = {
    "queryCondition": {"lastModifiedDateTime"},
    "schedule": {"nextRunDateTime"},
}


def _slugify(name: str) -> str:
    """Convert a display name to a slug ID."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return f"defender-{slug}"


def _strip_read_only(data: dict[str, Any]) -> dict[str, Any]:
    """Remove read-only fields from the API response."""
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        if key in READ_ONLY_FIELDS:
            continue
        if key in READ_ONLY_NESTED and isinstance(value, dict):
            nested_ro = READ_ONLY_NESTED[key]
            value = {k: v for k, v in value.items() if k not in nested_ro}
        cleaned[key] = value
    return cleaned


def collect_defender_rules(
    client: DefenderClient,
    output_dir: Path,
) -> list[Path]:
    """Collect all Defender detection rules, write to YAML.

    Returns the list of file paths written.
    """
    all_rules = client.list_rules()
    written: list[Path] = []

    for rule in all_rules:
        display_name = rule.get("displayName", "unknown")
        slug = _slugify(display_name)

        payload = _strip_read_only(rule)

        pipeline_fields = {
            "id": slug,
            "version": "0.0.0",
            "platform": "defender",
            "status": "production",
        }

        filename = _sanitize_filename(display_name)
        file_path = output_dir / "defender" / f"{filename}.yml"
        dump_rule(file_path, pipeline_fields, payload)
        written.append(file_path)
        click.echo(f"  collected: {filename}")

    return written
