# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Patterns of the repository's own gitleaks rules (``.gitleaks.toml``).

gitleaks uses Go's RE2; the patterns checked here use only syntax that
Python's ``re`` reads the same way.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
# All-zero: the gitleaks allowlist exempts it, so this file never trips a scan.
_GUID = "00000000-0000-0000-0000-000000000000"


def _rule(rule_id: str) -> re.Pattern[str]:
    config = tomllib.loads((REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    rule = next(r for r in config["rules"] if r["id"] == rule_id)
    return re.compile(rule["regex"])


@pytest.mark.parametrize(
    "text",
    [
        f"tenantId: {_GUID}",
        f"subscriptionId: '{_GUID}'",
        f'"tenantId": "{_GUID}"',
        f'"subscriptionId":"{_GUID}"',
        f"'logicAppResourceId': '{_GUID}'",
        f'"id": "/subscriptions/{_GUID}/resourceGroups/rg"',
    ],
    ids=["yaml", "yaml-quoted-value", "json", "json-no-space", "quoted-key", "arm-id"],
)
def test_support_asset_rule_catches_a_guid_in_yaml_and_json(text: str) -> None:
    """A playbook's ``.workflow.json`` sidecar is JSON: ``"tenantId": "<guid>"``
    slipped past the rule because the key's closing quote stood before the
    colon."""
    assert _rule("azure-guid-in-support-asset-envelope").search(text)


@pytest.mark.parametrize(
    "text",
    ['"tenantId": "[parameters(\'tenantId\')]"', "playbook: my-playbook", "tenantId: ''"],
    ids=["expression", "envelope-reference", "empty"],
)
def test_support_asset_rule_leaves_values_without_a_guid_alone(text: str) -> None:
    assert not _rule("azure-guid-in-support-asset-envelope").search(text)
