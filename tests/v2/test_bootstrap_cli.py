# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the `contentops bootstrap` CLI.

Live API call paths are not covered here — they're exercised by the
integration suite. The dry-run path is enough to verify the command
resolves its options correctly and constructs the right config-file
target path per env slug.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from contentops.cli import cli


def test_bootstrap_dry_run_no_env() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "bootstrap",
            "--subscription", "11111111-1111-1111-1111-111111111111",
            "--resource-group", "rg-x",
            "--workspace", "ws-x",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "config/tenant.yml" in result.output
    assert "Sentinel" in result.output


def test_bootstrap_dry_run_with_env_slug() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "bootstrap",
            "--subscription", "11111111-1111-1111-1111-111111111111",
            "--resource-group", "rg-x",
            "--workspace", "ws-x",
            "--location", "eastus",
            "--env", "dev",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "config/tenant.dev.yml" in result.output
    assert "eastus" in result.output


def test_bootstrap_required_flags_enforced() -> None:
    result = CliRunner().invoke(cli, ["bootstrap", "--dry-run"])
    assert result.exit_code != 0
    assert "Missing option" in result.output or "Error" in result.output
