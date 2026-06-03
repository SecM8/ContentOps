# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``pipeline test`` command.

Module named ``test_runner`` (not ``test``) so pytest collection
doesn't accidentally treat this command module as a test module.
"""

from __future__ import annotations

import os
import sys

import click

from contentops.devex.doctor import (
    aggregate_exit_code,
    format_results,
    run_checks,
)


@click.command("test")
@click.option(
    "--live", is_flag=True, default=False,
    help="Run the live integration suite against the configured tenant. Requires .env / OIDC credentials.",
)
@click.option(
    "-k", "keyword",
    default=None,
    help="Pytest -k expression filter.",
)
def test_cmd(live: bool, keyword: str | None) -> None:
    """Run pytest with sensible defaults.

    Without --live: unit suite (excludes tests/integration/).

    With --live: runs `contentops doctor --matrix` first; aborts if
    any check FAILs (warnings are tolerated). Then pytest
    tests/integration/ with RUN_LIVE_TESTS=1 set; per-handler
    progress; pytest fixtures handle teardown (zz-itest- prefix
    sweep on session end).
    """
    import subprocess

    args: list[str] = []
    env = dict(os.environ)
    if live:
        click.echo("Running contentops doctor --matrix before live tests...")
        results = run_checks(with_auth=True, with_matrix=True)
        click.echo(format_results(results))
        if aggregate_exit_code(results) != 0:
            click.echo("\nDoctor reports FAIL — refusing to run live tests.", err=True)
            sys.exit(1)
        click.echo("\nDoctor green; running live integration suite.")
        env["RUN_LIVE_TESTS"] = "1"
        args = ["-m", "pytest", "-v", "tests/integration/"]
    else:
        args = ["-m", "pytest", "-q", "--ignore=tests/integration"]

    if keyword:
        args.extend(["-k", keyword])

    cmd = [sys.executable, *args]
    click.echo(f"$ {' '.join(cmd)}\n")
    try:
        result = subprocess.run(cmd, env=env, timeout=600)
    except subprocess.TimeoutExpired:
        click.echo("test run timed out after 600s", err=True)
        sys.exit(2)
    sys.exit(result.returncode)
