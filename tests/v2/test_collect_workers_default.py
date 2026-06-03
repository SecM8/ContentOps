# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Test for the collect --workers default change (task #35).

Adopter test on 2026-05-18 showed that ``contentops collect`` defaulted
to 8 parallel workers, and on a Windows endpoint with Device Guard /
Application Control the bursty parallel ``az.cmd`` subprocess
invocations got throttled — many AzureCliCredential calls failed even
though single-process invocations worked fine.

Lowered to 4 as the new default. This test pins the value so an
accidental revert doesn't reintroduce the pathology.
"""

from __future__ import annotations

from click.testing import CliRunner


def test_collect_workers_default_is_four() -> None:
    """The Click `--workers` option defaults to 4 (not 8)."""
    from contentops.cli.commands.collect import collect_cmd as collect_command

    workers_param = next(
        p for p in collect_command.params if p.name == "workers"
    )
    assert workers_param.default == 4, (
        "collect --workers default should be 4 (lowered from 8 after "
        "2026-05 adopter test on a locked-down Windows endpoint)."
    )


def test_collect_help_mentions_workers_workaround() -> None:
    """The --help text should point adopters at `--workers 1` as the
    fallback for AzureCliCredential subprocess throttling."""
    runner = CliRunner()
    from contentops.cli.commands.collect import collect_cmd as collect_command

    result = runner.invoke(collect_command, ["--help"])
    assert result.exit_code == 0
    assert "--workers" in result.output
    # The help text refers to dropping to 1 worker; the exact phrasing
    # is flexible but "1" must appear so adopters know it's the fallback.
    assert "1" in result.output
