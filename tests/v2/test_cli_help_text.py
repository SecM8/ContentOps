# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Guard tests for adopter-facing CLI --help text.

Background: PRs #197–#200 (2026-05-18) changed behaviour that the
existing --help text didn't reflect, and added workarounds that
weren't reachable from the CLI. A targeted refresh of four help
strings fixed both. These tests pin the new wording so a future
refactor can't silently re-introduce the drift.
"""

from __future__ import annotations

from click.testing import CliRunner

from contentops.cli.commands.collect import collect_cmd
from contentops.cli.commands.doctor import doctor_cmd
from contentops.cli.commands.lint import lint_cmd
from contentops.cli.root import cli


def _help(command) -> str:
    """Invoke a Click command with --help and return its stdout."""
    runner = CliRunner()
    result = runner.invoke(command, ["--help"])
    assert result.exit_code == 0, result.output
    return result.output


def test_doctor_matrix_help_reflects_auto_pick_behaviour() -> None:
    """PR #197 changed --matrix from per-workspace iteration to a single
    auto-picked workspace + info note. The help text must match."""
    out = _help(doctor_cmd)
    assert "auto-pick" in out, (
        "doctor --help should mention the auto-pick behaviour; got:\n" + out
    )
    # The old wording is wrong and would mislead adopters.
    assert "iterates over every workspace" not in out, (
        "doctor --help still contains the stale 'iterates' wording"
    )


def test_collect_workers_help_points_at_token_credentials_workaround() -> None:
    """The --workers help already explains the Device-Guard / subprocess-
    throttling root cause. PR #200 added AZURE_TOKEN_CREDENTIALS=dev as
    the workaround for the related chain-ordering 401. The help must
    surface both fixes together so an adopter hitting either symptom
    finds the other."""
    out = _help(collect_cmd)
    assert "--workers" in out
    assert "AZURE_TOKEN_CREDENTIALS" in out, (
        "collect --help should reference the AZURE_TOKEN_CREDENTIALS "
        "workaround alongside the --workers throttling note; got:\n" + out
    )


def test_lint_help_points_at_generated_catalog() -> None:
    """PAYLOAD003/PAYLOAD004/META008/META009 landed in PR #197 and the
    rule registry will keep growing. Rather than enumerate rules in
    --help (which would drift again), the docstring points at the
    auto-regenerated catalog as the canonical source of truth."""
    out = _help(lint_cmd)
    assert "generated-catalog.md" in out, (
        "lint --help should point at docs/reference/generated-catalog.md "
        "as the canonical rule registry; got:\n" + out
    )


def test_root_group_help_clarifies_role_vs_workspace() -> None:
    """Adopters routinely confuse --role (matches multiple) with
    --workspace (matches one). The top-level group docstring now
    explains both so it's visible from `contentops --help`."""
    out = _help(cli)
    assert "--role" in out
    assert "--workspace" in out
    # The clarifier mentions both targeting and mutual exclusivity.
    assert "mutually exclusive" in out, (
        "root --help should explain --role and --workspace are mutually "
        "exclusive; got:\n" + out
    )
