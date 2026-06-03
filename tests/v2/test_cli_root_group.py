# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the root Click ``cli`` group layout.

Pins two invariants:

* The root group lives in ``contentops.cli.root`` and is re-exported as
  ``contentops.cli.cli`` — same object, no duplicate group.
* The legacy v1 commands (``validate``, ``deploy``, ``diff``,
  ``delete``) are NOT registered. R4 of the v1 retirement plan
  removed them along with ``contentops/cli/legacy.py``; this assertion
  fails closed if a future PR accidentally restores the side-effect
  import.
* ``cli.commands['collect']`` resolves to the v2 ``collect_cmd``.
"""

from __future__ import annotations

import contentops.cli as cli_pkg
from contentops.cli.commands import collect_cmd as v2_collect
from contentops.cli.root import cli as root_cli


def test_root_module_owns_the_cli_group() -> None:
    """``contentops.cli.cli`` is the same object as ``contentops.cli.root.cli``."""
    assert cli_pkg.cli is root_cli


def test_legacy_v1_commands_are_not_registered() -> None:
    """R4 removed the v1 command bodies. None of them should be reachable."""
    commands = cli_pkg.cli.commands
    for name in ("validate", "deploy", "diff", "delete"):
        assert name not in commands, (
            f"legacy v1 command {name!r} is registered — the v1 verbs "
            "(validate/deploy/diff/delete) were removed in R4 of the v1 "
            "hard cut. A side-effect import of contentops.cli.legacy may "
            "have been reintroduced."
        )


def test_collect_resolves_to_v2_implementation() -> None:
    """``cli.commands['collect']`` is the v2 ``collect_cmd``."""
    registered = cli_pkg.cli.commands.get("collect")
    assert registered is v2_collect
