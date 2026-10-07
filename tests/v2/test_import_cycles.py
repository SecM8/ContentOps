# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Each coverage-related module imports cleanly on its own.

The coverage engine is shared by the report, Navigator, portfolio and
alert-health code. A circular import only shows up when a module is the
*first* one imported in a process, so each is imported in a fresh
interpreter.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

MODULES = [
    "contentops.coverage",
    "contentops.coverage.corpus",
    "contentops.coverage.gaps",
    "contentops.coverage.sources",
    "contentops.coverage.matrix",
    "contentops.report",
    "contentops.report.assemble",
    "contentops.report.enrich",
    "contentops.navigator",
    "contentops.portfolio",
    "contentops.alerts.detection_health",
    "contentops.cli.commands.coverage",
    "contentops.rule_keys",
    "contentops.tuning",
    "contentops.lifecycle",
    "contentops.explain",
    "contentops.docs.render",
]


@pytest.mark.parametrize("module", MODULES)
def test_module_imports_first_in_a_fresh_process(module: str) -> None:
    result = subprocess.run(  # noqa: S603 -- fixed interpreter + module list
        [sys.executable, "-c", f"import {module}"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
