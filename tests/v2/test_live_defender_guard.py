# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live Defender tests write to the production tenant (Defender is
tenant-wide). Every one must go through ``confirmed_defender_client``,
which skips unless the run confirmed that (``i-know-this-hits-prod``),
and the rules they create must be unable to raise an alert.

The CRUD test used ``defender_client`` directly, so a ``run-integration``
label on a pull request created a rule without that confirmation. Its body
sent ``isEnabled: false`` (a key Graph dropped, so the rule was enabled)
and a query that returns rows.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "integration"


def _test_functions():
    for path in sorted(INTEGRATION_DIR.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                yield path.name, node.name, {a.arg for a in node.args.args}


@pytest.mark.parametrize(("module", "name", "args"), list(_test_functions()), ids=lambda v: v if isinstance(v, str) else "")
def test_no_live_test_uses_the_unconfirmed_defender_client(module: str, name: str, args: set[str]) -> None:
    assert "defender_client" not in args, f"{module}::{name} must request confirmed_defender_client"


def test_the_created_rules_fixture_needs_the_confirmation() -> None:
    tree = ast.parse((INTEGRATION_DIR / "conftest.py").read_text(encoding="utf-8"))
    fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "created_defender_rules")
    assert [a.arg for a in fixture.args.args] == ["confirmed_defender_client"]


def test_the_crud_rule_cannot_raise_an_alert() -> None:
    from tests.integration.defender_shape_probe import QUERY
    from tests.integration.test_defender_custom_detection_crud import _detection_body

    body = _detection_body("zz_itest_x")
    assert body["status"] == "disabled"
    assert "isEnabled" not in body
    assert body["queryCondition"]["queryText"] == QUERY
