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


class _LaggingGraph:
    """Graph whose list serves a new rule a few calls after it was created
    (seen in the lab: the create, read and update were done in 5 s and the
    list did not have the rule yet)."""

    def __init__(self, list_lag: int) -> None:
        self.rules: dict[str, dict] = {}
        self.list_lag = list_lag

    def create_rule(self, body: dict):
        rule = {**body, "id": "28770"}
        self.rules["28770"] = rule
        return _Response(201, rule)

    def get_rule(self, graph_id: str):
        return self.rules.get(graph_id)

    def update_rule(self, graph_id: str, body: dict):
        self.rules[graph_id] = {**self.rules[graph_id], **body}
        return _Response(200, self.rules[graph_id])

    def list_rules(self):
        if self.list_lag:
            self.list_lag -= 1
            return []
        return list(self.rules.values())

    def delete_rule(self, graph_id: str):
        self.rules.pop(graph_id, None)
        return _Response(204, None)


class _Response:
    def __init__(self, code: int, body) -> None:
        self.status_code = code
        self._body = body
        self.text = ""

    def json(self):
        return self._body


def test_the_crud_test_waits_for_the_list_as_for_the_other_reads(monkeypatch) -> None:
    import tests.integration.test_defender_custom_detection_crud as crud

    monkeypatch.setattr(crud.time, "sleep", lambda *_: None)
    created: list[str] = []
    crud.test_defender_custom_detection_full_crud(_LaggingGraph(list_lag=2), "zz-itest-1", created)
    assert created == []  # deleted and released
