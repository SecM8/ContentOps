# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""The kind kill switch (``CONTENTOPS_DISABLED_KINDS``) and the live suite.

The live tests build their own clients, so the switch did not reach them:
with ``defender_custom_detection`` switched off, the shape probe still
created, updated and deleted rules. Each live test module now declares
the kinds it writes (``LIVE_KINDS``), and a test whose kind is switched
off is skipped unless the run sets ``CONTENTOPS_LIVE_IGNORE_KILL_SWITCH=1``
(``integration.yml`` input ``ignore-kill-switch``), which keeps the probe
available to find out why a kind had to be switched off.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from contentops.core.asset import Asset
from tests.integration.kill_switch import ALL_KINDS, kinds_for, skip_reason

INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "integration"
LIVE_MODULES = sorted(INTEGRATION_DIR.glob("test_*.py"))


def _declared(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) and node.value is not None else []
        )
        if any(isinstance(t, ast.Name) and t.id == "LIVE_KINDS" for t in targets):
            return ast.literal_eval(node.value), {
                n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
            }
    return None, set()


@pytest.mark.parametrize("path", LIVE_MODULES, ids=lambda p: p.name)
def test_every_live_test_module_declares_the_kinds_it_writes(path: Path) -> None:
    declared, tests = _declared(path)
    assert declared is not None, f"{path.name} has no LIVE_KINDS"
    valid = {a.value for a in Asset}
    if isinstance(declared, dict):
        assert set(declared) == tests, f"{path.name}: LIVE_KINDS keys must be its test functions"
        values = [k for kinds in declared.values() for k in kinds]
    else:
        values = list(declared)
    assert set(values) <= valid, f"{path.name}: unknown kind in LIVE_KINDS"


def test_a_test_of_a_switched_off_kind_is_skipped() -> None:
    reason = skip_reason(("defender_custom_detection",), frozenset({"defender_custom_detection"}), override=False)
    assert reason is not None and "CONTENTOPS_DISABLED_KINDS" in reason and "ignore-kill-switch" in reason


def test_other_kinds_and_read_only_tests_still_run() -> None:
    assert skip_reason(("sentinel_analytic",), frozenset({"defender_custom_detection"}), override=False) is None
    assert skip_reason((), frozenset({"defender_custom_detection"}), override=False) is None


def test_the_override_runs_a_switched_off_kind() -> None:
    assert skip_reason(("defender_custom_detection",), frozenset({"defender_custom_detection"}), override=True) is None


def test_kinds_per_test_and_undeclared_modules() -> None:
    class Mod:
        LIVE_KINDS = {"test_a": ("sentinel_analytic",), "test_b": ("defender_custom_detection",)}

    class Whole:
        LIVE_KINDS = ("sentinel_parser",)

    class Undeclared:
        pass

    assert kinds_for(Mod, "test_b") == ("defender_custom_detection",)
    assert kinds_for(Whole, "test_x") == ("sentinel_parser",)
    # Fail safe: a module that does not say what it writes counts as writing everything.
    assert kinds_for(Undeclared, "test_x") == ALL_KINDS


def test_the_sweeps_are_never_skipped_by_the_kill_switch() -> None:
    """The sweeps only delete ``zz-itest-`` / ``zz_itest_`` test leftovers.
    Declaring Defender let a switched-off Defender kind (exactly when the
    probe runs with ignore-kill-switch) skip the Defender sweep, and a
    sweep-only run went green with test rules left in the tenant."""
    import tests.integration.test_sweep_leftovers as sweep
    from tests.integration.kill_switch import kinds_for

    for name in ("test_sweep_leftover_defender_rules", "test_sweep_leftover_sentinel_rules",
                 "test_sweep_leftover_saved_searches"):
        assert kinds_for(sweep, name) == (), name
