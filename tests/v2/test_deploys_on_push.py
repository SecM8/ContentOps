# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``scripts/deploys_on_push.py``: does this repository deploy on push?

The emergency-disable PR said "deploy.yml will roll the change to the
tenant on push-to-main". A deployment repo that deploys by hand (push
trigger commented out) got the same promise, and a merged disable sat
undeployed while the rule kept alerting. The PR now says which applies.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _script():
    spec = importlib.util.spec_from_file_location(
        "deploys_on_push", REPO_ROOT / "scripts" / "deploys_on_push.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(("text", "expected"), [
    ("on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n", True),
    ("on:\n  # push:\n  #   branches: [main]\n  workflow_dispatch:\n", False),
    ("on: [push, workflow_dispatch]\n", True),
    ("on: workflow_dispatch\n", False),
    ("on: push\n", True),
])
def test_reads_the_deploy_trigger(tmp_path: Path, text: str, expected: bool) -> None:
    wf = tmp_path / "deploy.yml"
    wf.write_text("name: Deploy\n" + text + "jobs: {}\n", encoding="utf-8")
    assert _script().deploys_on_push(wf) is expected


def test_a_missing_or_broken_workflow_reads_as_no_push_deploy(tmp_path: Path) -> None:
    mod = _script()
    assert mod.deploys_on_push(tmp_path / "absent.yml") is False
    broken = tmp_path / "deploy.yml"
    broken.write_text("on: [push\n", encoding="utf-8")
    assert mod.deploys_on_push(broken) is False


# No assertion on this repository's own deploy.yml: a deployment fork with
# the push trigger commented out must pass the same suite.


def test_the_emergency_pr_body_uses_the_check() -> None:
    """And it says how to deploy by hand: an empty ``changed_since`` is a
    full apply, which mid-incident re-sends every detection."""
    raw = (REPO_ROOT / ".github" / "workflows" / "emergency-disable.yml").read_text(encoding="utf-8")
    assert "scripts/deploys_on_push.py" in raw
    text = raw.replace("\\`", "`")  # the shell string escapes its backticks
    assert "run **Deploy to production** on `main` with `changed_since`" in text
    assert "An empty `changed_since` re-applies every detection" in text


@pytest.mark.parametrize("path", [
    "docs/operations/team-routine.md",
    "docs/emergency-disable-workflow.md",
    ".github/actions/refuse-stale-rerun/action.yml",
    "contentops/upstream/drift_pr.py",
])
def test_every_hint_to_deploy_by_hand_names_changed_since(path: str) -> None:
    assert "changed_since" in (REPO_ROOT / path).read_text(encoding="utf-8"), path
