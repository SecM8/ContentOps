# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pin the skip logic of ``production-promotion-check.yml``.

The gate must skip collect / drift PRs on two signals: the PR head
branch (``collect/*``, ``drift/auto-*``) and the head commit subject
(``chore(collect|drift):``). The branch signal is what survives
GitHub's *Update branch* button, which adds a ``Merge branch 'main'
into collect/...`` head commit that never matches the subject regex and
used to fail the gate on every unstamped collected rule.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github" / "workflows" / "production-promotion-check.yml"
)


def _gate_step() -> dict:
    with WORKFLOW.open(encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    steps = [s for job in wf["jobs"].values() for s in job.get("steps", [])]
    gate = [s for s in steps if s.get("id") == "gate"]
    assert len(gate) == 1, "expected exactly one step with id: gate"
    return gate[0]


def test_gate_receives_head_ref_through_env() -> None:
    step = _gate_step()
    assert step["env"]["HEAD_REF"] == "${{ github.head_ref }}"
    assert step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    # hardening: the expression must not be expanded inside the script
    assert "${{ github.head_ref }}" not in step["run"]


def test_gate_skips_on_branch_and_on_subject() -> None:
    run = _gate_step()["run"]
    assert "collect/*|drift/auto-*" in run
    assert "chore\\((collect|drift)\\):" in run
    assert run.count('echo "skip=true" >> "$GITHUB_OUTPUT"') == 2


def test_downstream_steps_are_gated() -> None:
    with WORKFLOW.open(encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    steps = [s for job in wf["jobs"].values() for s in job.get("steps", [])]
    after_gate = steps[[s.get("id") for s in steps].index("gate") + 1:]
    assert after_gate, "steps must follow the gate"
    for s in after_gate:
        assert "steps.gate.outputs.skip != 'true'" in str(s.get("if", "")), s.get("name")
