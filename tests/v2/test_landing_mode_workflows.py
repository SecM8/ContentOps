# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Static checks on the opt-in PR-landing mode and the auto-pr token path.

Three workflows land generated output on ``main``: ``status-refresh.yml``
(``docs/status/``), ``coverage.yml`` (Navigator layer + badge) and
``report.yml`` (``reports/``). Each has two mutually exclusive landing
steps selected by the repo variable ``CONTENTOPS_LAND_VIA_PR``:

* unset / not ``'true'`` -> the historical direct ``git push origin
  HEAD:main`` (upstream default);
* ``'true'`` -> the shared ``.github/actions/auto-pr`` composite action on
  a FIXED rolling branch, for deployments whose rulesets reject direct
  pushes.

These tests parse the YAML and pin the contract: both steps exist, they
are exclusive on the toggle, the event restrictions that existed before
are preserved on both, the PR step commits only the intended paths, and
every auto-pr caller declares which token it resolved (``token-source``)
so the action can warn about the silent ``GITHUB_TOKEN`` fallback.

Source-repo only: adopter forks are free to customise these workflows, so
the suite skips off-source (same sentinel as the catalog drift gate).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from contentops.config import is_operator_source_repo

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
AUTO_PR_ACTION = REPO_ROOT / ".github" / "actions" / "auto-pr" / "action.yml"
AUTO_PR_USES = "./.github/actions/auto-pr"

pytestmark = pytest.mark.skipif(
    not is_operator_source_repo(REPO_ROOT),
    reason="source-repo workflow contract; skipped off-source "
           "(public mirror / adopter clone may customise these workflows)",
)

TOKEN_EXPR = "${{ secrets.AUTO_PR_TOKEN || secrets.GITHUB_TOKEN }}"
TOKEN_SOURCE_EXPR = (
    "${{ secrets.AUTO_PR_TOKEN != '' && 'AUTO_PR_TOKEN' || 'GITHUB_TOKEN' }}"
)
TOGGLE_ON = "vars.CONTENTOPS_LAND_VIA_PR == 'true'"
TOGGLE_OFF = "vars.CONTENTOPS_LAND_VIA_PR != 'true'"
MAIN_PUSH_GUARD = "github.event_name == 'push' && github.ref == 'refs/heads/main'"
DIRECT_PUSH = "git push origin HEAD:main"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# The landing contract per workflow. ``event_guard`` is the pre-existing
# restriction both landing steps must keep (None = every run of the job
# lands; the job-level ``if:`` gates the schedule there).
LANDING = {
    "status-refresh.yml": {
        "job": "refresh",
        "branch": "status/refresh",
        "detect": "docs/status",
        "add_paths": {"docs/status/**"},
        "direct_add": "git add docs/status/",
        "event_guard": None,
        "triggers": {"schedule", "workflow_dispatch"},
        "push_paths": None,
        "permissions": {
            "contents": "write",
            "pull-requests": "write",
            "id-token": "write",
        },
    },
    "coverage.yml": {
        "job": "coverage",
        "branch": "coverage/refresh",
        "detect": "coverage",
        "add_paths": {"coverage/navigator-layer.json", "coverage/badge.json"},
        "direct_add": "git add coverage/navigator-layer.json coverage/badge.json",
        "event_guard": MAIN_PUSH_GUARD,
        "triggers": {"pull_request", "push", "workflow_dispatch"},
        "push_paths": {"detections/**", "contentops/**"},
        "permissions": {"contents": "write", "pull-requests": "write"},
    },
    "report.yml": {
        "job": "report",
        "branch": "report/refresh",
        "detect": "reports",
        "add_paths": {"reports/**"},
        "direct_add": "git add reports/",
        "event_guard": MAIN_PUSH_GUARD,
        "triggers": {"schedule", "push", "workflow_dispatch"},
        "push_paths": {
            "detections/**",
            "contentops/report/**",
            "contentops/coverage/**",
            "contentops/cli/commands/report.py",
            ".github/workflows/report.yml",
        },
        "permissions": {"contents": "write", "pull-requests": "write"},
    },
}


def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _triggers(wf: dict) -> dict:
    # PyYAML parses a bare ``on:`` key as the boolean True.
    return wf.get("on", wf.get(True))


def _steps(name: str) -> list[dict]:
    wf = _load(WORKFLOWS / name)
    return wf["jobs"][LANDING[name]["job"]]["steps"]


def _direct_steps(steps: list[dict]) -> list[dict]:
    return [s for s in steps if DIRECT_PUSH in (s.get("run") or "")]


def _pr_steps(steps: list[dict]) -> list[dict]:
    return [s for s in steps if s.get("uses") == AUTO_PR_USES]


def _split_paths(value: str) -> set[str]:
    return {line.strip() for line in value.splitlines() if line.strip()}


@pytest.fixture(params=sorted(LANDING))
def landing(request) -> tuple[str, dict]:
    return request.param, LANDING[request.param]


# ---------------------------------------------------------------------------
# The three landing workflows
# ---------------------------------------------------------------------------


def test_exactly_one_direct_and_one_pr_landing_step(landing) -> None:
    name, _ = landing
    steps = _steps(name)
    assert len(_direct_steps(steps)) == 1, f"{name}: expected one direct-push step"
    assert len(_pr_steps(steps)) == 1, f"{name}: expected one auto-pr step"


def test_landing_steps_are_mutually_exclusive_on_the_toggle(landing) -> None:
    name, spec = landing
    steps = _steps(name)
    direct_if = str(_direct_steps(steps)[0].get("if", ""))
    pr_if = str(_pr_steps(steps)[0].get("if", ""))
    assert TOGGLE_OFF in direct_if, f"{name}: direct step must be gated on {TOGGLE_OFF}"
    assert TOGGLE_ON in pr_if, f"{name}: PR step must be gated on {TOGGLE_ON}"
    assert TOGGLE_ON not in direct_if and TOGGLE_OFF not in pr_if


def test_pre_existing_event_restriction_is_kept_on_both_steps(landing) -> None:
    name, spec = landing
    steps = _steps(name)
    direct_if = str(_direct_steps(steps)[0].get("if", ""))
    pr_if = str(_pr_steps(steps)[0].get("if", ""))
    if spec["event_guard"] is None:
        # status-refresh lands on every run; the schedule gate lives on the
        # job. Neither step may grow an event restriction of its own.
        assert "github.event_name" not in direct_if and "github.event_name" not in pr_if
        job_if = _load(WORKFLOWS / name)["jobs"][spec["job"]]["if"]
        assert "vars.CONTENTOPS_SCHEDULES == 'true'" in job_if
    else:
        assert spec["event_guard"] in direct_if, f"{name}: direct step lost its event guard"
        assert spec["event_guard"] in pr_if, (
            f"{name}: PR mode must not write back on new event types"
        )


def test_pr_step_uses_fixed_rolling_branch_and_scoped_paths(landing) -> None:
    name, spec = landing
    pr = _pr_steps(_steps(name))[0]
    with_ = pr["with"]
    assert with_["branch"] == spec["branch"], f"{name}: rolling branch must be fixed"
    assert "${{" not in with_["branch"], f"{name}: a per-run branch would open a PR per run"
    assert with_["detect-paths"] == spec["detect"]
    assert _split_paths(str(with_["add-paths"])) == spec["add_paths"], (
        f"{name}: add-paths must match the workflow's intended outputs only"
    )
    assert with_["token"] == TOKEN_EXPR
    assert with_["token-source"] == TOKEN_SOURCE_EXPR
    assert str(with_["labels"]).endswith(",automated")
    assert with_["commit-message"].startswith("chore(")


def test_direct_step_stages_only_intended_paths(landing) -> None:
    name, spec = landing
    run = _direct_steps(_steps(name))[0]["run"]
    assert spec["direct_add"] in run
    assert "git add -A" not in run and "git add ." not in run
    # Both the no-diff and the pushed branch report the landing mode.
    assert "GITHUB_STEP_SUMMARY" in run and "landing mode: direct push" in run


def test_pr_mode_has_a_summary_step(landing) -> None:
    name, _ = landing
    steps = _steps(name)
    summaries = [
        s for s in steps
        if s.get("name", "").startswith("Step summary (PR-landing mode)")
    ]
    assert len(summaries) == 1, f"{name}: PR mode must report mode + outcome"
    assert TOGGLE_ON in str(summaries[0].get("if", ""))
    run = summaries[0]["run"]
    for marker in ("landing mode: rolling PR", "no changes", "Token source"):
        assert marker in run, f"{name}: summary lacks {marker!r}"


def test_triggers_and_path_filters_unchanged(landing) -> None:
    name, spec = landing
    wf = _load(WORKFLOWS / name)
    triggers = _triggers(wf)
    assert set(triggers) == spec["triggers"], f"{name}: trigger set changed"
    if spec["push_paths"] is not None:
        assert set(triggers["push"]["paths"]) == spec["push_paths"]
        assert triggers["push"]["branches"] == ["main"]


def test_permissions_are_exact(landing) -> None:
    name, spec = landing
    wf = _load(WORKFLOWS / name)
    assert wf["permissions"] == spec["permissions"], (
        f"{name}: permissions drifted from the documented set"
    )


def test_no_pull_request_target_and_actions_pinned(landing) -> None:
    name, _ = landing
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    assert "pull_request_target" not in text
    for step in _steps(name):
        uses = step.get("uses")
        if not uses or uses.startswith("./"):
            continue
        ref = uses.split("@", 1)[1]
        assert SHA_RE.match(ref), f"{name}: {uses} must be pinned to a 40-char SHA"


def test_direct_push_is_the_only_write_to_main(landing) -> None:
    name, _ = landing
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    assert text.count(DIRECT_PUSH) == 1, (
        f"{name}: exactly one direct push to main (the default-mode step)"
    )


# ---------------------------------------------------------------------------
# The auto-pr composite action
# ---------------------------------------------------------------------------


def test_auto_pr_token_source_input_is_optional() -> None:
    action = _load(AUTO_PR_ACTION)
    inp = action["inputs"]["token-source"]
    assert inp.get("required") is False
    assert inp.get("default") == ""
    assert action["inputs"]["token"]["required"] is True


def test_auto_pr_reports_token_source_before_opening_the_pr() -> None:
    action = _load(AUTO_PR_ACTION)
    steps = action["runs"]["steps"]
    names = [s["name"] for s in steps]
    assert names.index("Report token source") < names.index(
        "Open PR (peter-evans/create-pull-request)"
    )
    report = steps[names.index("Report token source")]
    assert report["if"] == "steps.tree.outputs.changed == 'true'"
    assert report["env"]["TOKEN_SOURCE"] == "${{ inputs.token-source }}"
    run = report["run"]
    for marker in (
        "::warning::", "GITHUB_STEP_SUMMARY", "AUTO_PR_TOKEN",
        "Approve and run", "undeclared",
    ):
        assert marker in run, f"auto-pr token report lacks {marker!r}"
    # Informational only: no exit on fallback.
    assert "exit 1" not in run


def test_auto_pr_outputs_and_signoff() -> None:
    action = _load(AUTO_PR_ACTION)
    assert {"changed", "pull-request-number", "pull-request-operation", "token-source"} <= set(
        action["outputs"]
    )
    cpr = [s for s in action["runs"]["steps"] if s.get("id") == "cpr"][0]
    assert cpr["with"]["signoff"] is True
    assert cpr["with"]["token"] == "${{ inputs.token }}"
    assert cpr["uses"].startswith("peter-evans/create-pull-request@")
    assert SHA_RE.match(cpr["uses"].split("@", 1)[1])


def test_auto_pr_never_references_the_secrets_context() -> None:
    # Composite actions have no ``secrets`` context; a literal
    # ``${{ secrets.* }}`` in action metadata fails at load time
    # (CLAUDE.md invariant 6). Comments are stripped before scanning.
    active = "\n".join(
        line for line in AUTO_PR_ACTION.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "${{ secrets." not in active


def test_every_auto_pr_caller_declares_its_token_source() -> None:
    callers = []
    for wf_path in sorted(WORKFLOWS.glob("*.yml")):
        wf = _load(wf_path)
        for job in wf.get("jobs", {}).values():
            for step in job.get("steps", []):
                if step.get("uses") == AUTO_PR_USES:
                    callers.append((wf_path.name, step))
    assert len(callers) >= 9, f"expected the nine auto-pr callers, found {len(callers)}"
    for name, step in callers:
        with_ = step["with"]
        assert with_["token"] == TOKEN_EXPR, f"{name}: token must fall back to GITHUB_TOKEN"
        assert with_["token-source"] == TOKEN_SOURCE_EXPR, (
            f"{name}: caller must declare token-source so the fallback is visible"
        )


def test_emergency_disable_reports_token_source() -> None:
    wf = _load(WORKFLOWS / "emergency-disable.yml")
    steps = wf["jobs"]["disable"]["steps"]
    names = [s.get("name", "") for s in steps]
    assert names.index("Report token source") < names.index("Open PR (manual merge required)")
    report = steps[names.index("Report token source")]
    assert report["env"]["TOKEN_SOURCE"] == TOKEN_SOURCE_EXPR
    assert "::warning::" in report["run"] and "AUTO_PR_TOKEN" in report["run"]
    opener = steps[names.index("Open PR (manual merge required)")]
    assert opener["env"]["GH_TOKEN"] == TOKEN_EXPR


def test_status_refresh_never_lands_from_a_non_main_ref() -> None:
    """status-refresh runs on dispatch from any ref; both landing modes
    push generated output to main, so each landing step must also be
    gated on the ref being main. Found 2026-10-18 when a dispatch from a
    feature branch tried `git push origin HEAD:main` (only a non-fast-
    forward reject stopped it)."""
    steps = _steps("status-refresh.yml")
    guard = "github.ref == 'refs/heads/main'"
    assert guard in str(_direct_steps(steps)[0].get("if", ""))
    assert guard in str(_pr_steps(steps)[0].get("if", ""))
    assert any("non-main" in (s.get("name") or "") for s in steps)

