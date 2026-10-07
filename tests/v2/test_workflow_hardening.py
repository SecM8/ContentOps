# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Guards for how workflows handle untrusted input and Azure credentials.

* No ``${{ inputs.* }}`` / ``${{ github.event.* }}`` / ``${{ github.head_ref }}``
  expression is expanded inside a ``run:`` script (workflows and composite
  actions). Those values are attacker-influenced; they must reach the shell
  through ``env:`` so the shell treats them as data.
* A job that a pull request can start, and that can mint an Azure OIDC token
  (``id-token: write``), carries an explicit guard: a same-repo check, a
  label gate, or a condition that excludes ``pull_request``. PR jobs run the
  PR's own code, so an unguarded one hands the environment's identity to it.
* ``validate`` (the required PR gate) holds no Azure credentials at all.
* Every tenant-config materialisation goes through
  ``scripts/materialise_tenant_config.py`` so a committed ``tenant.yml``
  can never silently override the secret.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
ACTIONS = sorted((REPO_ROOT / ".github" / "actions").glob("*/action.yml"))

_UNSAFE_EXPR = re.compile(
    r"\$\{\{\s*(inputs\.|github\.event\.|github\.head_ref)", re.IGNORECASE,
)
_SAME_REPO = "github.event.pull_request.head.repo.full_name == github.repository"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _triggers(wf: dict) -> set[str]:
    # PyYAML (YAML 1.1) reads the bare key ``on`` as boolean True.
    on = wf.get("on", wf.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    return set((on or {}).keys())


def _run_blocks(doc: dict):
    jobs = doc.get("jobs") or {}
    for job_name, job in jobs.items():
        for step in job.get("steps") or []:
            if "run" in step:
                yield f"{job_name}/{step.get('name', '?')}", str(step["run"])
    for step in ((doc.get("runs") or {}).get("steps") or []):
        if "run" in step:
            yield step.get("name", "?"), str(step["run"])


@pytest.mark.parametrize(
    "path", WORKFLOWS + ACTIONS, ids=lambda p: str(p.relative_to(REPO_ROOT)),
)
def test_no_untrusted_expression_inside_run_scripts(path: Path) -> None:
    offenders = [
        name for name, script in _run_blocks(_load(path))
        if _UNSAFE_EXPR.search(script)
    ]
    assert not offenders, (
        f"{path.name}: pass these values through env: instead of expanding "
        f"them inside run: — {offenders}"
    )


def _job_guard(if_expr: str) -> str | None:
    expr = " ".join(if_expr.split())
    if _SAME_REPO in expr:
        return "same-repo"
    if "github.event.label.name" in expr:
        return "label"
    if expr.startswith("github.event_name != 'pull_request'") and " || " not in expr.split("&&")[0]:
        return "not-on-pr"
    if expr.startswith(("github.event_name == 'workflow_dispatch' &&",
                        "github.event_name == 'schedule' &&")):
        return "not-on-pr"
    return None


def test_pr_reachable_jobs_with_oidc_are_guarded() -> None:
    unguarded: list[str] = []
    for path in WORKFLOWS:
        wf = _load(path)
        if not ({"pull_request", "pull_request_target"} & _triggers(wf)):
            continue
        workflow_perms = wf.get("permissions") or {}
        for name, job in (wf.get("jobs") or {}).items():
            perms = job.get("permissions", workflow_perms) or {}
            if not (isinstance(perms, dict) and perms.get("id-token") == "write"):
                continue
            if _job_guard(str(job.get("if") or "")) is None:
                unguarded.append(f"{path.name}:{name}")
    assert not unguarded, (
        "PR-reachable jobs that can mint an Azure OIDC token need a same-repo "
        f"guard, a label gate, or a condition excluding pull_request: {unguarded}"
    )


def test_validate_gate_holds_no_azure_credentials() -> None:
    wf = _load(REPO_ROOT / ".github" / "workflows" / "validate.yml")
    job = wf["jobs"]["validate"]
    assert "environment" not in job
    assert (job.get("permissions") or {}).get("id-token") is None
    assert (wf.get("permissions") or {}).get("id-token") is None
    lint_step = next(
        s for s in job["steps"] if s.get("uses") == "./.github/actions/lint-strict"
    )
    assert lint_step["with"]["pre-pr-refresh"] == "false"


def test_tenant_config_is_materialised_through_the_conflict_check() -> None:
    sources = [
        REPO_ROOT / ".github" / "actions" / "pipeline-setup" / "action.yml",
        REPO_ROOT / ".github" / "workflows" / "integration-deploy.yml",
        REPO_ROOT / ".github" / "workflows" / "e2e-capability-tests.yml",
    ]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "scripts/materialise_tenant_config.py" in text, path.name
        # The old skip-if-exists shortcut let a committed file win silently.
        assert "if [ ! -f config/tenant.yml ]" not in text, path.name
        assert 'if [ ! -f "$default_cfg" ]' not in text, path.name
