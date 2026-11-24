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


def _drift_write_steps() -> list[dict]:
    wf = _load(REPO_ROOT / ".github" / "workflows" / "drift.yml")
    return wf["jobs"]["drift-write"]["steps"]


def _drift_close_step() -> dict:
    return next(s for s in _drift_write_steps() if s.get("name") == "Close superseded auto-drift PRs")


def test_drift_closes_older_prs_only_after_the_replacement_exists() -> None:
    """The previous drift PR must stay open, with its branch, until the
    new one exists. Closing first loses it when the new PR fails to open,
    and on a re-run the step would close the PR of its own earlier
    attempt. The step therefore runs after the PR is opened, only when a
    PR number came back, and never selects that PR."""
    names = [s.get("name") for s in _drift_write_steps()]
    assert names.index("Open PR if tree changed") < names.index("Close superseded auto-drift PRs")
    step = _drift_close_step()
    assert step["if"] == "steps.auto-pr.outputs.pull-request-number != ''"
    assert step["env"]["NEW_PR"] == "${{ steps.auto-pr.outputs.pull-request-number }}"
    assert "(.number != (env.NEW_PR | tonumber))" in step["run"]


def test_drift_looks_at_every_open_pr_when_closing_older_ones() -> None:
    """``gh pr list`` returns 30 pull requests unless told otherwise; an
    older drift PR beyond the limit would never be closed."""
    assert "--limit 1000" in _drift_close_step()["run"]


def test_drift_closes_superseded_prs_by_exact_head_branch() -> None:
    """drift.yml must select superseded auto-PRs by an exact
    ``headRefName`` prefix, never a fuzzy ``--search "head:..."`` query
    (which closed an operator's draft PR when drift was dispatched from
    that PR's branch, 2026-10-18)."""
    text = (REPO_ROOT / ".github" / "workflows" / "drift.yml").read_text(encoding="utf-8")
    assert '--search "head:' not in text
    assert '.headRefName | startswith("drift/auto-")' in text


def test_drift_closes_only_prs_the_automation_opened_in_this_repository() -> None:
    """The branch prefix alone is not proof that a pull request is an
    older drift import: a fork, or a person, can use a ``drift/auto-``
    branch. The supersede step must also require that the PR comes from
    this repository and was opened by the identity that opens drift PRs."""
    step = _drift_close_step()["run"]
    assert "--json number,headRefName,isCrossRepository,author" in step
    assert "(.isCrossRepository | not)" in step
    assert ".author.login" in step
    assert '"app/github-actions"' in step


def test_drift_never_calls_gh_pr_close_with_an_empty_selector() -> None:
    """When nothing is superseded the list is empty, and ``"${PRS[@]:-}"``
    still yields one empty item. ``gh pr close ""`` does not fail: gh reads
    an empty selector as "the pull request of the current branch", so a
    drift run dispatched from a PR branch would close that PR. The loop
    must skip an empty number before it reaches ``gh pr close``."""
    step = _drift_close_step()["run"]
    loop = step[step.index("for n in"):]
    guard = loop.index('[ -n "$n" ] || continue')
    assert guard < loop.index("gh pr close")


def test_drift_deletes_the_branch_of_a_superseded_pr() -> None:
    """Closing a superseded drift PR must also delete its branch, or one
    stale ``drift/auto-*`` branch is left behind per day."""
    step = _drift_close_step()["run"]
    close = step.index('gh pr close "$n"')
    assert "--delete-branch" in step[close:close + 120]


def test_deploy_fetches_an_operator_supplied_changed_since_ref() -> None:
    """deploy.yml checks out with fetch-depth 2, so a ``changed_since``
    dispatch input older than that failed with "unknown revision" before
    the diff ran (2026-10-18). The apply step must fetch the ref (and
    fall back to unshallowing) before passing it to ``--changed-since``.

    A fetched branch or tag name does not become a local ref: the fetch
    only records the commit in ``FETCH_HEAD``. The step must therefore
    diff against that commit, not against the name it was given."""
    text = (REPO_ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    fetch = text.index('git fetch --no-tags --depth=1 origin "$INPUT_CHANGED_SINCE"')
    after = text[fetch:fetch + 1100]
    assert "--unshallow" in after
    assert "git rev-parse --verify 'FETCH_HEAD^{commit}'" in after
    assert 'ARGS+=( "--changed-since" "$SINCE" )' in after
    assert 'ARGS+=( "--changed-since" "$INPUT_CHANGED_SINCE" )' not in text


def _deploy_push_branch() -> str:
    """The part of the apply step that runs for a push (not a dispatch)."""
    text = (REPO_ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    start = text.index("# A push deploys what that push changed, never more.")
    return text[start:text.index('contentops apply "${ARGS[@]}"')]


def test_push_deploy_never_falls_back_to_a_full_apply() -> None:
    """A push must deploy what that push changed, or nothing. When the
    commit before the push is unknown the step stops; applying every
    detection is a decision for a person, through a manual run."""
    text = (REPO_ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    assert "running full apply" not in text
    branch = _deploy_push_branch()
    unknown = branch.index('[ -z "$EVENT_BEFORE" ] || [ "$EVENT_BEFORE" = "0000000000000000000000000000000000000000" ]')
    assert "exit 1" in branch[unknown:unknown + 400]
    assert 'ARGS+=( "--changed-since" "$SINCE" )' in branch
    assert 'ARGS+=( "--changed-since" "$EVENT_BEFORE" )' not in text


def test_push_deploy_fetches_a_baseline_outside_the_shallow_checkout() -> None:
    """After a rebase merge of several commits the commit before the push
    is not in the two-commit-deep checkout. It is fetched; if it still
    does not resolve, the step stops before anything is applied."""
    branch = _deploy_push_branch()
    verify = 'git rev-parse --verify --quiet "${EVENT_BEFORE}^{commit}"'
    first = branch.index(verify)
    fetch = branch.index('git fetch --no-tags --depth=1 origin "$EVENT_BEFORE"')
    second = branch.index(verify, fetch)
    assert first < fetch < second
    assert "exit 1" in branch[second:second + 400]


def test_a_failed_push_deploy_opens_a_pipeline_alert() -> None:
    """A deploy that fails after a merge leaves the merged change out of
    the tenant, and the next drift import proposes to undo it. That must
    not stay a red mark on a commit: a separate job opens an issue. It is
    a separate job so the deploy job's token gains nothing."""
    wf = _load(REPO_ROOT / ".github" / "workflows" / "deploy.yml")
    job = wf["jobs"]["notify-failure"]
    assert "deploy" in job["needs"]
    condition = " ".join(str(job["if"]).split())
    assert "github.event_name == 'push'" in condition
    assert "needs.deploy.result == 'failure'" in condition
    assert job["permissions"] == {"contents": "read", "issues": "write"}
    assert "environment" not in job
    uses = [s.get("uses") for s in job["steps"]]
    assert "./.github/actions/notify-workflow-failure" in uses
    notify = next(s for s in job["steps"] if s.get("uses") == "./.github/actions/notify-workflow-failure")
    assert notify["with"]["trigger"] == "push"
    # The deploy job and the workflow default keep their permissions.
    assert "issues" not in (wf.get("permissions") or {})
    assert "permissions" not in wf["jobs"]["deploy"]


def test_notify_action_names_the_trigger_and_keeps_the_scheduled_title() -> None:
    """Callers that do not say what started the run keep the issue title
    they always had, so an open alert is still found and commented on."""
    action = _load(REPO_ROOT / ".github" / "actions" / "notify-workflow-failure" / "action.yml")
    assert action["inputs"]["trigger"]["default"] == "scheduled"
    script = action["runs"]["steps"][0]["run"]
    assert 'TITLE="[pipeline-alert] ${WORKFLOW_NAME} ${TRIGGER} run failed"' in script
    assert action["runs"]["steps"][0]["env"]["TRIGGER"] == "${{ inputs.trigger }}"


def test_validate_checks_the_mitre_ids_of_changed_rules() -> None:
    """Sentinel rejects a sub-technique id under ``techniques`` at deploy.
    The pull request gate checks the rules a pull request adds or changes."""
    wf = _load(REPO_ROOT / ".github" / "workflows" / "validate.yml")
    steps = wf["jobs"]["validate"]["steps"]
    step = next(s for s in steps if "check_mitre_ids.py" in str(s.get("run", "")))
    assert 'python scripts/check_mitre_ids.py "origin/$BASE_REF"' in step["run"]
    assert step["env"]["BASE_REF"] == "${{ github.base_ref }}"


def test_deploy_passes_only_a_verified_commit_as_changed_since() -> None:
    """The baseline of a manual deploy decides what is applied, so the
    step must never guess it.

    * A ref that already resolves in the checkout (``HEAD``, ``HEAD~1``,
      a commit that is there) is resolved there first. Fetching ``HEAD``
      from the remote would return the default branch instead, a
      different baseline on any other branch.
    * Whatever is used ends up as a commit id that ``git rev-parse
      --verify`` accepted. A value that is no commit stops the step
      before anything is applied; passed on as it is, git could read it
      as a path and report "nothing changed".
    """
    text = (REPO_ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    local = text.index('git rev-parse --verify --quiet "${INPUT_CHANGED_SINCE}^{commit}"')
    fetch = text.index('git fetch --no-tags --depth=1 origin "$INPUT_CHANGED_SINCE"')
    unshallow = text.index("git fetch --no-tags --unshallow origin")
    assert local < fetch < unshallow
    tail = text[unshallow:text.index('ARGS+=( "--changed-since" "$SINCE" )')]
    assert 'git rev-parse --verify --quiet "${INPUT_CHANGED_SINCE}^{commit}"' in tail
    assert "exit 1" in tail


def test_retry_failed_fetches_the_deploy_audit_artefact() -> None:
    """The audit trail is never committed (deploy.yml uploads it as the
    ``audit-<run id>`` artefact), so retry-failed on a fresh checkout saw
    no audit/ and always answered "nothing to retry" (2026-10-18). The
    workflow must download the deploy audit before running the retry,
    with ``actions: read`` and an optional ``deploy_run_id`` input."""
    from pathlib import Path

    import yaml

    path = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "retry-failed.yml"
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert wf["permissions"].get("actions") == "read"
    inputs = wf.get("on", wf.get(True))["workflow_dispatch"]["inputs"]
    assert inputs["deploy_run_id"]["default"] == ""
    steps = wf["jobs"]["retry"]["steps"]
    names = [s.get("name") for s in steps]
    assert names.index("Fetch the deploy audit trail") < names.index("Run contentops retry-failed")
    fetch = next(s for s in steps if s.get("name") == "Fetch the deploy audit trail")
    assert 'gh run download "$RUN_ID" -n "audit-$RUN_ID" -D audit' in fetch["run"]
    assert "$INPUT_DEPLOY_RUN_ID" in fetch["run"] and "inputs.deploy_run_id" in str(fetch.get("env"))
    # Default selection must skip completed deploy runs without an audit
    # artefact (deploy job skipped on a push that changed no detection).
    assert 'actions/runs/$id/artifacts' in fetch["run"] and 'grep -qx "audit-$id"' in fetch["run"]



def _integration_step() -> tuple[dict, dict, str]:
    wf = _load(REPO_ROOT / ".github" / "workflows" / "integration.yml")
    job = wf["jobs"]["integration"]
    step = next(s for s in job["steps"] if s.get("name") == "Run integration suite")
    return wf, step, str(step["run"])


def test_integration_runs_the_whole_live_suite_unless_one_test_is_named() -> None:
    """The default stays the whole live suite. The optional ``tests`` input
    runs one file under tests/integration instead; the value reaches the
    shell through env, must name a plain test file, and anything else
    stops the job before pytest starts."""
    wf, step, script = _integration_step()
    inputs = wf.get("on", wf.get(True))["workflow_dispatch"]["inputs"]
    assert inputs["tests"]["required"] is False
    assert inputs["tests"].get("default", "") == ""
    assert step["env"]["INPUT_TESTS"] == "${{ inputs.tests }}"
    assert "${{ inputs.tests }}" not in script

    assert "pytest -q -rs tests/integration\n" in script + "\n"
    assert 'pytest -q -rs "$INPUT_TESTS"' in script
    assert "^tests/integration/test_[a-z0-9_]+\\.py$" in script
    named = script.index('elif [ -n "$INPUT_TESTS" ]')
    refuse = script.index("exit 1", named)
    assert refuse < script.index('pytest -q -rs "$INPUT_TESTS"')
    assert script.index('if [ "$SWEEP_ONLY" = "true" ]') < named


def test_integration_passes_the_probe_device_group_and_keeps_the_report() -> None:
    """The live Defender probe puts a named device group on its disabled
    test rule (a tenant may have no scoped rule to copy one from). Its
    report is uploaded whatever the outcome."""
    wf, _step, _script = _integration_step()
    job = wf["jobs"]["integration"]
    assert job["env"]["DEFENDER_PROBE_DEVICE_GROUP"] == "${{ vars.DEFENDER_PROBE_DEVICE_GROUP }}"
    upload = next(s for s in job["steps"] if s.get("name") == "Upload the shape report")
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "defender-shape-report.md"
    assert upload["with"]["if-no-files-found"] == "ignore"
