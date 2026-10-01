# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Static checks for workflow wiring added from the security-content roadmap.

These tests parse workflow YAML only; they do not execute GitHub Actions.
They guard two operational contracts:

* production deploys pull/push the durable ``state/<env>`` branch and
  upload the structured apply report;
* silent-rule telemetry runs on a schedule and is read-only against the repo.
"""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / ".github" / "workflows" / "deploy.yml"
SILENT = ROOT / ".github" / "workflows" / "silent-rules.yml"


def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _triggers(workflow: dict) -> dict:
    # PyYAML uses YAML 1.1 rules, where the GitHub Actions key `on:`
    # is parsed as boolean True. Exactly one of the two shapes is valid.
    candidates = [key for key in ("on", True) if key in workflow]
    assert len(candidates) == 1, f"unexpected trigger keys: {candidates!r}"
    return workflow[candidates[0]]


def test_deploy_workflow_syncs_state_and_uploads_apply_report() -> None:
    wf = _load(DEPLOY)
    assert wf["permissions"]["contents"] == "write"

    steps = wf["jobs"]["deploy"]["steps"]
    names = [step.get("name", "") for step in steps]
    assert "Pull durable state" in names
    assert "Push durable state" in names
    assert "Upload apply JSON report" in names

    text = DEPLOY.read_text(encoding="utf-8")
    assert "contentops state sync pull" in text
    assert "contentops state sync push" in text
    assert "github.event.inputs.dry_run != 'true'" in text
    assert "--json-report apply-report.json" in text
    assert "persist-credentials: 'true'" in text


def test_silent_rules_workflow_is_scheduled_read_only_and_uploads_reports() -> None:
    wf = _load(SILENT)
    triggers = _triggers(wf)
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    # silent-rules.yml gained `issues: write` in PR #182 so the
    # notify-workflow-failure action can open a pipeline-alert issue
    # when the weekly scheduled run fails.
    assert wf["permissions"] == {
        "id-token": "write",
        "contents": "read",
        "issues": "write",
    }

    job = wf["jobs"]["silent-rules"]
    assert job["environment"] == "automation"
    assert job["env"]["PIPELINE_WORKSPACE_ID"] == "${{ vars.PIPELINE_WORKSPACE_ID }}"

    text = SILENT.read_text(encoding="utf-8")
    assert "contentops silent-rules" in text
    assert "--format csv" in text
    assert "--format json" in text
    assert "actions/upload-artifact@" in text


WORKFLOWS = ROOT / ".github" / "workflows"
_STATE_PUSHERS = (
    "deploy.yml",
    "prune.yml",
    "retry-failed.yml",
    "rollback.yml",
)


def test_integration_lane_does_not_push_shared_state() -> None:
    """State is keyed by tenant name, not role: an integration apply
    pushing state would mark integration-only rules managed in prod."""
    text = (WORKFLOWS / "promote-to-integration.yml").read_text(encoding="utf-8")
    assert "contentops state sync push" not in text


def test_state_push_gates_on_env_scoped_state_file() -> None:
    """`state sync push` reads state/<env>/state.json. The old gate tested
    the env-less state/state.json, which nothing writes, so every push
    was skipped and the durable state branch never moved."""
    for name in _STATE_PUSHERS:
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        assert "contentops state sync push" in text, name
        assert "[ -f state/state.json ]" not in text, name
        assert 'compgen -G "state/*/state.json"' in text, name


def test_status_refresh_pulls_state_before_rendering() -> None:
    path = WORKFLOWS / "status-refresh.yml"
    steps = _load(path)["jobs"]["refresh"]["steps"]
    names = [step.get("name", "") for step in steps]
    assert "Pull durable state" in names
    pull = names.index("Pull durable state")
    render = next(i for i, n in enumerate(names) if n.startswith("Regenerate status pages"))
    assert pull < render
    assert "contentops state sync pull" in steps[pull]["run"]


def test_state_adopt_workflow_is_manual_and_dry_run_by_default() -> None:
    path = WORKFLOWS / "state-adopt.yml"
    wf = _load(path)
    triggers = _triggers(wf)
    assert set(triggers) == {"workflow_dispatch"}
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["dry_run"]["default"] is True
    assert inputs["role"]["default"] == "prod"
    assert wf["permissions"] == {"id-token": "write", "contents": "write"}

    job = wf["jobs"]["adopt"]
    assert job["environment"] == "automation"
    steps = job["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert "./.github/actions/pipeline-setup" in uses
    runs = "\n".join(s.get("run", "") for s in steps)
    assert runs.index("contentops state sync pull") < runs.index("contentops state adopt")
    assert runs.index("contentops state adopt") < runs.index("contentops state sync push")
    # Free-text inputs reach the shell through env vars only.
    assert "${{" not in runs
    push_step = next(s for s in steps if "state sync push" in s.get("run", ""))
    assert "inputs.dry_run == false" in push_step["if"]
