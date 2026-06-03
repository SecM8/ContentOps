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
