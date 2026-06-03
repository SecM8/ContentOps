# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Static safety checks on .github/workflows/emergency-disable.yml.

These tests don't run the workflow — they parse it and assert that the
high-risk surface area (triggers, permissions, auto-merge, blast radius)
matches the documented break-glass design.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "emergency-disable.yml"


def _load() -> dict:
    with WORKFLOW.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_workflow_file_exists() -> None:
    assert WORKFLOW.is_file(), f"missing workflow: {WORKFLOW}"


def test_only_workflow_dispatch_trigger() -> None:
    wf = _load()
    # PyYAML parses bare `on:` as the boolean True, so accept either key.
    triggers = wf.get("on", wf.get(True))
    assert isinstance(triggers, dict), f"unexpected on: shape: {triggers!r}"
    assert set(triggers.keys()) == {"workflow_dispatch"}, (
        f"only workflow_dispatch is allowed, got {sorted(triggers.keys())}"
    )


def test_required_inputs_present() -> None:
    wf = _load()
    triggers = wf.get("on", wf.get(True))
    inputs = triggers["workflow_dispatch"]["inputs"]
    for name in ("rule_id", "reason", "confirm"):
        assert name in inputs, f"missing input: {name}"
        assert inputs[name].get("required") is True, f"input {name} must be required"


def test_permissions_are_minimal() -> None:
    wf = _load()
    perms = wf.get("permissions", {})
    assert perms == {"contents": "write", "pull-requests": "write"}, (
        f"permissions must be exactly contents:write + pull-requests:write, got {perms}"
    )


def test_no_dangerous_keywords() -> None:
    # Strip YAML comments so documentation about *what we forbid* doesn't trip
    # the substring scan; we only care about active workflow content.
    lines = []
    for raw in WORKFLOW.read_text(encoding="utf-8").splitlines():
        stripped = raw.lstrip()
        if stripped.startswith("#"):
            continue
        # Drop trailing inline comments too.
        if " #" in raw:
            raw = raw.split(" #", 1)[0]
        lines.append(raw)
    text = "\n".join(lines)
    forbidden = [
        "pull_request_target",
        "id-token:",
        "actions: write",
        "actions:write",
        "--auto",
        "auto-merge",
        "automerge",
        "gh pr merge",
    ]
    for token in forbidden:
        assert token not in text, f"forbidden token present in workflow: {token!r}"


def test_confirmation_string_enforced() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert '!= "DISABLE"' in text or "!= 'DISABLE'" in text, (
        "workflow must reject any confirm value other than the literal DISABLE"
    )


def test_uses_pinned_action_shas() -> None:
    wf = _load()
    job = wf["jobs"]["disable"]
    for step in job["steps"]:
        uses = step.get("uses")
        if not uses:
            continue
        # Must be pinned to a 40-char commit SHA, not a tag or branch.
        ref = uses.split("@", 1)[1]
        assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), (
            f"action {uses} must be pinned to a full 40-char commit SHA"
        )


def test_explicit_detection_only_staging() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    # Explicit-path staging only; no `git add -A` / `git add .` blast radius.
    assert "git add -A" not in text
    assert "git add ." not in text
    assert "git add -- detections" in text


def test_single_file_blast_radius_check() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'changed=$(git diff --name-only -- detections | wc -l)' in text
    assert '[ "$changed" -ne 1 ]' in text


def test_concurrency_scoped_per_rule() -> None:
    wf = _load()
    group = wf.get("concurrency", {}).get("group", "")
    assert "inputs.rule_id" in group, (
        f"concurrency group must be scoped per rule_id, got {group!r}"
    )
