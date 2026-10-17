# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Playbook definition sidecars: loader inlining, scaffold output, the
drift writer's split, and the version-bump script's sidecar mapping."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from contentops.core.discovery import load_asset
from contentops.devex.scaffold import scaffold

REPO_ROOT = Path(__file__).resolve().parents[2]


def _definition() -> dict:
    return {"$schema": "x", "contentVersion": "1.0.0.0",
            "triggers": {"manual": {"type": "Request"}}, "actions": {}}


def _envelope(tmp_path: Path, payload: dict, *, env_id: str = "pb-one") -> Path:
    d = tmp_path / "sentinel_playbook"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{env_id}.yml"
    p.write_text(yaml.safe_dump({
        "id": env_id, "version": "1.0.0", "asset": "sentinel_playbook", "status": "production",
        "metadata": {"arm_name": env_id}, "payload": payload,
    }), encoding="utf-8")
    return p


def test_loader_inlines_sidecar_and_drops_pointer(tmp_path: Path) -> None:
    p = _envelope(tmp_path, {"definitionFile": "pb-one.workflow.json", "connections": []})
    (tmp_path / "sentinel_playbook" / "pb-one.workflow.json").write_text(
        json.dumps(_definition()), encoding="utf-8",
    )
    la = load_asset(p)
    assert la.payload["definition"] == _definition()
    assert "definitionFile" not in la.payload
    # raw["payload"] is the same object, so readers of raw see it too.
    assert la.raw["payload"]["definition"] == _definition()


def test_loader_errors_are_specific(tmp_path: Path) -> None:
    p = _envelope(tmp_path, {"definitionFile": "pb-one.workflow.json"})
    with pytest.raises(FileNotFoundError, match="pb-one.workflow.json"):
        load_asset(p)
    p2 = _envelope(tmp_path, {"definitionFile": "../escape.workflow.json"}, env_id="pb-two")
    with pytest.raises(ValueError, match="bare file name"):
        load_asset(p2)
    p3 = _envelope(tmp_path, {"definitionFile": "pb-three.workflow.json", "definition": {}}, env_id="pb-three")
    with pytest.raises(ValueError, match="both"):
        load_asset(p3)
    (tmp_path / "sentinel_playbook" / "pb-four.workflow.json").write_text("not json", encoding="utf-8")
    p4 = _envelope(tmp_path, {"definitionFile": "pb-four.workflow.json"}, env_id="pb-four")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_asset(p4)


def test_inline_definition_still_accepted(tmp_path: Path) -> None:
    p = _envelope(tmp_path, {"definition": _definition()})
    assert load_asset(p).payload["definition"] == _definition()


def test_scaffold_writes_envelope_and_sidecar_that_load_and_validate(tmp_path: Path) -> None:
    out = tmp_path / "sentinel_playbook" / "notify-soc.yml"
    written = scaffold("sentinel_playbook", "notify-soc", display_name="Notify SOC", out=out)
    assert written == out
    sidecar = tmp_path / "sentinel_playbook" / "notify-soc.workflow.json"
    assert sidecar.is_file()
    assert "notify-soc" in sidecar.read_text(encoding="utf-8")
    la = load_asset(out)
    from contentops.handlers.sentinel_playbook_models import SentinelPlaybookPayload
    SentinelPlaybookPayload(**la.payload)
    # Refuses to overwrite the sidecar without --force.
    from contentops.devex.scaffold import ScaffoldError
    with pytest.raises(ScaffoldError, match="refusing to overwrite"):
        scaffold("sentinel_playbook", "notify-soc", out=out)
    scaffold("sentinel_playbook", "notify-soc", out=out, force=True)


def test_scaffold_automation_rule_validates(tmp_path: Path) -> None:
    out = tmp_path / "sentinel_automation_rule" / "tag-low.yml"
    scaffold("sentinel_automation_rule", "tag-low", out=out)
    from contentops.handlers.sentinel_automation_rule_models import SentinelAutomationRulePayload
    SentinelAutomationRulePayload(**load_asset(out).payload)


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "check_version_bump", REPO_ROOT / "scripts" / "check_version_bump.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_version_bump_script_maps_sidecar_to_envelope(monkeypatch) -> None:
    mod = _load_script()
    monkeypatch.setattr(mod, "_run", lambda *args: (
        "detections/sentinel_playbook/pb-one.workflow.json\n"
        "detections/sentinel_analytic/x.yml\n"
    ))
    assert mod._changed_files("origin/main") == [
        "detections/sentinel_analytic/x.yml",
        "detections/sentinel_playbook/pb-one.yml",
    ]


def test_version_bump_script_requires_bump_when_only_sidecar_changed(tmp_path: Path, monkeypatch) -> None:
    mod = _load_script()
    monkeypatch.chdir(tmp_path)
    env_text = yaml.safe_dump({"id": "pb-one", "version": "1.0.0", "asset": "sentinel_playbook",
                               "status": "production", "payload": {"definitionFile": "pb-one.workflow.json"}})
    d = tmp_path / "detections" / "sentinel_playbook"
    d.mkdir(parents=True)
    (d / "pb-one.yml").write_text(env_text, encoding="utf-8")
    (d / "pb-one.workflow.json").write_text('{"actions": {"new": {}}}', encoding="utf-8")

    base_files = {
        "detections/sentinel_playbook/pb-one.yml": env_text,
        "detections/sentinel_playbook/pb-one.workflow.json": '{"actions": {}}',
    }
    monkeypatch.setattr(mod, "_changed_files", lambda ref: ["detections/sentinel_playbook/pb-one.yml"])
    monkeypatch.setattr(mod, "_file_at_ref", lambda ref, path: base_files.get(path))
    assert mod.main("origin/main") == 1

    # Bumped version passes.
    (d / "pb-one.yml").write_text(env_text.replace("1.0.0", "1.0.1"), encoding="utf-8")
    assert mod.main("origin/main") == 0
