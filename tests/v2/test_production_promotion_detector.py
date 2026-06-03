# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "detect_production_promotions.py"

ENVELOPE_TEMPLATE = """\
id: {rule_id}
version: 0.0.0
platform: sentinel
status: {status}
sentinel:
  kind: Scheduled
  severity: Medium
  query: |-
    SecurityEvent | take 1
"""


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=check,
        capture_output=True,
        text=True,
    )


def _write(repo: Path, rel: str, content: str) -> None:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def _run_detector(repo: Path, base: str, head: str = "HEAD") -> tuple[int, str]:
    out = repo / "out.md"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--base",
            base,
            "--head",
            head,
            "--out",
            str(out),
            "--repo",
            str(repo),
            # These tests pin the markdown-rendering surface, not the
            # Phase 2.2a stamp gate (covered separately by
            # test_detect_production_promotions.py). --no-gate keeps the
            # legacy advisory-only behaviour: exit 0 even on unstamped
            # promotions.
            "--no-gate",
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode, out.read_text(encoding="utf-8") if out.exists() else ""


def test_detects_status_change_dev_to_production(repo: Path) -> None:
    _write(repo, "detections/sentinel/r1.yml", ENVELOPE_TEMPLATE.format(rule_id="r1", status="development"))
    base = _commit_all(repo, "base")
    _write(repo, "detections/sentinel/r1.yml", ENVELOPE_TEMPLATE.format(rule_id="r1", status="production"))
    _commit_all(repo, "promote")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert "Production promotions detected" in md
    assert "detections/sentinel/r1.yml" in md
    assert "`r1`" in md
    assert "development" in md


def test_detects_new_file_in_production_status(repo: Path) -> None:
    _write(repo, "detections/sentinel/keep.yml", ENVELOPE_TEMPLATE.format(rule_id="keep", status="testing"))
    base = _commit_all(repo, "base")
    _write(repo, "detections/sentinel/new.yml", ENVELOPE_TEMPLATE.format(rule_id="new", status="production"))
    _commit_all(repo, "add new prod rule")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert "detections/sentinel/new.yml" in md
    assert "(new file)" in md
    assert "`new`" in md


def test_ignores_unchanged_production_rule(repo: Path) -> None:
    _write(repo, "detections/sentinel/p.yml", ENVELOPE_TEMPLATE.format(rule_id="p", status="production"))
    base = _commit_all(repo, "base")
    _write(repo, "detections/sentinel/other.yml", ENVELOPE_TEMPLATE.format(rule_id="other", status="testing"))
    _commit_all(repo, "add unrelated")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert "No production promotions" in md


def test_ignores_promotion_to_testing(repo: Path) -> None:
    _write(repo, "detections/sentinel/r.yml", ENVELOPE_TEMPLATE.format(rule_id="r", status="development"))
    base = _commit_all(repo, "base")
    _write(repo, "detections/sentinel/r.yml", ENVELOPE_TEMPLATE.format(rule_id="r", status="testing"))
    _commit_all(repo, "promote to testing")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert "No production promotions" in md


def test_skips_non_detection_files(repo: Path) -> None:
    _write(repo, "contentops/foo.py", "x = 1\n")
    _write(repo, ".github/workflows/x.yml", "name: x\n")
    base = _commit_all(repo, "base")
    _write(repo, "contentops/foo.py", "x = 2\n")
    _write(repo, ".github/workflows/x.yml", "name: y\n")
    _commit_all(repo, "edit non-detection")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert "No production promotions" in md


def test_handles_deleted_file(repo: Path) -> None:
    _write(repo, "detections/sentinel/gone.yml", ENVELOPE_TEMPLATE.format(rule_id="gone", status="production"))
    _write(repo, "detections/sentinel/keep.yml", ENVELOPE_TEMPLATE.format(rule_id="keep", status="testing"))
    base = _commit_all(repo, "base")
    (repo / "detections/sentinel/gone.yml").unlink()
    _commit_all(repo, "delete a rule")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert "No production promotions" in md
    assert "gone.yml" not in md


def test_outputs_no_promotions_message_when_clean(repo: Path) -> None:
    _write(repo, "detections/sentinel/r.yml", ENVELOPE_TEMPLATE.format(rule_id="r", status="development"))
    base = _commit_all(repo, "base")
    _write(repo, "detections/sentinel/r.yml", ENVELOPE_TEMPLATE.format(rule_id="r", status="development") + "# tweak\n")
    _commit_all(repo, "comment only")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert md.strip() == "No production promotions in this PR."


def test_handles_malformed_yaml_gracefully(repo: Path) -> None:
    _write(repo, "detections/sentinel/ok.yml", ENVELOPE_TEMPLATE.format(rule_id="ok", status="development"))
    _write(repo, "detections/sentinel/bad.yml", ENVELOPE_TEMPLATE.format(rule_id="bad", status="development"))
    base = _commit_all(repo, "base")
    _write(repo, "detections/sentinel/ok.yml", ENVELOPE_TEMPLATE.format(rule_id="ok", status="production"))
    _write(repo, "detections/sentinel/bad.yml", "status: production\n  : : not: yaml :\n  bad indent\n\t\tmix")
    _commit_all(repo, "promote ok, corrupt bad")

    code, md = _run_detector(repo, base)

    assert code == 0
    assert "detections/sentinel/ok.yml" in md
    assert "detections/sentinel/bad.yml" not in md
