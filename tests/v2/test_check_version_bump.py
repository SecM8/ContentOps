# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/check_version_bump.py — the semantic-diff version gate.

Covers the pure comparison core (``_requires_bump``): a cosmetic-only edit
must NOT demand a version bump, while a real content change with an
unchanged version must. The git plumbing (_changed_files / _file_at_ref)
is a thin subprocess wrapper exercised end-to-end in CI, not unit-tested
here.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# The script lives under scripts/ which isn't on sys.path by default.
SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_version_bump as cvb  # noqa: E402


_BASE = """\
id: my-rule
version: 1.0.0
asset: sentinel_analytic
status: experimental
metadata:
  owner: secops@example.com
  severity: medium
payload:
  displayName: My Rule
  query: SecurityEvent | take 1
"""


def test_cosmetic_whitespace_diff_needs_no_bump() -> None:
    # Trailing whitespace + a blank line: byte-different, semantically same.
    head = _BASE.replace("status: experimental", "status: experimental   ") + "\n"
    assert cvb._requires_bump(head, _BASE) is None


def test_key_reorder_needs_no_bump() -> None:
    # Reorder top-level keys: dict equality ignores order.
    head = (
        "asset: sentinel_analytic\n"
        "id: my-rule\n"
        "version: 1.0.0\n"
        "status: experimental\n"
        "metadata:\n"
        "  severity: medium\n"
        "  owner: secops@example.com\n"
        "payload:\n"
        "  query: SecurityEvent | take 1\n"
        "  displayName: My Rule\n"
    )
    assert cvb._requires_bump(head, _BASE) is None


def test_comment_only_diff_needs_no_bump() -> None:
    head = "# a new comment\n" + _BASE
    assert cvb._requires_bump(head, _BASE) is None


def test_content_change_without_bump_fails() -> None:
    head = _BASE.replace("take 1", "take 999")  # query changed, version same
    msg = cvb._requires_bump(head, _BASE)
    assert msg is not None
    assert "version unchanged (1.0.0)" in msg


def test_content_change_with_bump_passes() -> None:
    head = _BASE.replace("take 1", "take 999").replace("version: 1.0.0", "version: 1.1.0")
    assert cvb._requires_bump(head, _BASE) is None


def test_unparseable_is_exempt() -> None:
    # The validate step owns malformed YAML; this gate must not double-fail.
    assert cvb._requires_bump("::: not yaml :::", _BASE) is None


def test_parse_doc_rejects_non_mapping() -> None:
    assert cvb._parse_doc("- just\n- a\n- list\n") is None
    assert cvb._parse_doc("id: x\nversion: 1.0.0\n") == {"id": "x", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# End to end in a git repository: playbook sidecars
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)


def _playbook_repo(root: Path, envelope_name: str, sidecar_name: str) -> Path:
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "test")
    _git(root, "config", "commit.gpgsign", "false")
    folder = root / "detections" / "sentinel_playbook"
    folder.mkdir(parents=True)
    (folder / envelope_name).write_text(
        "id: pb-one\nversion: 1.0.0\nasset: sentinel_playbook\nstatus: production\n"
        f"payload:\n  definitionFile: {sidecar_name}\n",
        encoding="utf-8",
    )
    (folder / sidecar_name).write_text('{"actions": {"a": "v1"}}', encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "switch", "-q", "-c", "change")
    (folder / sidecar_name).write_text('{"actions": {"a": "v2"}}', encoding="utf-8")
    _git(root, "commit", "-q", "-am", "edit the definition only")
    return root


@pytest.mark.parametrize("envelope_name", ["pb-one.yml", "custom.yml"], ids=["same-name", "other-name"])
def test_a_changed_sidecar_without_a_bump_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    envelope_name: str,
) -> None:
    """The sidecar was paired with ``<sidecar stem>.yml``. An envelope with
    another file name (``contentops new --out``) that points at it through
    ``definitionFile`` was never checked, so its definition could change
    without a version bump."""
    monkeypatch.chdir(_playbook_repo(tmp_path, envelope_name, "pb-one.workflow.json"))
    assert cvb.main("main") == 1
    assert f"sentinel_playbook/{envelope_name}" in capsys.readouterr().err
