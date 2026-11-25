# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Dependabot keeps the tool's pins current.

``.github/dependabot.yml`` replaces ``.github/renovate.json``. Renovate
never ran here (no Renovate pull request was ever opened), while
SECURITY.md said it kept the action digests and the Python pins current.

The ``github-actions`` ecosystem reads ``.github/workflows`` and a root
``action.yml`` only. A composite action's folder has to be listed, or its
pins are never bumped (``pipeline-setup`` carries checkout, setup-python
and azure/login for every tenant workflow).

These checks run in the source repository only (the one with
``.github/sync-allowlist.txt``). The config ships to every deployment
through the public mirror, and a deployment may change or delete its copy.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / ".github" / "dependabot.yml"
ALLOWLIST = REPO_ROOT / ".github" / "sync-allowlist.txt"
COMPOSITE_ACTION_DIRS = sorted(
    f"/.github/actions/{p.parent.name}"
    for p in (REPO_ROOT / ".github" / "actions").glob("*/action.yml")
)

pytestmark = pytest.mark.skipif(
    not ALLOWLIST.is_file(),
    reason="source-repository check; a deployment may change or delete .github/dependabot.yml",
)


def _config() -> dict:
    assert CONFIG.is_file(), ".github/dependabot.yml is missing"
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}


def _entry(ecosystem: str) -> dict:
    entries = [u for u in _config().get("updates") or [] if u.get("package-ecosystem") == ecosystem]
    assert len(entries) == 1, f"expected one {ecosystem!r} entry, found {len(entries)}"
    return entries[0]


def _directories(entry: dict) -> list[str]:
    if "directories" in entry:
        return [str(d) for d in entry["directories"]]
    return [str(entry.get("directory"))]


def test_the_config_is_version_2() -> None:
    assert _config().get("version") == 2


@pytest.mark.parametrize("ecosystem", ["pip", "github-actions", "pre-commit"])
def test_each_ecosystem_gets_one_weekly_pull_request_after_a_cooldown(ecosystem: str) -> None:
    """One grouped PR a week per ecosystem, and only for releases at least a
    week old: a compromised release is usually pulled within days."""
    entry = _entry(ecosystem)
    assert "/" in _directories(entry)
    assert (entry.get("schedule") or {}).get("interval") == "weekly"
    assert int((entry.get("cooldown") or {}).get("default-days") or 0) >= 7
    assert entry.get("groups"), "group the updates into one pull request"


def test_every_composite_action_is_scanned() -> None:
    assert COMPOSITE_ACTION_DIRS, "no composite actions found under .github/actions"
    listed = _directories(_entry("github-actions"))
    missing = [d for d in COMPOSITE_ACTION_DIRS if d not in listed]
    assert not missing, f"github-actions entry does not list {missing}; their pins would never be bumped"


def test_pip_moves_the_exact_pins_and_leaves_the_floors_alone() -> None:
    """Runtime dependencies are exact pins; the dev and build dependencies in
    pyproject.toml are ``>=`` floors on purpose (contributors keep newer
    tools). ``increase-if-necessary`` raises a requirement only when it does
    not allow the new release."""
    assert _entry("pip").get("versioning-strategy") == "increase-if-necessary"


def test_the_renovate_config_is_gone() -> None:
    assert not (REPO_ROOT / ".github" / "renovate.json").exists()


def test_the_mirror_ships_the_dependabot_config_and_not_renovate() -> None:
    entries = {
        line.strip()
        for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert ".github/dependabot.yml" in entries
    assert ".github/renovate.json" not in entries
