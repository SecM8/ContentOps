# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Drift names the changed rules whose file changed after their last deploy.

In a deployment repo that deploys by hand (push deploy off), a merged
change sits in ``main`` until someone runs Deploy. The tenant still has
the old value, so the next drift PR proposes it: merging that PR undoes
the merge. The state file records the commit each rule was last applied
from; a file that differs between that commit and HEAD is a change the
tenant has not received yet.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from contentops.core.asset import Asset
from contentops.core.drift import DriftEntry
from contentops.state import EnvState
from contentops.undeployed import changed_since_last_deploy
from contentops.upstream.drift_pr import parse_report, render_pr_body


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def _rule(path: Path, rule_id: str, query: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({
        "id": rule_id, "version": "1.0.0", "asset": "sentinel_analytic", "status": "production",
        "payload": {"displayName": rule_id, "kind": "Scheduled", "query": query},
    }), encoding="utf-8")


def _repo(tmp_path: Path) -> tuple[Path, str, Path, Path]:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    edited = tmp_path / "detections" / "sentinel_analytic" / "edited.yml"
    untouched = tmp_path / "detections" / "sentinel_analytic" / "untouched.yml"
    _rule(edited, "edited", "T | take 1")
    _rule(untouched, "untouched", "T | take 2")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "deployed")
    deployed = _git(tmp_path, "rev-parse", "HEAD")
    _rule(edited, "edited", "T | take 100")
    _git(tmp_path, "commit", "-q", "-am", "merged, not deployed")
    return tmp_path, deployed, edited, untouched


def _changed(asset_id: str, path: Path) -> DriftEntry:
    return DriftEntry(asset=Asset.SENTINEL_ANALYTIC, asset_id=asset_id, kind="changed",
                      local_path=path, envelope={})


def test_a_file_changed_after_its_last_deploy_is_named(tmp_path: Path) -> None:
    repo, deployed, edited, untouched = _repo(tmp_path)
    state = EnvState(env="t")
    state.remember("sentinel_analytic", "edited", sha=deployed)
    state.remember("sentinel_analytic", "untouched", sha=deployed)
    flagged = changed_since_last_deploy(
        [_changed("edited", edited), _changed("untouched", untouched)], state, repo=repo,
    )
    assert flagged == {("sentinel_analytic", "edited")}


def test_no_state_entry_or_an_unknown_commit_flags_nothing(tmp_path: Path) -> None:
    repo, _deployed, edited, _ = _repo(tmp_path)
    assert changed_since_last_deploy([_changed("edited", edited)], EnvState(env="t"), repo=repo) == set()
    state = EnvState(env="t")
    state.remember("sentinel_analytic", "edited", sha="0" * 40)
    assert changed_since_last_deploy([_changed("edited", edited)], state, repo=repo) == set()


def test_the_state_entry_is_found_by_the_file_id(tmp_path: Path) -> None:
    """The drift entry's id is the tenant slug; state is keyed by the id the
    file has (a renamed rule keeps its file id)."""
    repo, deployed, edited, _ = _repo(tmp_path)
    state = EnvState(env="t")
    state.remember("sentinel_analytic", "edited", sha=deployed)
    assert changed_since_last_deploy(
        [_changed("renamed-in-portal", edited)], state, repo=repo,
    ) == {("sentinel_analytic", "renamed-in-portal")}


def test_drift_marks_the_entry_in_its_report_and_output(tmp_path: Path, monkeypatch) -> None:
    import json

    from click.testing import CliRunner

    from contentops.cli import cli
    from contentops.config import SentinelWorkspaceConfig, TenantConfig
    from contentops.state import save_state

    repo, deployed, _edited, _ = _repo(tmp_path)
    state = EnvState(env="t")
    state.remember("sentinel_analytic", "edited", sha=deployed)
    save_state(state, root=repo)

    class Tenant:  # the tenant still has the deployed query
        asset = Asset.SENTINEL_ANALYTIC

        def list_remote(self):
            return [{"name": "edited"}]

        def to_envelope(self, remote):
            return {"id": "edited", "version": "0.0.0", "asset": "sentinel_analytic",
                    "status": "production", "metadata": {"arm_name": "edited"},
                    "payload": {"displayName": "edited", "kind": "Scheduled", "query": "T | take 1"}}

    cfg = TenantConfig(name="t", tenantId="x", sentinelWorkspaces=[SentinelWorkspaceConfig(
        role="prod", subscriptionId="s", resourceGroup="rg", workspaceName="ws")])
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda *_a, **_kw: cfg)
    monkeypatch.setattr("contentops.cli.commands.drift.register_default_handlers", lambda **_kw: None)
    monkeypatch.setattr("contentops.cli.commands.drift._collect_drift_handlers", lambda _a: [Tenant()])
    monkeypatch.chdir(repo)
    result = CliRunner().invoke(cli, [
        "drift", "--path", "detections", "--report", "drift_report.json", "--no-exit-on-drift",
        "--suppressions", "ignore",
    ])
    assert result.exit_code == 0, result.output
    assert "changed in the repository after its last deploy" in result.output
    entries = json.loads((repo / "drift_report.json").read_text(encoding="utf-8"))["entries"]
    assert entries == [{"asset": "sentinel_analytic", "id": "edited", "kind": "changed", "undeployed": True,
                        "changed_since": deployed}]


def test_the_pr_body_warns_before_the_lists() -> None:
    report = parse_report({
        "tenant": "t", "workspace": "w", "run_id": "1",
        "entries": [
            {"asset": "sentinel_analytic", "id": "edited", "kind": "changed", "undeployed": True},
            {"asset": "sentinel_analytic", "id": "portal-edit", "kind": "changed"},
        ],
    })
    body = render_pr_body(report, id_to_owner={})
    assert "Changed in the repository after the last deploy (1)" in body
    warning = body.split("Changed in the repository after the last deploy", 1)[1].split("###", 1)[0]
    assert "`edited`" in warning and "portal-edit" not in warning
    assert body.index("after the last deploy") < body.index("### New")


def test_a_pr_body_without_undeployed_entries_has_no_warning() -> None:
    report = parse_report({"tenant": "t", "workspace": "w", "run_id": "1", "entries": [
        {"asset": "sentinel_analytic", "id": "portal-edit", "kind": "changed"},
    ]})
    assert "after the last deploy" not in render_pr_body(report, id_to_owner={})


def test_a_rule_whose_last_deploy_failed_is_named(tmp_path: Path) -> None:
    """State records the commit of a failed apply too. A rule deployed at A,
    changed at B and rejected at B had ``sha=B, status=failed``: B..HEAD has
    no diff, so its drift (the tenant still holds A) was not named."""
    repo, _deployed, edited, _ = _repo(tmp_path)
    head = _git(repo, "rev-parse", "HEAD")
    state = EnvState(env="t")
    state.remember("sentinel_analytic", "edited", sha=head, status="failed")
    assert changed_since_last_deploy([_changed("edited", edited)], state, repo=repo) == {
        ("sentinel_analytic", "edited"),
    }


def test_each_flagged_rule_names_the_changed_since_to_deploy_it(tmp_path: Path) -> None:
    """The PR told the operator to set ``changed_since`` to "the commit before
    the merge (HEAD~1 when the merge is the newest commit)". In the lab a
    scheduled bot commit landed after the merge, HEAD~1 selected nothing and
    the change stayed undeployed. The state records the commit each rule was
    last deployed from: that is the exact ``changed_since`` to use (after a
    failed deploy, the commit before it)."""
    from contentops.undeployed import deploy_bases

    repo, deployed, edited, untouched = _repo(tmp_path)
    head = _git(repo, "rev-parse", "HEAD")
    state = EnvState(env="t")
    state.remember("sentinel_analytic", "edited", sha=deployed)
    state.remember("sentinel_analytic", "untouched", sha=head, status="failed")
    assert deploy_bases(
        [_changed("edited", edited), _changed("untouched", untouched)], state, repo=repo,
    ) == {("sentinel_analytic", "edited"): deployed, ("sentinel_analytic", "untouched"): f"{head}~1"}


def test_the_pr_body_names_changed_since_per_rule() -> None:
    report = parse_report({"tenant": "t", "workspace": "w", "run_id": "1", "entries": [
        {"asset": "sentinel_analytic", "id": "edited", "kind": "changed", "undeployed": True,
         "changed_since": "0123456789abcdef0123456789abcdef01234567"},
    ]})
    body = render_pr_body(report, id_to_owner={})
    section = body.split("after the last deploy", 1)[1].split("### New", 1)[0]
    assert "`changed_since`" in section
    assert "`0123456789ab`" in section
    assert "HEAD~1" not in body
