# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""End-to-end rollback drill against the integration Sentinel workspace.

Skipped unless ``RUN_LIVE_TESTS=1``. Mirrors the operator procedure
documented in ``docs/operations/rollback-drill.md``:

  1. Synthesise a detection envelope with a v1 marker in its
     description; commit to a throwaway git repo.
  2. Modify the envelope to a v2 marker; commit.
  3. Apply the v2 envelope to the live integration workspace.
  4. Confirm the live rule's description contains the v2 marker.
  5. Use ``contentops.rollback.materialize_at_sha`` to extract the
     detections tree as it existed at the v1 commit into a temp dir.
  6. Apply the v1 envelope from that temp tree against the same live
     workspace (this is what ``contentops rollback`` does internally
     after its dry-run gate).
  7. Confirm the live rule's description now contains the v1 marker —
     proves the replay-at-SHA contract end-to-end.

Cleanup is handled by the ``created_sentinel_rules`` session-scoped
fixture; a session-end sweep also removes any ``zz-itest-*`` rules
left behind by a crashed run.

Hardening: rules are created with ``enabled=False`` and have
informational severity so they cannot fire alerts during the drill.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from contentops.core.discovery import discover_assets, load_asset


def _git(repo: Path, *args: str) -> str:
    """Run a git command inside ``repo`` and return stdout (stripped)."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True, timeout=15,
    )
    return result.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "rollback-drill@test.invalid")
    _git(repo, "config", "user.name", "rollback drill")
    # Pre-create the detections tree so the empty-commit case never fires.
    (repo / "detections" / "sentinel_analytic").mkdir(parents=True)


def _envelope_yaml(rule_id: str, marker: str) -> str:
    """Render a synthetic sentinel_analytic envelope.

    ``marker`` lands in ``payload.description`` so we can tell v1 and
    v2 apart by reading the remote rule back. Using ``legacy: true``
    keeps the strict authoring-metadata schema out of the way — this
    test exercises rollback's git+API plumbing, not metadata lint.
    """
    return yaml.safe_dump({
        "id": rule_id,
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "legacy": True,
        "payload": {
            "kind": "Scheduled",
            "displayName": rule_id,
            "description": f"rollback-drill marker={marker} (zz-itest)",
            "severity": "Informational",
            "enabled": False,
            "query": 'print Test = "synthetic"',
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "tactics": [],
            "techniques": [],
        },
    }, sort_keys=False)


def _commit_yaml(repo: Path, rule_id: str, marker: str, message: str) -> str:
    """Write the envelope at the v1/v2 marker, commit, return full SHA."""
    yml = repo / "detections" / "sentinel_analytic" / f"{rule_id}.yml"
    yml.write_text(_envelope_yaml(rule_id, marker), encoding="utf-8")
    _git(repo, "add", "detections")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _live_description(client, rule_id: str) -> str:
    """Read the rule from ARM, return ``properties.description`` (or '')."""
    body = client.get_resource("alertRules", rule_id)
    if body is None:
        return ""
    return body.get("properties", {}).get("description", "")


def test_rollback_drill_replays_prior_yaml_against_live_workspace(
    sentinel_client, integration_id, created_sentinel_rules, tmp_path,
):
    """Full drill: commit v1 → commit v2 → apply v2 → rollback → apply v1.

    The contract proven here is "rolling back to a SHA replays exactly
    the YAML that existed at that SHA against the live tenant." If a
    future change to materialize_at_sha, the discovery walker, or the
    Sentinel handler breaks that contract, this test fails before the
    next prod incident response would.
    """
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
    from contentops.rollback import materialize_at_sha, resolve_sha

    rule_id = integration_id  # zz-itest-* prefix → sweep finds it on crash
    repo = tmp_path / "repo"
    _init_repo(repo)

    # 1. Commit v1 (the "good" version we'll roll back to).
    sha_v1_short = _commit_yaml(repo, rule_id, "v1", "feat: add v1 rule")
    sha_v1 = resolve_sha(sha_v1_short, repo=repo)
    assert len(sha_v1) == 40

    # 2. Commit v2 (the "bad" deploy we want to revert).
    _commit_yaml(repo, rule_id, "v2", "feat: bump rule to v2")

    # 3. Apply v2 directly via the handler — same call path apply_cmd
    #    uses, just bypassing the CLI argv parsing.
    handler = SentinelAnalyticHandler(lambda: sentinel_client)
    [v2_yaml] = discover_assets(repo / "detections")
    la_v2 = load_asset(v2_yaml)
    handler.validate(la_v2)
    # Register cleanup intent BEFORE the live call. handler.apply may raise
    # after the ARM PUT has succeeded server-side (network blip, transient
    # auth expiry, unexpected handler exception); registering after the
    # call leaves an orphan rule that only the session-end sweep can
    # reach. The fixture's teardown delete is idempotent on a rule that
    # was never created (conftest.py:225-235 swallows the 404), so
    # pre-registering is safe.
    created_sentinel_rules.append(rule_id)
    result_v2 = handler.apply(la_v2, dry_run=False)
    assert result_v2.status == "success", (
        f"v2 apply did not succeed: status={result_v2.status} "
        f"error={result_v2.error}"
    )

    # 4. Live tenant should now have v2.
    live = _live_description(sentinel_client, rule_id)
    assert "marker=v2" in live, (
        f"expected live description to carry v2 marker after apply, got: {live!r}"
    )
    assert "marker=v1" not in live, (
        f"live description unexpectedly still has v1 marker: {live!r}"
    )

    # 5. Materialise the detections tree as it existed at v1 into a
    #    fresh temp dir — this is the same plumbing `contentops rollback`
    #    runs after its dry-run gate.
    rollback_root = tmp_path / "rollback-materialize"
    rollback_root.mkdir()
    n_files = materialize_at_sha(sha_v1, "detections", rollback_root, repo=repo)
    assert n_files >= 1, "expected at least one file materialised from v1 SHA"

    # The materialised tree must contain only the v1 envelope.
    [v1_yaml] = discover_assets(rollback_root / "detections")
    assert "marker=v1" in v1_yaml.read_text(encoding="utf-8"), (
        "materialised envelope is not the v1 version we committed"
    )

    # 6. Apply the v1 envelope from the materialised tree.
    la_v1 = load_asset(v1_yaml)
    handler.validate(la_v1)
    result_v1 = handler.apply(la_v1, dry_run=False)
    assert result_v1.status == "success", (
        f"rollback apply did not succeed: status={result_v1.status} "
        f"error={result_v1.error}"
    )

    # 7. Live tenant should now be back at v1 — the contract.
    live = _live_description(sentinel_client, rule_id)
    assert "marker=v1" in live, (
        f"expected live description to carry v1 marker after rollback, got: {live!r}"
    )
    assert "marker=v2" not in live, (
        f"live description still has v2 marker after rollback: {live!r}"
    )


def test_rollback_drill_with_missing_sha_raises_clearly(tmp_path):
    """Smoke: rollback.resolve_sha surfaces a useful error on a bogus SHA.

    Unit-level but lives here because the message text is part of the
    operator-facing rollback drill — if it ever stops surfacing the
    bad SHA verbatim, the drill instructions need updating. Doesn't
    hit Azure; collected but skipped unless RUN_LIVE_TESTS=1 (per the
    ``pytest_collection_modifyitems`` hook in
    ``tests/integration/conftest.py``).
    """
    from contentops.rollback import RollbackError, resolve_sha

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "rollback-drill@test.invalid")
    _git(repo, "config", "user.name", "rollback drill")
    (repo / "f.txt").write_text("seed")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "seed")

    with pytest.raises(RollbackError, match="could not resolve"):
        resolve_sha("deadbeefnotacommit", repo=repo)
