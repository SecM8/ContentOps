# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Capability registry for the end-to-end CLI matrix test.

One entry per ``contentops`` leaf command path we want to exercise. Each
entry declares the argv (with sandbox placeholders), which execution
modes apply, which mock route bundles to load, and how to classify the
result. The matrix test (``test_full_capability_matrix.py``) iterates
this registry; the drift-guard test cross-checks it against the live
Click tree from ``contentops.catalog.inspect.inspect_cli``.

Placeholders the dispatcher resolves at call time (see ``Sandbox`` in
``conftest.py``):

* ``{detections}``  -> sandbox detections directory
* ``{audit}``       -> sandbox audit directory
* ``{state}``       -> sandbox state directory (root, not the .json)
* ``{config}``      -> sandbox tenant.yml path
* ``{drift_json}``  -> pre-rendered sample drift report
* ``{archive_a}``   -> first pre-built collect archive
* ``{archive_b}``   -> second pre-built collect archive (one rule diff)
* ``{catalog_out}`` -> sandbox path to write the generated catalog into
* ``{repo_root}``   -> sandbox root (used by ``catalog check``)
* ``{rule_seeded}`` -> envelope id of the seeded sample rule
* ``{rule_lifecycle}`` -> envelope id of the experimental rule for promote
* ``{rule_defender}``  -> envelope id of the seeded Defender rule
* ``{last_sha}``    -> HEAD sha of the sandbox git repo
* ``{coverage_md}`` -> sandbox path to write the coverage markdown
* ``{portfolio_csv}`` -> sandbox path to write the portfolio CSV
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal


Mode = Literal["offline", "mocked", "live"]
Needs = Literal["none", "sentinel", "defender", "both", "git"]


@dataclass(frozen=True)
class Capability:
    """One CLI invocation we want to exercise end-to-end."""

    id: str
    cli: tuple[str, ...]
    needs: Needs
    modes: frozenset[Mode]
    mock_routes: tuple[str, ...] = ()
    setup: Callable[[object], None] | None = None
    cleanup: Callable[[object], None] | None = None
    expect_exit: tuple[int, ...] = (0,)
    expect_substrings: tuple[str, ...] = ()
    catalog_path: str | None = None
    notes: str = ""


# Click command paths in the catalog that we deliberately do NOT exercise
# in the matrix. The drift-guard test allows these to be missing from
# the registry without failing.
#
# Each entry must carry a one-line justification.
INTENTIONALLY_UNCOVERED: dict[str, str] = {
    "test": (
        "contentops test invokes pytest as a subprocess; including it in "
        "the matrix would recurse into the same test session."
    ),
    "defender-patch-probe": (
        "Operator diagnostic that PATCHes/creates+deletes live Defender "
        "detection rules with --send; must not run unattended in the e2e "
        "matrix. Body-construction + cleanup covered by "
        "tests/v2/test_defender_patch_probe.py."
    ),
    "audit": "Click group container — leaf subcommands cover the surface.",
    "audit query": "Click group container — leaf subcommands cover the surface.",
    "config": "Click group container — leaf subcommands cover the surface.",
    "catalog": "Click group container — leaf subcommands cover the surface.",
    "state": "Click group container — leaf subcommands cover the surface.",
    "state sync": "Click group container — leaf subcommands cover the surface.",
    "lifecycle": "Click group container — leaf subcommands cover the surface.",
    "status": "Click group container — leaf subcommands cover the surface.",
    "status all": (
        "Convenience wrapper that invokes `status configuration` + "
        "`status deployments` with their default output paths; the two "
        "leaf entries below cover the matrix."
    ),
    "enable": (
        "Inverse of `disable`; the surgical YAML mutation pattern is "
        "the same as the disable command (which IS exercised). Covered "
        "by tests/v2/test_enable_pattern.py (15 tests including a "
        "disable -> enable round-trip)."
    ),
    "upstream": "Click group container — leaf subcommands cover the surface.",
    "upstream check-marketplace": (
        "Calls Sentinel ARM `contentPackages` against a live workspace; "
        "the mocked-provider path is exercised by "
        "tests/v2/test_upstream_cli.py."
    ),
    "upstream check-templates": (
        "Calls Sentinel ARM `alertRuleTemplates` against a live "
        "workspace; the mocked-provider path is exercised by "
        "tests/v2/test_upstream_cli.py."
    ),
    "upstream check-schemas": (
        "Calls the LA workspace metadata API against a live workspace; "
        "the mocked-fetcher path is exercised by "
        "tests/v2/test_upstream_schemas.py."
    ),
    "upstream check-defender-schema": (
        "Calls Microsoft Graph `runHuntingQuery` against a live tenant "
        "with `ThreatHunting.Read.All`; the mocked-fetcher path is "
        "exercised by tests/v2/test_upstream_defender_schema.py."
    ),
    "upstream pre-pr-refresh": (
        "One-shot umbrella command that runs check-schemas + "
        "check-defender-schema for the validate.yml pre-PR refresh. "
        "Honours config/lint_strict.yml's refresh_on_pr + mode + "
        "per-source enable. Skip-path is unit-tested in "
        "tests/v2/test_upstream_defender_schema.py."
    ),
    "auto-disabled-rules": (
        "NVISO Part 7. Queries SentinelHealth + LAQueryLogs via the "
        "LA workspace; mocked-path coverage in "
        "tests/v2/test_workspace_kql.py (auto_disabled_query tests)."
    ),
    "undeployed-rules": (
        "Offline repo-vs-applied-state reconciliation (authored but never "
        "deployed); no live tenant. Fully covered end-to-end "
        "(find_undeployed + render + CLI) in tests/v2/test_undeployed.py."
    ),
    "audit head": (
        "Offline read-only summary of the audit-chain head (for the deploy "
        "workflow's GitHub Artifact Attestation). No live tenant. Covered by "
        "head_summary + CLI tests in tests/v2/test_audit_chain.py."
    ),
    "detection-docs": "Click group container -- leaf subcommands cover the surface.",
    "detection-docs check": (
        "Pure-function drift gate over docs/detections/. Unit-tested "
        "end-to-end (load envelopes -> render -> compare disk) in "
        "tests/v2/test_detection_docs.py."
    ),
    "detection-docs regenerate": (
        "Sibling of `catalog regenerate` -- writes per-detection "
        "markdown files. Behavior unit-tested in "
        "tests/v2/test_detection_docs.py against an isolated tmp_path."
    ),
    "tuning": "Click group container -- leaf subcommands cover the surface.",
    "tuning preview": (
        "NVISO Part 8 PR-time impact preview. Diff + displayName lookup "
        "+ markdown rendering covered by tests/v2/test_tuning.py; the "
        "LA query path runs in CI only on base-repo PRs (OIDC required)."
    ),
    "navigator": (
        "MITRE ATT&CK Navigator layer renderer. Pure extractors + "
        "deterministic JSON renderer covered by "
        "tests/v2/test_navigator_extract.py and "
        "tests/v2/test_navigator_render.py. The live-tenant axes "
        "(--deployed / --firings) hit ARM + Graph + LA; mocked-provider "
        "coverage in the same files."
    ),
    "report": (
        "SOC-grade detection inventory. Pure-function assembler "
        "(envelope + git log + audit JSONL) covered end-to-end by "
        "tests/v2/test_report.py including the CLI integration. "
        "The renderers (HTML / Markdown / shields.io badge) are "
        "deterministic stdlib-only — same test file pins HTML "
        "escaping, markdown pipe escaping, and badge schema "
        "conformance. The live-enrichment variants land in a "
        "follow-up PR."
    ),
    "alerts": "Click group container -- leaf subcommands cover the surface.",
    "alerts collect": (
        "Calls Graph Security alerts_v2 or Sentinel ARM incidents "
        "against a live tenant. Requires SecurityAlert.Read.All or "
        "Sentinel Contributor RBAC. Pydantic model validation and "
        "source-detection logic covered by "
        "tests/v2/test_alerts_models.py (28 tests). Live path "
        "covered by tests/integration/test_alerts_collect.py."
    ),
    "alerts rollup": (
        "Calls Graph/Sentinel to compute a daily classification "
        "rollup. Pure-function rollup engine + markdown renderer "
        "covered by tests/v2/test_alerts_rollup.py (28 tests). "
        "Live path covered by tests/integration/test_alerts_collect.py."
    ),
    "alerts report": (
        "Trend report over a multi-day period. Pure-function trend "
        "computation + rendering covered by "
        "tests/v2/test_alerts_rollup.py. Live path requires "
        "Graph/Sentinel credentials."
    ),
    "alerts health": (
        "Detection health report — maps alerts to detections and "
        "computes per-detection TP/FP rates + recommendations. "
        "Pure-function engine covered by "
        "tests/v2/test_detection_health.py (42 tests). Live path "
        "covered by tests/integration/test_detection_health_live.py."
    ),
    "alerts sync": (
        "Syncs alerts from Graph/Sentinel into a persistent PII-free "
        "ledger. Smart lookback engine + watermark logic covered by "
        "tests/v2/test_alerts_ledger.py (20 tests) and "
        "tests/v2/test_alerts_sync.py (11 tests). Live path requires "
        "Graph/Sentinel credentials."
    ),
}


# Stable Click leaf paths the matrix exercises. The drift-guard test
# uses this set to detect new commands added without a registry entry.
COVERED_LEAVES: tuple[str, ...] = (
    "apply",
    "audit query by-actor",
    "audit query failures",
    "audit query latest",
    "audit query rollbacks",
    "audit query timeline",
    "audit verify",
    "bootstrap",
    "catalog check",
    "catalog regenerate",
    "clean",
    "collect",
    "config list-workspaces",
    "config validate",
    "conformance",
    "coverage",
    "defender-extensions-probe",
    "defender-roundtrip-diff",
    "disable",
    "doctor",
    "drift",
    "drift-pr-body",
    "drift-resolve",
    "explain",
    "lifecycle promote",
    "lint",
    "lock",
    "new",
    "plan",
    "portfolio",
    "prune",
    "retry-failed",
    "rollback",
    "restore",
    "rule-test",
    "sentinel-roundtrip-diff",
    "silent-rules",
    "snapshot-diff",
    "state forget",
    "state show",
    "state sync pull",
    "state sync push",
    "state sync status",
    "status configuration",
    "status deployments",
    "unlock",
)


# -- Capability definitions -------------------------------------------------
#
# All three modes unless noted. ``offline`` skips anything requiring
# Azure or a remote git ref. ``mocked`` loads the bundle named under
# ``mock_routes`` (see _mocks.py); the dispatcher activates the bundles
# in conftest before invoking the command.


CAPABILITIES: tuple[Capability, ...] = (
    # -- Pure-local commands ------------------------------------------------
    Capability(
        id="plan",
        cli=("plan", "--path", "{detections}", "--skip-deps-check"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="plan",
        # Synthetic envelopes may trip handler validation in modes the
        # tenant config doesn't fully exercise; tolerant exit accepts
        # either clean plan or per-asset validation failures.
        expect_exit=(0, 1),
    ),
    Capability(
        id="plan.filter_asset",
        cli=(
            "plan", "--path", "{detections}", "--skip-deps-check",
            "--asset", "sentinel_analytic",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        expect_exit=(0, 1),
    ),
    Capability(
        id="lint.strict",
        cli=("lint", "--strict", "--path", "{detections}", "--severity", "warning"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="lint",
        # KQL101 etc. fire on intentionally-noisy synthetic envelopes;
        # the e2e exercises the command flow, not policy-perfection.
        expect_exit=(0, 1),
    ),
    Capability(
        id="new.sentinel_analytic",
        cli=(
            "new", "sentinel_analytic", "e2e-scaffolded-001",
            "--out", "{detections}/sentinel_analytic/e2e-scaffolded-001.yml",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="new",
    ),
    Capability(
        id="audit.verify",
        cli=("audit", "verify", "--root", "{root}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="audit verify",
        expect_substrings=("audit chain:",),
    ),
    Capability(
        id="audit.query.latest",
        cli=(
            "audit", "query", "latest", "{rule_seeded}",
            "--audit-dir", "{audit}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="audit query latest",
    ),
    Capability(
        id="audit.query.failures",
        cli=("audit", "query", "failures", "--audit-dir", "{audit}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="audit query failures",
    ),
    Capability(
        id="audit.query.by_actor",
        cli=(
            "audit", "query", "by-actor", "e2e",
            "--audit-dir", "{audit}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="audit query by-actor",
    ),
    Capability(
        id="audit.query.rollbacks",
        cli=("audit", "query", "rollbacks", "--audit-dir", "{audit}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="audit query rollbacks",
    ),
    Capability(
        id="audit.query.timeline",
        cli=(
            "audit", "query", "timeline", "{rule_seeded}",
            "--audit-dir", "{audit}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="audit query timeline",
    ),
    Capability(
        id="coverage.markdown",
        cli=(
            "coverage", "--path", "{detections}",
            "--format", "markdown", "--out-md", "{coverage_md}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="coverage",
    ),
    Capability(
        id="coverage.json",
        cli=(
            "coverage", "--path", "{detections}",
            "--format", "json", "--out-json", "{coverage_json}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
    ),
    Capability(
        id="portfolio.csv",
        cli=(
            "portfolio", "--path", "{detections}",
            "--out-csv", "{portfolio_csv}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="portfolio",
    ),
    Capability(
        id="portfolio.json",
        cli=(
            "portfolio", "--path", "{detections}",
            "--out-json", "{portfolio_json}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
    ),
    Capability(
        id="state.show",
        cli=("state", "show", "--env", "e2e"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="state show",
    ),
    Capability(
        id="state.show.json",
        cli=("state", "show", "--env", "e2e", "--format", "json"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
    ),
    Capability(
        id="state.forget",
        cli=(
            "state", "forget", "{rule_seeded}",
            "--asset", "sentinel_analytic", "--env", "e2e",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="state forget",
    ),
    Capability(
        id="config.validate",
        cli=("config", "validate", "--path", "{config}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="config validate",
    ),
    Capability(
        id="config.list_workspaces",
        cli=("config", "list-workspaces", "--path", "{config}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="config list-workspaces",
    ),
    Capability(
        id="conformance.l1_l2",
        cli=("conformance", "--scope", "L1,L2", "--exit-zero"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="conformance",
        expect_substrings=("Conformance:",),
    ),
    Capability(
        id="catalog.regenerate",
        cli=(
            "catalog", "regenerate",
            "--out", "{catalog_out}",
            "--repo-root", "{root}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="catalog regenerate",
    ),
    Capability(
        id="catalog.check",
        cli=("catalog", "check", "--repo-root", "{root}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="catalog check",
        # Catalog check exits 1 if generated-catalog.md is out of date or
        # missing — we don't seed one in the sandbox, so non-zero exit
        # is the expected pre-regenerate state.
        expect_exit=(0, 1),
    ),
    Capability(
        id="doctor",
        cli=("doctor",),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="doctor",
        # Doctor returns non-zero when env vars are unset / .env is
        # missing; the sandbox has neither.
        expect_exit=(0, 1, 2),
    ),
    Capability(
        id="apply.dry_run",
        cli=(
            "apply", "--path", "{detections}",
            "--dry-run", "--no-audit", "--skip-deps-check",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="apply",
        # Some handlers may fail validation on the synthetic envelopes;
        # tolerant exit code.
        expect_exit=(0, 1, 2),
    ),
    Capability(
        id="clean.yes",
        cli=("clean", "--path", "{clean_target}", "--yes"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="clean",
    ),
    Capability(
        id="disable.rule",
        cli=(
            "disable", "{rule_seeded}",
            "--reason", "e2e capability test",
            "--path", "{detections}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="disable",
    ),
    Capability(
        id="lock.rule",
        cli=("lock", "{rule_seeded}", "--path", "{detections}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="lock",
    ),
    Capability(
        id="unlock.rule",
        cli=("unlock", "{rule_seeded}", "--path", "{detections}"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="unlock",
    ),
    Capability(
        id="snapshot_diff",
        cli=(
            "snapshot-diff", "{archive_a}", "{archive_b}",
            "--format", "json",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="snapshot-diff",
        # Exit 2 means "changes detected" — the two archives differ by
        # one rule, so this is the expected outcome.
        expect_exit=(0, 2),
    ),
    Capability(
        id="restore",
        cli=(
            "restore", "{archive_a}",
            "--out", "{restore_target}", "--force",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="restore",
    ),
    Capability(
        id="drift_pr_body",
        cli=(
            "drift-pr-body",
            "--report", "{drift_json}",
            "--path", "{detections}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="drift-pr-body",
    ),
    Capability(
        id="drift_resolve.git",
        cli=(
            "drift-resolve", "{rule_seeded}",
            "--strategy", "git",
            "--path", "{detections}",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="drift-resolve",
    ),
    Capability(
        id="lifecycle.promote.dry_run",
        cli=(
            "lifecycle", "promote", "{rule_lifecycle}",
            "--path", "{detections}", "--dry-run",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="lifecycle promote",
        # Lifecycle gates can fail if metadata isn't recent enough; we
        # accept both pass-and-promote and gates-failed-no-promote.
        expect_exit=(0, 1),
    ),
    Capability(
        id="explain.rule",
        cli=(
            "explain", "{rule_seeded}",
            "--path", "{detections}", "--audit-dir", "{audit}",
            "--format", "json",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="explain",
    ),
    Capability(
        id="retry_failed.dry_run",
        cli=(
            "retry-failed", "--path", "{detections}",
            "--audit-dir", "{audit}", "--dry-run",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="retry-failed",
    ),
    Capability(
        id="bootstrap.dry_run",
        cli=(
            "bootstrap",
            "--subscription", "00000000-0000-0000-0000-000000000000",
            "--resource-group", "rg-e2e-itest",
            "--workspace", "law-e2e-itest",
            "--dry-run",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="bootstrap",
        expect_substrings=("[DRY-RUN]",),
    ),
    Capability(
        id="state.sync.status",
        cli=("state", "sync", "status", "--env", "e2e"),
        needs="git",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="state sync status",
        # Local-only ref state; OK if the ref is missing.
        expect_exit=(0, 1),
    ),
    Capability(
        id="state.sync.push.no_push",
        cli=("state", "sync", "push", "--env", "e2e", "--no-push"),
        needs="git",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="state sync push",
        # Sandbox repo has no remote; --no-push avoids the network.
        expect_exit=(0, 1),
    ),
    Capability(
        id="state.sync.pull.no_fetch",
        cli=("state", "sync", "pull", "--env", "e2e", "--no-fetch"),
        needs="git",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="state sync pull",
        # Local ref may not exist; tolerant exit.
        expect_exit=(0, 1),
    ),
    Capability(
        id="status.configuration",
        cli=("status", "configuration", "--scope", "L1", "--out", "-"),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="status configuration",
        # L1 only — no tenant config required for the offline sandbox.
        # L2 expects config/tenant.yml which the sandbox doesn't seed.
    ),
    Capability(
        id="status.deployments",
        cli=(
            "status", "deployments",
            "--detections", "{detections}",
            "--audit", "{audit}",
            "--out", "-",
        ),
        needs="none",
        modes=frozenset({"offline", "mocked", "live"}),
        catalog_path="status deployments",
    ),

    # -- Commands that need Azure (mocked or live) --------------------------
    # NOTE: every live-mode capability MUST be read-only against Azure.
    # The non_destructive_guard fixture in conftest.py blocks any write
    # (PUT / PATCH / DELETE) to ARM or Graph. For ``apply`` we therefore
    # always pass --dry-run so the command exercises plan + remote read
    # but never deploys.
    Capability(
        id="apply.live_dry_run",
        cli=(
            "apply", "--path", "{detections}",
            "--dry-run", "--no-audit", "--skip-deps-check",
            "--continue-on-error", "--role", "integration",
        ),
        needs="both",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "arm_sentinel", "graph_defender"),
        expect_exit=(0, 1),
    ),
    Capability(
        id="collect",
        cli=(
            "collect", "--path", "{collect_target}",
            "--workers", "1", "--workspace", "law-e2e-itest",
        ),
        needs="both",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "arm_sentinel", "graph_defender"),
        catalog_path="collect",
        expect_exit=(0, 1, 2),
    ),
    Capability(
        id="drift.report",
        cli=(
            "drift", "--path", "{detections}",
            "--no-exit-on-drift", "--workspace", "law-e2e-itest",
            "--report", "{drift_out}",
        ),
        needs="both",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "arm_sentinel", "graph_defender"),
        catalog_path="drift",
        expect_exit=(0, 1, 2),
    ),
    Capability(
        id="prune.dry_run",
        cli=(
            "prune", "--path", "{detections}",
            "--dry-run", "--workspace", "law-e2e-itest",
        ),
        needs="both",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "arm_sentinel", "graph_defender"),
        catalog_path="prune",
        expect_exit=(0, 1),
    ),
    Capability(
        id="rollback.dry_run",
        cli=(
            "rollback", "{last_sha}", "--asset", "sentinel_analytic",
            "--dry-run", "--workspace", "law-e2e-itest",
        ),
        needs="both",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "arm_sentinel", "graph_defender"),
        catalog_path="rollback",
        expect_exit=(0, 1),
    ),
    Capability(
        id="defender_extensions_probe",
        cli=("defender-extensions-probe", "--format", "json"),
        needs="defender",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "graph_defender"),
        catalog_path="defender-extensions-probe",
        # Exit 2 if any endpoint reports available — bundle returns
        # 404s so we expect 0; tolerate 2 to be safe.
        expect_exit=(0, 2),
    ),
    Capability(
        id="defender_roundtrip_diff",
        cli=(
            "defender-roundtrip-diff", "{rule_defender}",
            "--path", "{detections}",
        ),
        needs="defender",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "graph_defender"),
        catalog_path="defender-roundtrip-diff",
        # Exit 1 if remote not found (mock returns empty map); exit 2
        # if diffs present.
        expect_exit=(0, 1, 2),
    ),
    Capability(
        id="sentinel_roundtrip_diff",
        cli=(
            "sentinel-roundtrip-diff", "{rule_seeded}",
            "--path", "{detections}",
            "--workspace", "law-e2e-itest",
        ),
        needs="sentinel",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "arm_sentinel"),
        catalog_path="sentinel-roundtrip-diff",
        expect_exit=(0, 1, 2),
    ),
    Capability(
        id="silent_rules",
        cli=(
            "silent-rules",
            "--workspace-id", "00000000-0000-0000-0000-000000000001",
            "--since", "1", "--format", "json",
        ),
        needs="sentinel",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "kql_query"),
        catalog_path="silent-rules",
        expect_exit=(0, 1),
    ),
    Capability(
        id="rule_test",
        cli=(
            "rule-test", "{rule_seeded}",
            "--path", "{detections}",
            "--asset", "sentinel_analytic",
            "--workspace-id", "00000000-0000-0000-0000-000000000001",
            "--limit", "1",
        ),
        needs="sentinel",
        modes=frozenset({"mocked", "live"}),
        mock_routes=("oidc_token", "kql_query"),
        catalog_path="rule-test",
        expect_exit=(0, 1),
    ),
)


def select_for_mode(mode: Mode) -> list[Capability]:
    """Return capabilities the matrix should run in this mode.

    Capabilities not in the mode's set are still yielded (the test
    body records them as SKIP); this keeps the row count constant
    across modes for diff-friendly reporting.
    """
    return list(CAPABILITIES)


__all__ = [
    "Capability",
    "CAPABILITIES",
    "COVERED_LEAVES",
    "INTENTIONALLY_UNCOVERED",
    "Mode",
    "select_for_mode",
]
