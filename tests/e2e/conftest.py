# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""pytest plumbing for the e2e capability matrix.

This conftest is intentionally gated. The matrix test is heavy (it
materialises a sandbox + git repo + sample envelopes + audit chain on
every session and invokes ~40 CLI commands) and is NOT meant to run
on every PR via the default ``pytest`` invocation. Two opt-ins:

1. ``RUN_E2E=1`` env var, OR
2. the ``--mode`` flag is explicitly passed.

Without either, this conftest's collection hook skips every test under
``tests/e2e/`` so the default ``pytest`` / ``pytest -n auto`` run
ignores us. Mirrors the gate pattern in ``tests/integration/conftest.py``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import httpx
import pytest


_E2E_DIR = Path(__file__).parent.resolve()


# ---------------------------------------------------------------------------
# Mode plumbing
# ---------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--mode",
        action="store",
        default=None,
        choices=("offline", "mocked", "live"),
        help="E2E execution mode. Defaults to 'mocked' when RUN_E2E=1.",
    )
    parser.addoption(
        "--e2e-json",
        action="store",
        default=None,
        help="Write the per-capability results to this JSON path.",
    )


def _e2e_active(config: pytest.Config) -> bool:
    """E2E is active when RUN_E2E=1 or --mode was explicitly passed."""
    if os.environ.get("RUN_E2E") == "1":
        return True
    return config.getoption("--mode") is not None


_GATED_FILES = {
    "test_full_capability_matrix.py",
    "test_deployment_conformance.py",
}


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item],
) -> None:
    """Skip the heavy capability matrix unless explicitly opted in.

    The lightweight drift-guard test (``test_capability_drift_guard.py``)
    is NOT gated — it's a pure metadata check that should run on every
    PR to catch newly-added CLI commands without a registry entry.
    """
    if _e2e_active(config):
        return
    skip = pytest.mark.skip(reason="RUN_E2E!=1 and --mode unset; e2e matrix skipped")
    for item in items:
        try:
            item_path = Path(str(item.fspath)).resolve()
        except Exception:
            continue
        if item_path.name in _GATED_FILES:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def mode(request: pytest.FixtureRequest) -> str:
    return request.config.getoption("--mode") or "mocked"


# ---------------------------------------------------------------------------
# Sandbox dataclass + fixture
# ---------------------------------------------------------------------------


@dataclass
class Sandbox:
    """Resolved paths and identifiers the dispatcher needs to substitute
    into capability argv placeholders.
    """

    root: Path
    detections: Path
    audit: Path
    state: Path
    config: Path                # tenant.yml path (absolute)
    drift_json: Path
    drift_out: Path
    archive_a: Path
    archive_b: Path
    catalog_out: Path
    coverage_md: Path
    coverage_json: Path
    portfolio_csv: Path
    portfolio_json: Path
    restore_target: Path
    collect_target: Path
    clean_target: Path
    rule_seeded: str
    rule_lifecycle: str
    rule_defender: str
    last_sha: str
    placeholders: dict[str, str] = field(default_factory=dict)


_REPO_ROOT = Path(__file__).resolve().parents[2]


_TENANT_YML = """\
tenant:
  name: e2e
  tenantId: "00000000-0000-0000-0000-000000000099"
  defender:
    enabled: true
  sentinelWorkspaces:
    - role: integration
      subscriptionId: "00000000-0000-0000-0000-000000000001"
      resourceGroup: "rg-e2e-itest"
      workspaceName: "law-e2e-itest"
      location: westeurope
"""


def _seed_envelopes(detections: Path, *, rule_id: str,
                    lifecycle_id: str, defender_id: str) -> None:
    """Write one envelope per supported asset kind into the sandbox.

    Synthetic envelopes follow the v2 schema (id / version / asset /
    status / metadata / payload). Kept minimal so the lint runner
    doesn't trip on author-grade metadata gaps — the e2e test is about
    exercising the command flow, not validating production policy.
    """
    # sentinel_analytic — must satisfy KQL lint rules and be liveable
    # for explain / drift-resolve / state forget targets.
    (detections / "sentinel_analytic").mkdir(parents=True, exist_ok=True)
    (detections / "sentinel_analytic" / f"{rule_id}.yml").write_text(
        f"""id: {rule_id}
version: 0.1.0
asset: sentinel_analytic
status: production
metadata:
  arm_name: {rule_id}
  owner: e2e@example.invalid
payload:
  displayName: E2E Seeded Analytic
  description: Synthetic rule for the e2e capability matrix.
  kind: Scheduled
  enabled: false
  severity: Low
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | where EventID == 4625
    | summarize count() by IpAddress
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 0
  tactics:
    - Execution
""",
        encoding="utf-8",
    )

    # Second analytic in status: experimental + recent lastValidatedAt
    # so lifecycle promote can run through its gates.
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (detections / "sentinel_analytic" / f"{lifecycle_id}.yml").write_text(
        f"""id: {lifecycle_id}
version: 0.1.0
asset: sentinel_analytic
status: experimental
metadata:
  arm_name: {lifecycle_id}
  owner: e2e@example.invalid
  lastValidatedAt: "{recent}"
payload:
  displayName: E2E Lifecycle Candidate
  description: Synthetic experimental rule for the lifecycle promote gate test.
  kind: Scheduled
  enabled: false
  severity: Low
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | where EventID == 4625
    | summarize count() by IpAddress
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 0
  tactics:
    - Discovery
""",
        encoding="utf-8",
    )

    # sentinel_hunting
    (detections / "sentinel_hunting").mkdir(parents=True, exist_ok=True)
    (detections / "sentinel_hunting" / "e2e-hunting-001.yml").write_text(
        """id: e2e-hunting-001
version: 0.1.0
asset: sentinel_hunting
status: production
metadata:
  arm_name: e2e-hunting-001
  owner: e2e@example.invalid
payload:
  displayName: E2E Seeded Hunting
  description: Synthetic hunting query.
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4625
    | summarize count() by IpAddress
  tactics:
    - Discovery
""",
        encoding="utf-8",
    )

    # sentinel_watchlist
    (detections / "sentinel_watchlist").mkdir(parents=True, exist_ok=True)
    (detections / "sentinel_watchlist" / "e2e-watchlist-001.yml").write_text(
        """id: e2e-watchlist-001
version: 0.1.0
asset: sentinel_watchlist
status: production
payload:
  displayName: E2E Watchlist
  provider: e2e
  source: e2e.csv
  sourceType: Local
  itemsSearchKey: Key
  description: Synthetic watchlist.
  watchlistType: watchlist
  labels: []
  defaultDuration: P1DT0H
  sasUri: ''
  watchlistKind: Regular
  watchlistAlias: e2eWatchlist
""",
        encoding="utf-8",
    )

    # sentinel_parser
    (detections / "sentinel_parser").mkdir(parents=True, exist_ok=True)
    (detections / "sentinel_parser" / "e2e-parser-001.yml").write_text(
        """id: e2e-parser-001
version: 0.1.0
asset: sentinel_parser
status: production
metadata:
  arm_name: e2e-parser-001
payload:
  displayName: E2E Parser
  query: |-
    SecurityEvent
    | project TimeGenerated, EventID
  category: Function
  functionAlias: E2EParser
""",
        encoding="utf-8",
    )

    # sentinel_data_connector
    (detections / "sentinel_data_connector").mkdir(parents=True, exist_ok=True)
    (detections / "sentinel_data_connector" / "e2e-connector-001.yml").write_text(
        """id: e2e-connector-001
version: 0.1.0
asset: sentinel_data_connector
status: production
metadata:
  arm_name: e2e-connector-001
payload:
  kind: AzureActiveDirectory
  properties:
    tenantId: "00000000-0000-0000-0000-000000000099"
    dataTypes:
      alerts:
        state: enabled
""",
        encoding="utf-8",
    )

    # defender_custom_detection
    (detections / "defender_custom_detection").mkdir(parents=True, exist_ok=True)
    (detections / "defender_custom_detection" / f"{defender_id}.yml").write_text(
        f"""id: {defender_id}
version: 0.1.0
asset: defender_custom_detection
status: production
metadata:
  arm_name: '9999'
payload:
  displayName: E2E Defender Custom Detection
  isEnabled: false
  queryCondition:
    queryText: |-
      DeviceProcessEvents
      | where Timestamp > ago(1h)
      | where FileName =~ "cmd.exe"
      | summarize count() by DeviceId
  schedule:
    period: 1H
  detectionAction:
    organizationalScope: null
    alertTemplate:
      title: E2E Detection
      description: Synthetic for the e2e capability matrix.
      severity: low
      category: Execution
      recommendedActions: null
      mitreTechniques:
        - T1059
      impactedAssets: []
    responseActions: []
""",
        encoding="utf-8",
    )


def _seed_state(state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    # The e2e tenant slug from _TENANT_YML.
    env_dir = state_dir / "e2e"
    env_dir.mkdir(exist_ok=True)
    # State file under state/state.json (the loader checks both
    # state/state.json and state/<env>/state.json depending on env).
    (state_dir / "state.json").write_text(
        json.dumps({
            "schema_version": "1.0",
            "env": "e2e",
            "last_apply_sha": "",
            "last_apply_at": "",
            "managed_assets": {},
        }, indent=2),
        encoding="utf-8",
    )


def _seed_drift_report(drift_path: Path, rule_id: str) -> None:
    """Write a synthetic drift JSON report (drift-pr-body input)."""
    drift_path.write_text(json.dumps({
        "tenant": "e2e",
        "workspace": "law-e2e-itest",
        "run_id": "",
        "entries": [
            {"asset": "sentinel_analytic", "id": rule_id, "kind": "changed"},
        ],
    }, indent=2), encoding="utf-8")


def _git_init(root: Path) -> str:
    """Initialise a git repo + signed-off initial commit. Returns HEAD sha.

    Sandbox is gitignore-free; everything copied/seeded goes in the
    initial commit so rollback / snapshot-diff have a real ref to
    materialise.
    """
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "e2e",
        "GIT_AUTHOR_EMAIL": "e2e@example.invalid",
        "GIT_COMMITTER_NAME": "e2e",
        "GIT_COMMITTER_EMAIL": "e2e@example.invalid",
    }
    subprocess.run(
        ["git", "init", "-b", "main", "--quiet"], cwd=root, env=env, check=True,
    )
    subprocess.run(["git", "add", "-A"], cwd=root, env=env, check=True)
    subprocess.run(
        ["git", "commit", "--quiet", "-s", "-m", "e2e initial"],
        cwd=root, env=env, check=True,
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, env=env,
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return sha


def _build_collect_archive(root: Path, detections: Path, target: Path,
                           extra_rule_path: Path | None = None) -> Path:
    """Pack detections/ (+ optional extra rule) into a .tar.gz at target."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, "w:gz") as tar:
        tar.add(detections, arcname="detections")
        if extra_rule_path is not None and extra_rule_path.exists():
            tar.add(
                extra_rule_path,
                arcname=f"detections/sentinel_analytic/{extra_rule_path.name}",
            )
    return target


def _build_extra_rule(extra_path: Path) -> None:
    extra_path.parent.mkdir(parents=True, exist_ok=True)
    extra_path.write_text("""id: e2e-extra-only-in-b
version: 0.1.0
asset: sentinel_analytic
status: production
metadata:
  arm_name: e2e-extra-only-in-b
  owner: e2e@example.invalid
payload:
  displayName: E2E Extra Only In Archive B
  description: Synthetic delta for snapshot-diff.
  kind: Scheduled
  enabled: false
  severity: Low
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | summarize count() by EventID
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 0
  tactics:
    - Discovery
""", encoding="utf-8")


def _copy_audit_chain(target: Path) -> None:
    """Copy the real audit/*.jsonl chain into the sandbox.

    The hash chain spans every file in the directory, so copying a
    partial subset breaks verification. We copy them all (small JSONL
    files) or none.
    """
    target.mkdir(parents=True, exist_ok=True)
    src = _REPO_ROOT / "audit"
    if not src.is_dir():
        return
    for f in sorted(src.glob("*.jsonl")):
        shutil.copy2(f, target / f.name)


@pytest.fixture(scope="session")
def sandbox(tmp_path_factory: pytest.TempPathFactory, mode: str) -> Iterator[Sandbox]:
    """Materialise a self-contained sandbox tree, yield, autoclean."""
    root = tmp_path_factory.mktemp("contentops-e2e", numbered=True)

    rule_seeded = "e2e-seeded-001"
    rule_lifecycle = "e2e-lifecycle-001"
    rule_defender = "e2e-defender-001"

    detections = root / "detections"
    audit_dir = root / "audit"
    state_dir = root / "state"
    config_dir = root / "config"
    drift_json = root / "drift_report.json"
    drift_out = root / "drift_out.json"
    archive_dir = root / "_archives"
    coverage_md = root / "coverage.md"
    coverage_json = root / "coverage.json"
    portfolio_csv = root / "portfolio.csv"
    portfolio_json = root / "portfolio.json"
    catalog_out = root / "generated-catalog.md"
    restore_target = root / "_restore"
    collect_target = root / "_collect_target"
    clean_target = root / "_clean_target" / "detections"

    config_dir.mkdir(parents=True, exist_ok=True)
    config = config_dir / "tenant.yml"
    config.write_text(_TENANT_YML, encoding="utf-8")

    detections.mkdir(parents=True, exist_ok=True)
    # No dependencies.yml — discover_assets walks `*.yml` recursively, so
    # a file at the detections/ root would be parsed as an envelope.
    # Every capability invocation already passes --skip-deps-check.

    _seed_envelopes(
        detections,
        rule_id=rule_seeded,
        lifecycle_id=rule_lifecycle,
        defender_id=rule_defender,
    )
    _seed_state(state_dir)
    _seed_drift_report(drift_json, rule_seeded)
    _copy_audit_chain(audit_dir)

    # Build two archives that differ by a single rule, for snapshot-diff.
    extra_rule = archive_dir / "extra_rule.yml"
    _build_extra_rule(extra_rule)
    archive_a = _build_collect_archive(
        root, detections, archive_dir / "snapshot_a.tar.gz",
    )
    # Build B with the extra rule on disk first.
    shutil.copy2(extra_rule, detections / "sentinel_analytic" / extra_rule.name)
    archive_b = _build_collect_archive(
        root, detections, archive_dir / "snapshot_b.tar.gz",
    )
    # Remove the extra rule from detections/ so the matrix starts clean.
    (detections / "sentinel_analytic" / extra_rule.name).unlink(missing_ok=True)

    # Seed a separate detections tree under clean_target for the clean
    # capability (so we don't wipe the matrix's own detections/).
    clean_target.mkdir(parents=True, exist_ok=True)
    (clean_target / "sentinel_analytic").mkdir(exist_ok=True)
    (clean_target / "sentinel_analytic" / "ephemeral.yml").write_text(
        """id: ephemeral
version: 0.1.0
asset: sentinel_analytic
status: production
metadata:
  arm_name: ephemeral
payload:
  displayName: Ephemeral
  kind: Scheduled
  enabled: false
  severity: Low
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | summarize count() by EventID
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 0
  tactics:
    - Execution
""", encoding="utf-8",
    )

    # Init git AFTER everything is seeded so the initial commit has a
    # rollback-able snapshot.
    last_sha = _git_init(root)

    sb = Sandbox(
        root=root,
        detections=detections,
        audit=audit_dir,
        state=state_dir,
        config=config,
        drift_json=drift_json,
        drift_out=drift_out,
        archive_a=archive_a,
        archive_b=archive_b,
        catalog_out=catalog_out,
        coverage_md=coverage_md,
        coverage_json=coverage_json,
        portfolio_csv=portfolio_csv,
        portfolio_json=portfolio_json,
        restore_target=restore_target,
        collect_target=collect_target,
        clean_target=clean_target.parent,  # --path expects the detections dir parent
        rule_seeded=rule_seeded,
        rule_lifecycle=rule_lifecycle,
        rule_defender=rule_defender,
        last_sha=last_sha,
    )
    sb.placeholders = {
        "root": str(root),
        "detections": str(detections),
        "audit": str(audit_dir),
        "state": str(state_dir),
        "config": str(config),
        "drift_json": str(drift_json),
        "drift_out": str(drift_out),
        "archive_a": str(archive_a),
        "archive_b": str(archive_b),
        "catalog_out": str(catalog_out),
        "coverage_md": str(coverage_md),
        "coverage_json": str(coverage_json),
        "portfolio_csv": str(portfolio_csv),
        "portfolio_json": str(portfolio_json),
        "restore_target": str(restore_target),
        "collect_target": str(collect_target),
        "clean_target": str(clean_target),
        "rule_seeded": rule_seeded,
        "rule_lifecycle": rule_lifecycle,
        "rule_defender": rule_defender,
        "last_sha": last_sha,
    }
    yield sb
    # tmp_path_factory autocleans on session exit.


# ---------------------------------------------------------------------------
# Per-test env scoping (chdir + CONFIG_PATH monkeypatch)
# ---------------------------------------------------------------------------


@pytest.fixture
def scoped_env(sandbox: Sandbox, mode: str,
               monkeypatch: pytest.MonkeyPatch) -> None:
    """Chdir into the sandbox + redirect CONFIG_PATH for the duration
    of one capability invocation.

    Critical: ``contentops.config.CONFIG_PATH`` is computed at module
    import time relative to the installed package. ``chdir`` alone
    won't redirect the loader; the monkeypatch must rewrite both
    ``CONFIG_DIR`` and ``CONFIG_PATH``.
    """
    monkeypatch.chdir(sandbox.root)
    # Don't set PIPELINE_ENV — we write the sandbox config as
    # config/tenant.yml (the default), and resolve_config_path would
    # otherwise look for config/tenant.<env>.yml.
    monkeypatch.delenv("PIPELINE_ENV", raising=False)

    # Synthetic AAD creds in offline + mocked modes so:
    #   * conformance L2 ``auth_env`` check sees env vars set,
    #   * DefaultAzureCredential in mocked mode walks past
    #     EnvironmentCredential without prompting.
    # In live mode we leave the operator's real creds untouched.
    if mode in ("offline", "mocked"):
        monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000099")
        monkeypatch.setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000099")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "mock-secret-not-used")

    # Redirect the config loader to the sandbox tenant.yml.
    import contentops.config as _config
    monkeypatch.setattr(_config, "CONFIG_DIR", sandbox.config.parent)
    monkeypatch.setattr(_config, "CONFIG_PATH", sandbox.config)


# ---------------------------------------------------------------------------
# Respx router (mocked mode)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Non-destructive write guard (live mode only)
# ---------------------------------------------------------------------------


# Hosts and methods the guard permits in live mode. Everything else
# (PUT / PATCH / DELETE against ARM or Graph, POST to write endpoints)
# fails the test with the offending URL — even an accidental bug in a
# CLI command can't write to a real tenant.
_GUARD_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_GUARD_TOKEN_HOSTS = frozenset({
    "login.microsoftonline.com",
    "169.254.169.254",          # IMDS
    "localhost",                # IMDS / Workload Identity local probes
})
_GUARD_READ_HOSTS = frozenset({
    "management.azure.com",     # ARM
    "graph.microsoft.com",      # Graph
})
_GUARD_LA_QUERY_RE_TEXT = (
    r"^/v\d+/workspaces/[^/]+/query$"  # Log Analytics read-only KQL
)


@pytest.fixture
def non_destructive_guard(
    mode: str, monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """In live mode, monkeypatch httpx to block every write to Azure.

    The guard wraps ``httpx.Client.send`` and lets through only:

    * Read methods (``GET`` / ``HEAD`` / ``OPTIONS``) against
      ``management.azure.com`` and ``graph.microsoft.com``.
    * ``POST`` against the AAD token endpoint and the IMDS probes
      that ``DefaultAzureCredential`` walks.
    * ``POST`` against the Log Analytics ``/query`` endpoint (KQL is
      read-only by design).

    Anything else raises ``AssertionError`` with the exact URL, which
    pytest reports as a failure. In offline / mocked modes the guard
    is a no-op — the sandbox already protects those modes.
    """
    if mode != "live":
        yield
        return

    import re as _re
    la_re = _re.compile(_GUARD_LA_QUERY_RE_TEXT)
    original_send = httpx.Client.send

    def _guarded_send(self, request, **kwargs):
        host = (request.url.host or "").lower()
        method = request.method.upper()
        path = request.url.path or ""

        # AAD / IMDS token endpoints — pass through every method.
        if host in _GUARD_TOKEN_HOSTS:
            return original_send(self, request, **kwargs)
        # ARM / Graph reads — pass through.
        if host in _GUARD_READ_HOSTS and method in _GUARD_READ_METHODS:
            return original_send(self, request, **kwargs)
        # Log Analytics read-only query.
        if host == "api.loganalytics.io" and method == "POST" and la_re.match(path):
            return original_send(self, request, **kwargs)
        # Everything else: refuse and fail the test loudly.
        raise AssertionError(
            f"non-destructive guard refused {method} {host}{path}\n"
            f"  -- live mode only allows GET/HEAD/OPTIONS on ARM + Graph, "
            f"POST to AAD token endpoints, and POST to LA /query.\n"
            f"  -- if this request is legitimately read-only, add its "
            f"host/method to _GUARD_* in tests/e2e/conftest.py."
        )

    import httpx as _httpx
    monkeypatch.setattr(_httpx.Client, "send", _guarded_send)
    # NOTE: httpx.AsyncClient is intentionally NOT patched — contentops uses
    # only the sync httpx.Client. A sync guard on the async .send would be
    # incorrect (a live-mode `await` would break), so guarding it is deferred
    # until an async client is actually introduced.
    yield


# ---------------------------------------------------------------------------
# Respx router (mocked mode)
# ---------------------------------------------------------------------------


@pytest.fixture
def mocked_azure(mode: str) -> Iterator[object]:
    """Yield a respx.MockRouter in mocked mode, else None.

    Per-test scope (not session) so each capability gets a clean
    matcher list — important because ``assert_all_called=False`` would
    still surface confusing 'unexpected request' errors if a stale
    handler from a previous test fired first.
    """
    if mode != "mocked":
        yield None
        return
    import respx
    from tests.e2e._mocks import reset_stores

    reset_stores()
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        # Token / credential-probe hosts pass through to the real
        # network so DefaultAzureCredential can acquire a token.
        # Everything else (management.azure.com / graph.microsoft.com)
        # must be explicitly registered or respx raises loudly, instead
        # of silently leaking an unmocked call to a real tenant.
        router.route(host="login.microsoftonline.com").pass_through()
        router.route(host="169.254.169.254").pass_through()  # IMDS
        router.route(host="localhost").pass_through()         # local cred probes
        yield router


# ---------------------------------------------------------------------------
# Results collector + table renderer
# ---------------------------------------------------------------------------


@dataclass
class _RowRecord:
    capability: str
    status: str
    duration_ms: float
    message: str = ""


class _ResultsCollector:
    def __init__(self) -> None:
        self.rows: list[_RowRecord] = []

    def record(self, capability: str, status: str,
               duration_ms: float, message: str = "") -> None:
        self.rows.append(_RowRecord(
            capability=capability, status=status,
            duration_ms=duration_ms, message=message,
        ))

    def to_json(self) -> str:
        return json.dumps(
            [r.__dict__ for r in self.rows], indent=2, sort_keys=True,
        )


@pytest.fixture(scope="session")
def results_collector(
    request: pytest.FixtureRequest,
) -> Iterator[_ResultsCollector]:
    coll = _ResultsCollector()

    def _finalize() -> None:
        # Write the JSON sidecar if requested.
        out = request.config.getoption("--e2e-json")
        if out:
            out_path = Path(out).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(coll.to_json(), encoding="utf-8")
        # Render the table to the terminal regardless.
        from tests.e2e._render_table import render_rows
        # terminalreporter prints during the post-session footer;
        # we just print to stderr so it shows up in pytest output.
        import sys
        sys.stderr.write("\n")
        sys.stderr.write(render_rows(coll.rows))
        sys.stderr.write("\n")
        sys.stderr.flush()

    request.addfinalizer(_finalize)
    yield coll


__all__ = [
    "Sandbox",
    "mocked_azure",
    "mode",
    "results_collector",
    "sandbox",
    "scoped_env",
]
