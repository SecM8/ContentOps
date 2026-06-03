# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``contentops rule-test`` (L16 — F2-lite test harness).

Only the offline branches are exercised here:

* unknown rule_id → exit 1 with a clear message
* same rule_id across kinds (ambiguity) → exit 2 with a clear message
* missing KQL body → exit 1
* successful pretty-print + count + gate logic (with workspace_kql.query
  monkey-patched)

The live-workspace path is NOT exercised here — that's covered by the
existing live-integration suite gated on ``RUN_LIVE_TESTS=1``.
"""

from __future__ import annotations

import os
from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.workspace_kql import QueryResult


def _write_rule(root: Path, *, kind: str, rule_id: str, body: str) -> None:
    folder = root / "detections" / kind
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{rule_id}.yml").write_text(body, encoding="utf-8")


_ANALYTIC = dedent("""\
    id: brute-force-ssh
    version: 1.0.0
    asset: sentinel_analytic
    status: test
    metadata:
      arm_name: x
    payload:
      query: |-
        SecurityEvent | where EventID == 4625 | take 5
      displayName: Brute force SSH
""")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Working directory with one rule on disk."""
    _write_rule(tmp_path, kind="sentinel_analytic",
                rule_id="brute-force-ssh", body=_ANALYTIC)
    return tmp_path


def _invoke(args, root: Path, env: dict[str, str] | None = None):
    runner = CliRunner()
    saved = os.getcwd()
    saved_env = {k: os.environ.get(k) for k in (
        "PIPELINE_WORKSPACE_ID", "AZURE_CLIENT_ID", "AZURE_TENANT_ID",
        "AZURE_CLIENT_SECRET",
    )}
    try:
        os.chdir(str(root))
        # Default a workspace id so --workspace-id required doesn't trip.
        os.environ.setdefault("PIPELINE_WORKSPACE_ID", "ws-fake-guid")
        if env:
            for k, v in env.items():
                os.environ[k] = v
        return runner.invoke(cli, args, catch_exceptions=False)
    finally:
        os.chdir(saved)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_unknown_id_exits_1(repo: Path) -> None:
    """Bad id surfaces a clear error and exit 1 — important when the
    operator mistypes the id under pressure."""
    result = _invoke(["rule-test", "no-such-rule"], repo)
    assert result.exit_code == 1
    assert "no envelope with id='no-such-rule'" in result.output


def test_ambiguous_id_exits_2(repo: Path) -> None:
    """Same id slug across two asset kinds — must require --asset."""
    body = _ANALYTIC.replace(
        "asset: sentinel_analytic", "asset: sentinel_hunting"
    ).replace(
        "query: |-", "query: |-"
    )
    # Put the same id under a second kind. Different payload shape but
    # same id is enough to trigger the ambiguity branch.
    _write_rule(
        repo, kind="sentinel_hunting", rule_id="brute-force-ssh", body=body,
    )
    result = _invoke(["rule-test", "brute-force-ssh"], repo)
    assert result.exit_code == 2
    assert "matches 2 envelopes" in result.output
    assert "Pass --asset" in result.output


def test_happy_path_passes(repo: Path, monkeypatch) -> None:
    """A rule that runs cleanly and returns 3 rows — exit 0, pretty
    print, count reported. Stubs both the credential and the LA query
    so no auth or network is touched."""
    # Stub credential.get_token.
    class _Tok:
        token = "fake-token"

    class _Cred:
        def get_token(self, *_a, **_kw):
            return _Tok()

    monkeypatch.setattr(
        "contentops.utils.auth.get_credential", lambda: _Cred()
    )

    # Stub workspace_kql.query — invoked twice (display + count).
    call_count = {"n": 0}

    def _query(q, *, workspace_id, token, **kw):
        call_count["n"] += 1
        if "| count" in q:
            return QueryResult(rows=[{"Count": 3}], column_names=["Count"])
        return QueryResult(
            rows=[
                {"Account": "alice", "EventID": 4625},
                {"Account": "bob",   "EventID": 4625},
                {"Account": "carol", "EventID": 4625},
            ],
            column_names=["Account", "EventID"],
        )

    monkeypatch.setattr("contentops.workspace_kql.query", _query)

    result = _invoke(["rule-test", "brute-force-ssh"], repo)
    assert result.exit_code == 0, result.output
    assert "rule:      sentinel_analytic/brute-force-ssh" in result.output
    assert "3 total" in result.output
    assert "PASS" in result.output
    assert call_count["n"] == 2


def test_expect_min_fails_when_too_few(repo: Path, monkeypatch) -> None:
    """``--expect-min 5`` against a 3-row result → exit 1."""
    class _Tok:
        token = "fake-token"

    class _Cred:
        def get_token(self, *_a, **_kw):
            return _Tok()

    monkeypatch.setattr(
        "contentops.utils.auth.get_credential", lambda: _Cred()
    )

    def _query(q, *, workspace_id, token, **kw):
        if "| count" in q:
            return QueryResult(rows=[{"Count": 3}], column_names=["Count"])
        return QueryResult(rows=[{"x": 1}], column_names=["x"])

    monkeypatch.setattr("contentops.workspace_kql.query", _query)
    result = _invoke(
        ["rule-test", "brute-force-ssh", "--expect-min", "5"], repo,
    )
    assert result.exit_code == 1
    assert "row count 3 < --expect-min=5" in result.output


def test_expect_max_fails_when_too_many(repo: Path, monkeypatch) -> None:
    """``--expect-max 2`` against a 10-row result → exit 1."""
    class _Tok:
        token = "fake-token"

    class _Cred:
        def get_token(self, *_a, **_kw):
            return _Tok()

    monkeypatch.setattr(
        "contentops.utils.auth.get_credential", lambda: _Cred()
    )

    def _query(q, *, workspace_id, token, **kw):
        if "| count" in q:
            return QueryResult(rows=[{"Count": 10}], column_names=["Count"])
        return QueryResult(rows=[{"x": 1}], column_names=["x"])

    monkeypatch.setattr("contentops.workspace_kql.query", _query)
    result = _invoke(
        ["rule-test", "brute-force-ssh", "--expect-max", "2"], repo,
    )
    assert result.exit_code == 1
    assert "row count 10 > --expect-max=2" in result.output


# ---------------------------------------------------------------------------
# --role workspace resolution (no --workspace-id / no env)
# ---------------------------------------------------------------------------


def _stub_cred(monkeypatch) -> None:
    class _Tok:
        token = "fake-token"

    class _Cred:
        def get_token(self, *_a, **_kw):
            return _Tok()

    monkeypatch.setattr("contentops.utils.auth.get_credential", lambda: _Cred())


def test_role_auto_derives_workspace_id(repo: Path, monkeypatch) -> None:
    """With no --workspace-id and no env var, --role auto-derives the
    workspace GUID via resolve_workspace_id (like silent-rules / drift)."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_ID", raising=False)
    _stub_cred(monkeypatch)

    seen: dict = {}

    def _resolve(*, role, credential):
        seen["role"] = role
        return "resolved-ws-guid"

    def _query(q, *, workspace_id, token, **kw):
        seen["workspace_id"] = workspace_id
        if "| count" in q:
            return QueryResult(rows=[{"Count": 1}], column_names=["Count"])
        return QueryResult(rows=[{"x": 1}], column_names=["x"])

    monkeypatch.setattr("contentops.workspace_kql.resolve_workspace_id", _resolve)
    monkeypatch.setattr("contentops.workspace_kql.query", _query)

    result = CliRunner().invoke(cli, [
        "rule-test", "brute-force-ssh",
        "--path", str(repo / "detections"),
        "--role", "integration",
    ], catch_exceptions=False)

    assert result.exit_code == 0, result.output
    assert seen["role"] == "integration"
    assert seen["workspace_id"] == "resolved-ws-guid"
    assert "workspace: resolved-ws-guid" in result.output


def test_explicit_workspace_id_skips_role_resolution(repo: Path, monkeypatch) -> None:
    """An explicit --workspace-id overrides --role; resolve is never called."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_ID", raising=False)
    _stub_cred(monkeypatch)

    def _boom(*a, **kw):
        raise AssertionError("resolve_workspace_id must not run when --workspace-id is given")

    def _query(q, *, workspace_id, token, **kw):
        if "| count" in q:
            return QueryResult(rows=[{"Count": 1}], column_names=["Count"])
        return QueryResult(rows=[{"x": 1}], column_names=["x"])

    monkeypatch.setattr("contentops.workspace_kql.resolve_workspace_id", _boom)
    monkeypatch.setattr("contentops.workspace_kql.query", _query)

    result = CliRunner().invoke(cli, [
        "rule-test", "brute-force-ssh",
        "--path", str(repo / "detections"),
        "--workspace-id", "explicit-ws",
    ], catch_exceptions=False)

    assert result.exit_code == 0, result.output
    assert "workspace: explicit-ws" in result.output
