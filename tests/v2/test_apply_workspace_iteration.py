# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Direct unit tests for the apply/plan workspace-iteration helpers.

These cover the functions extracted from apply.py into apply_support.py
(WorkspaceRunContext, _print_multi_workspace_banner, _process_plan_asset,
_process_apply_asset, _run_workspace_iteration) at the function level —
the command CLIs (apply_cmd / plan_cmd) exercise them end-to-end elsewhere
(test_multi_workspace_targeting.py etc.), but the per-asset control flow
(no-handler-no-append, SnippetError append shape, error-validate vs
error-apply, the audit_pairs guard, the explicit command dispatch) is
pinned here.

apply_snippets + _compute_snippet_digest + register_default_handlers are
monkeypatched so the tests isolate the loop's control flow from snippet
substitution + real handler registration.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from contentops.cli.commands import apply_support as A
from contentops.core.asset import Asset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction
from contentops.snippets import SnippetError


def _la(rule_id: str, asset: Asset = Asset.SENTINEL_ANALYTIC):
    return SimpleNamespace(
        envelope=SimpleNamespace(id=rule_id, asset=asset),
        path=Path(f"{rule_id}.yml"),
        payload={"query": "SecurityEvent | take 1"},
    )


def _ws(name: str, role: str = "prod"):
    return SimpleNamespace(workspaceName=name, role=role)


class _FakeHandler:
    def __init__(self, asset: Asset, *, fail_validate=False, fail_apply=False):
        self.asset = asset
        self.fail_validate = fail_validate
        self.fail_apply = fail_apply
        self.applied: list[tuple[str, str | None, bool]] = []
        self.planned: list[str] = []
        self.closed = False

    def validate(self, la):
        if self.fail_validate:
            raise ValueError("validate boom")

    def plan(self, la):
        self.planned.append(la.envelope.id)
        return ActionResult(
            asset_id=la.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="planned",
        )

    def apply(self, la, *, dry_run=False):
        if self.fail_apply:
            raise ValueError("apply boom")
        self.applied.append((la.envelope.id, os.environ.get("PIPELINE_WORKSPACE_NAME"), dry_run))
        return ActionResult(
            asset_id=la.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="success", verified=True,
        )

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    """Passthrough snippets + stub digest + no-op re-register + clean env."""
    monkeypatch.setattr(A, "apply_snippets", lambda la, ws, overrides_root=None: la)
    monkeypatch.setattr(A, "_compute_snippet_digest", lambda la, la_resolved: "digest-x")
    # The per-workspace re-register would otherwise install the REAL factories
    # (and need tenant config); the registry stays as the test set it.
    monkeypatch.setattr(A, "register_default_handlers", lambda: None)
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    yield


def _register(handler: _FakeHandler) -> None:
    default_registry.register(handler.asset, lambda: handler)


# ---------------------------------------------------------------------------
# WorkspaceRunContext + banner
# ---------------------------------------------------------------------------


def test_context_defaults_plan_vs_apply() -> None:
    plan = A.WorkspaceRunContext(command="plan", detections_path=Path("detections"))
    assert plan.audit_pairs is None and plan.results == [] and plan.dry_run is False
    appl = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"), audit_pairs=[])
    assert appl.audit_pairs == []


def test_banner_silent_for_single_workspace(capsys) -> None:
    A._print_multi_workspace_banner("apply", "prod", [_ws("ws-a")])
    assert capsys.readouterr().out == ""


def test_banner_printed_for_multiple_workspaces(capsys) -> None:
    A._print_multi_workspace_banner("apply", "prod", [_ws("ws-a"), _ws("ws-b")])
    out = capsys.readouterr().out
    assert "iterating 2 workspaces" in out and "ws-a" in out and "ws-b" in out


# ---------------------------------------------------------------------------
# _process_plan_asset
# ---------------------------------------------------------------------------


def test_plan_no_handler_echoes_and_does_not_append(capsys) -> None:
    ctx = A.WorkspaceRunContext(command="plan", detections_path=Path("detections"))
    A._process_plan_asset(_la("r1"), None, ctx)  # nothing registered
    assert ctx.results == []
    assert "no handler" in capsys.readouterr().out


def test_plan_snippet_error_appends_error_validate_no_audit(monkeypatch) -> None:
    def boom(*a, **k):
        raise SnippetError("snip")
    monkeypatch.setattr(A, "apply_snippets", boom)
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC))
    ctx = A.WorkspaceRunContext(command="plan", detections_path=Path("detections"))
    A._process_plan_asset(_la("r1"), None, ctx)
    assert len(ctx.results) == 1 and ctx.results[0].status == "error-validate"
    assert ctx.audit_pairs is None  # plan never touches audit_pairs


def test_plan_success_records_plan_result() -> None:
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC))
    ctx = A.WorkspaceRunContext(command="plan", detections_path=Path("detections"))
    A._process_plan_asset(_la("r1"), None, ctx)
    assert len(ctx.results) == 1 and ctx.results[0].status == "planned"


def test_plan_validate_failure_is_error_validate() -> None:
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC, fail_validate=True))
    ctx = A.WorkspaceRunContext(command="plan", detections_path=Path("detections"))
    A._process_plan_asset(_la("r1"), None, ctx)
    assert ctx.results[0].status == "error-validate"


# ---------------------------------------------------------------------------
# _process_apply_asset
# ---------------------------------------------------------------------------


def test_apply_requires_audit_pairs() -> None:
    # apply ctx with audit_pairs left None must fail loudly (not silently skip).
    ctx = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"))
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC))
    with pytest.raises(RuntimeError, match="audit_pairs"):
        A._process_apply_asset(_la("r1"), "ws-a", ctx)


def test_apply_no_handler_echoes_err_and_does_not_append(capsys) -> None:
    ctx = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"), audit_pairs=[])
    A._process_apply_asset(_la("r1"), "ws-a", ctx)  # nothing registered
    assert ctx.results == [] and ctx.audit_pairs == []
    assert "no handler" in capsys.readouterr().err


def test_apply_snippet_error_appends_la_and_none_digest(monkeypatch) -> None:
    def boom(*a, **k):
        raise SnippetError("snip")
    monkeypatch.setattr(A, "apply_snippets", boom)
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC))
    ctx = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"), audit_pairs=[])
    la = _la("r1")
    A._process_apply_asset(la, "ws-a", ctx)
    assert ctx.results[0].status == "error-validate"
    assert len(ctx.audit_pairs) == 1
    pair_la, result, ws_name, digest = ctx.audit_pairs[0]
    assert pair_la is la and ws_name == "ws-a" and digest is None  # raw la, no digest


def test_apply_success_records_resolved_la_and_digest() -> None:
    handler = _FakeHandler(Asset.SENTINEL_ANALYTIC)
    _register(handler)
    ctx = A.WorkspaceRunContext(
        command="apply", detections_path=Path("detections"), dry_run=True, audit_pairs=[],
    )
    la = _la("r1")
    A._process_apply_asset(la, "ws-a", ctx)
    assert ctx.results[0].status == "success"
    assert handler.applied == [("r1", None, True)]  # dry_run threaded via ctx.dry_run
    _la_resolved, _result, ws_name, digest = ctx.audit_pairs[0]
    assert ws_name == "ws-a" and digest == "digest-x"


def test_apply_apply_failure_is_error_apply_and_still_audited() -> None:
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC, fail_apply=True))
    ctx = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"), audit_pairs=[])
    A._process_apply_asset(_la("r1"), "ws-a", ctx)
    assert ctx.results[0].status == "error-apply"
    assert len(ctx.audit_pairs) == 1  # failures are still recorded in the trail


# ---------------------------------------------------------------------------
# _run_workspace_iteration
# ---------------------------------------------------------------------------


def test_iteration_dispatches_plan_vs_apply() -> None:
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC))
    plan_ctx = A.WorkspaceRunContext(command="plan", detections_path=Path("detections"))
    A._run_workspace_iteration([_la("r1")], [None], role=None, ctx=plan_ctx)
    assert len(plan_ctx.results) == 1 and plan_ctx.audit_pairs is None

    apply_ctx = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"), audit_pairs=[])
    A._run_workspace_iteration([_la("r1")], [None], role=None, ctx=apply_ctx)
    assert len(apply_ctx.results) == 1 and len(apply_ctx.audit_pairs) == 1


def test_iteration_rejects_unknown_command() -> None:
    bad = A.WorkspaceRunContext(command="bogus", detections_path=Path("detections"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown WorkspaceRunContext command"):
        A._run_workspace_iteration([_la("r1")], [None], role=None, ctx=bad)


def test_iteration_single_ws_none_sets_no_env() -> None:
    _register(_FakeHandler(Asset.SENTINEL_ANALYTIC))
    ctx = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"), audit_pairs=[])
    A._run_workspace_iteration([_la("r1")], [None], role=None, ctx=ctx)
    # ws=None branch must not touch the env var.
    assert os.environ.get("PIPELINE_WORKSPACE_NAME") is None
    assert ctx.audit_pairs[0][2] is None  # ws_name is None for the implicit single workspace


def test_iteration_defender_applied_once_across_workspaces() -> None:
    sentinel = _FakeHandler(Asset.SENTINEL_ANALYTIC)
    defender = _FakeHandler(Asset.DEFENDER_CUSTOM_DETECTION)
    _register(sentinel)
    _register(defender)
    loaded = [_la("sen", Asset.SENTINEL_ANALYTIC), _la("def", Asset.DEFENDER_CUSTOM_DETECTION)]
    ctx = A.WorkspaceRunContext(command="apply", detections_path=Path("detections"), audit_pairs=[])
    A._run_workspace_iteration(loaded, [_ws("ws-a"), _ws("ws-b")], role="prod", ctx=ctx)
    # Sentinel: 1 rule x 2 workspaces = 2 applies; Defender (tenant-scoped): first pass only = 1.
    assert [r[0] for r in sentinel.applied] == ["sen", "sen"]
    assert [r[0] for r in defender.applied] == ["def"]
    # Per-workspace env was rebound (each Sentinel apply saw its workspace).
    assert sorted(r[1] for r in sentinel.applied) == ["ws-a", "ws-b"]
    # Cached instances were closed between workspaces.
    assert sentinel.closed is True
