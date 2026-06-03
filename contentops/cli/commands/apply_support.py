# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Helpers for ``plan`` and ``apply`` used by multiple command modules."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import click

from contentops.cli.handler_factories import register_default_handlers
from contentops.cli.commands._shared import (
    _collect_drift_handlers,
    _emit_dependency_report,
    _filter_changed_since,
    _filter_disabled_engines,
    _is_locked,
    _load_all,
)
import contentops.config as _config
from contentops.config import (
    SentinelWorkspaceConfig,
    TenantConfig,
)
from contentops.audit import (
    AuditRecord,
    _resolve_actor,
    _resolve_sha,
)
from contentops.core.asset import Asset
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction
from contentops.snippets import SnippetError, apply_snippets

# One workspace-loop entry: a tenant workspace, or None when running without workspace binding.
WorkspaceLoopEntry = SentinelWorkspaceConfig | None

# (loaded_asset, result, workspace_name, snippet_digest) for apply audit JSONL.
ApplyAuditPair = tuple[LoadedAsset, ActionResult, str | None, str | None]


def _load_assets_for_run(
    detections_path: Path,
    *,
    asset: str | None,
    changed_since: str | None,
) -> list[LoadedAsset]:
    """Load detections and apply shared plan/apply asset filters.

    Order:
    _load_all -> --asset -> --changed-since -> _filter_disabled_engines

    Dependency reporting remains in the callers.
    """
    loaded = _load_all(detections_path)
    if asset:
        target = Asset(asset)
        loaded = [la for la in loaded if la.envelope.asset == target]
    if changed_since:
        loaded = _filter_changed_since(loaded, changed_since)
        click.echo(f"  --changed-since={changed_since}: {len(loaded)} asset(s) selected")

    # Drop envelopes whose deployment engine is disabled before dependency
    # checks and handler dispatch.
    loaded = _filter_disabled_engines(loaded)
    return loaded


def _resolve_workspaces_for_run(
    role: str | None,
    workspace_name: str | None,
) -> tuple[TenantConfig | None, list[SentinelWorkspaceConfig]]:
    """Load tenant.yml and resolve ``--role`` / ``--workspace`` for plan/apply.

    Returns ``(cfg, workspaces)``. Missing tenant.yml → ``(None, [])``.
    Bad config or ambiguous flags → error message and exit code 2.

    Missing tenant.yml is allowed (unit tests). Selector errors must not
    be swallowed or apply might use a stale ``PIPELINE_WORKSPACE_NAME`` env var.
    """
    try:
        cfg = _config.load_tenant_config()
        workspaces = _config.select_workspaces(
            cfg, role=role, workspace=workspace_name,
        )
    except FileNotFoundError:
        return None, []
    except (ValueError, KeyError) as exc:
        click.echo(f"error: tenant config issue — {exc}", err=True)
        raise click.exceptions.Exit(2)
    return cfg, workspaces


def _check_apply_write_allowed_or_exit(
    cfg: TenantConfig | None,
    workspaces: list[SentinelWorkspaceConfig],
    asset: str | None,
    dry_run: bool,
) -> None:
    """Refuse apply when tenant.yml marks a workspace or Defender as read-only.

    Runs before handler registration. Exits with code 2 on violation.
    Skipped when ``dry_run`` is set so operators can preview a locked env.
    """
    if cfg is not None and not dry_run:
        defender_touched = (
            asset is None
            or (asset and asset.startswith("defender_"))
        )
        for ws in workspaces:
            if not ws.writeAllowed:
                click.echo(
                    f"error: tenant.yml safeguard refuses write to "
                    f"sentinel workspace {ws.workspaceName!r} ({ws.role}): "
                    f"writeAllowed={ws.writeAllowed!r}. Set "
                    f"`writeAllowed: true` on this workspace in "
                    f"config/tenant.yml (or the TENANT_CONFIG_YAML "
                    f"secret in CI) to enable applies. Re-run with "
                    f"--dry-run to preview without the gate.",
                    err=True,
                )
                sys.exit(2)
        if defender_touched and cfg.defender is not None and not cfg.defender.writeAllowed:
            click.echo(
                f"error: tenant.yml safeguard refuses write to Defender XDR "
                f"(tenant-level): writeAllowed={cfg.defender.writeAllowed!r}. "
                f"Set `writeAllowed: true` on the `defender:` block in "
                f"config/tenant.yml (or the TENANT_CONFIG_YAML secret in CI) "
                f"to enable Defender applies. Re-run with --dry-run to "
                f"preview without the gate, or pass --asset sentinel_<kind> "
                f"to skip Defender entirely.",
                err=True,
            )
            sys.exit(2)


def _apply_integration_no_workspace_skip(role: str | None) -> bool:
    """Return True when apply should stop: ``--role integration`` but no workspace."""
    if role == "integration":
        # Graceful no-op for PR-deploy-to-integration when tenant has no
        # integration workspace defined.
        click.echo(
            "[apply] no Sentinel workspace with role=integration — skipping. "
            "(Add one to config/tenant.yml or remove --role integration.)"
        )
        return True
    return False


def _filter_loaded_by_env_status(
    loaded: list[LoadedAsset],
    cfg: TenantConfig | None,
    workspaces: list[SentinelWorkspaceConfig],
) -> list[LoadedAsset]:
    """Drop assets whose ``status`` is not allowed for the target workspace role.

    Uses the first selected workspace's role when present; otherwise tenant name.
    Defender assets may be skipped on non-prod Sentinel workspaces. If tenant
    config cannot be loaded, returns ``loaded`` unchanged.
    """
    try:
        from contentops.core.env_status import _PROD_ALIASES, allowed_statuses_for_env
        if cfg is not None and workspaces:
            gate_key = workspaces[0].role
        elif cfg is not None:
            gate_key = cfg.name
        else:
            gate_key = _config.load_tenant_config().name
        allowed = {s.value for s in allowed_statuses_for_env(gate_key)}
        # Defender assets are prod-only when targeting non-prod Sentinel workspaces.
        defender_gate_active = bool(workspaces) and gate_key not in _PROD_ALIASES
        kept_after_status: list = []
        skipped_for_status: list[tuple[str, str]] = []
        for la in loaded:
            if (
                la.envelope.asset.value.startswith("defender_")
                and defender_gate_active
            ):
                skipped_for_status.append(
                    (la.envelope.id, f"{la.envelope.status} [defender:prod-only]")
                )
                continue
            if la.envelope.status in allowed:
                kept_after_status.append(la)
            else:
                skipped_for_status.append((la.envelope.id, la.envelope.status))
        if skipped_for_status:
            click.echo(
                f"  env-status filter (gate={gate_key}): "
                f"{len(skipped_for_status)} asset(s) skipped "
                f"(allowed: {sorted(allowed)})"
            )
            for asset_id, status_val in skipped_for_status:
                click.echo(f"    - {asset_id} (status={status_val})")
        return kept_after_status
    except FileNotFoundError:
        return loaded


def _apply_no_loaded_assets_or_return(loaded: list[LoadedAsset]) -> bool:
    """Return True when apply should stop because there is nothing to deploy."""
    if not loaded:
        click.echo("No assets to apply.")
        return True
    return False


def _apply_dependency_violations_or_exit(
    loaded: list[LoadedAsset],
    skip_deps_check: bool,
) -> None:
    """Exit with code 1 when dependency prerequisites fail (unless skipped)."""
    if not skip_deps_check and _emit_dependency_report(loaded):
        click.echo(
            "\nApply aborted — dependency violations. Re-run with --skip-deps-check to override.",
            err=True,
        )
        sys.exit(1)


def _filter_locked_loaded_assets(
    loaded: list[LoadedAsset],
    force_overwrite: bool,
) -> list[LoadedAsset]:
    """Remove locally locked assets unless ``force_overwrite`` is set."""
    locked_skipped = 0
    if not force_overwrite:
        kept: list = []
        for la in loaded:
            if _is_locked(la):
                click.echo(
                    f"  skipped (locked — re-run with --force-overwrite to push): "
                    f"{la.envelope.id}"
                )
                locked_skipped += 1
                continue
            kept.append(la)
        return kept
    return loaded


@dataclass
class WorkspaceRunContext:
    """Holds running totals while plan/apply walk each workspace.

    results: one row per asset (what happened).
    audit_pairs: apply-only — pairs each result with workspace + snippet
    digest for the JSONL audit trail (plan leaves audit_pairs unset).
    """

    command: Literal["plan", "apply"]
    detections_path: Path
    results: list[ActionResult] = field(default_factory=list)
    dry_run: bool = False
    audit_pairs: list[ApplyAuditPair] | None = None


def _print_multi_workspace_banner(
    command: Literal["plan", "apply"],
    role: str | None,
    iter_workspaces: list[WorkspaceLoopEntry],
) -> None:
    if len(iter_workspaces) <= 1:
        return
    click.echo(
        f"\n[{command}] iterating {len(iter_workspaces)} workspaces "
        f"(matched by --role={role!r}):"
    )
    for workspace in iter_workspaces:
        click.echo(f"  - {workspace.workspaceName} (role={workspace.role})")


def _process_plan_asset(
    la: LoadedAsset,
    ws_name: str | None,
    ctx: WorkspaceRunContext,
) -> None:
    if not default_registry.has(la.envelope.asset):
        click.echo(f"  no handler for {la.envelope.asset.value}: {la.path}")
        return

    handler = default_registry.get(la.envelope.asset)

    try:
        la_resolved = apply_snippets(
            la, ws_name,
            overrides_root=ctx.detections_path.parent / "overrides",
        )
    except SnippetError as exc:
        ctx.results.append(ActionResult(
            asset_id=la.envelope.id,
            asset_kind=la.envelope.asset.value,
            action=PlanAction.NOOP,
            status="error-validate",
            detail=f"snippet substitution failed: {exc}",
        ))
        return

    try:
        handler.validate(la_resolved)
        ctx.results.append(handler.plan(la_resolved))
    except Exception as exc:
        ctx.results.append(ActionResult(
            asset_id=la.envelope.id,
            asset_kind=la.envelope.asset.value,
            action=PlanAction.NOOP,
            status="error-validate",
            detail=str(exc),
        ))


def _process_apply_asset(
    la: LoadedAsset,
    ws_name: str | None,
    ctx: WorkspaceRunContext,
) -> None:
    if ctx.audit_pairs is None:
        raise RuntimeError(
            "apply workspace iteration requires audit_pairs on WorkspaceRunContext"
        )

    if not default_registry.has(la.envelope.asset):
        click.echo(
            f"  no handler for {la.envelope.asset.value}: {la.path}",
            err=True,
        )
        return

    handler = default_registry.get(la.envelope.asset)

    try:
        la_resolved = apply_snippets(
            la, ws_name,
            overrides_root=ctx.detections_path.parent / "overrides",
        )
    except SnippetError as exc:
        result = ActionResult(
            asset_id=la.envelope.id,
            asset_kind=la.envelope.asset.value,
            action=PlanAction.NOOP,
            status="error-validate",
            detail=f"snippet substitution failed: {exc}",
        )

        click.echo(
            f"  error: {la.envelope.id}: snippet substitution failed: {exc}",
            err=True,
        )

        ctx.results.append(result)
        ctx.audit_pairs.append((la, result, ws_name, None))
        return

    snippet_digest = _compute_snippet_digest(la, la_resolved)

    try:
        handler.validate(la_resolved)
        result = handler.apply(la_resolved, dry_run=ctx.dry_run)
    except Exception as exc:
        result = ActionResult(
            asset_id=la.envelope.id,
            asset_kind=la.envelope.asset.value,
            action=PlanAction.NOOP,
            status="error-apply",
            detail=str(exc),
        )

        click.echo(f"  error: {la.envelope.id}: {exc}", err=True)

    ctx.results.append(result)
    ctx.audit_pairs.append((la_resolved, result, ws_name, snippet_digest))


def _run_workspace_iteration(
    loaded: list[LoadedAsset],
    iter_workspaces: list[WorkspaceLoopEntry],
    *,
    role: str | None,
    ctx: WorkspaceRunContext,
) -> None:
    _print_multi_workspace_banner(ctx.command, role, iter_workspaces)
    # Explicit dispatch, not a binary plan/else: a bad command must fail
    # loudly here rather than silently routing an unexpected value to the
    # apply (write) path.
    if ctx.command == "plan":
        process = _process_plan_asset
    elif ctx.command == "apply":
        process = _process_apply_asset
    else:
        raise ValueError(
            f"unknown WorkspaceRunContext command: {ctx.command!r} "
            "(expected 'plan' or 'apply')"
        )

    try:
        for idx, workspace in enumerate(iter_workspaces):
            if workspace is not None:
                os.environ["PIPELINE_WORKSPACE_NAME"] = workspace.workspaceName
                default_registry.close_all()
                register_default_handlers()

                if len(iter_workspaces) > 1:
                    click.echo(
                        f"\n=== {workspace.workspaceName} (role={workspace.role}) ==="
                    )

            is_first = (idx == 0)
            workspace_loaded = (
                loaded if is_first
                else [
                    la for la in loaded
                    if not la.envelope.asset.value.startswith("defender_")
                ]
            )

            workspace_name = (
                workspace.workspaceName if workspace is not None else None
            )
            for la in workspace_loaded:
                process(la, workspace_name, ctx)
    finally:
        default_registry.close_all()


def _print_against_tenant_summary(
    loaded: list, detections_path: Path,
) -> None:
    """Overlay a CREATE / UPDATE / NO-CHANGE / ORPHAN summary against
    live tenant state. Reuses ``contentops.core.drift.detect_drift``
    so the classification matches what ``contentops drift`` would
    report on the same checkout. Read-only; surfaces a banner if the
    tenant call fails so the human plan output above is still useful.
    """
    try:
        from contentops.core.drift import detect_drift
    except Exception as exc:
        click.echo(f"\n--against-tenant: import error ({exc}); skipped.")
        return

    drift_capable = _collect_drift_handlers()
    if not drift_capable:
        click.echo(
            "\n--against-tenant: no DriftCapable handler registered; "
            "skipped (likely a registry-close race in a unit-test harness)."
        )
        return

    try:
        report = detect_drift(drift_capable, detections_path)
    except Exception as exc:
        click.echo(
            f"\n--against-tenant: detect_drift failed ({exc}); plan above "
            "still applies, but the tenant overlay is unavailable."
        )
        return

    # Drift's framing: NEW = exists in tenant but not in local; CHANGED
    # = exists in both with different content; IN-SYNC = match. To
    # translate to apply-side verbs:
    #   * envelopes in local NOT in tenant -> apply would CREATE.
    #   * envelopes in local AND tenant, CHANGED -> apply would UPDATE.
    #   * envelopes in local AND tenant, IN-SYNC -> apply NO-CHANGE.
    #   * envelopes in tenant NOT in local (drift's "new") -> apply
    #     would not touch; these are pruning candidates.
    local_count = len(loaded)
    in_sync = len(report.in_sync)
    changed = len(report.changed)
    orphans_in_tenant = len(report.new)
    # Predicted CREATEs = locals whose arm_name / id isn't accounted for
    # in the in-sync + changed buckets.
    accounted = in_sync + changed
    creates = max(0, local_count - accounted)
    click.echo("\nAgainst-tenant overlay (closes G17):")
    click.echo(
        f"  CREATE: {creates}   UPDATE: {changed}   "
        f"NO-CHANGE: {in_sync}   ORPHAN-IN-TENANT: {orphans_in_tenant}"
    )
    if report.has_errors():
        click.echo(
            f"  {len(report.errors)} asset kind(s) failed remote-list "
            "(see drift log); overlay is partial."
        )
    click.echo(
        "  (ORPHAN-IN-TENANT entries would only be removed by "
        "`contentops prune`, never by `apply`.)"
    )


def _build_audit_record(
    result: ActionResult,
    loaded: LoadedAsset | None = None,
    *,
    envelope_id: str | None = None,
    asset_value: str | None = None,
    workspace: str | None = None,
    snippet_digest: str | None = None,
    success_detail: str | None = None,
) -> AuditRecord:
    """Build an ``AuditRecord`` for apply, prune, lifecycle, or rollback.

    Pass ``loaded`` for apply/lifecycle/rollback (extracts id, asset,
    metadata_owner). Pass ``envelope_id`` + ``asset_value`` for prune
    (no ``LoadedAsset`` available at that point).
    """
    if loaded is not None:
        rec_id = loaded.envelope.id
        rec_asset = loaded.envelope.asset.value
        metadata_owner = (
            loaded.envelope.metadata.owner
            if loaded.envelope.metadata is not None
            else None
        )
    else:
        rec_id = envelope_id or ""
        rec_asset = asset_value or ""
        metadata_owner = None

    if result.is_failure:
        status = "failed"
        message: str | None = result.error or result.detail or result.status
    elif result.action is PlanAction.SKIP:
        status = "skipped"
        message = result.detail or None
    else:
        status = "success"
        message = success_detail

    return AuditRecord(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        asset=rec_asset,
        id=rec_id,
        action=result.action.value,
        status=status,
        sha=_resolve_sha(Path.cwd()),
        actor=_resolve_actor(),
        workflow_run=os.getenv("GITHUB_RUN_ID") or None,
        message=message,
        metadata_owner=metadata_owner,
        workspace=workspace,
        snippet_digest=snippet_digest,
    )


def _compute_snippet_digest(
    original: LoadedAsset, resolved: LoadedAsset,
) -> str | None:
    """SHA-256 of the resolved asset's KQL fields, hex-encoded.

    Returns ``None`` when no substitution happened (the resolved
    payload is the original payload by identity OR the substituted
    KQL fields are byte-for-byte identical). Cheap to compute -- a
    few microseconds vs. the existing handler-side hash for the
    deploy body.
    """
    import hashlib
    import json
    if resolved is original:
        return None
    # The KQL fields differ only when substitution actually rewrote
    # something. Compare payloads field-by-field for the asset's
    # known KQL keys.
    from contentops.snippets.apply import _KQL_FIELDS_BY_ASSET, _get_dotted
    fields = _KQL_FIELDS_BY_ASSET.get(original.envelope.asset, ())
    snapshot: dict[str, str] = {}
    diverged = False
    for dotted in fields:
        ov = _get_dotted(original.payload, dotted)
        rv = _get_dotted(resolved.payload, dotted)
        if isinstance(rv, str):
            snapshot[dotted] = rv
        if ov != rv:
            diverged = True
    if not diverged:
        return None
    return hashlib.sha256(
        json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
