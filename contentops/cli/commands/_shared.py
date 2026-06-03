# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers used by 2+ command modules in :mod:`contentops.cli.commands`.

Kept in one place so individual command modules can import the
helpers they need without circular dependencies.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import click
import yaml

from contentops.core.discovery import iter_loaded_assets
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry


# ---------------------------------------------------------------------------
# Logging — quiet azure.identity / httpx by default, opt in with -v / -vv
# ---------------------------------------------------------------------------
#
# The legacy CLI calls logging.basicConfig(INFO) which floods the
# terminal with azure.identity probes (~3000 lines per `collect` run on
# a real tenant). Demote those loggers to WARNING by default; the
# top-level pipeline logger stays at INFO so per-asset progress is
# still visible. -v promotes the noisy loggers to INFO; -vv promotes
# them to DEBUG.

_NOISY_LOGGERS = ("azure.identity", "azure.core", "httpx", "urllib3", "msal")

# Loggers whose *WARNING*-level output is high-volume, expected, and
# already surfaced more usefully elsewhere — hidden below their natural
# level by default, brought back under -v.
#
# ``contentops.core.envelope`` emits one "metadata fell back to loose
# parse" WARNING per collected/grandfathered rule missing the strict
# authoring fields (e.g. ``runbookUrl``). On a real operator repo that's
# one line (plus a multi-line pydantic cause) PER detection — 150+ rules
# bury every command's real output and make a green run look broken in a
# demo. The same per-rule gap is reported, in context, by ``contentops
# lint`` (META rules) and the gap-assessment report, so the loose-parse
# line is pure noise at the default verbosity. Suppress to ERROR by
# default; -v restores it at WARNING, -vv at DEBUG.
_VERBOSE_ONLY_LOGGERS = ("contentops.core.envelope",)


def _apply_log_levels(verbosity: int = 0) -> None:
    """Set sane defaults for noisy loggers across CLI subcommands."""
    if verbosity >= 2:
        target = logging.DEBUG
    elif verbosity >= 1:
        target = logging.INFO
    else:
        target = logging.WARNING
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(target)

    # Verbose-only loggers sit one notch quieter: their natural output is
    # WARNING, so "default" must mean ERROR (suppressed) rather than the
    # WARNING used for the SDK loggers above.
    if verbosity >= 2:
        vo_target = logging.DEBUG
    elif verbosity >= 1:
        vo_target = logging.WARNING
    else:
        vo_target = logging.ERROR
    for name in _VERBOSE_ONLY_LOGGERS:
        logging.getLogger(name).setLevel(vo_target)


def _emit_loose_parse_summary(verbosity: int = 0) -> None:
    """Print one aggregated note for envelopes that fell back to loose
    metadata parse this invocation, replacing the per-rule WARNING flood.

    No-op when nothing fell back. Written to stderr so it never pollutes
    stdout payloads (e.g. ``doctor --format json``). The CLI registers
    this on the root context's close, so it fires once after the command
    finishes regardless of which command loaded the detections.
    """
    from contentops.core.envelope import loose_parse_fallback_ids

    ids = loose_parse_fallback_ids()
    if not ids:
        return
    tail = (
        " Run `contentops lint` for the per-rule list."
        if verbosity
        else " Run `contentops lint` for the per-rule list, or re-run with "
        "-v to show them inline."
    )
    click.secho(
        f"note: {len(ids)} detection(s) loaded with incomplete authoring "
        f"metadata (e.g. missing runbookUrl)." + tail,
        err=True, fg="yellow",
    )


# ---------------------------------------------------------------------------
# Run banner — printed at the top of every collect / apply / drift run
# ---------------------------------------------------------------------------


def _print_run_banner(
    command: str,
    detections_path: Path | None = None,
    *,
    extra: dict[str, str] | None = None,
) -> None:
    """Print a tenant + scope banner before any API call.

    The analyst sees what's about to happen (which subscription /
    workspace / api version / output path) before we hit the API, so
    accidentally targeting the wrong tenant is easy to abort.
    """
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
    except Exception:
        cfg = None

    env_name = (cfg.name if cfg else os.getenv("PIPELINE_ENV") or "(unset)")
    click.echo(f"pipeline {command} — {env_name}")
    if cfg is not None:
        active_name = os.environ.get("PIPELINE_WORKSPACE_NAME")
        if active_name:
            try:
                ws = cfg.workspace_by_name(active_name)
                click.echo(f"  subscription   : {ws.subscriptionId}")
                click.echo(f"  resource_group : {ws.resourceGroup}")
                click.echo(f"  workspace      : {ws.workspaceName} ({ws.role})")
            except KeyError:
                pass
        elif cfg.sentinelWorkspaces:
            click.echo(
                f"  workspaces     : "
                + ", ".join(
                    f"{w.workspaceName}({w.role})" for w in cfg.sentinelWorkspaces
                )
            )
    click.echo(
        "  api version    : 2025-07-01-preview (ARM) / beta (Graph)"
    )
    if detections_path is not None:
        click.echo(f"  path           : {detections_path}")
    if extra:
        for key, value in extra.items():
            click.echo(f"  {key:<14} : {value}")
    click.echo("")


def _format_summary_table(
    by_asset: dict[str, dict[str, int]],
    *,
    duration_s: float | None = None,
    title: str = "Summary",
) -> list[str]:
    """Format the new/changed/in-sync/failed/duration table consistently."""
    lines: list[str] = []
    if duration_s is not None:
        lines.append(f"\n{title} (duration {duration_s:.1f}s):")
    else:
        lines.append(f"\n{title}:")
    header = (
        f"  {'asset':40s} {'new':>6s} {'changed':>8s} "
        f"{'in-sync':>8s} {'failed':>7s}"
    )
    lines.append(header)
    totals = {"new": 0, "changed": 0, "in-sync": 0, "failed": 0}
    for asset_value in sorted(by_asset):
        bucket = by_asset[asset_value]
        n_new = bucket.get("new", 0)
        n_changed = bucket.get("changed", 0)
        n_in_sync = bucket.get("in-sync", 0)
        n_failed = bucket.get("failed", 0)
        totals["new"] += n_new
        totals["changed"] += n_changed
        totals["in-sync"] += n_in_sync
        totals["failed"] += n_failed
        lines.append(
            f"  {asset_value:40s} {n_new:>6d} {n_changed:>8d} "
            f"{n_in_sync:>8d} {n_failed:>7d}"
        )
    lines.append(
        f"  {'TOTAL':40s} {totals['new']:>6d} {totals['changed']:>8d} "
        f"{totals['in-sync']:>8d} {totals['failed']:>7d}"
    )
    return lines


def _load_all(detections_path: Path):
    return list(iter_loaded_assets(
        detections_path,
        on_error=lambda p, exc: click.echo(f"  load error: {p}: {exc}", err=True),
    ))


def _filter_changed_since(loaded, ref: str):
    """Restrict ``loaded`` to assets whose YAML changed since ``ref``."""
    from contentops.utils.git_diff import GitDiffError, changed_paths
    try:
        diff = changed_paths(ref)
    except GitDiffError as exc:
        raise click.ClickException(f"--changed-since={ref}: {exc}") from exc
    return [la for la in loaded if la.path.resolve() in diff]


def _emit_dependency_report(loaded) -> bool:
    """Run dependency validation. Returns True if violations were found."""
    from contentops.core.dependencies import (
        load_graph as load_dependency_graph,
        validate as validate_dependencies,
    )
    report = validate_dependencies(loaded, load_dependency_graph())
    if report.violations:
        click.echo(f"\nDependency check — {len(report.violations)} violation(s):")
        for v in report.violations:
            click.echo(v.as_row())
    return bool(report.violations)


# ---------------------------------------------------------------------------
# Engine-disabled envelope filter (used by plan, apply)
# ---------------------------------------------------------------------------


# Asset kinds grouped by deployment engine. Used by ``_filter_disabled_engines``
# to decide which envelopes to skip when an engine is disabled in tenant.yml.
#
# Derived from the ``Asset`` enum so a future taxonomy addition / rename
# updates both groupings automatically. The enum-prefix convention
# (``sentinel_*`` / ``defender_*``) is the implicit contract; pinned by
# ``test_engine_asset_value_sets_partition_asset_enum`` in
# ``tests/v2/test_optional_engines.py``. Cross-phase review-2 Seam B.
from contentops.core.asset import Asset as _Asset  # local import: avoid top-level cycle  # noqa: E402

_SENTINEL_ASSET_VALUES = frozenset(
    a.value for a in _Asset if a.value.startswith("sentinel_")
)
_DEFENDER_ASSET_VALUES = frozenset(
    a.value for a in _Asset if a.value.startswith("defender_")
)


def _filter_disabled_engines(loaded: list[LoadedAsset]) -> list[LoadedAsset]:
    """Drop envelopes whose deployment engine is disabled in tenant.yml.

    Mirrors the registration-time gating in
    :func:`contentops.cli.handler_factories.register_default_handlers`:
    skip Sentinel envelopes when ``sentinelWorkspaces`` is empty, skip
    Defender envelopes when ``defender:`` is absent or ``enabled:
    false``. Prints a single info line per skipped engine.

    Only ``FileNotFoundError`` (no tenant.yml) is treated as "both
    engines enabled" to preserve unit-test behaviour that bypasses
    config loading entirely. A malformed config (Pydantic
    ``ValidationError``, ``ValueError``, ``KeyError``) propagates so a
    real schema bug fails loud at filter-time instead of silently
    leaving every envelope in place and surfacing later as an obscure
    handler error.
    """
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
        sentinel_enabled = bool(cfg.sentinelWorkspaces)
        defender_enabled = cfg.defender is not None and cfg.defender.enabled
    except FileNotFoundError:
        return loaded  # no config -> assume both engines

    if sentinel_enabled and defender_enabled:
        return loaded  # nothing to skip

    skipped_sentinel: list[LoadedAsset] = []
    skipped_defender: list[LoadedAsset] = []
    kept: list[LoadedAsset] = []
    for la in loaded:
        v = la.envelope.asset.value
        if not sentinel_enabled and v in _SENTINEL_ASSET_VALUES:
            skipped_sentinel.append(la)
            continue
        if not defender_enabled and v in _DEFENDER_ASSET_VALUES:
            skipped_defender.append(la)
            continue
        kept.append(la)

    if skipped_sentinel:
        click.echo(
            f"  no Sentinel workspaces configured — skipping "
            f"{len(skipped_sentinel)} Sentinel envelope(s)"
        )
    if skipped_defender:
        click.echo(
            f"  Defender disabled in tenant.yml — skipping "
            f"{len(skipped_defender)} defender_custom_detection envelope(s)"
        )
    return kept


# ---------------------------------------------------------------------------
# Lock detection (used by apply, prune, rollback)
# ---------------------------------------------------------------------------


def _is_locked(loaded: LoadedAsset) -> bool:
    """True when the envelope on disk declares localCustomization=true.

    Top-level ``localCustomization: true`` is the supported syntax.
    The flag is intentionally kept off the strict envelope schema so
    an analyst can lock a rule without a model migration.
    """
    try:
        raw = yaml.safe_load(loaded.path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(raw, dict):
        return False
    return raw.get("localCustomization") is True


# ---------------------------------------------------------------------------
# Single-workspace selector (used by prune, drift)
# ---------------------------------------------------------------------------


def _resolve_single_workspace_or_exit(
    role: str | None, workspace_name: str | None,
    *, default_role_for_multi: str | None = None,
) -> None:
    """Resolve ``--role`` / ``--workspace`` for single-workspace commands.

    ``prune`` and ``drift`` operate against one workspace per
    invocation. This helper is **additive** — it only acts when the
    operator has actually passed one of the flags. When neither flag
    is set, we fall through silently and let the existing behaviour
    (``PIPELINE_WORKSPACE_NAME`` env var, or the implicit
    single-workspace pick inside the handler factories) apply. That
    preserves backward compatibility with unit tests, with operators
    setting the env var directly, and with single-workspace tenants
    where the flag is redundant.

    When a flag IS passed:

      * ``--workspace foo`` → sets ``PIPELINE_WORKSPACE_NAME=foo``
        after verifying ``foo`` exists in ``config/tenant.yml``.
      * ``--role prod`` matches exactly one workspace → sets that
        one's name.
      * ``--role prod`` matches multiple → exit 2 with a "run once
        per workspace" message. Iteration is supported by
        ``contentops apply`` because it's the write path; ``prune`` /
        ``drift`` would need to merge orphan/diff sets across
        workspaces in non-obvious ways, so they punt to the operator.
      * No matches → exit 2.

    ``default_role_for_multi`` lets a caller opt in to a default role
    when NEITHER selector is passed AND the tenant has more than one
    Sentinel workspace. ``collect`` uses ``"prod"`` here so a
    cron-driven collect targets prod instead of failing on the
    "ambiguous, be explicit" path. When entered only via this default
    (no explicit flag), a missing ``tenant.yml`` and an empty match are
    tolerated as silent no-ops — matching the inline behaviour collect
    used before this helper absorbed it. drift/prune pass ``None`` here
    and are unaffected.

    Sets ``PIPELINE_WORKSPACE_NAME`` before handler registration so
    the factories in ``contentops/cli/handler_factories.py`` pick up the
    correct ARM endpoint.
    """
    if (
        role is None
        and workspace_name is None
        and default_role_for_multi is None
    ):
        return  # additive — no flag passed, leave the existing behaviour

    # Whether the operator passed an explicit selector. Entry via
    # ``default_role_for_multi`` alone (collect's prod default) must not
    # turn a missing config / empty match into a hard error.
    explicit = role is not None or workspace_name is not None

    from contentops.config import load_tenant_config, select_workspaces

    try:
        cfg = load_tenant_config()
    except FileNotFoundError:
        if not explicit:
            return
        click.echo(
            "error: --role / --workspace require config/tenant.yml.",
            err=True,
        )
        sys.exit(2)

    # Defender-only tenant: no Sentinel workspaces are configured at
    # all, so any --role / --workspace selector is meaningless. Treat
    # as a no-op with an info message rather than a hard error so the
    # caller can still operate on Defender content.
    if not cfg.sentinelWorkspaces:
        if explicit:
            click.echo(
                f"info: --role / --workspace ignored — no Sentinel workspaces "
                f"in this tenant ({cfg.name!r}).",
            )
        return

    # Default an ambiguous (>1 workspace, no explicit selector) invocation
    # to a fixed role when the caller opts in. Pulling prod is the common
    # case for collect; "ambiguous, be explicit" would break cron collects.
    effective_role = role
    if (
        not explicit
        and default_role_for_multi is not None
        and len(cfg.sentinelWorkspaces) > 1
    ):
        effective_role = default_role_for_multi

    try:
        workspaces = select_workspaces(
            cfg, role=effective_role, workspace=workspace_name,
        )
    except (ValueError, KeyError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)

    if not workspaces:
        if explicit:
            click.echo(
                f"error: no Sentinel workspace matched "
                f"(role={effective_role!r}, workspace={workspace_name!r}).",
                err=True,
            )
            sys.exit(2)
        # Default-injected role matched nothing → no-op, let the handler
        # factories fall back (matches collect's pre-helper behaviour).
        return

    if len(workspaces) > 1:
        click.echo(
            f"error: --role={effective_role!r} matches {len(workspaces)} workspaces "
            f"({', '.join(w.workspaceName for w in workspaces)}). "
            "This command targets one workspace per run; re-run with "
            "--workspace <name> for each, or use `contentops apply` which "
            "iterates the matched set.",
            err=True,
        )
        sys.exit(2)

    os.environ["PIPELINE_WORKSPACE_NAME"] = workspaces[0].workspaceName


def _skip_if_integration_role_absent(
    role: str | None,
    workspace_name: str | None = None,
    *,
    command: str = "",
) -> bool:
    """Graceful no-op when ``--role integration`` is requested but the tenant
    has no ``role: integration`` Sentinel workspace.

    Returns ``True`` (the caller should ``return`` immediately, exit 0) after
    printing a skip notice; ``False`` otherwise. Honours the operator rule
    that a tenant without an integration environment must NEVER fail the
    pipeline — it skips, the same way ``integration-deploy.yml`` and
    ``contentops apply --role integration`` (see
    ``_apply_integration_no_workspace_skip`` in ``apply_support.py``) already
    do. Call it BEFORE :func:`_resolve_single_workspace_or_exit`, which would
    otherwise ``sys.exit(2)`` on the explicit-role-matches-nothing path.

    Scoped to ``integration`` ONLY: a missing ``prod`` workspace is a real
    misconfiguration and must still hard-fail. An explicit ``--workspace``
    defers to the normal resolver; an unreadable ``tenant.yml`` also falls
    through so the resolver reports it.
    """
    if role != "integration" or workspace_name:
        return False
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
    except Exception:
        return False
    if cfg.workspaces_for_role("integration"):
        return False
    prefix = f"[{command}] " if command else ""
    click.echo(
        f"{prefix}no Sentinel workspace with role=integration — skipping. "
        "(Add one to config/tenant.yml or remove --role integration.)"
    )
    return True


# ---------------------------------------------------------------------------
# Drift-handler collection
# ---------------------------------------------------------------------------


def _collect_drift_handlers(
    target_asset: "Asset | None" = None,
) -> list:
    """Return registered handlers that implement ``DriftCapable``.

    Centralises the loop that was duplicated in drift, prune, collect,
    and apply_support. The defensive ``try/except`` around ``get()``
    tolerates registry-close races in unit-test harnesses.
    """
    from contentops.core.drift import DriftCapable

    handlers: list[DriftCapable] = []
    for a in default_registry.assets():
        if target_asset is not None and a is not target_asset:
            continue
        try:
            h = default_registry.get(a)
        except Exception:
            continue
        if isinstance(h, DriftCapable):
            handlers.append(h)
    return handlers
