# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Lifecycle commands: disable / lock / unlock / retry-failed / lifecycle promote.

Grouped because ``disable``, ``lock``, ``unlock`` all share
``_find_yaml_for_id`` and the same ID-on-disk resolution semantics.
``retry-failed`` and ``lifecycle promote`` are status-mutation siblings.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from contentops.audit import write_records
from contentops.cli.handler_factories import register_default_handlers
from contentops.cli.commands._shared import _load_all
from contentops.cli.commands.apply_support import _build_audit_record
from contentops.cli.commands.lifecycle_support import (
    _LOCK_TOPLEVEL_RE,
    _STATUS_LINE_RE,
    _disable_one,
    _enable_one,
    _ENABLE_TARGETS,
    _find_yaml_for_id,
    _find_yamls_by_cohort,
    _find_yamls_by_pattern,
    _select_one_of,
    write_lifecycle_audit,
    write_lifecycle_audit_batch,
)
from contentops.core.asset import Asset
from contentops.core.discovery import discover_assets, load_asset
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


@click.command("disable")
@click.argument("rule_id", required=False)
@click.option(
    "--pattern", "pattern", default=None,
    help=(
        "fnmatch-style glob (e.g. 'aad-*' or 'o365-*-anomaly'). "
        "Disables every rule whose envelope id matches. Mutually "
        "exclusive with the positional ``rule_id`` and ``--cohort``. "
        "Requires ``--yes`` to actually mutate the YAMLs; without "
        "``--yes`` the command lists matches and exits (dry-run by default)."
    ),
)
@click.option(
    "--cohort", "cohort", default=None,
    help=(
        "Cohort name matched exactly against ``metadata.cohort`` "
        "(parallel to ``portfolio --cohort``). Mutually exclusive "
        "with the positional ``rule_id`` and ``--pattern``. Requires "
        "``--yes`` to mutate."
    ),
)
@click.option(
    "--yes", "yes", is_flag=True, default=False,
    help="Required alongside ``--pattern``/``--cohort`` to actually disable the cohort.",
)
@click.option("--reason", default=None, help="Free-text reason recorded in each YAML.")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
def disable_cmd(
    rule_id: str | None,
    pattern: str | None,
    cohort: str | None,
    yes: bool,
    reason: str | None,
    detections_path: Path,
) -> None:
    """Emergency-disable a detection rule (or cohort) by setting
    ``status: deprecated``.

    Single-rule (existing behaviour):

        contentops disable my-rule-id

    Cohort by glob (closes G18 -- bulk disable):

        contentops disable --pattern 'o365-*'        # dry-run: list
        contentops disable --pattern 'o365-*' --yes  # actually disable

    Cohort by metadata.cohort (closes G18 -- bulk disable):

        contentops disable --cohort o365             # dry-run: list
        contentops disable --cohort o365 --yes       # actually disable

    The glob is matched against the envelope ``id`` (case-sensitive
    ``fnmatch.fnmatchcase``); ``--cohort`` is exact-matched against the
    ``metadata.cohort`` field. Dry-run output is deterministically
    sorted so reviewer diffs are stable. Does NOT git-commit -- the
    caller (workflow or human) inspects the diff.
    """
    _select_one_of(rule_id=rule_id, pattern=pattern, cohort=cohort)

    # Single-rule path -- unchanged behaviour, just routed through the
    # shared _disable_one helper for symmetry with the cohort paths.
    if rule_id:
        target = _find_yaml_for_id(detections_path, rule_id)
        if _disable_one(target, rule_id, reason):
            write_lifecycle_audit("disable", rule_id, target, message=reason)
        return

    if pattern:
        matches = _find_yamls_by_pattern(detections_path, pattern)
        selector_label = f"--pattern {pattern!r}"
    else:
        matches = _find_yamls_by_cohort(detections_path, cohort)
        selector_label = f"--cohort {cohort!r}"

    if not matches:
        click.echo(
            f"error: no rules matched {selector_label} under {detections_path}",
            err=True,
        )
        sys.exit(1)
    if not yes:
        click.echo(f"{selector_label} would disable {len(matches)} rule(s):")
        for rid, p in matches:
            click.echo(f"  {rid}  ({p})")
        click.echo("Pass --yes to proceed.")
        return

    changed = 0
    skipped = 0
    audit_items: list[tuple[str, Path]] = []
    for rid, p in matches:
        if _disable_one(p, rid, reason):
            changed += 1
            audit_items.append((rid, p))
        else:
            skipped += 1
    write_lifecycle_audit_batch("disable", audit_items, message=reason)
    click.echo(
        f"\nCohort disable complete: {changed} rule(s) deprecated, "
        f"{skipped} already deprecated."
    )


# ---------------------------------------------------------------------------
# `contentops enable` — inverse of disable (closes G18 round-trip)
# ---------------------------------------------------------------------------


@click.command("enable")
@click.argument("rule_id", required=False)
@click.option(
    "--pattern", "pattern", default=None,
    help=(
        "fnmatch-style glob matched against envelope id. Enables every "
        "matching deprecated rule. Mutually exclusive with the positional "
        "``rule_id`` and ``--cohort``. Requires ``--yes`` to mutate."
    ),
)
@click.option(
    "--cohort", "cohort", default=None,
    help=(
        "Cohort name matched exactly against ``metadata.cohort``. "
        "Mutually exclusive with ``rule_id`` and ``--pattern``. "
        "Requires ``--yes`` to mutate."
    ),
)
@click.option(
    "--to", "to_status",
    type=click.Choice(_ENABLE_TARGETS),
    default="experimental",
    show_default=True,
    help=(
        "Status to restore to. Default ``experimental`` routes a fresh "
        "promotion through ``lifecycle promote``'s gates. ``production`` "
        "is a direct restore: it writes the lifecycle.promotedAt/"
        "promotedBy stamp + ``forcedPromotion: true`` and an audit record, "
        "so it passes production-promotion-check and the PR sticky comment "
        "flags it for Code Owner review (no gates re-run; intended for "
        "restoring a previously-vetted rule)."
    ),
)
@click.option(
    "--yes", "yes", is_flag=True, default=False,
    help="Required alongside ``--pattern``/``--cohort`` to actually re-enable the cohort.",
)
@click.option(
    "--reason", default=None,
    help="Free-text reason recorded in each YAML as ``enableReason``.",
)
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
def enable_cmd(
    rule_id: str | None,
    pattern: str | None,
    cohort: str | None,
    to_status: str,
    yes: bool,
    reason: str | None,
    detections_path: Path,
) -> None:
    """Inverse of ``contentops disable`` -- flip ``status: deprecated``
    back to ``--to`` (default ``experimental``).

    Single-rule:

        contentops enable my-rule-id                # -> experimental
        contentops enable my-rule-id --to production

    Cohort by glob:

        contentops enable --pattern 'o365-*'        # dry-run
        contentops enable --pattern 'o365-*' --yes  # restore the cohort

    Cohort by metadata.cohort:

        contentops enable --cohort o365             # dry-run
        contentops enable --cohort o365 --yes       # restore the cohort

    Skips rules that aren't currently deprecated (warn-and-skip,
    matches ``disable``'s already-deprecated UX). Strips the exact
    marker that ``disable`` writes and appends an enable marker so the
    YAML carries a symmetric audit trail, and writes a ``enable`` audit
    record (single + cohort) mirroring ``disable``. ``--to production``
    additionally stamps the lifecycle promotion block + ``forcedPromotion``
    so a direct restore stays gate-compliant. Does NOT git-commit -- the
    caller inspects the diff.
    """
    _select_one_of(rule_id=rule_id, pattern=pattern, cohort=cohort)

    audit_msg = "enable to " + to_status + (
        " (forced promotion)" if to_status == "production" else ""
    )

    if rule_id:
        target = _find_yaml_for_id(detections_path, rule_id)
        if _enable_one(target, rule_id, to_status=to_status, reason=reason):
            # Mirror disable's audit trail — enable was writing none. A
            # restore-to-production also carries the promotion stamp (see
            # _enable_one), so the audit record + the YAML stamp agree.
            write_lifecycle_audit("enable", rule_id, target, message=audit_msg)
        return

    if pattern:
        matches = _find_yamls_by_pattern(detections_path, pattern)
        selector_label = f"--pattern {pattern!r}"
    else:
        matches = _find_yamls_by_cohort(detections_path, cohort)
        selector_label = f"--cohort {cohort!r}"

    if not matches:
        click.echo(
            f"error: no rules matched {selector_label} under {detections_path}",
            err=True,
        )
        sys.exit(1)
    if not yes:
        click.echo(
            f"{selector_label} would re-enable up to {len(matches)} rule(s) "
            f"-> status: {to_status}:"
        )
        for rid, p in matches:
            click.echo(f"  {rid}  ({p})")
        click.echo("Pass --yes to proceed.")
        return

    changed_items: list[tuple[str, Path]] = []
    skipped = 0
    for rid, p in matches:
        if _enable_one(p, rid, to_status=to_status, reason=reason):
            changed_items.append((rid, p))
        else:
            skipped += 1
    if changed_items:
        write_lifecycle_audit_batch("enable", changed_items, message=audit_msg)
    click.echo(
        f"\nCohort enable complete: {len(changed_items)} rule(s) restored to "
        f"{to_status}, {skipped} skipped (not deprecated)."
    )


@click.command("lock")
@click.argument("rule_id")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
def lock_cmd(rule_id: str, detections_path: Path) -> None:
    """Pin a rule as locally customised - apply will skip it without --force-overwrite.

    Sets a top-level ``localCustomization: true`` flag in the envelope.
    This is the customisation-protection pattern from Sentinel-as-Code
    Wave 2: an analyst hand-tunes a rule (threshold, KQL filter) and
    we don't want a future bulk apply to flatten the change.
    """
    target = _find_yaml_for_id(detections_path, rule_id)
    text = target.read_text(encoding="utf-8")
    if _LOCK_TOPLEVEL_RE.search(text):
        new_text = _LOCK_TOPLEVEL_RE.sub("localCustomization: true\n", text, count=1)
        if new_text == text:
            click.echo(f"already locked: {rule_id} ({target})")
            return
    else:
        if not text.endswith("\n"):
            text += "\n"
        new_text = text + "localCustomization: true\n"
    target.write_text(new_text, encoding="utf-8")
    write_lifecycle_audit("lock", rule_id, target)
    click.echo(f"locked: {rule_id} ({target})")


@click.command("unlock")
@click.argument("rule_id")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
def unlock_cmd(rule_id: str, detections_path: Path) -> None:
    """Inverse of `contentops lock` - remove the localCustomization flag."""
    target = _find_yaml_for_id(detections_path, rule_id)
    text = target.read_text(encoding="utf-8")
    if not _LOCK_TOPLEVEL_RE.search(text):
        click.echo(f"not locked: {rule_id} ({target})")
        return
    new_text = _LOCK_TOPLEVEL_RE.sub("", text, count=1)
    target.write_text(new_text, encoding="utf-8")
    write_lifecycle_audit("unlock", rule_id, target)
    click.echo(f"unlocked: {rule_id} ({target})")


@click.command("retry-failed")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--audit-dir",
    type=click.Path(path_type=Path),
    default=Path("audit"),
    help="Audit JSONL directory (default: audit/).",
)
@click.option(
    "--since",
    "since_spec",
    default=None,
    help="Restrict to audit records within this time window. Either a "
         "duration (e.g. '1h', '30m', '7d') or an ISO 8601 timestamp. "
         "Mutually exclusive with --run-id. Without --since/--run-id, "
         "only the latest audit file is read (current behaviour).",
)
@click.option(
    "--run-id",
    "run_id",
    default=None,
    help="Restrict to audit records whose workflow_run matches RUN_ID "
         "(the GITHUB_RUN_ID stamped at apply time). Mutually exclusive "
         "with --since.",
)
@click.option("--dry-run", is_flag=True, help="Print which assets would be retried; no API calls.")
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role (sets "
         "PIPELINE_WORKSPACE_NAME). Mutex with --workspace. "
         "Single-workspace tenants pick implicitly when both omitted. "
         "Required on multi-workspace tenants -- without it, "
         "register_default_handlers raises an ambiguity error before "
         "the first retry can run.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName`` "
         "(must match config/tenant.yml). Mutex with --role.",
)
def retry_failed_cmd(
    detections_path: Path, audit_dir: Path,
    since_spec: str | None, run_id: str | None,
    dry_run: bool,
    role: str | None, workspace_name: str | None,
) -> None:
    """Re-apply only the assets a previous apply marked as failed.

    Default scope is the most recent ``audit/*.jsonl`` file. Pass
    ``--since`` or ``--run-id`` (mutually exclusive) to widen or narrow.

    On a multi-workspace tenant, pass ``--role`` or ``--workspace``
    so handler registration knows which workspace to target.
    Single-workspace tenants pick implicitly.

    \b
    Use --since when:
      * The latest audit file is a *successful* later run that
        masks the partial failure two runs ago.
      * You want to retry everything that failed in a recovery
        window (e.g. last 4 hours after a Graph outage).
    Use --run-id when:
      * A workflow needs to retry exactly one run-id without
        touching anything else.

    Examples:

    \b
        contentops retry-failed                          # latest file
        contentops retry-failed --since 4h               # last 4 hours
        contentops retry-failed --since 2026-05-07T08:00Z
        contentops retry-failed --run-id 9123456789
        contentops retry-failed --role integration       # multi-workspace
    """
    if since_spec is not None and run_id is not None:
        click.echo(
            "error: --since and --run-id are mutually exclusive.",
            err=True,
        )
        sys.exit(2)

    # Resolve --role / --workspace BEFORE register_default_handlers
    # so multi-workspace tenants get a clean Click error (exit 2)
    # rather than the bare RuntimeError ``_active_workspace`` would
    # raise. Cross-phase review-2 Seam C.
    from contentops.cli.commands._shared import _resolve_single_workspace_or_exit
    _resolve_single_workspace_or_exit(role, workspace_name)

    # Re-apply must honour the same write-allowed and env-status gates
    # that `apply` enforces — otherwise retry-failed is a back-door that
    # bypasses tenant.yml safeguards. Resolve (cfg, workspaces) the same
    # way apply does; a missing tenant.yml yields (None, []) and the
    # gates degrade gracefully (apply tolerates the unit-test path too).
    from contentops.cli.commands.apply_support import (
        _check_apply_write_allowed_or_exit,
        _filter_loaded_by_env_status,
        _resolve_workspaces_for_run,
    )
    cfg, workspaces = _resolve_workspaces_for_run(role, workspace_name)

    if not audit_dir.exists():
        click.echo(f"no audit directory at {audit_dir} — nothing to retry")
        return
    files = sorted(audit_dir.glob("*.jsonl"))
    if not files:
        click.echo(f"no audit files under {audit_dir} — nothing to retry")
        return

    from contentops.audit_filter import (
        AuditFilterError, collect_failed_pairs, parse_since,
    )

    # Decide which files + which predicate to use.
    if since_spec is not None:
        try:
            since_dt = parse_since(since_spec)
        except AuditFilterError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(2)
        scope = files
        predicate = ("since", since_dt)
        scope_label = f"--since={since_spec} ({since_dt.isoformat()})"
    elif run_id is not None:
        scope = files
        predicate = ("run_id", run_id)
        scope_label = f"--run-id={run_id}"
    else:
        scope = [files[-1]]
        predicate = ("none", None)
        scope_label = f"latest file ({files[-1].name})"

    failed = collect_failed_pairs(scope, predicate)

    if not failed:
        click.echo(f"no failed records in scope ({scope_label}) — nothing to retry")
        return

    click.echo(f"scope: {scope_label} → {len(failed)} failed (asset, id) pair(s)")

    register_default_handlers()
    loaded = _load_all(detections_path)
    target_set = {(la.envelope.asset.value, la.envelope.id) for la in loaded}
    missing = sorted(failed - target_set)
    if missing:
        click.echo("[warn] failed records with no matching local YAML (skipped):")
        for asset_value, rule_id in missing:
            click.echo(f"  {asset_value}  {rule_id}")

    selected = [la for la in loaded
                if (la.envelope.asset.value, la.envelope.id) in failed]
    if not selected:
        click.echo("nothing to retry — all failed records lack a local YAML.")
        return

    # Same env-status gate apply uses: drop assets whose status is not
    # allowed for the target workspace role (no-op when tenant.yml is
    # absent). Filter before the retry echo so the count is accurate.
    selected = _filter_loaded_by_env_status(selected, cfg, workspaces)
    if not selected:
        click.echo("nothing to retry — all selected assets filtered out by env-status gate.")
        return

    click.echo(f"retrying {len(selected)} failed asset(s) ({scope_label}):")
    for la in selected:
        click.echo(f"  - {la.envelope.asset.value}  {la.envelope.id}  ({la.path})")

    if dry_run:
        click.echo("[dry-run] no API calls made.")
        return

    # Same write-allowed gate apply enforces: refuse the re-apply when
    # tenant.yml marks the target workspace or Defender as read-only.
    # asset=None because retry-failed re-applies a mixed set; the gate
    # is internally skipped on dry_run (dry-run already returned above).
    _check_apply_write_allowed_or_exit(cfg, workspaces, asset=None, dry_run=dry_run)

    results: list[ActionResult] = []
    audit_pairs: list[tuple[LoadedAsset, ActionResult]] = []
    try:
        for la in selected:
            handler = default_registry.get(la.envelope.asset)
            try:
                handler.validate(la)
                result = handler.apply(la, dry_run=False)
            except Exception as exc:
                result = ActionResult(
                    asset_id=la.envelope.id, asset_kind=la.envelope.asset.value,
                    action=PlanAction.NOOP, status="error-apply", detail=str(exc),
                )
            results.append(result)
            audit_pairs.append((la, result))
    finally:
        default_registry.close_all()

    click.echo(f"\nRetry summary ({len(results)} assets):")
    for r in results:
        click.echo(r.as_row())

    if audit_pairs:
        # Thread the active
        # workspace into each record so multi-workspace retries are
        # attributable.
        active_ws = os.environ.get("PIPELINE_WORKSPACE_NAME")
        records = [
            _build_audit_record(r, la, workspace=active_ws)
            for la, r in audit_pairs
        ]
        path = write_records(Path.cwd(), records)
        click.echo(f"[audit] wrote {len(records)} records to {path}")

    failed_now = [r for r in results if r.is_failure]
    if failed_now:
        click.echo(f"\n{len(failed_now)} asset(s) still failing.", err=True)
        sys.exit(1)


@click.group("lifecycle")
def lifecycle_group() -> None:
    """Status promotion gates (F8). Reduced gate set in this PR."""


@lifecycle_group.command("promote")
@click.argument("rule_id", required=False)
@click.option(
    "--rules", "rules_csv", default=None,
    help=(
        "Bulk-promote a comma-separated list of rule IDs. Mutually "
        "exclusive with the positional rule_id argument and --cohort. "
        "Each rule is gated independently."
    ),
)
@click.option(
    "--cohort", "cohort", default=None,
    help=(
        "Bulk-promote every envelope whose metadata.cohort matches "
        "this value. Mutually exclusive with the positional rule_id "
        "argument and --rules. Each rule is gated independently."
    ),
)
@click.option(
    "--continue-on-failure", "continue_on_failure",
    is_flag=True, default=False,
    help=(
        "Bulk mode: exit 0 even if some rules failed their gates "
        "(failures are still printed in the summary). Default exits "
        "1 if any rule failed promotion. Has no effect in single-rule "
        "mode (a single failed rule always exits 1)."
    ),
)
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
)
@click.option(
    "--max-validation-age-days", type=int, default=30,
    help="metadata.lastValidatedAt must be no older than this. Default 30.",
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help="LA workspace ID for the fp_rate_threshold gate (env: "
         "PIPELINE_WORKSPACE_ID). When unset OR --no-workspace-query "
         "is on, the gate stays deferred.",
)
@click.option(
    "--telemetry-since", "telemetry_since_days",
    type=int, default=30,
    help="Telemetry lookback window in days for the fp_rate_threshold "
         "gate (default 30).",
)
@click.option(
    "--no-workspace-query", "no_workspace_query",
    is_flag=True, default=False,
    help="Skip the workspace query even when --workspace-id is set. "
         "Useful for offline dry-runs or when the operator already "
         "has out-of-band FP-rate evidence. The fp_rate_threshold "
         "gate is reported as deferred.",
)
@click.option(
    "--force", is_flag=True, default=False,
    help="Promote even when gates fail (record reviewer approval "
         "elsewhere - PR comment, audit-trail message).",
)
@click.option("--dry-run", is_flag=True, default=False,
              help="Print the gate report without mutating the YAML.")
def lifecycle_promote_cmd(
    rule_id: str | None, rules_csv: str | None, cohort: str | None,
    continue_on_failure: bool,
    detections_path: Path,
    max_validation_age_days: int,
    workspace_id: str | None, telemetry_since_days: int,
    no_workspace_query: bool,
    force: bool, dry_run: bool,
) -> None:
    """Promote RULE_ID (or --rules / --cohort) from `experimental` to `production`.

    \b
    Selector modes (mutually exclusive):
      * Positional RULE_ID -- single rule, detailed output (original behaviour).
      * --rules a,b,c -- comma-separated rule ID list, summary table output.
      * --cohort foo -- every envelope with metadata.cohort == "foo",
        summary table output.

    \b
    Gates (applied per-rule):
      * status_is_experimental - current status must be experimental.
      * recent_validation - metadata.lastValidatedAt within
        --max-validation-age-days (default 30).
      * live_test_pass - live when a workspace is set (--role /
        --workspace-id) and --no-workspace-query is unset. Executes
        the rule's KQL against the workspace via the Log Analytics
        Query API (the rule-test path); a server-side parse/schema
        error or 403 blocks the promotion. Fail-closed on workspace
        errors (use --force or --no-workspace-query to bypass).
      * fp_rate_threshold - live when a workspace is set and
        --no-workspace-query is unset. Compares closed_fp_30d /
        incidents_30d against config/lifecycle.yml's
        fp_rate_threshold (default 0.5). Fail-closed on workspace
        errors (use --force or --no-workspace-query to bypass).
    """
    from contentops.lifecycle import (
        LifecycleError, load_lifecycle_config, promote, promote_many,
    )

    # Validate selectors: exactly one mode.
    selectors_given = [
        name for name, val in (
            ("rule_id", rule_id),
            ("--rules", rules_csv),
            ("--cohort", cohort),
        ) if val
    ]
    if len(selectors_given) == 0:
        click.echo(
            "error: exactly one selector required -- positional rule_id, "
            "--rules, or --cohort.",
            err=True,
        )
        sys.exit(2)
    if len(selectors_given) > 1:
        click.echo(
            f"error: positional rule_id, --rules, and --cohort are "
            f"mutually exclusive ({', '.join(selectors_given)} given).",
            err=True,
        )
        sys.exit(2)

    # Resolve bulk selectors to a rule_id list.
    bulk_rule_ids: list[str] | None = None
    if rules_csv is not None:
        bulk_rule_ids = [
            r.strip() for r in rules_csv.split(",") if r.strip()
        ]
        if not bulk_rule_ids:
            click.echo(
                "error: --rules was empty after splitting on commas.",
                err=True,
            )
            sys.exit(2)
    elif cohort is not None:
        matches = _find_yamls_by_cohort(detections_path, cohort)
        if not matches:
            click.echo(
                f"error: no envelopes with metadata.cohort={cohort!r} "
                f"under {detections_path}",
                err=True,
            )
            sys.exit(1)
        bulk_rule_ids = [env_id for env_id, _ in matches]
        click.echo(
            f"cohort {cohort!r} matched {len(bulk_rule_ids)} envelope(s).",
            err=True,
        )

    config, info = load_lifecycle_config()
    if info:
        click.echo(f"info: {info}", err=True)

    effective_workspace_id: str | None = None
    token: str | None = None
    if not no_workspace_query:
        from contentops.utils.auth import get_credential
        from contentops.workspace_kql import (
            LA_SCOPE, WorkspaceKqlError, resolve_workspace_id,
        )
        try:
            cred = get_credential()
            if not workspace_id:
                workspace_id = resolve_workspace_id(
                    role="prod", credential=cred,
                )
            if workspace_id:
                token = cred.get_token(LA_SCOPE).token
                effective_workspace_id = workspace_id
        except WorkspaceKqlError as exc:
            click.echo(
                f"info: workspace-backed gates (live_test_pass, fp_rate) "
                f"stay deferred (workspace auto-derive failed: {exc}).",
                err=True,
            )
        except Exception as exc:
            click.echo(
                f"info: workspace-backed gates (live_test_pass, fp_rate) "
                f"stay deferred (credential/token acquisition failed: {exc}). "
                "Pass --no-workspace-query to silence this notice.",
                err=True,
            )

    # ------------------------------------------------------------------
    # Bulk mode: iterate via promote_many and emit a summary table.
    # Single-rule mode falls through to the detailed report below.
    # ------------------------------------------------------------------
    if bulk_rule_ids is not None:
        reports = promote_many(
            bulk_rule_ids,
            detections_root=detections_path,
            max_validation_age_days=max_validation_age_days,
            force=force, dry_run=dry_run,
            workspace_id=effective_workspace_id,
            token=token,
            fp_rate_threshold=config.fp_rate_threshold,
            telemetry_since_days=telemetry_since_days,
        )
        promoted = sum(1 for r in reports if r.promoted)
        passed_no_write = sum(
            1 for r in reports if r.all_passed() and not r.promoted
        )
        failed = sum(1 for r in reports if not r.all_passed())

        click.echo("")
        click.echo(
            f"## Bulk promote — {len(reports)} rule(s)  "
            f"({'dry-run' if dry_run else 'live'}, force={force})"
        )
        click.echo("")
        click.echo(
            f"{'rule_id':<50} {'status':<14} {'outcome':<16} detail"
        )
        click.echo("-" * 100)
        for r in reports:
            if r.promoted:
                outcome = "PROMOTED"
            elif r.all_passed() and dry_run:
                outcome = "would-promote"
            elif r.all_passed():
                outcome = "no-change"
            elif force:
                outcome = "FORCED" if not dry_run else "would-force"
            else:
                outcome = "REFUSED"
            failed_gates = [g.name for g in r.gates if not g.passed and not g.deferred]
            detail = ", ".join(failed_gates) if failed_gates else "all gates pass"
            click.echo(
                f"{r.rule_id:<50} {r.current_status:<14} {outcome:<16} {detail}"
            )
        click.echo("")
        click.echo(
            f"Summary: {promoted} promoted, {passed_no_write} no-change, "
            f"{failed} failed/refused."
        )

        if failed > 0 and not continue_on_failure and not force:
            sys.exit(1)
        return

    # ------------------------------------------------------------------
    # Single-rule mode (original behaviour, unchanged).
    # ------------------------------------------------------------------
    try:
        report = promote(
            rule_id, detections_root=detections_path,
            max_validation_age_days=max_validation_age_days,
            force=force, dry_run=dry_run,
            workspace_id=effective_workspace_id,
            token=token,
            fp_rate_threshold=config.fp_rate_threshold,
            telemetry_since_days=telemetry_since_days,
        )
    except LifecycleError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"## {rule_id}  (status: {report.current_status})")
    click.echo("")
    for g in report.gates:
        if g.deferred:
            tag = "[skip]"
        elif g.passed:
            tag = "[pass]"
        else:
            tag = "[FAIL]"
        click.echo(f"  {tag} {g.name}: {g.detail}")
    click.echo("")
    if report.promoted:
        click.echo(f"PROMOTED: {report.path} now has status: production")
    elif report.all_passed():
        if dry_run:
            click.echo("[dry-run] all gates pass; would write status: production")
        else:
            click.echo("(no change — already promoted? See status line.)")
    else:
        if force:
            click.echo("FORCED PROMOTION: gates failed but --force was set.")
            if dry_run:
                click.echo("[dry-run] no write performed.")
        else:
            click.echo(
                "REFUSED: gates failed. Re-run with --force after recording "
                "explicit reviewer approval, or fix the gates and re-run."
            )
            sys.exit(1)
