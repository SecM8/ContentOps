# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Helpers for lifecycle commands: YAML discovery and status mutation.

Extracted from ``lifecycle.py`` so the command file reads as
orchestration ("what happens") while this module holds the
implementation details ("how it happens").
"""

from __future__ import annotations

import logging
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import click
import yaml

from contentops.audit import AuditRecord, _resolve_actor, _resolve_sha, write_records
from contentops.core.discovery import iter_loaded_assets

logger = logging.getLogger(__name__)


def _log_skip(path: Path, exc: Exception) -> None:
    """on_error sink for :func:`iter_loaded_assets` — warn and keep walking."""
    logger.warning("lifecycle: skipping %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_STATUS_LINE_RE = re.compile(r"(?m)^status:[ \t]*\S+[ \t]*$")
_LOCK_TOPLEVEL_RE = re.compile(r"(?m)^localCustomization:[ \t]*\S+[ \t]*\n")
_DISABLE_REASON_LINE_RE = re.compile(r'(?m)^disableReason:[ \t]*".*"[ \t]*\n')
_DISABLE_COMMENT_LINE_RE = re.compile(
    r"(?m)^# disabled by contentops disable on \d{4}-\d{2}-\d{2}[ \t]*\n"
)


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def _find_yaml_for_id(detections_path: Path, rule_id: str) -> Path:
    """Resolve a rule_id to exactly one YAML on disk; click-exits otherwise."""
    matches: list[Path] = []
    for la in iter_loaded_assets(detections_path, on_error=_log_skip):
        if la.envelope.id == rule_id:
            matches.append(la.path)
    if not matches:
        click.echo(
            f"error: no rule with id={rule_id!r} found under {detections_path}",
            err=True,
        )
        sys.exit(1)
    if len(matches) > 1:
        click.echo(
            f"error: rule id={rule_id!r} matches {len(matches)} files (data integrity issue):",
            err=True,
        )
        for m in matches:
            click.echo(f"  {m}", err=True)
        sys.exit(1)
    return matches[0]


def _find_yamls_by_pattern(
    detections_path: Path, pattern: str,
) -> list[tuple[str, Path]]:
    """Walk detections/ and return ``(envelope_id, path)`` pairs whose
    envelope id matches ``pattern`` via ``fnmatch`` (shell glob)."""
    import fnmatch as _fnmatch
    matches: list[tuple[str, Path]] = []
    for la in iter_loaded_assets(detections_path, on_error=_log_skip):
        if _fnmatch.fnmatchcase(la.envelope.id, pattern):
            matches.append((la.envelope.id, la.path))
    matches.sort(key=lambda t: t[0])
    return matches


def _find_yamls_by_cohort(
    detections_path: Path, cohort: str,
) -> list[tuple[str, Path]]:
    """Walk detections/ and return ``(envelope_id, path)`` pairs whose
    ``metadata.cohort`` equals ``cohort`` exactly."""
    matches: list[tuple[str, Path]] = []
    for la in iter_loaded_assets(detections_path, on_error=_log_skip):
        md = la.envelope.metadata
        if md is not None and md.cohort == cohort:
            matches.append((la.envelope.id, la.path))
    matches.sort(key=lambda t: t[0])
    return matches


def _select_one_of(
    *, rule_id: str | None, pattern: str | None, cohort: str | None,
) -> None:
    """Enforce that exactly one of the three selectors is provided."""
    given = [name for name, val in (
        ("rule_id", rule_id), ("--pattern", pattern), ("--cohort", cohort),
    ) if val]
    if len(given) > 1:
        raise click.UsageError(
            "``rule_id``, ``--pattern``, and ``--cohort`` are mutually exclusive "
            f"(got: {', '.join(given)})."
        )
    if not given:
        raise click.UsageError(
            "exactly one of positional ``rule_id``, ``--pattern``, or ``--cohort`` is required."
        )


# ---------------------------------------------------------------------------
# Mutation helpers
# ---------------------------------------------------------------------------


def _disable_one(target: Path, rule_id: str, reason: str | None) -> bool:
    """Apply the status -> deprecated mutation to a single YAML.

    Returns True if the file changed, False if already deprecated.
    """
    text = target.read_text(encoding="utf-8")
    status_match = _STATUS_LINE_RE.search(text)
    if status_match is None:
        raise click.ClickException(
            f"cannot find a top-level `status:` line in {target}; "
            f"refusing to mutate"
        )
    if status_match.group(0).strip() == "status: deprecated":
        click.echo(f"warn: {rule_id} already deprecated ({target}); no changes made")
        return False
    new_text = _STATUS_LINE_RE.sub("status: deprecated", text, count=1)
    if reason:
        # Let PyYAML emit a correctly double-quoted scalar so backslashes
        # and newlines in the reason don't produce malformed YAML. Force
        # double-quote style so the value round-trips through
        # _DISABLE_REASON_LINE_RE (which matches the "..." form) on enable.
        addition = (
            "disableReason: "
            + yaml.safe_dump(reason, default_flow_style=True, default_style='"').strip()
            + "\n"
        )
    else:
        addition = f"# disabled by contentops disable on {date.today().isoformat()}\n"
    if not new_text.endswith("\n"):
        new_text += "\n"
    new_text += addition
    target.write_text(new_text, encoding="utf-8")
    click.echo(f"disabled {rule_id}: status -> deprecated ({target})")
    return True


def _build_lifecycle_audit_record(
    action: str,
    rule_id: str,
    asset_kind: str,
    message: str | None = None,
) -> AuditRecord:
    """Build an audit record for lifecycle mutations (lock/unlock/disable)."""
    return AuditRecord(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        asset=asset_kind,
        id=rule_id,
        action=action,
        status="ok",
        sha=_resolve_sha(),
        actor=_resolve_actor(),
        workflow_run=os.environ.get("GITHUB_RUN_ID"),
        message=message,
        metadata_owner=None,
        workspace=os.environ.get("PIPELINE_WORKSPACE_NAME"),
    )


def write_lifecycle_audit(
    action: str,
    rule_id: str,
    target: Path,
    message: str | None = None,
) -> None:
    """Write a single lifecycle audit record, deriving asset kind from path."""
    record = _build_lifecycle_audit_record(
        action=action,
        rule_id=rule_id,
        asset_kind=target.parent.name,
        message=message,
    )
    write_records(Path.cwd(), [record])


def write_lifecycle_audit_batch(
    action: str,
    items: list[tuple[str, Path]],
    message: str | None = None,
) -> None:
    """Write audit records for a batch of lifecycle mutations."""
    records = [
        _build_lifecycle_audit_record(
            action=action,
            rule_id=rule_id,
            asset_kind=target.parent.name,
            message=message,
        )
        for rule_id, target in items
    ]
    if records:
        write_records(Path.cwd(), records)


_ENABLE_TARGETS = ("experimental", "production", "test")


def _enable_one(
    target: Path, rule_id: str, *, to_status: str, reason: str | None,
) -> bool:
    """Flip ``status: deprecated`` back to ``to_status`` on a single YAML.

    Returns True if the file changed. Already-active rules are
    warned-and-skipped.
    """
    text = target.read_text(encoding="utf-8")
    status_match = _STATUS_LINE_RE.search(text)
    if status_match is None:
        raise click.ClickException(
            f"cannot find a top-level `status:` line in {target}; "
            f"refusing to mutate"
        )
    current = status_match.group(0).strip()
    if current != "status: deprecated":
        click.echo(
            f"warn: {rule_id} is not deprecated (current: {current!r}); "
            f"no changes made"
        )
        return False
    new_text = _STATUS_LINE_RE.sub(f"status: {to_status}", text, count=1)
    new_text = _DISABLE_REASON_LINE_RE.sub("", new_text, count=1)
    new_text = _DISABLE_COMMENT_LINE_RE.sub("", new_text, count=1)
    if not new_text.endswith("\n"):
        new_text += "\n"
    if reason:
        escaped = reason.replace('"', '\\"')
        new_text += f'enableReason: "{escaped}"\n'
    else:
        new_text += (
            f"# re-enabled by contentops enable on {date.today().isoformat()}\n"
        )
    # A direct restore to production must carry the same
    # lifecycle.promotedAt/promotedBy stamp that ``lifecycle promote``
    # writes — otherwise ``production-promotion-check`` red-X's it as an
    # un-stamped (hand-edited) promotion. Mark it ``forcedPromotion: true``
    # so the sticky PR comment flags it for Code Owner review: this is a
    # direct restore, not a gated experimental->production promotion.
    if to_status == "production":
        from contentops.lifecycle import _resolve_promoter_actor, _stamp_promotion
        new_text = _stamp_promotion(
            new_text,
            promoted_at=date.today().isoformat(),
            promoted_by=_resolve_promoter_actor(),
            forced=True,
        )
    target.write_text(new_text, encoding="utf-8")
    suffix = " (stamped forcedPromotion)" if to_status == "production" else ""
    click.echo(f"enabled {rule_id}: status -> {to_status}{suffix} ({target})")
    return True
