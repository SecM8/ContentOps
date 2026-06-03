# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Lifecycle promotion gates (F8).

The roadmap entry for F8 listed four promotion gates:
    1. Live test currently passes (F2 live path).
    2. FP-rate threshold met (depends on F20 telemetry).
    3. N days at experimental.
    4. Reviewer approval (PR-time, not CLI-gateable).

Both workspace-backed gates now run live when the CLI is given a
workspace (``--role`` / ``--workspace-id``):
* ``gate_live_test_pass`` executes the rule's KQL against the
  workspace via the retrospective Log Analytics Query path (the F2
  live path that ``contentops rule-test`` uses — never a Python KQL
  evaluator). A server-side parse/schema error or 403 means the rule
  can't run, so the gate blocks the promotion.
* ``gate_fp_rate_threshold`` compares the rule's measured FP-rate
  against ``config/lifecycle.yml``'s threshold.

Without a workspace id (or with ``--no-workspace-query``), both stay
deferred so offline / dry-run paths keep working.

Workspace-call failures are **fail-closed**: an auth error, a
SemanticError, or a transient LA outage makes the gate
``passed=False`` so promotions don't go through unverified. The
escape hatch is ``--force`` or ``--no-workspace-query``.

Implemented today:
* status must currently be ``experimental``.
* ``metadata.lastValidatedAt`` must be within the last
  ``--max-validation-age-days`` (default 30). Closes G19's
  enforcement gap as a side effect.
* ``live_test_pass`` (live when a workspace is set; deferred otherwise).
* ``fp_rate_threshold`` (live when a workspace is set; deferred otherwise).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable

import yaml


class LifecycleError(RuntimeError):
    """Raised when promotion can't proceed (rule not found, malformed YAML)."""


@dataclass(frozen=True)
class GateResult:
    """One promotion gate's outcome."""
    name: str
    passed: bool
    detail: str = ""
    deferred: bool = False  # True for gates not implemented in this batch


@dataclass
class PromotionReport:
    rule_id: str
    path: Path | None
    current_status: str | None
    gates: list[GateResult] = field(default_factory=list)
    promoted: bool = False  # True if YAML was actually modified

    def all_passed(self) -> bool:
        # Deferred gates are considered "skipped" — pass them through.
        return all(g.passed or g.deferred for g in self.gates)


@dataclass(frozen=True)
class LifecycleConfig:
    """Tunables for `contentops lifecycle promote` gates."""
    fp_rate_threshold: float = 0.5


DEFAULT_LIFECYCLE_CONFIG = LifecycleConfig()
# Repo-root-anchored (mirrors contentops.config.CONFIG_DIR) so the gate
# resolves config/lifecycle.yml regardless of the process CWD. The
# previous CWD-relative Path("config")/... silently fell back to baked-in
# defaults when `contentops lifecycle promote` ran from a subdirectory.
DEFAULT_LIFECYCLE_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "lifecycle.yml"
)


def load_lifecycle_config(
    path: Path | None = None,
) -> tuple[LifecycleConfig, str | None]:
    """Load lifecycle thresholds from YAML; return (config, info_or_None).

    Falls back to baked-in defaults on any read / parse / shape error and
    returns a human-readable info note. Mirrors the contract of
    ``contentops.lint.strict_config.load_lint_strict_config``.
    """
    target = path if path is not None else DEFAULT_LIFECYCLE_CONFIG_PATH
    if not target.exists():
        return (
            DEFAULT_LIFECYCLE_CONFIG,
            f"lifecycle: {target} not found; using baked-in defaults.",
        )
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return (
            DEFAULT_LIFECYCLE_CONFIG,
            f"lifecycle: failed to parse {target} ({exc}); using defaults.",
        )
    if not isinstance(data, dict):
        return (
            DEFAULT_LIFECYCLE_CONFIG,
            f"lifecycle: {target} is not a mapping; using defaults.",
        )
    raw = data.get("fp_rate_threshold", DEFAULT_LIFECYCLE_CONFIG.fp_rate_threshold)
    try:
        threshold = float(raw)
    except (TypeError, ValueError):
        return (
            DEFAULT_LIFECYCLE_CONFIG,
            f"lifecycle: {target} fp_rate_threshold not a number; using defaults.",
        )
    if not (0.0 <= threshold <= 1.0):
        return (
            DEFAULT_LIFECYCLE_CONFIG,
            f"lifecycle: fp_rate_threshold {threshold!r} outside [0.0, 1.0]; using defaults.",
        )
    return LifecycleConfig(fp_rate_threshold=threshold), None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_envelope(detections_root: Path, rule_id: str) -> Path | None:
    """Locate the YAML for ``rule_id`` under ``detections_root``."""
    if not detections_root.is_dir():
        return None
    for path in detections_root.rglob("*.yml"):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(raw, dict) and raw.get("id") == rule_id:
            return path
    return None


def _parse_iso_date(value: str | None) -> date | None:
    if not value:
        return None
    s = str(value).strip()
    try:
        # Accept "2026-05-07" or full ISO timestamps; we only need the date.
        normalised = s.replace("Z", "+00:00") if s.endswith("Z") else s
        return datetime.fromisoformat(normalised).date()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def gate_currently_experimental(envelope: dict) -> GateResult:
    status = str(envelope.get("status") or "")
    return GateResult(
        name="status_is_experimental",
        passed=(status == "experimental"),
        detail=f"current status: {status!r}",
    )


def gate_recent_validation(
    envelope: dict, *, max_age_days: int, today: date | None = None,
) -> GateResult:
    """Check metadata.lastValidatedAt is within `max_age_days`."""
    today = today or date.today()
    metadata = envelope.get("metadata") or {}
    raw = metadata.get("lastValidatedAt") if isinstance(metadata, dict) else None
    parsed = _parse_iso_date(raw)
    if parsed is None:
        return GateResult(
            name="recent_validation",
            passed=False,
            detail=(
                "metadata.lastValidatedAt is missing or unparseable — "
                "set it before promoting"
            ),
        )
    age_days = (today - parsed).days
    passed = 0 <= age_days <= max_age_days
    return GateResult(
        name="recent_validation",
        passed=passed,
        detail=(
            f"lastValidatedAt={parsed.isoformat()} "
            f"(age {age_days}d; max {max_age_days}d)"
        ),
    )


def gate_live_test_pass(
    envelope: dict, *,
    workspace_id: str | None,
    token: str | None,
    query_fn: Callable | None = None,
) -> GateResult:
    """Live-execute the rule's KQL against the workspace (F2 live path).

    Proves the rule actually RUNS — its KQL parses server-side,
    references tables/columns the workspace actually has, and the
    identity can read it — so a never-executed rule can't ride
    lint-clean to production. Reuses the retrospective Log Analytics
    Query path that ``contentops rule-test`` uses; **never** a Python
    KQL evaluator (per the F2 design / user memory).

    Behaviour mirrors ``gate_fp_rate_threshold``:
      * No ``workspace_id`` / token -> deferred (offline /
        ``--no-workspace-query`` opted out).
      * Asset kind carries no KQL (watchlist, data_connector) -> passed;
        nothing to live-test.
      * Workspace/query failure (a 400 ``SemanticError``, a 403, a
        transient LA outage) -> **fail-closed** (``passed=False``): the
        rule is broken or unverifiable. Escape hatch: ``--force`` or
        ``--no-workspace-query``.
      * Query succeeds -> passed (the rule executes against the live
        schema); the row count over the rule's own window is reported.
    """
    if not workspace_id or not token:
        return GateResult(
            name="live_test_pass",
            passed=True, deferred=True,
            detail="workspace credentials not provided (pass --workspace-id or unset --no-workspace-query)",
        )

    from contentops.core.asset import Asset, kql_body_from_payload
    try:
        asset = Asset(str(envelope.get("asset") or ""))
    except ValueError:
        asset = None
    payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
    kql_body = kql_body_from_payload(asset, payload) if asset is not None else None
    if not kql_body:
        return GateResult(
            name="live_test_pass",
            passed=True,
            detail="asset kind carries no KQL body — nothing to live-test",
        )

    if query_fn is None:
        from contentops.workspace_kql import query as _real_query
        query_fn = _real_query
    from contentops.workspace_kql import WorkspaceKqlError

    try:
        result = query_fn(
            f"{kql_body}\n| count",
            workspace_id=workspace_id,
            token=token,
        )
    except WorkspaceKqlError as exc:
        return GateResult(
            name="live_test_pass",
            passed=False,
            detail=f"live KQL execution failed: {exc}",
        )
    except Exception as exc:  # pragma: no cover - defensive
        return GateResult(
            name="live_test_pass",
            passed=False,
            detail=f"live KQL execution crashed: {exc}",
        )

    total = 0
    if result.rows:
        first = result.rows[0]
        val = first.get("Count")
        if val is None and first:
            val = next(iter(first.values()))
        try:
            total = int(val) if val is not None else 0
        except (TypeError, ValueError):
            total = 0
    return GateResult(
        name="live_test_pass",
        passed=True,
        detail=f"rule executed against the live workspace ({total} row(s) over its window)",
    )


def gate_fp_rate_threshold(
    envelope: dict, *,
    workspace_id: str | None,
    token: str | None,
    threshold: float,
    since_days: int = 30,
    query_fn: Callable | None = None,
) -> GateResult:
    """Compare the rule's measured FP-rate against ``threshold``.

    When ``workspace_id`` is None (or no token) the gate stays
    deferred — the caller opted out of the workspace query. When the
    workspace call fails we fail-closed: ``passed=False`` so promotion
    blocks until the operator investigates (the escape hatch is
    ``--force`` or ``--no-workspace-query``).

    Behaviour:
      * KQL call fails -> fail-closed.
      * Rule's ``payload.displayName`` not in response rows ->
        passed=True (rule hasn't fired; no data to evaluate).
      * incidents_30d == 0 -> passed=True (no incidents; FP-rate
        undefined).
      * Otherwise compare ``closed_fp_30d / incidents_30d`` against
        ``threshold`` and pass iff the ratio is at or below the cap.
    """
    if not workspace_id or not token:
        return GateResult(
            name="fp_rate_threshold",
            passed=True, deferred=True,
            detail="workspace credentials not provided (pass --workspace-id or unset --no-workspace-query)",
        )

    if query_fn is None:
        from contentops.workspace_kql import query as _real_query
        query_fn = _real_query

    from contentops.workspace_kql import (
        WorkspaceKqlError,
        telemetry_query,
    )

    try:
        result = query_fn(
            telemetry_query(since_days=since_days),
            workspace_id=workspace_id,
            token=token,
        )
    except WorkspaceKqlError as exc:
        return GateResult(
            name="fp_rate_threshold",
            passed=False,
            detail=f"workspace query failed: {exc}",
        )
    except Exception as exc:  # pragma: no cover - defensive
        return GateResult(
            name="fp_rate_threshold",
            passed=False,
            detail=f"workspace query crashed: {exc}",
        )

    payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
    display_name = str(payload.get("displayName") or "")
    by_name = {str(r.get("rule_name") or ""): r for r in (result.rows or [])}
    row = by_name.get(display_name)
    if row is None:
        return GateResult(
            name="fp_rate_threshold",
            passed=True,
            detail=f"displayName {display_name!r} not in workspace telemetry window",
        )
    incidents = int(row.get("incidents_30d") or 0)
    closed_fp = int(row.get("closed_fp_30d") or 0)
    if incidents == 0:
        return GateResult(
            name="fp_rate_threshold",
            passed=True,
            detail="no incidents in window — FP-rate undefined",
        )
    fp_rate = closed_fp / incidents
    passed = fp_rate <= threshold
    return GateResult(
        name="fp_rate_threshold",
        passed=passed,
        detail=(
            f"fp_rate={fp_rate:.3f} "
            f"({'<=' if passed else '>'} threshold {threshold:.3f}; "
            f"closed_fp={closed_fp}/incidents={incidents} over {since_days}d)"
        ),
    )


def check_gates(
    envelope: dict, *,
    max_validation_age_days: int = 30,
    today: date | None = None,
    workspace_id: str | None = None,
    token: str | None = None,
    fp_rate_threshold: float = DEFAULT_LIFECYCLE_CONFIG.fp_rate_threshold,
    telemetry_since_days: int = 30,
    fp_rate_query_fn: Callable | None = None,
    live_test_query_fn: Callable | None = None,
) -> list[GateResult]:
    """Run every gate and return the per-gate result list.

    When ``workspace_id`` is None the workspace-backed gates
    (``live_test_pass``, ``fp_rate_threshold``) stay deferred — the same
    shape callers relied on before they were wired up. Pass
    ``workspace_id`` + ``token`` to evaluate them live.
    """
    return [
        gate_currently_experimental(envelope),
        gate_recent_validation(
            envelope, max_age_days=max_validation_age_days, today=today,
        ),
        gate_live_test_pass(
            envelope,
            workspace_id=workspace_id,
            token=token,
            query_fn=live_test_query_fn,
        ),
        gate_fp_rate_threshold(
            envelope,
            workspace_id=workspace_id,
            token=token,
            threshold=fp_rate_threshold,
            since_days=telemetry_since_days,
            query_fn=fp_rate_query_fn,
        ),
    ]


# ---------------------------------------------------------------------------
# Promotion mutation — surgical line edit (mirrors `contentops disable`)
# ---------------------------------------------------------------------------


_STATUS_LINE_RE = re.compile(r"(?m)^status:[ \t]*\S+[ \t]*$")
_LIFECYCLE_BLOCK_RE = re.compile(
    r"(?ms)^lifecycle:[ \t]*\n(?:[ \t]+.+\n)+",
)
_PROMOTED_AT_RE = re.compile(r"(?m)^(?P<indent>[ \t]+)promotedAt:[ \t]*\S+[ \t]*$")
_PROMOTED_BY_RE = re.compile(r"(?m)^(?P<indent>[ \t]+)promotedBy:[ \t]*\S+[ \t]*$")
_FORCED_PROMOTION_RE = re.compile(r"(?m)^(?P<indent>[ \t]+)forcedPromotion:[ \t]*\S+[ \t]*$")


def _resolve_promoter_actor() -> str:
    """Identify who is running the promote command.

    Order of preference matches the audit writer's
    ``_resolve_actor``: GitHub Actor → git user.email → unknown.
    """
    import os
    import subprocess
    actor = os.getenv("GITHUB_ACTOR")
    if actor:
        return actor
    try:
        result = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        email = result.stdout.strip()
        if email:
            return email
    except (subprocess.SubprocessError, OSError):
        pass
    return "unknown"


def _rewrite_status_to_production(text: str) -> str:
    """Rewrite the top-level `status:` line to `status: production`.

    Mirrors the surgical edit pattern used by `contentops disable`
    so the diff stays a one-liner.
    """
    if _STATUS_LINE_RE.search(text) is None:
        raise LifecycleError(
            "no top-level `status:` line found — refusing to mutate"
        )
    return _STATUS_LINE_RE.sub("status: production", text, count=1)


def _stamp_promotion(
    text: str, *, promoted_at: str, promoted_by: str, forced: bool = False,
) -> str:
    """Insert or update a ``lifecycle:`` block carrying the promotion stamp.

    The block records ``promotedAt`` (ISO date) and ``promotedBy`` (actor)
    so ``scripts/detect_production_promotions.py`` can verify that any
    PR flipping ``status: experimental`` → ``status: production`` went
    through this code path. A direct YAML edit that bypasses the CLI
    has no stamp and is rejected by the script.

    When ``forced=True``, also writes ``forcedPromotion: true`` so PR
    review can distinguish forced promotions from clean ones.

    Idempotent: re-promoting an already-promoted rule updates the
    existing stamp rather than appending a duplicate block.
    """
    if _LIFECYCLE_BLOCK_RE.search(text):
        new_text = text
        if _PROMOTED_AT_RE.search(new_text):
            new_text = _PROMOTED_AT_RE.sub(
                lambda m: f"{m.group('indent')}promotedAt: {promoted_at}",
                new_text, count=1,
            )
        else:
            new_text = _LIFECYCLE_BLOCK_RE.sub(
                lambda m: m.group(0).rstrip("\n")
                + f"\n  promotedAt: {promoted_at}\n",
                new_text, count=1,
            )
        if _PROMOTED_BY_RE.search(new_text):
            new_text = _PROMOTED_BY_RE.sub(
                lambda m: f"{m.group('indent')}promotedBy: {promoted_by}",
                new_text, count=1,
            )
        else:
            new_text = _LIFECYCLE_BLOCK_RE.sub(
                lambda m: m.group(0).rstrip("\n")
                + f"\n  promotedBy: {promoted_by}\n",
                new_text, count=1,
            )
        if forced:
            if _FORCED_PROMOTION_RE.search(new_text):
                new_text = _FORCED_PROMOTION_RE.sub(
                    lambda m: f"{m.group('indent')}forcedPromotion: true",
                    new_text, count=1,
                )
            else:
                new_text = _LIFECYCLE_BLOCK_RE.sub(
                    lambda m: m.group(0).rstrip("\n")
                    + "\n  forcedPromotion: true\n",
                    new_text, count=1,
                )
        elif _FORCED_PROMOTION_RE.search(new_text):
            new_text = _FORCED_PROMOTION_RE.sub("", new_text, count=1)
        return new_text
    suffix = "" if text.endswith("\n") else "\n"
    forced_line = "\n  forcedPromotion: true" if forced else ""
    return (
        text + suffix
        + f"lifecycle:\n  promotedAt: {promoted_at}\n  promotedBy: {promoted_by}{forced_line}\n"
    )


def promote(
    rule_id: str, *,
    detections_root: Path,
    max_validation_age_days: int = 30,
    force: bool = False,
    dry_run: bool = False,
    today: date | None = None,
    workspace_id: str | None = None,
    token: str | None = None,
    fp_rate_threshold: float = DEFAULT_LIFECYCLE_CONFIG.fp_rate_threshold,
    telemetry_since_days: int = 30,
    fp_rate_query_fn: Callable | None = None,
    live_test_query_fn: Callable | None = None,
) -> PromotionReport:
    """Run gates and (if all pass or `force`) flip status to production.

    With ``dry_run=True``, runs gates but never writes the YAML —
    the report still reports ``promoted=False`` so the caller can
    distinguish "would have promoted" from "did promote."

    When ``workspace_id`` + ``token`` are both supplied, the
    fp_rate_threshold gate runs live against the LA workspace. When
    either is absent, the gate stays deferred (skipped). The CLI
    surfaces this via the ``--workspace-id`` / ``--no-workspace-query``
    flags.

    Returns the structured report. Caller (CLI) decides exit code
    based on report.all_passed() / promoted.
    """
    path = _find_envelope(detections_root, rule_id)
    if path is None:
        raise LifecycleError(
            f"no rule with id={rule_id!r} found under {detections_root}"
        )
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise LifecycleError(f"{path}: top-level YAML is not a mapping")

    gates = check_gates(
        raw,
        max_validation_age_days=max_validation_age_days,
        today=today,
        workspace_id=workspace_id,
        token=token,
        fp_rate_threshold=fp_rate_threshold,
        telemetry_since_days=telemetry_since_days,
        fp_rate_query_fn=fp_rate_query_fn,
        live_test_query_fn=live_test_query_fn,
    )
    report = PromotionReport(
        rule_id=rule_id, path=path,
        current_status=str(raw.get("status") or ""),
        gates=gates,
    )
    if not (report.all_passed() or force):
        return report
    if dry_run:
        # Gates would have passed; no mutation in dry-run.
        return report

    # All gates pass (or --force) and not dry-run — apply the surgical edit
    # AND stamp the lifecycle block so detect_production_promotions.py can
    # verify this PR went through the CLI gate (and not via direct YAML edit).
    stamp_date = (today or date.today()).isoformat()
    actor = _resolve_promoter_actor()
    new_text = _rewrite_status_to_production(text)
    new_text = _stamp_promotion(
        new_text, promoted_at=stamp_date, promoted_by=actor,
        forced=force and not report.all_passed(),
    )
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        report.promoted = True
    return report


def promote_many(
    rule_ids: list[str], *,
    detections_root: Path,
    max_validation_age_days: int = 30,
    force: bool = False,
    dry_run: bool = False,
    today: date | None = None,
    workspace_id: str | None = None,
    token: str | None = None,
    fp_rate_threshold: float = DEFAULT_LIFECYCLE_CONFIG.fp_rate_threshold,
    telemetry_since_days: int = 30,
    fp_rate_query_fn: Callable | None = None,
    live_test_query_fn: Callable | None = None,
    continue_on_failure: bool = False,
) -> list[PromotionReport]:
    """Run :func:`promote` against every rule_id in ``rule_ids``.

    Per-rule gate evaluation is independent — one failure doesn't
    short-circuit the rest by default (``continue_on_failure`` only
    governs whether the BATCH exits non-zero). Each rule is loaded
    fresh from disk, gated, optionally mutated, and the
    :class:`PromotionReport` collected in input order.

    Bulk promotion is the most common DE workflow once a cohort has
    cleared its FP-rate / telemetry bar — promoting 20 rules one at
    a time burns hours of operator-CLI time. This helper keeps the
    single-rule API intact (still the right choice for an
    interactive review) while making the batch case one call.

    The caller (CLI) renders the summary and decides exit code based
    on the report list + ``continue_on_failure``.
    """
    out: list[PromotionReport] = []
    for rule_id in rule_ids:
        try:
            report = promote(
                rule_id,
                detections_root=detections_root,
                max_validation_age_days=max_validation_age_days,
                force=force,
                dry_run=dry_run,
                today=today,
                workspace_id=workspace_id,
                token=token,
                fp_rate_threshold=fp_rate_threshold,
                telemetry_since_days=telemetry_since_days,
                fp_rate_query_fn=fp_rate_query_fn,
                live_test_query_fn=live_test_query_fn,
            )
        except LifecycleError as exc:
            # Synthesize an explicit "not found" report so the bulk
            # summary stays one-row-per-input-id — easier to scan than
            # a mixed "some IDs raised, some returned" output.
            report = PromotionReport(
                rule_id=rule_id, path=Path("<not-found>"),
                current_status="",
                gates=[GateResult(
                    name="locate_envelope", passed=False,
                    detail=str(exc),
                )],
            )
        out.append(report)
    return out


__all__ = [
    "LifecycleError",
    "GateResult", "PromotionReport",
    "LifecycleConfig", "DEFAULT_LIFECYCLE_CONFIG", "DEFAULT_LIFECYCLE_CONFIG_PATH",
    "load_lifecycle_config",
    "promote_many",
    "gate_currently_experimental",
    "gate_recent_validation",
    "gate_live_test_pass",
    "gate_fp_rate_threshold",
    "check_gates",
    "promote",
    # Promotion-stamp helpers exposed so the detect-promotions script
    # and tests can reuse the canonical regex patterns.
    "_LIFECYCLE_BLOCK_RE",
    "_PROMOTED_AT_RE",
    "_PROMOTED_BY_RE",
    "_FORCED_PROMOTION_RE",
    "_stamp_promotion",
]
