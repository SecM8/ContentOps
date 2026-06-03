# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops lint`` command."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.core.asset import Asset
from contentops.lint.kql import at_or_above
from contentops.lint.runner import lint_assets


@click.command("lint")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict to one asset kind.",
)
@click.option(
    "--severity",
    type=click.Choice(["error", "warning", "info"]),
    default="error",
    help="Exit non-zero if any finding is at-or-above this severity.",
)
@click.option(
    "--fail-on-warn",
    is_flag=True,
    default=False,
    help="Treat warnings as gating (exit 1 if any warning is reported).",
)
@click.option(
    "--strict", "strict_mode", is_flag=True, default=False,
    help=(
        "Augment regex lint with strict policy rules (F1). Ships "
        "with KQL101 (`| take` / `| limit` forbidden in production). "
        "If the optional Kusto.Language wrapper is installed at "
        "tools/kql_strict.dll, its semantic diagnostics are layered "
        "on top; otherwise an advisory is printed once and Python "
        "rules continue. See contentops/lint/strict_rules.py for the "
        "rule registry."
    ),
)
def lint_cmd(
    detections_path: Path,
    asset: str | None,
    severity: str,
    fail_on_warn: bool,
    strict_mode: bool,
) -> None:
    """Run pure-Python KQL lint checks across all detections.

    The full set of rules (KQL00x, META00x, PAYLOAD00x) is documented
    in docs/reference/generated-catalog.md, which is auto-regenerated
    from the live rule registry. Use that as the canonical source of
    truth -- this command's help shows option flags, not rule details.
    """
    asset_filter = Asset(asset) if asset else None

    # Resolve the META002-005 strict-vs-lenient policy from tenant.yml.
    # Lenient-by-default everywhere:
    #   1. tenant.yml absent (fresh clone, CI without tenant secret,
    #      unit tests) -> LENIENT.
    #   2. tenant.yml present but policy block / scaffoldStrict unset
    #      -> LENIENT. Matches the operational reality that the G24
    #      authoring backlog still exists on collected envelopes; a
    #      fresh tenant.yml should not fail CI on metadata gaps the
    #      operator hasn't authored yet.
    # The only path to strict mode is explicit
    # ``policy.scaffoldStrict: true``.
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
        strict_policy = cfg.is_scaffold_strict()
    except Exception:
        strict_policy = False

    linted = lint_assets(
        detections_path,
        asset_filter=asset_filter,
        strict_policy=strict_policy,
    )

    # F1 strict mode — augment each LintedFile's findings with the
    # Kusto.Language parser output (or the advisory if not installed).
    if strict_mode:
        from contentops.lint.strict import (
            ADVISORY_MESSAGE, is_available, run_strict,
        )
        from contentops.lint.runner import _query_for as _strict_query_for  # type: ignore
        if not is_available():
            click.echo(f"[strict] {ADVISORY_MESSAGE}")
        for lf in linted:
            try:
                from contentops.core.discovery import load_asset
                la = load_asset(lf.path)
                query = _strict_query_for(la)
            except Exception:
                query = None
            if not query:
                continue
            lf.findings.extend(run_strict(lf.path, query))

    total_findings = 0
    gating_findings = 0
    for lf in linted:
        if not lf.findings:
            continue
        click.echo(str(lf.path))
        for f in lf.findings:
            line_str = f"line {f.line}" if f.line is not None else "      "
            click.echo(
                f"  {f.rule_id} {f.severity:<7} {line_str:>8}: {f.message}"
            )
        total_findings += len(lf.findings)
        effective_severity = "warning" if fail_on_warn else severity
        gating_findings += len(at_or_above(lf.findings, effective_severity))

    files_with_findings = sum(1 for lf in linted if lf.findings)
    click.echo(
        f"\nLint summary: {len(linted)} files scanned, "
        f"{files_with_findings} with findings, {total_findings} finding(s) total."
    )

    # Surface the META strict-mode state so operators can connect
    # "my build went red after I filled out the policy block" to the
    # right knob. Only print when there are META002-005 findings —
    # the message is irrelevant noise otherwise.
    has_meta_strict_findings = any(
        f.rule_id in ("META002", "META003", "META004", "META005")
        for lf in linted for f in lf.findings
    )
    if has_meta_strict_findings:
        if strict_policy:
            click.echo(
                "META rules in strict mode "
                "(tenant.policy.scaffoldStrict=true). META002-005 "
                "errors are CI-blocking. Remove the flag or set it "
                "false to downgrade these to warnings while the "
                "authoring backlog drains."
            )
        else:
            click.echo(
                "META rules in lenient mode "
                "(tenant.policy.scaffoldStrict=false, the default). "
                "META002-005 are warnings; set "
                "`policy.scaffoldStrict: true` in config/tenant.yml "
                "once the authoring backlog is drained to gate CI on "
                "metadata gaps."
            )

    if gating_findings:
        gate_label = "warning" if fail_on_warn else severity
        click.echo(
            f"{gating_findings} finding(s) at-or-above severity '{gate_label}'."
        )
        sys.exit(1)
