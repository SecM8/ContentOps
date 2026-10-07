# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops portfolio`` command."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.portfolio import (
    build_rows as portfolio_build_rows,
    write_csv as portfolio_write_csv,
    write_json as portfolio_write_json,
)
from contentops.cli.commands._shared import coverage_scope_options
from contentops.portfolio.report import render_csv_string as _portfolio_render_csv_string


_TELEMETRY_COUNTS = (
    "alerts_30d", "incidents_30d", "closed_tp_30d", "closed_fp_30d", "closed_bp_30d",
)
_TELEMETRY_COLUMNS = (*_TELEMETRY_COUNTS, "fp_rate")


@click.command("portfolio")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--out-csv",
    type=click.Path(path_type=Path),
    default=None,
    help="Write CSV to this path instead of stdout.",
)
@click.option(
    "--out-json",
    type=click.Path(path_type=Path),
    default=None,
    help="Also write a JSON report to this path.",
)
@click.option(
    "--cohort",
    "cohort",
    type=str,
    default=None,
    help="Restrict the report to detections tagged with this cohort.",
)
@click.option(
    "--with-telemetry", "with_telemetry", is_flag=True, default=False,
    help="Augment with F20 telemetry columns (alerts_30d, "
         "incidents_30d, closed_tp_30d, closed_fp_30d, closed_bp_30d, "
         "fp_rate = closed FP / closed TP+FP+BP). Requires "
         "--workspace-id (or PIPELINE_WORKSPACE_ID env var).",
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help="LA workspace ID for --with-telemetry (env: PIPELINE_WORKSPACE_ID).",
)
@click.option(
    "--telemetry-since", "telemetry_since_days",
    type=int, default=30,
    help="Telemetry lookback window in days (default 30).",
)
@click.option(
    "--rank", "rank", is_flag=True, default=False,
    help=(
        "Compute an effectiveness score per rule and sort ascending "
        "(retirement candidates surface first). Requires --with-telemetry; "
        "without telemetry the score column is empty. Formula + weights "
        "documented in contentops/portfolio/score.py."
    ),
)
@click.option(
    "--score-weights", "score_weights", default=None,
    help=(
        "Override default scoring weights as key=value,key=value. "
        "Known keys: tp, fp, silence. Defaults: tp=1,fp=2,silence=30. "
        "Example: --score-weights tp=1,fp=3,silence=60."
    ),
)
@coverage_scope_options
def portfolio_cmd(
    detections_path: Path,
    out_csv: Path | None,
    out_json: Path | None,
    cohort: str | None,
    with_telemetry: bool,
    workspace_id: str | None,
    telemetry_since_days: int,
    rank: bool,
    score_weights: str | None,
    include_non_production: bool,
    include_hunting: bool,
) -> None:
    """Emit a flat per-detection portfolio report (CSV / JSON).

    Without --with-telemetry: inputs only (the original behaviour).
    With --with-telemetry: augments rows with F20 telemetry columns
    sourced from the LA workspace via the F4 silent-rules KQL. A rule's
    telemetry is the sum of its rule-id rows (`metadata.arm_name` /
    envelope id vs. the incident's RelatedAnalyticRuleIds and the alert's
    incident or AlertType) and its display-name rows.
    """
    from contentops.coverage import CoverageScope, load_corpus

    # One corpus walk feeds the rows and the coverage footer.
    corpus = load_corpus(
        detections_path,
        scope=CoverageScope.from_flags(
            include_non_production=include_non_production,
            include_hunting=include_hunting,
        ),
    )
    rows = portfolio_build_rows(
        detections_path,
        cohort=cohort,
        corpus=corpus,
    )

    extra_columns: tuple[str, ...] = ()
    if with_telemetry:
        from contentops.utils.auth import get_credential
        from contentops.workspace_kql import (
            LA_SCOPE, WorkspaceKqlError, query, resolve_workspace_id,
            telemetry_query,
        )
        try:
            cred = get_credential()
            if not workspace_id:
                # Auto-derive from config/tenant.yml — same flow as
                # silent_rules + lifecycle promote + check-schemas
                # (closes the PIPELINE_WORKSPACE_ID-duplicates-tenant-yml
                # design seam).
                workspace_id = resolve_workspace_id(
                    role="prod", credential=cred,
                )
            token = cred.get_token(LA_SCOPE).token
            result = query(
                telemetry_query(since_days=telemetry_since_days),
                workspace_id=workspace_id, token=token,
            )
        except WorkspaceKqlError as exc:
            click.echo(
                f"[warn] telemetry fetch failed: {exc}; "
                "continuing without telemetry", err=True,
            )
            result = None
        except Exception as exc:
            click.echo(
                f"[warn] telemetry token/auth failed: {exc}; "
                "continuing without telemetry", err=True,
            )
            result = None
        if result is not None:
            from contentops.rule_keys import TelemetryIndex, rule_keys_for
            from contentops.workspace_kql import closed_fp_rate

            index = TelemetryIndex(result.rows)
            keys_by_rule = {
                (entry.asset.value, entry.id): rule_keys_for(entry)
                for entry in corpus.entries
            }
            for row in rows:
                keys = keys_by_rule.get((row["asset"], row["id"]))
                tel = index.lookup(keys) if keys is not None else None
                if tel is None:
                    for column in _TELEMETRY_COLUMNS:
                        row[column] = None
                    continue
                for column in _TELEMETRY_COUNTS:
                    row[column] = int(tel.get(column) or 0)
                rate = closed_fp_rate(row)
                row["fp_rate"] = round(rate, 3) if rate is not None else None
        extra_columns = _TELEMETRY_COLUMNS

    if rank:
        from contentops.portfolio.score import parse_weights, rank_rows
        try:
            weights = parse_weights(score_weights)
        except ValueError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(2)
        if not with_telemetry:
            click.echo(
                "[warn] --rank without --with-telemetry: score column "
                "will be empty for every row.", err=True,
            )
        rows = rank_rows(rows, weights)
        extra_columns = (*extra_columns, "score")

    wrote_anything = False
    if out_csv is not None:
        portfolio_write_csv(rows, out_csv, extra_columns=extra_columns)
        click.echo(f"wrote {len(rows)} row(s) -> {out_csv}", err=True)
        wrote_anything = True
    if out_json is not None:
        # JSON writer dumps every key in the row dict, so extra_columns
        # are already reflected when present.
        portfolio_write_json(rows, out_json)
        click.echo(f"wrote {len(rows)} row(s) -> {out_json}", err=True)
        wrote_anything = True

    if not wrote_anything:
        sys.stdout.write(_portfolio_render_csv_string(
            rows, extra_columns=extra_columns,
        ))
        sys.stdout.flush()

    # MITRE coverage footer (stderr, suppressed when the corpus is
    # empty so the no-detections short-circuit stays clean). The
    # number matches the README badge — same engine and scope — and
    # covers the same --cohort as the rows above. stdout is flushed
    # above so the footer never interleaves into the CSV body in
    # CliRunner's mixed-stream output.
    if rows:
        from contentops.coverage import coverage_summary
        try:
            summary = coverage_summary(detections_path, corpus=corpus, cohort=cohort)
            cohort_note = f", cohort {cohort}" if cohort else ""
            click.echo(
                f"MITRE ATT&CK coverage: {summary.covered}/{summary.total} "
                f"techniques ({summary.pct}%)  --  matrix: {summary.matrix_label}"
                f"  --  counted: {summary.scope_label}{cohort_note}",
                err=True,
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"[warn] MITRE coverage summary unavailable: {exc}",
                err=True,
            )
