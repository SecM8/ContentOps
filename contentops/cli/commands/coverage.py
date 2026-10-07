# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops coverage`` command."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.cli.commands._shared import coverage_scope_options
from contentops.coverage import (
    CoverageScope,
    compute_coverage,
    load_corpus,
    render_badge,
    render_json,
    render_markdown,
    summary_from_corpus,
)
from contentops.core.registry import default_registry


@click.command("coverage")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["markdown", "json", "both"]),
    default="markdown",
    help="Render markdown, JSON, or both.",
)
@click.option(
    "--out-md", "out_md",
    type=click.Path(path_type=Path),
    default=None,
    help="Write markdown report to this path instead of stdout.",
)
@click.option(
    "--out-json", "out_json",
    type=click.Path(path_type=Path),
    default=None,
    help="Write JSON report to this path.",
)
@click.option(
    "--gaps", "gaps_mode", is_flag=True, default=False,
    help=(
        "Render the inverse of the heatmap - techniques from a MITRE "
        "reference list that are NOT covered by any detection. Pair with "
        "--techniques-file to drive against an org-specific threat model."
    ),
)
@click.option(
    "--techniques-file", "techniques_file",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help=(
        "Custom JSON technique reference for --gaps. Same shape as the "
        "bundled contentops/coverage/data/mitre_attack_techniques.json."
    ),
)
@click.option(
    "--matrix-mode", "matrix_mode",
    type=click.Choice(["full", "curated"]),
    default="full",
    help=(
        "Reference matrix for --gaps: 'full' (default) is the complete "
        "MITRE ATT&CK Enterprise matrix incl. sub-techniques (refreshed "
        "weekly); 'curated' is the high-value shortlist. Ignored when "
        "--techniques-file is given."
    ),
)
@click.option(
    "--d3fend", "d3fend_mode", is_flag=True, default=False,
    help=(
        "Render MITRE D3FEND defensive-coverage report (companion to "
        "ATT&CK). Reads metadata.defensiveTechniques from each envelope "
        "and matches against the bundled D3FEND reference list."
    ),
)
@click.option(
    "--d3fend-file", "d3fend_file",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help=(
        "Custom JSON D3FEND reference for --d3fend. Same shape as the "
        "bundled contentops/coverage/data/d3fend_techniques.json."
    ),
)
@click.option(
    "--by-source", "by_source_mode", is_flag=True, default=False,
    help=(
        "Render a per-log-source rollup: group detections by the data "
        "source (KQL table) they read from, validated against the "
        "committed schema surface (tools/kql_strict/schemas*.json). Shows "
        "where coverage concentrates across log sources."
    ),
)
@click.option(
    "--out-badge", "out_badge",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Also write a shields.io-endpoint JSON to this path ('<n>% "
        "techniques - <m>% sub-techniques'), in any mode. Designed for a "
        "README badge that updates on every push-to-main. See "
        "docs/reference/feature-catalog.md."
    ),
)
@coverage_scope_options
def coverage_cmd(
    detections_path: Path,
    output_format: str,
    out_md: Path | None,
    out_json: Path | None,
    gaps_mode: bool,
    techniques_file: Path | None,
    matrix_mode: str,
    d3fend_mode: bool,
    d3fend_file: Path | None,
    by_source_mode: bool,
    out_badge: Path | None,
    include_non_production: bool,
    include_hunting: bool,
) -> None:
    """Render a MITRE ATT&CK coverage heatmap (or --gaps / --d3fend / --by-source)."""
    try:
        scope = CoverageScope.from_flags(
            include_non_production=include_non_production,
            include_hunting=include_hunting,
        )
        # One corpus walk feeds every view and the badge, so they always
        # count the same detections.
        corpus = load_corpus(detections_path, scope=scope)
        report = compute_coverage(detections_path, corpus=corpus)

        want_md = output_format in ("markdown", "both")
        want_json = output_format in ("json", "both")

        if output_format == "both":
            stem = (
                "coverage-by-source" if by_source_mode
                else "coverage-d3fend" if d3fend_mode
                else "coverage-gaps" if gaps_mode
                else "coverage"
            )
            out_md = out_md or Path(f"{stem}.md")
            out_json = out_json or Path(f"{stem}.json")

        def _emit(text: str, target: Path | None, what: str) -> None:
            if target is not None:
                target.write_text(text, encoding="utf-8")
                click.echo(f"wrote {what}: {target}")
            else:
                sys.stdout.buffer.write(text.encode("utf-8"))
                sys.stdout.flush()

        if by_source_mode:
            from contentops.coverage.sources import (
                compute_source_coverage,
                render_json as render_sources_json,
                render_markdown as render_sources_markdown,
            )
            src_report = compute_source_coverage(detections_path, corpus=corpus)
            if want_md:
                _emit(render_sources_markdown(src_report), out_md, "markdown by-source report")
            if want_json:
                _emit(render_sources_json(src_report), out_json, "json by-source report")
        elif d3fend_mode:
            from contentops.coverage.d3fend import (
                compute_d3fend_report, load_d3fend_techniques,
                render_json as render_d3fend_json,
                render_markdown as render_d3fend_markdown,
            )
            techniques, source_label = load_d3fend_techniques(d3fend_file)
            d3fend_report = compute_d3fend_report(
                detections_path, techniques, source_label=source_label,
            )
            if want_md:
                _emit(render_d3fend_markdown(d3fend_report), out_md, "markdown D3FEND report")
            if want_json:
                _emit(render_d3fend_json(d3fend_report), out_json, "json D3FEND report")
        elif gaps_mode:
            from contentops.coverage.gaps import (
                compute_gaps, load_techniques,
                render_json as render_gaps_json,
                render_markdown as render_gaps_markdown,
            )
            techniques, source_label = load_techniques(
                techniques_file, mode=matrix_mode,
            )
            gaps_report = compute_gaps(report, techniques, source=source_label)

            # Mode-aware note on stderr (never pollutes a piped report).
            # Curated: flag it's a subset + how to get the full matrix.
            # Full: flag the large gap surface is expected, not a regression.
            # Custom --techniques-file: the operator's own reference, no note.
            if techniques_file is None and matrix_mode == "curated":
                click.echo(
                    f"note: --gaps --matrix-mode curated uses the curated "
                    f"subset ({gaps_report.reference_count} techniques), not "
                    f"the full MITRE ATT&CK Enterprise matrix; drop "
                    f"--matrix-mode for the full matrix.",
                    err=True,
                )
            elif techniques_file is None and matrix_mode == "full":
                click.echo(
                    f"note: --gaps uses the full MITRE ATT&CK Enterprise "
                    f"matrix ({gaps_report.reference_count} techniques incl. "
                    f"sub-techniques); a large uncovered surface is expected. "
                    f"Use --matrix-mode curated for the high-value shortlist.",
                    err=True,
                )
            if want_md:
                _emit(render_gaps_markdown(gaps_report), out_md, "markdown gaps report")
            if want_json:
                _emit(render_gaps_json(gaps_report), out_json, "json gaps report")
        else:
            if want_md:
                _emit(render_markdown(report), out_md, "markdown report")
            if want_json:
                _emit(render_json(report), out_json, "json report")

        if out_badge is not None:
            summary = summary_from_corpus(corpus)
            out_badge.parent.mkdir(parents=True, exist_ok=True)
            out_badge.write_text(render_badge(summary), encoding="utf-8")
            click.echo(
                f"wrote badge: {out_badge} "
                f"({summary.pct}% — {summary.covered}/{summary.total}; "
                f"{summary.scope_label})"
            )
    finally:
        default_registry.close_all()
