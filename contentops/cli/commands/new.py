# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops new`` command."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.core.asset import Asset
from contentops.devex.scaffold import ScaffoldError, scaffold
from contentops.lint.kql import at_or_above
from contentops.lint.runner import lint_assets


@click.command("new")
@click.argument("asset", required=False)
@click.argument("id_", metavar="ID", required=False)
@click.option("--name", "display_name", default=None, help="Human display name (defaults to ID).")
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=None,
    help="Output path (defaults to detections/<asset>/<id>.yml).",
)
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
@click.option(
    "--from-template", "from_template", default=None,
    help=(
        "Scaffold from a Microsoft-shipped Alert Rule Template. Pass the "
        "template GUID (the ARM `name` segment). Hits the live workspace, "
        "so requires a working Azure credential."
    ),
)
@click.option(
    "--search-template", "search_template", default=None,
    help=(
        "List up to 20 alertRuleTemplates whose ARM name or displayName "
        "contains this substring. Read-only - does not write any file."
    ),
)
def new_cmd(
    asset: str | None,
    id_: str | None,
    display_name: str | None,
    out: Path | None,
    force: bool,
    from_template: str | None,
    search_template: str | None,
) -> None:
    """Scaffold a valid YAML envelope.

    Two modes:

    \b
      * Local scaffold (asset + id positional, no Azure auth needed):
          contentops new sentinel_analytic my-rule-001
      * From a Microsoft-shipped Alert Rule Template:
          contentops new --from-template <template-guid>
          contentops new --from-template <template-guid> --id custom-id
      * Discover available templates without writing anything:
          contentops new --search-template "brute force"
    """
    if search_template:
        from contentops.devex.templates_remote import search_templates
        from contentops.providers.sentinel_arm import SentinelArmProvider
        provider = SentinelArmProvider.from_env()
        try:
            matches = search_templates(provider, search_template)
        finally:
            provider.close()
        if not matches:
            click.echo(f"No templates matching {search_template!r}.")
            return
        click.echo(f"Found {len(matches)} template(s) matching {search_template!r}:")
        for item in matches:
            props = item.get("properties") or {}
            click.echo(
                f"  {item.get('name'):<40} {item.get('kind'):<10} "
                f"{props.get('severity', '-'):<14} {props.get('displayName', '')}"
            )
        return

    if from_template:
        from contentops.devex.templates_remote import (
            TemplateError, scaffold_from_template,
        )
        from contentops.providers.sentinel_arm import SentinelArmProvider
        provider = SentinelArmProvider.from_env()
        try:
            try:
                path = scaffold_from_template(
                    provider, from_template,
                    override_id=id_,
                    out_path=out,
                    force=force,
                )
            except TemplateError as exc:
                click.echo(f"error: {exc}", err=True)
                sys.exit(exc.exit_code)
        finally:
            provider.close()
        click.echo(f"wrote {path}")
        # Lint round-trip on the scaffolded sentinel_analytic.
        linted = lint_assets(path.parent, asset_filter=Asset.SENTINEL_ANALYTIC)
        for lf in linted:
            if lf.path == path:
                gating = at_or_above(lf.findings, "error")
                if gating:
                    click.echo("lint: errors:")
                    for f in gating:
                        line_str = f"line {f.line}" if f.line is not None else "      "
                        click.echo(f"  {f.rule_id} {f.severity:<7} {line_str:>8}: {f.message}")
                    sys.exit(1)
                if lf.findings:
                    click.echo(f"lint: {len(lf.findings)} non-blocking finding(s)")
                else:
                    click.echo("lint: clean")
                break
        return

    # Local scaffold path (no template fetch).
    if not asset or not id_:
        click.echo(
            "error: pass ASSET and ID positionally, or use --from-template / "
            "--search-template",
            err=True,
        )
        sys.exit(2)
    try:
        path = scaffold(asset, id_, display_name=display_name, out=out, force=force)
    except ScaffoldError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(exc.exit_code)

    click.echo(f"wrote {path}")

    # Lint round-trip — call into contentops.lint programmatically.
    linted = lint_assets(path.parent, asset_filter=Asset(asset))
    findings = []
    for lf in linted:
        if lf.path == path:
            findings = lf.findings
            break
    gating = at_or_above(findings, "error")
    if gating:
        click.echo("lint: errors:")
        for f in gating:
            line_str = f"line {f.line}" if f.line is not None else "      "
            click.echo(f"  {f.rule_id} {f.severity:<7} {line_str:>8}: {f.message}")
        sys.exit(1)
    if findings:
        click.echo(f"lint: {len(findings)} non-blocking finding(s)")
    else:
        click.echo("lint: clean")
