# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops navigator`` Click command.

Renders a MITRE ATT&CK Navigator layer JSON aggregating three axes:

* repo envelopes (claimed coverage),
* live Sentinel + Defender rule definitions (deployed surface),
* live SecurityAlert firings over the lookback window.

See ``contentops/navigator/__init__.py`` for the design rationale.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click


@click.command("navigator")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory (--repo axis).",
)
@click.option(
    "--repo/--no-repo", default=True, show_default=True,
    help="Include repo envelopes (metadata.techniques) as the claimed-coverage axis.",
)
@click.option(
    "--deployed/--no-deployed", default=True, show_default=True,
    help="Include Sentinel analytic rules (ARM) + Defender custom detection "
         "rules (Graph beta) as the deployed-surface axis.",
)
@click.option(
    "--firings/--no-firings", default=True, show_default=True,
    help="Include SecurityAlert firings over --since N days as the live "
         "coverage axis. Requires LA Query API access (same path as "
         "`contentops silent-rules`).",
)
@click.option(
    "--since", "since_days", type=int, default=365, show_default=True,
    help="Lookback window in days for the firings axis.",
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID", default=None,
    help="Log Analytics workspace ID (GUID). Defaults to auto-derive from tenant.yml.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default="prod", show_default=True,
    help="Tenant role for workspace + ARM resolution. Ignored when --workspace-id is given.",
)
@click.option(
    "--out", "out_path",
    type=click.Path(path_type=Path),
    default=Path("coverage-navigator.json"),
    show_default=True,
    help="Output JSON path.",
)
@click.option(
    "--name", "layer_name",
    default="Microsoft Security Coverage", show_default=True,
    help="Navigator layer name (shown at the top of the rendered matrix).",
)
@click.option(
    "--description", "layer_description",
    default=(
        "MITRE ATT&CK coverage rendered by `contentops navigator`. "
        "Score = distinct rule display names per technique."
    ),
    help="Navigator layer description (shown in the metadata panel).",
)
@click.option(
    "--fail-soft/--fail-loud", default=True, show_default=True,
    help="On fail-soft, missing-credential / OIDC-unavailable axes are "
         "skipped with a warning. On fail-loud, any axis failure exits "
         "non-zero. Default fail-soft so fork PRs without OIDC can still "
         "render the repo axis alone.",
)
def navigator_cmd(
    detections_path: Path,
    repo: bool,
    deployed: bool,
    firings: bool,
    since_days: int,
    workspace_id: str | None,
    role: str,
    out_path: Path,
    layer_name: str,
    layer_description: str,
    fail_soft: bool,
) -> None:
    """Generate a MITRE Navigator layer JSON across three coverage axes.

    \b
    Defaults: all three axes ON, 365-day firings lookback. Output JSON
    uploads to https://mitre-attack.github.io/attack-navigator/ via
    "Open Existing Layer -> Upload from local". Skip the SVG step;
    the hosted UI renders the JSON without any local dependency.
    """
    from contentops.navigator import (
        TechniqueHit,
        extract_defender_rule_techniques,
        extract_firing_techniques,
        extract_repo_techniques,
        extract_sentinel_rule_techniques,
        render_layer,
        score_techniques,
    )

    hits: list = []
    warnings: list[str] = []

    if repo:
        try:
            repo_hits = extract_repo_techniques(detections_path)
            hits.extend(repo_hits)
            click.echo(f"repo:     {len(repo_hits)} hit(s) from {detections_path}", err=True)
        except Exception as exc:
            _record_failure(warnings, "repo", exc, fail_soft)

    if deployed:
        for label, fn in (
            ("sentinel", _extract_sentinel),
            ("defender", _extract_defender),
        ):
            try:
                axis_hits = fn(role=role)
                hits.extend(axis_hits)
                click.echo(f"deployed: {len(axis_hits)} hit(s) from {label}", err=True)
            except Exception as exc:
                _record_failure(warnings, f"deployed/{label}", exc, fail_soft)

    if firings:
        try:
            firing_hits = _extract_firings(
                workspace_id=workspace_id, role=role, since_days=since_days,
            )
            hits.extend(firing_hits)
            click.echo(
                f"firings:  {len(firing_hits)} hit(s) over last {since_days}d",
                err=True,
            )
        except Exception as exc:
            _record_failure(warnings, "firings", exc, fail_soft)

    scored = score_techniques(hits)
    click.echo(
        f"scored:   {len(scored)} technique(s) "
        f"(top score = {max((s.score for s in scored), default=0)})",
        err=True,
    )

    layer = render_layer(
        scored, name=layer_name, description=layer_description,
    )
    out_path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    click.echo(
        f"wrote {len(scored)} technique(s) to {out_path} "
        f"(upload to https://mitre-attack.github.io/attack-navigator/)",
    )

    if warnings and not fail_soft:
        sys.exit(1)


def _record_failure(warnings: list[str], axis: str, exc: Exception, fail_soft: bool) -> None:
    msg = f"{axis}: {exc}"
    warnings.append(msg)
    if fail_soft:
        click.echo(f"warn: {msg} (axis skipped)", err=True)
    else:
        click.echo(f"error: {msg}", err=True)


def _extract_sentinel(*, role: str):
    """Resolve the workspace + ARM provider and run the sentinel extractor."""
    from contentops.config import load_tenant_config
    from contentops.navigator import extract_sentinel_rule_techniques
    from contentops.providers.sentinel_arm import SentinelArmProvider
    from contentops.utils.auth import get_credential

    cfg = load_tenant_config()
    workspaces = [w for w in cfg.sentinelWorkspaces if w.role == role]
    if not workspaces:
        raise RuntimeError(
            f"no Sentinel workspace with role={role} in tenant.yml"
        )
    ws = workspaces[0]
    cred = get_credential()
    provider = SentinelArmProvider(ws, credential=cred)
    try:
        return extract_sentinel_rule_techniques(provider)
    finally:
        provider.close()


def _extract_defender(*, role: str):
    """Construct a DefenderClient and run the defender extractor."""
    from contentops.defender.client import DefenderClient
    from contentops.navigator import extract_defender_rule_techniques
    from contentops.utils.auth import get_credential

    cred = get_credential()
    client = DefenderClient(credential=cred)
    try:
        return extract_defender_rule_techniques(client)
    finally:
        client.close()


def _extract_firings(*, workspace_id: str | None, role: str, since_days: int):
    """Resolve the LA workspace + token and run the firings extractor."""
    from contentops.navigator import extract_firing_techniques
    from contentops.utils.auth import get_credential
    from contentops.workspace_kql import LA_SCOPE, resolve_workspace_id

    cred = get_credential()
    if not workspace_id:
        workspace_id = resolve_workspace_id(role=role, credential=cred)
    token = cred.get_token(LA_SCOPE).token
    return extract_firing_techniques(
        workspace_id=workspace_id, token=token, since_days=since_days,
    )


__all__ = ["navigator_cmd"]
