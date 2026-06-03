# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops tuning preview`` — NVISO Part 8 PR-time impact estimate.

Reads the diff of ``detections/drift_suppressions.yml`` between two git
refs (typically PR head and base), and renders a markdown report
quantifying how many alerts + incidents each new suppression would
have silenced over the last 30 days. The calling workflow posts the
output as a PR comment.

Fork-PR caveat: GitHub's OIDC token is unavailable on PRs from forks,
so the calling workflow exits early for fork PRs and only the
base-repo PR path actually runs this command. See
``.github/workflows/tuning-impact-preview.yml``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click


def _git_show(ref: str, path: str) -> str | None:
    """Return the file content at ``ref:path``, or None if not present."""
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


@click.group("tuning")
def tuning_group() -> None:
    """Detection-tuning helpers (NVISO Part 8)."""


@tuning_group.command("preview")
@click.option(
    "--base-ref", default="origin/main", show_default=True,
    help="Git ref to diff against (PR base).",
)
@click.option(
    "--suppressions-path",
    type=click.Path(path_type=Path),
    default=Path("detections/drift_suppressions.yml"),
    show_default=True,
    help="Path to the suppressions file (relative to repo root).",
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help="Log Analytics workspace ID (GUID). Defaults to auto-derive from tenant.yml.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default="prod", show_default=True,
    help="Tenant role to resolve the workspace from. Ignored when --workspace-id is given.",
)
@click.option(
    "--since", "since_days", type=int, default=30, show_default=True,
    help="Lookback window in days.",
)
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write markdown report to this file. Defaults to stdout.",
)
@click.option(
    "--no-workspace-query", is_flag=True,
    help="Skip the LA query. Renders the table with a dash for counts. "
         "Use when running on a fork PR without OIDC credentials.",
)
def tuning_preview_cmd(
    base_ref: str, suppressions_path: Path,
    workspace_id: str | None, role: str, since_days: int,
    out: Path | None, no_workspace_query: bool,
) -> None:
    """Estimate the blast-radius of new drift suppressions in this PR."""
    from contentops.tuning import (
        new_suppressions, render_report, resolve_display_name,
    )

    head_text = (
        suppressions_path.read_text(encoding="utf-8")
        if suppressions_path.exists() else None
    )
    base_text = _git_show(base_ref, str(suppressions_path).replace("\\", "/"))
    entries = new_suppressions(head_text, base_text)

    repo_root = Path.cwd()
    name_lookup: dict[tuple[str, str], str | None] = {}
    for e in entries:
        name_lookup[(e.asset, e.id)] = resolve_display_name(
            repo_root / "detections", e.asset, e.id,
        )

    impact_rows: dict[str, dict[str, int]] | None
    if no_workspace_query or not entries:
        impact_rows = None if no_workspace_query else {}
    else:
        names = sorted({n for n in name_lookup.values() if n})
        if not names:
            impact_rows = {}
        else:
            impact_rows = _run_impact_query(
                names, workspace_id=workspace_id, role=role,
                since_days=since_days,
            )

    body = render_report(
        entries, impact_rows,
        name_lookup=name_lookup, since_days=since_days,
    )

    if out is not None:
        out.write_text(body, encoding="utf-8")
        click.echo(f"wrote {len(entries)} new suppression(s) to {out}", err=True)
    else:
        sys.stdout.write(body)
        sys.stdout.flush()


def _run_impact_query(
    rule_names: list[str], *,
    workspace_id: str | None, role: str, since_days: int,
) -> dict[str, dict[str, int]] | None:
    """Run the LA query and return {displayName: {alerts_count, incidents_count}}.

    Returns ``None`` on any auth/query failure — the caller renders '—'
    in that case rather than failing the PR. The workflow shouldn't
    block a PR just because the workspace was temporarily unreachable.
    """
    from contentops.utils.auth import get_credential
    from contentops.workspace_kql import (
        LA_SCOPE, WorkspaceKqlError, query, resolve_workspace_id,
        suppression_impact_query,
    )

    try:
        cred = get_credential()
        if not workspace_id:
            workspace_id = resolve_workspace_id(role=role, credential=cred)
        token = cred.get_token(LA_SCOPE).token
        result = query(
            suppression_impact_query(rule_names=rule_names, since_days=since_days),
            workspace_id=workspace_id, token=token,
        )
    except (WorkspaceKqlError, Exception) as exc:
        click.echo(f"warn: workspace query skipped: {exc}", err=True)
        return None

    out: dict[str, dict[str, int]] = {}
    for row in result.rows:
        name = str(row.get("rule_name") or "")
        if not name:
            continue
        out[name] = {
            "alerts_count": int(row.get("alerts_count") or 0),
            "incidents_count": int(row.get("incidents_count") or 0),
        }
    return out


__all__ = ["tuning_group"]
