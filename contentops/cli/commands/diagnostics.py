# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Diagnostic commands: defender-extensions-probe, defender-roundtrip-diff, explain."""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("defender-extensions-probe")
@click.option(
    "--format", "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
)
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write rendered output to this file instead of stdout.",
)
def defender_extensions_probe_cmd(output_format: str, out: Path | None) -> None:
    """Probe Defender Graph extension endpoints for availability (F11).

    \b
    Today these endpoints are documented in
    docs/assets/defender_graph_extensions_deferred.md as "not GA":
      * /security/savedQueries
      * /security/rules/detectionTuningRules
      * /security/alertSuppressionRules

    The probe runs HEAD against each. When Microsoft GAs one, the
    probe's ``available=true`` row tells us to author the handler.
    Until then it's a no-op-by-design.

    Exit 2 if any endpoint reports available - so a scheduled
    workflow can branch on that and open an issue.

    Defender-disabled tenants (``defender:`` absent or
    ``defender.enabled: false``) skip the probe with an info message
    and exit 0 -- no point hitting Graph for an engine the operator
    doesn't deploy to.
    """
    # Skip the probe entirely when Defender is disabled in tenant.yml.
    # This mirrors the symmetric optional-engine gating in
    # ``register_default_handlers``.
    #
    # ``FileNotFoundError`` (no tenant.yml) falls through to the probe;
    # let auth fail cleanly downstream if credentials aren't available.
    # A malformed tenant.yml (``ValidationError`` / ``ValueError`` /
    # ``KeyError``) is reported as a clean error and exits 1 - better
    # than burying the operator under a Pydantic stack trace from a
    # diagnostic command.
    from pydantic import ValidationError
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
        if cfg.defender is None or not cfg.defender.enabled:
            click.echo(
                "Defender is disabled in tenant.yml -- skipping probe.",
            )
            return
    except FileNotFoundError:
        pass
    except (ValidationError, ValueError, KeyError) as exc:
        click.echo(
            f"error: tenant.yml is malformed -- cannot decide whether "
            f"to skip the Defender probe: {exc}",
            err=True,
        )
        sys.exit(1)

    from contentops.defender.client import DefenderClient
    from contentops.defender_extensions_probe import (
        probe, render_json, render_markdown,
    )
    from contentops.utils.auth import get_credential

    client = DefenderClient(credential=get_credential())
    try:
        def _request(method: str, url: str) -> int:
            r = client._client.request(method, url)  # noqa: SLF001
            return r.status_code
        report = probe(_request)
    finally:
        client.close()

    rendered = (
        render_json(report) if output_format == "json"
        else render_markdown(report)
    )
    if out is not None:
        out.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {out}", err=True)
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()

    if report.has_available():
        sys.exit(2)


@click.command("defender-roundtrip-diff")
@click.argument("envelope_id")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--raw", "show_raw", is_flag=True, default=False,
    help="Diff raw API bodies without applying the apply-verify "
         "strip. Useful for spotting NEW server-managed fields the "
         "stripper doesn't yet know about. Default off - diagnostic "
         "shows the same canonical view `contentops apply` hashes, so "
         "[OK] here means the apply verify would also report verified=True.",
)
def defender_roundtrip_diff_cmd(
    envelope_id: str, detections_path: Path, show_raw: bool,
) -> None:
    """Diagnose a Defender custom-detection MISMATCH after apply.

    \b
    Loads the local envelope, fetches the live remote rule, and
    reports which `_HASHED_FIELDS` paths differ under the same
    canonical-JSON projection `compute_content_hash` uses. Read-only;
    makes no writes against the tenant.

    By default, applies the same `_strip_server_fields` filter the
    apply path uses before hashing - so this diagnostic reflects
    what `contentops apply` would see. Pass `--raw` to skip the strip
    and inspect the literal API response (useful when Microsoft adds
    a new server-managed field the stripper doesn't yet know about).

    Use this when `contentops apply` reports `verified=False` /
    `MISMATCH` for a Defender rule. The output identifies the
    field(s) that differ; the fix is typically one of: extend
    `_SERVER_NESTED_FIELDS` (for new server-managed fields),
    remove a field from `_HASHED_FIELDS` (when it's purely server
    state), or add canonicalisation at apply-time (when both sides
    should agree but don't).

    \b
    Exit codes:
      0 - no differences (round-trip is clean for this rule).
      1 - invocation error (envelope or remote not found).
      2 - at least one field differs (diagnostic produced output).
    """
    from contentops.core.asset import Asset
    from contentops.core.discovery import iter_loaded_assets
    from contentops.defender.client import DefenderClient
    from contentops.defender.deploy import build_display_name_map
    from contentops.defender_roundtrip import diff_bodies, render_diff
    from contentops.handlers.defender_custom_detection import (
        _HASHED_FIELDS, _strip_server_fields,
    )
    from contentops.utils.auth import get_credential

    # 1. Find the local envelope.
    local = None
    for la in iter_loaded_assets(detections_path):
        if (
            la.envelope.asset == Asset.DEFENDER_CUSTOM_DETECTION
            and la.envelope.id == envelope_id
        ):
            local = la
            break
    if local is None:
        click.echo(
            f"error: no defender_custom_detection envelope with id={envelope_id!r} "
            f"under {detections_path}",
            err=True,
        )
        sys.exit(1)

    local_body = local.payload  # to_defender_body is a pass-through.
    display_name = local_body.get("displayName")

    # 2. Fetch the live remote via the rule's Graph id (looked up by displayName).
    client = DefenderClient(credential=get_credential())
    try:
        name_map = build_display_name_map(client)
        graph_id = name_map.get(display_name or "")
        if not graph_id:
            click.echo(
                f"error: no remote Defender rule with displayName={display_name!r}",
                err=True,
            )
            sys.exit(1)
        remote = client.get_rule(graph_id)
    finally:
        client.close()

    if remote is None:
        click.echo(
            f"error: GET on Graph id {graph_id} returned no body",
            err=True,
        )
        sys.exit(1)

    # 3. Diff + render. By default apply the same strip the apply
    # path uses for hash verification, so the diagnostic mirrors what
    # apply sees. --raw skips the strip and shows the literal API
    # response (the "is there a new server-managed field?" mode).
    if show_raw:
        remote_for_diff = remote
    else:
        remote_for_diff = _strip_server_fields(remote)
    diffs = diff_bodies(local_body, remote_for_diff, _HASHED_FIELDS)
    sys.stdout.write(
        render_diff(
            diffs,
            envelope_id=envelope_id,
            display_name=display_name,
            remote_id=graph_id,
            remote_id_label="Graph ID",
            fix_hint_module="contentops/handlers/defender_custom_detection.py",
        )
    )
    sys.stdout.flush()

    if any(d.differs for d in diffs):
        sys.exit(2)


@click.command("sentinel-roundtrip-diff")
@click.argument("envelope_id")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--raw", "show_raw", is_flag=True, default=False,
    help="Diff raw API bodies without applying the apply-verify "
         "strip. Useful for spotting NEW server-managed fields the "
         "stripper doesn't yet know about. Default off - diagnostic "
         "shows the same canonical view `contentops apply` hashes, so "
         "[OK] here means the apply verify would also report verified=True.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role (sets "
         "PIPELINE_WORKSPACE_NAME). Mutex with --workspace. "
         "Single-workspace tenants pick implicitly when both omitted.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName`` "
         "(must match config/tenant.yml). Mutex with --role.",
)
def sentinel_roundtrip_diff_cmd(
    envelope_id: str, detections_path: Path, show_raw: bool,
    role: str | None, workspace_name: str | None,
) -> None:
    """Diagnose a Sentinel rule MISMATCH after apply.

    \b
    Loads the local envelope, fetches the live remote rule via ARM,
    and reports which `_HASHED_FIELDS` paths differ under the same
    canonical-JSON projection `compute_content_hash` uses. Read-only;
    makes no writes against the tenant.

    Mirrors `defender-roundtrip-diff` for Sentinel content. Dispatches
    by asset kind (analytic / hunting / parser / watchlist) to the
    right handler's `_HASHED_FIELDS` + `_strip_server_fields`.
    `data_connector` is not currently supported (it uses a
    `_projection()` helper, not `_HASHED_FIELDS`); use the apply
    summary for connector mismatches.

    By default, applies the same `_strip_server_fields` filter the
    apply path would use before hashing. Pass `--raw` to skip the
    strip and inspect the literal API response (useful when ARM adds
    a new server-managed field the stripper doesn't yet know about).

    On a multi-workspace tenant, pass `--role` or `--workspace` to
    pick which workspace the diagnostic queries; single-workspace
    tenants pick implicitly. The diagnostic prints the active
    workspace name in the header so the operator can confirm at a
    glance.

    \b
    Exit codes:
      0 - no differences (round-trip is clean for this rule).
      1 - invocation error (envelope or remote not found, unsupported
          asset kind, network failure).
      2 - at least one field differs (diagnostic produced output).
    """
    import httpx
    from contentops.cli.commands._shared import _resolve_single_workspace_or_exit
    from contentops.cli.handler_factories import _active_workspace
    from contentops.core.asset import Asset
    from contentops.core.discovery import iter_loaded_assets
    from contentops.providers.sentinel_arm import SentinelArmProvider
    from contentops.sentinel_roundtrip import dispatch_for_asset
    from contentops.utils.auth import get_credential
    from contentops.utils.roundtrip_diff import diff_bodies, render_diff

    SENTINEL_KINDS = {
        Asset.SENTINEL_ANALYTIC, Asset.SENTINEL_HUNTING,
        Asset.SENTINEL_PARSER, Asset.SENTINEL_WATCHLIST,
    }

    # Resolve --role / --workspace BEFORE _active_workspace() so a
    # multi-workspace tenant gets a clean Click error (exit 2) rather
    # than the bare RuntimeError _active_workspace would raise.
    _resolve_single_workspace_or_exit(role, workspace_name)

    # 1. Find the local envelope.
    local = None
    for la in iter_loaded_assets(detections_path):
        if (
            la.envelope.asset in SENTINEL_KINDS
            and la.envelope.id == envelope_id
        ):
            local = la
            break
    if local is None:
        click.echo(
            f"error: no Sentinel envelope with id={envelope_id!r} "
            f"under {detections_path} (supported kinds: "
            f"{sorted(a.value for a in SENTINEL_KINDS)})",
            err=True,
        )
        sys.exit(1)

    # 2. Dispatch + fetch the live remote.
    try:
        dispatch = dispatch_for_asset(local.envelope.asset)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    # ARM resource name. Analytic carries an alternate ``arm_name``
    # in metadata for collected GUID-named rules; for hunting /
    # parser / watchlist the envelope id IS the ARM resource name
    # (those handlers don't use arm_name in their apply path).
    if local.envelope.asset == Asset.SENTINEL_ANALYTIC:
        remote_id = local.envelope.arm_name or local.envelope.id
    else:
        remote_id = local.envelope.id

    try:
        workspace = _active_workspace()
    except RuntimeError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)

    provider = SentinelArmProvider(workspace, credential=get_credential())
    try:
        # Hunting and parser are savedSearches under the LA workspace
        # path; analytic and watchlist live under the SecurityInsights
        # namespace. The dispatch table records which to use.
        if dispatch.use_la_path:
            url = provider.la_resource_url(dispatch.resource, remote_id)
            response = provider.request("GET", url)
            if response.status_code == 404:
                remote = None
            else:
                response.raise_for_status()
                remote = response.json()
        else:
            remote = provider.get_resource(dispatch.resource, remote_id)
    except httpx.HTTPError as exc:
        click.echo(
            f"error: GET failed against workspace "
            f"{workspace.workspaceName!r}: {exc}",
            err=True,
        )
        sys.exit(1)
    finally:
        provider.close()

    if remote is None:
        click.echo(
            f"error: GET on {dispatch.resource}/{remote_id} returned 404 "
            f"in workspace {workspace.workspaceName!r}",
            err=True,
        )
        sys.exit(1)

    # 3. Diff + render. Apply the strip by default so the diagnostic
    # mirrors what apply-verify sees; --raw skips it.
    if show_raw:
        remote_for_diff = remote
    else:
        remote_for_diff = dispatch.strip_server_fields(remote)

    local_body = local.payload
    fields = dispatch.hashed_fields(local_body)
    diffs = diff_bodies(local_body, remote_for_diff, fields)

    fix_hint_module = (
        f"contentops/handlers/{local.envelope.asset.value}.py"
    )
    # Show the active workspace name in the header so a multi-workspace
    # operator can confirm at a glance which workspace was queried.
    sys.stdout.write(f"Workspace: {workspace.workspaceName}\n")
    sys.stdout.write(
        render_diff(
            diffs,
            envelope_id=envelope_id,
            display_name=(local_body.get("displayName")
                          or (local_body.get("properties") or {}).get("displayName")),
            remote_id=remote_id,
            remote_id_label="ARM name",
            fix_hint_module=fix_hint_module,
        )
    )
    sys.stdout.flush()

    if any(d.differs for d in diffs):
        sys.exit(2)


@click.command("explain")
@click.argument("rule_id")
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
    "--format", "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Render markdown (default) or JSON.",
)
def explain_cmd(
    rule_id: str, detections_path: Path, audit_dir: Path, output_format: str,
) -> None:
    """Surface everything the pipeline knows about RULE_ID in one shot.

    \b
    Useful when:
      * Paged about a misbehaving rule and you need owner / runbook /
        last-applied / recent failures without grepping five places.
      * Investigating a drift PR - was this rule recently touched?
      * Compliance audit - when was rule X last validated?

    Walks: the YAML envelope, detections/dependencies.yml,
    state/state.json, audit/*.jsonl, and drift_report.json (if
    present in cwd).
    """
    from contentops.explain import build_explain, render_json, render_markdown

    e = build_explain(
        rule_id,
        detections_root=detections_path,
        audit_dir=audit_dir,
        state_root=Path.cwd(),
        drift_root=Path.cwd(),
    )
    if output_format == "json":
        sys.stdout.write(render_json(e))
    else:
        sys.stdout.write(render_markdown(e))
    sys.stdout.flush()
    if not e.found:
        sys.exit(1)


@click.command("defender-patch-probe")
@click.argument("envelope_id")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--send", is_flag=True, default=False,
    help="Actually send the PATCH/POST/DELETE calls. Default OFF: preview "
         "only - prints the exact bodies it would send and makes no writes.",
)
@click.option(
    "--replicate", is_flag=True, default=False,
    help="Create a disabled CLONE of this rule's EXACT payload (renamed), "
         "then delete it. A PATCH returns only a generic `400 Bad request`, "
         "but a create returns Graph's detailed validation reason - so this "
         "surfaces verbatim WHY this exact rule config is rejected. Prod side "
         "effect: creates one throwaway rule and deletes it (cleanup in a "
         "finally block; leftover id printed loudly if delete fails). Only "
         "takes effect with --send.",
)
@click.option(
    "--query-file",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="With --replicate: override the clone's queryText with this file's "
         "contents (keeping the rule's real mappings/schedule), to bisect "
         "which query construct the save-validator rejects. Read the clone "
         "result: 201 = query+mapping OK; generic 400 = this query is "
         "rejected; 'Entity mappings...' = query passed, mapping mismatch.",
)
def defender_patch_probe_cmd(
    envelope_id: str, detections_path: Path, send: bool, replicate: bool,
    query_file: Path | None,
) -> None:
    """Isolate which field the Defender beta detectionRules API rejects.

    \b
    A Defender custom-detection rule that deployed cleanly in the past can
    start returning a generic `400 Bad request` from the beta
    `PATCH /security/rules/detectionRules/{id}` endpoint without any change
    on our side - the beta surface tightens validation without notice. This
    probe runs a controlled, ordered sequence of PATCHes against ONE rule to
    pin down exactly which field/value is now rejected.

    \b
    Each PATCH below re-sends the rule's CURRENT remote value, so a 200 is a
    true no-op and a 400 mutates nothing - the live rule is never changed:
      A. full local body (what `apply` sends)  -> expect 400 (reproduce)
      B. only schedule.period                  -> expect 200 (partial works)
      C. only queryCondition.queryText         -> expect 400 (query rejected)
      D. only detectionAction.alertTemplate.severity -> expect 200

    With --replicate, a disabled clone of this rule's exact payload is
    created (then deleted) to surface Graph's detailed create-time
    validation error - the definitive, rule-specific reason a PATCH only
    reports as a generic 400.

    \b
    Default is preview-only; pass --send to actually call the API. Needs
    `CustomDetection.ReadWrite.All` and a credential (az login / OIDC /
    client secret).

    \b
    Exit codes:
      0 - probe completed (preview, or sent and reproduced the failure).
      1 - invocation error (envelope/remote not found, missing fields).
      2 - sent, but the full-body PATCH returned 200 (could not reproduce -
          likely transient/environment).
    """
    import copy
    import json
    import time

    from contentops.core.asset import Asset
    from contentops.core.discovery import iter_loaded_assets
    from contentops.defender.client import DefenderClient
    from contentops.defender.deploy import build_display_name_map
    from contentops.utils.auth import get_credential
    from contentops.utils.yaml_io import to_defender_body

    # 1. Find the local envelope.
    local = None
    for la in iter_loaded_assets(detections_path):
        if (
            la.envelope.asset == Asset.DEFENDER_CUSTOM_DETECTION
            and la.envelope.id == envelope_id
        ):
            local = la
            break
    if local is None:
        click.echo(
            f"error: no defender_custom_detection envelope with id={envelope_id!r} "
            f"under {detections_path}",
            err=True,
        )
        sys.exit(1)

    local_body = local.payload  # to_defender_body is a pass-through.
    display_name = local_body.get("displayName")

    client = DefenderClient(credential=get_credential())
    created_ids: list[str] = []
    try:
        # 2. Resolve graph id - prefer the envelope's arm_name, else the
        # displayName->id map.
        graph_id = str(local.envelope.arm_name or "")
        if not graph_id:
            name_map = build_display_name_map(client)
            graph_id = name_map.get(display_name or "") or ""
        if not graph_id:
            click.echo(
                f"error: could not resolve Graph id for {envelope_id!r} "
                f"(displayName={display_name!r})",
                err=True,
            )
            sys.exit(1)

        remote = client.get_rule(graph_id)
        if remote is None:
            click.echo(
                f"error: GET on Graph id {graph_id} returned no body", err=True,
            )
            sys.exit(1)

        # 3. Build the probe bodies from CURRENT remote values (non-mutating).
        r_sched = (remote.get("schedule") or {}).get("period")
        r_query = (remote.get("queryCondition") or {}).get("queryText")
        r_sev = (
            ((remote.get("detectionAction") or {}).get("alertTemplate") or {})
            .get("severity")
        )

        probes: list[tuple[str, dict, str]] = [
            ("A full-local-body", to_defender_body(local_body), "400"),
        ]
        if r_sched is not None:
            probes.append(("B schedule.period-only",
                           {"schedule": {"period": r_sched}}, "200"))
        if r_query is not None:
            probes.append(("C queryText-only",
                           {"queryCondition": {"queryText": r_query}}, "400"))
        if r_sev is not None:
            probes.append(("D alertTemplate.severity-only",
                           {"detectionAction": {"alertTemplate": {"severity": r_sev}}},
                           "200"))

        click.echo(f"\n# defender-patch-probe - {envelope_id} (graph:{graph_id})")
        click.echo(f"# mode: {'SEND' if send else 'PREVIEW (no writes)'}\n")

        results: list[tuple[str, str, str]] = []  # (label, expected, actual)

        for label, body, expected in probes:
            preview = json.dumps(body)
            if len(preview) > 300:
                preview = preview[:297] + "..."
            click.echo(f"[{label}] expect {expected}")
            click.echo(f"  body: {preview}")
            if send:
                resp = client.update_rule(graph_id, body)
                txt = (resp.text or "").replace("\n", " ")[:300]
                click.echo(f"  -> {resp.status_code}  {txt}")
                results.append((label, expected, str(resp.status_code)))
            click.echo("")

        # 4. Exact-clone create - surfaces Graph's detailed validation
        # reason for THIS rule's config (a PATCH only returns a generic
        # 400; a create returns the specifics).
        clone_reason = ""
        if send and replicate:
            stamp = time.strftime("%Y%m%d%H%M%S")
            clone = copy.deepcopy(to_defender_body(local_body))
            clone["displayName"] = f"ZZ-probe-clone-{stamp}"
            clone["isEnabled"] = False
            # Defender also enforces a unique alertTemplate.title - rename it
            # too, otherwise a clone of an otherwise-valid rule collides (409)
            # with the real rule's alert title instead of telling us the
            # validation result.
            _da = clone.get("detectionAction")
            if isinstance(_da, dict) and isinstance(_da.get("alertTemplate"), dict):
                _da["alertTemplate"]["title"] = f"ZZ-probe-clone-{stamp}"
            if query_file is not None:
                clone["queryCondition"] = {
                    "queryText": query_file.read_text(encoding="utf-8").rstrip("\n")
                }
                label = f"clone-create (query from {query_file.name})"
                click.echo(
                    f"[clone-create] this rule's mappings + query from "
                    f"{query_file} (renamed, disabled)"
                )
            else:
                label = "clone-create (exact rule)"
                click.echo("[clone-create] exact copy of this rule (renamed, disabled)")
            r_clone = client.create_rule(clone)
            clone_reason = (r_clone.text or "").replace("\n", " ")
            click.echo(f"  -> {r_clone.status_code}")
            click.echo(f"  reason: {clone_reason[:800]}")
            if r_clone.status_code == 201:
                created_ids.append(str(r_clone.json().get("id", "")))
            results.append((label, "400|201", str(r_clone.status_code)))
            click.echo("")

        # 5. Verdict.
        if not send:
            click.echo(
                "PREVIEW only - no calls made. Re-run with --send "
                "(add --replicate for Graph's verbatim reason via an exact "
                "disposable clone)."
            )
            return

        click.echo("## Verdict")
        click.echo(f"  {'probe':30} {'note':10} {'actual':7}")
        by_label: dict[str, str] = {}
        for label, expected, actual in results:
            by_label[label.split()[0]] = actual
            click.echo(f"  {label:30} {expected:10} {actual:7}")

        click.echo("\n## Conclusion")
        if clone_reason:
            # The clone-create error is the definitive, rule-specific reason.
            click.echo("  Graph's create-time reason for THIS exact rule config:")
            click.echo(f"    {clone_reason[:800]}")
            click.echo("  (A PATCH only reports this as a generic 400.)")
        a, b, c, d = (by_label.get(k) for k in ("A", "B", "C", "D"))
        if a == "200":
            click.echo("  NOTE: full body returned 200 - could not reproduce the "
                       "failure here. Likely transient/environment.")
            sys.exit(2)
        if d == "200" and (b != "200" or (c and c != "200")):
            click.echo("  Alert-metadata PATCH (severity) succeeds but query/schedule "
                       "PATCH fails -> the rejection is tied to query/mapping "
                       "re-validation, not the deploy mechanism. Fix is in the "
                       "detection content; see the reason above.")
        elif not clone_reason:
            click.echo("  Inconclusive - re-run with --replicate for Graph's "
                       "verbatim reason.")
    finally:
        # Best-effort cleanup of any disposable rules we created.
        for gid in created_ids:
            if not gid:
                continue
            try:
                resp = client.delete_rule(gid)
                if resp.status_code not in (200, 204):
                    click.echo(
                        f"WARNING: could not delete disposable rule {gid} "
                        f"(status {resp.status_code}) - delete it manually.",
                        err=True,
                    )
            except Exception as exc:  # noqa: BLE001
                click.echo(
                    f"WARNING: error deleting disposable rule {gid}: {exc} "
                    f"- delete it manually.",
                    err=True,
                )
        client.close()
