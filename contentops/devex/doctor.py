# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops doctor`` — environment & configuration sanity checks.

The doctor never modifies state. Exit code is 0 if every check is PASS
or WARN, and 1 if any check is FAIL.
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Literal

import click


Status = Literal["PASS", "FAIL", "WARN"]


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: Status
    detail: str = ""


# --- Individual checks -----------------------------------------------------


def _check_python_version() -> CheckResult:
    v = sys.version_info
    if (v.major, v.minor) >= (3, 12):
        return CheckResult("python_version", "PASS", f"{v.major}.{v.minor}.{v.micro}")
    return CheckResult(
        "python_version", "FAIL",
        f"need Python >= 3.12, found {v.major}.{v.minor}.{v.micro}",
    )


def _az_signed_in() -> bool:
    """Best-effort check that `az account show` returns 0."""
    az = shutil.which("az")
    if az is None:
        return False
    try:
        result = subprocess.run(
            [az, "account", "show"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover — defensive
        return False
    return result.returncode == 0


def _check_auth_env() -> CheckResult:
    tenant = os.getenv("AZURE_TENANT_ID")
    client = os.getenv("AZURE_CLIENT_ID")
    secret = os.getenv("AZURE_CLIENT_SECRET")
    have_secret = bool(secret)
    have_az = _az_signed_in()

    bits = []
    bits.append(f"AZURE_TENANT_ID={'set' if tenant else 'unset'}")
    bits.append(f"AZURE_CLIENT_ID={'set' if client else 'unset'}")
    if have_secret:
        bits.append("AZURE_CLIENT_SECRET=set")
    elif have_az:
        bits.append("az CLI=signed-in")
    else:
        bits.append("AZURE_CLIENT_SECRET=unset; az CLI=not signed-in")

    detail = ", ".join(bits)
    if tenant and client and (have_secret or have_az):
        return CheckResult("auth_env", "PASS", detail)
    # Read-only commands work without auth — never FAIL here.
    return CheckResult("auth_env", "WARN", detail)


def _check_tenant_yml() -> CheckResult:
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
    except FileNotFoundError:
        # A *missing* tenant.yml is WARN, not FAIL. The offline /
        # author-only path (a fresh public-mirror clone running `new`,
        # `lint`, `plan`) works without it, so making `doctor` exit 1
        # on a clean clone is a gotcha that contradicts the
        # "author-only adopters never need Azure" story (lenient public
        # default, same rationale as WorkspaceSafeguards.writeAllowed).
        # The file is only *required* for tenant calls, and those paths
        # still fail-closed: `doctor --auth` FAILs on token_acquisition
        # / workspace_reachable, and `conformance --scope L2` FAILs its
        # dedicated tenant_yml_present check. A *present-but-broken*
        # file (parse / validation error) stays FAIL below.
        return CheckResult(
            "tenant_yml", "WARN",
            "config/tenant.yml not found — fine for offline authoring "
            "(new / lint / plan). Required for tenant calls: copy "
            "config/tenant.yml.example to config/tenant.yml, then "
            "`doctor --auth`.",
        )
    except Exception as exc:
        return CheckResult("tenant_yml", "FAIL", f"parse error: {exc}")
    if cfg.sentinelWorkspaces:
        ws_summary = ", ".join(
            f"{w.workspaceName}({w.role})" for w in cfg.sentinelWorkspaces
        )
        detail = f"tenant={cfg.name}, sentinel=[{ws_summary}]"
    else:
        detail = f"tenant={cfg.name}, sentinel=(none)"
    return CheckResult("tenant_yml", "PASS", detail)


def _check_detections_dir() -> CheckResult:
    p = Path("detections")
    if p.is_dir():
        return CheckResult("detections_dir", "PASS", str(p.resolve()))
    return CheckResult("detections_dir", "FAIL", f"not a directory: {p}")


def _check_detections_parse() -> CheckResult:
    p = Path("detections")
    if not p.is_dir():
        return CheckResult("detections_parse", "FAIL", "detections/ missing")
    try:
        from contentops.core.discovery import discover_assets, load_asset
    except Exception as exc:  # pragma: no cover — defensive
        return CheckResult("detections_parse", "FAIL", f"import error: {exc}")
    parsed = 0
    errors: list[str] = []
    for path in discover_assets(p):
        try:
            load_asset(path)
            parsed += 1
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        return CheckResult(
            "detections_parse", "FAIL",
            f"{parsed} parsed, {len(errors)} error(s); first: {errors[0]}",
        )
    return CheckResult("detections_parse", "PASS", f"{parsed} parsed, 0 errors")


def _check_dotenv() -> CheckResult:
    loaded = os.getenv("PIPELINE_DOTENV_LOADED")
    if loaded:
        return CheckResult("dotenv", "PASS", f"loaded {loaded}")
    from contentops.utils.env import find_dotenv
    found = find_dotenv()
    if found is None:
        return CheckResult(
            "dotenv", "WARN",
            "no .env found (fine for CI / OIDC; copy .env.example for local dev)",
        )
    return CheckResult(
        "dotenv", "WARN",
        f"found {found} but not loaded — invoke via `contentops` or `python -m contentops`",
    )


def _check_git() -> CheckResult:
    git = shutil.which("git")
    if git is None:
        return CheckResult("git", "WARN", "git not on PATH")
    try:
        r = subprocess.run(
            [git, "--version"], capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        return CheckResult("git", "WARN", "git invocation failed")
    if r.returncode != 0:
        return CheckResult("git", "WARN", "git --version returned non-zero")
    return CheckResult("git", "PASS", r.stdout.strip())


_REQUIRED_IMPORTS = ("httpx", "pydantic", "yaml", "azure.identity", "click")


def _check_python_deps() -> CheckResult:
    missing: list[str] = []
    for mod in _REQUIRED_IMPORTS:
        try:
            importlib.import_module(mod)
        except Exception:
            missing.append(mod)
    if missing:
        return CheckResult(
            "python_deps", "FAIL",
            f"missing: {', '.join(missing)}",
        )
    return CheckResult("python_deps", "PASS", ", ".join(_REQUIRED_IMPORTS))


def _check_token_acquisition() -> CheckResult:
    try:
        from contentops.utils.auth import get_credential, ARM_SCOPE, GRAPH_SCOPE
    except Exception as exc:  # pragma: no cover — covered by deps check
        return CheckResult("token_acquisition", "WARN", f"auth module unavailable: {exc}")
    try:
        cred = get_credential()
        arm = cred.get_token(ARM_SCOPE)
        graph = cred.get_token(GRAPH_SCOPE)
    except Exception as exc:
        return CheckResult(
            "token_acquisition", "WARN",
            f"could not acquire tokens: {exc}",
        )
    if arm.token and graph.token:
        return CheckResult("token_acquisition", "PASS", "ARM + Graph tokens acquired")
    return CheckResult("token_acquisition", "WARN", "tokens missing")


def _check_workspace_reachable() -> CheckResult:
    """Verify the configured Sentinel workspace responds to a basic GET."""
    try:
        from contentops.config import load_tenant_config
        from contentops.providers.sentinel_arm import SentinelArmProvider
        from contentops.utils.auth import get_credential
    except Exception as exc:
        return CheckResult("workspace_reachable", "WARN", f"import error: {exc}")
    try:
        cfg = load_tenant_config()
        if not cfg.sentinelWorkspaces:
            return CheckResult(
                "workspace_reachable", "WARN",
                "no Sentinel workspaces configured in tenant.yml",
            )
        # Pinned via --role / --workspace (CLI sets PIPELINE_WORKSPACE_NAME)
        # takes priority. Otherwise probe the first prod workspace if there
        # is one; else the first listed.
        pinned = os.environ.get("PIPELINE_WORKSPACE_NAME")
        if pinned:
            ws = next(
                (w for w in cfg.sentinelWorkspaces if w.workspaceName == pinned),
                cfg.sentinelWorkspaces[0],
            )
        else:
            ws = next(
                (w for w in cfg.sentinelWorkspaces if w.role == "prod"),
                cfg.sentinelWorkspaces[0],
            )
        # Credential-backed construction routes through BearerTokenAuth
        # so the (admittedly sub-second) probe doesn't risk an expired
        # static token. Previously this used ``get_arm_token`` which
        # discards expires_on; the new code uses the provider's own
        # auth flow which calls ``get_arm_access_token`` under the
        # covers.
        provider = SentinelArmProvider(ws, credential=get_credential())
    except Exception as exc:
        return CheckResult(
            "workspace_reachable", "FAIL",
            f"could not construct ARM provider: {exc}",
        )
    try:
        resp = provider.request("GET", provider.resource_url("alertRules"))
    except Exception as exc:
        # Network-level errors (timeout, DNS, connection refused) are
        # WARN: transient blips shouldn't block the live test gate.
        # Auth failures come back as 401/403 responses, not exceptions.
        return CheckResult(
            "workspace_reachable", "WARN",
            f"GET alertRules raised (transient?): {exc}",
        )
    finally:
        provider.close()
    if resp.status_code == 200:
        return CheckResult(
            "workspace_reachable", "PASS",
            f"workspace={ws.workspaceName} (HTTP 200)",
        )
    if resp.status_code == 401:
        # 401 != 403. 401 means the ARM endpoint rejected the token as
        # unauthenticated — wrong tenant, expired, or
        # ``DefaultAzureCredential`` returned a token from a stale
        # cached identity (SharedTokenCache / VSCode account) instead
        # of the one ``az login`` minted. Conflating with 403 sent
        # adopters chasing RBAC for a chain-ordering bug. See task #31
        # in the adopter-friction notes.
        return CheckResult(
            "workspace_reachable", "FAIL",
            f"GET alertRules returned 401 — token rejected as "
            f"unauthenticated. Check `az account show` tenant context "
            f"matches tenant.yml. If they match, try "
            f"`$env:AZURE_TOKEN_CREDENTIALS = 'dev'` to bypass stale "
            f"SharedTokenCache / VSCode credentials in the chain.",
        )
    if resp.status_code == 403:
        return CheckResult(
            "workspace_reachable", "FAIL",
            f"GET alertRules returned 403 — authenticated but lacks "
            f"RBAC on this workspace. Grant `Microsoft Sentinel "
            f"Contributor` on the workspace's resource group to "
            f"whichever identity you're authenticated as (your user "
            f"on Path A / az login, OR the App Registration on "
            f"Path B / .env).",
        )
    return CheckResult(
        "workspace_reachable", "WARN",
        f"GET alertRules returned {resp.status_code}: {resp.text[:120]}",
    )


def _check_sentinel_health() -> CheckResult:
    """Verify the ``SentinelHealth`` diagnostic table is populated.

    Prerequisite for ``contentops auto-disabled-rules`` (NVISO Part 7).
    The diagnostic is opt-in on the Sentinel workspace; without it the
    auto-disabled-rules query returns zero rows silently and platform
    disables stay invisible. This check distinguishes "all rules
    healthy" from "diagnostic not configured" so operators can tell
    them apart without opening the Azure portal.
    """
    try:
        from contentops.utils.auth import get_credential
        from contentops.workspace_kql import (
            LA_SCOPE, WorkspaceKqlError, query, resolve_workspace_id,
        )
    except Exception as exc:
        return CheckResult("sentinel_health", "WARN", f"import error: {exc}")
    try:
        cred = get_credential()
        workspace_id = resolve_workspace_id(role="prod", credential=cred)
        token = cred.get_token(LA_SCOPE).token
        result = query(
            "SentinelHealth | where TimeGenerated > ago(1d) | take 1",
            workspace_id=workspace_id, token=token,
        )
    except WorkspaceKqlError as exc:
        # 4xx from LA is the most informative case ("table not found"
        # comes back as a 400). Keep the message short — operators
        # follow the docs URL in the WARN body for the real fix.
        return CheckResult(
            "sentinel_health", "WARN",
            f"SentinelHealth probe failed: {exc}",
        )
    except Exception as exc:
        return CheckResult(
            "sentinel_health", "WARN",
            f"SentinelHealth probe raised (transient?): {exc}",
        )
    if result.rows:
        return CheckResult(
            "sentinel_health", "PASS",
            "SentinelHealth has data in last 24h — auto-disabled-rules ready",
        )
    return CheckResult(
        "sentinel_health", "WARN",
        "SentinelHealth returned 0 rows in last 24h — diagnostic may be "
        "disabled. Without it, `contentops auto-disabled-rules` cannot "
        "surface platform-side disables. Enable per "
        "https://learn.microsoft.com/en-us/azure/sentinel/health-audit",
    )


def _check_graph_reachable() -> CheckResult:
    """Verify Microsoft Graph beta is reachable for Defender handlers.

    Uses ``DefenderClient`` (the production client for the Defender
    custom-detection handler) so the probe shares the exact auth +
    retry path the handler uses. Previously routed through a separate
    ``DefenderGraphProvider`` — deleted 2026-05-15 as part of P2-1
    cleanup (no other consumer).
    """
    try:
        from contentops.defender.client import DefenderClient
        from contentops.utils.auth import get_credential
    except Exception as exc:
        return CheckResult("graph_reachable", "WARN", f"import error: {exc}")
    try:
        client = DefenderClient(credential=get_credential())
    except Exception as exc:
        return CheckResult(
            "graph_reachable", "FAIL",
            f"could not construct Graph client: {exc}",
        )
    try:
        # Light probe — one page only with $top=1, no pagination
        # follow-up. ``_request_with_retry`` is intra-package private
        # but stable; same 429 + 5xx retry semantics as the previous
        # provider path.
        resp = client._request_with_retry(
            "GET", "/detectionRules", params={"$top": 1},
        )
    except Exception as exc:
        return CheckResult(
            "graph_reachable", "FAIL", f"GET detectionRules raised: {exc}",
        )
    finally:
        client.close()
    if resp.status_code == 200:
        return CheckResult(
            "graph_reachable", "PASS",
            "Graph beta /security/rules/detectionRules HTTP 200",
        )
    if resp.status_code == 403:
        return CheckResult(
            "graph_reachable", "WARN",
            "Graph beta /security/rules/detectionRules HTTP 403 — "
            "the Defender custom-detection handler will fail; check "
            "CustomDetection.ReadWrite.All app permission",
        )
    return CheckResult(
        "graph_reachable", "FAIL",
        f"Graph beta returned {resp.status_code}: {resp.text[:120]}",
    )


def _classify_handler_matrix_failure(
    check_name: str, exc_msg: str,
) -> CheckResult:
    """Classify a handler ``list_remote()`` exception into a CheckResult.

    Extracted so the rules can be unit-tested without standing up
    every handler against a live tenant.

    Rules:

    * **403 / Forbidden** → ``WARN``. Common for Defender Graph
      endpoints that require scope-specific admin consent (the auth
      principal can reach the API, just not this scope).
    * **400 on a Workspace Manager handler** (handler name starts
      with ``handler:sentinel_workspace_manager``) → ``WARN``.
      Workspace Manager is an opt-in Sentinel feature; tenants that
      have not provisioned a manager workspace get 400 from the
      ``workspaceManagerAssignments`` / ``…Configurations`` /
      ``…Groups`` / ``…Members`` collections. This is "feature
      unavailable," not "broken handler." Same semantics as the
      Defender 403 case above. Narrowed to 400 specifically so
      Workspace Manager 500s — real server-side breakage — still
      surface as FAIL.
    * Anything else → ``FAIL``.
    """
    short = exc_msg[:160]
    if "403" in short or "Forbidden" in short:
        return CheckResult(check_name, "WARN", f"403 (lacks RBAC) — {short}")
    if "401" in short or "Unauthorized" in short:
        # Same split rationale as workspace_reachable above (task #31).
        # 401 is a token/identity problem, not an RBAC problem; the
        # remediation differs and conflating them sent adopters down
        # the wrong path in an adopter session on 2026-05-18.
        return CheckResult(
            check_name, "FAIL",
            f"401 (token rejected — try "
            f"`$env:AZURE_TOKEN_CREDENTIALS = 'dev'` or check "
            f"`az account show` tenant context) — {short}",
        )
    if (
        check_name.startswith("handler:sentinel_workspace_manager")
        and "400" in short
    ):
        return CheckResult(
            check_name, "WARN",
            f"Workspace Manager endpoint unavailable or not configured "
            f"on this workspace (400) — {short}",
        )
    return CheckResult(check_name, "FAIL", short)


def _check_handler_matrix() -> list[CheckResult]:
    """Per-handler list_remote() smoke test.

    Each registered drift-capable handler is asked to list one page.
    PASS = listing returned 200 (count reported); see
    :func:`_classify_handler_matrix_failure` for the FAIL / WARN
    rules applied to exceptions.

    Multi-workspace tenants: Sentinel handlers iterate over every
    workspace in ``tenant.yml`` (one row per ``handler × workspace``).
    When ``PIPELINE_WORKSPACE_NAME`` is already set (operator passed
    ``--role`` / ``--workspace``), only that workspace is tested. The
    Defender handler is workspace-independent and runs exactly once.

    The handler caches its provider after first use
    (see ``sentinel_analytic.py:_provider_or_create``); we call
    ``handler.close()`` between workspace iterations so the next
    ``list_remote()`` re-resolves ``PIPELINE_WORKSPACE_NAME`` via
    ``handler_factories._active_workspace()``.
    """
    results: list[CheckResult] = []
    try:
        from contentops.cli.handler_factories import register_default_handlers
        from contentops.config import load_tenant_config
        from contentops.core.drift import DriftCapable
        from contentops.core.registry import default_registry
    except Exception as exc:
        return [CheckResult("handler_matrix", "FAIL", f"import error: {exc}")]

    try:
        cfg = load_tenant_config()
    except Exception as exc:
        return [CheckResult("handler_matrix", "FAIL", f"tenant.yml unreadable: {exc}")]

    workspaces = cfg.sentinelWorkspaces or []
    pinned = os.environ.get("PIPELINE_WORKSPACE_NAME")
    auto_pick_note: CheckResult | None = None
    if pinned:
        target_ws = [w for w in workspaces if w.workspaceName == pinned]
    elif len(workspaces) <= 1:
        target_ws = workspaces
    else:
        # Multi-workspace tenants used to iterate handler × workspace,
        # producing N × 6+ rows of mostly-identical output that drowned
        # out the real signals (auth failures, RBAC gaps). The matrix
        # is a reachability probe, not a per-workspace test plan —
        # pick the prod-role workspace (or the first listed if there
        # is no prod role) and emit a single info row so the operator
        # knows which one was tested. Use `--role` / `--workspace` to
        # target a specific one. See task #29 in the adopter-friction
        # notes.
        picked = next(
            (w for w in workspaces if getattr(w, "role", None) == "prod"),
            workspaces[0],
        )
        target_ws = [picked]
        # Note for the operator. Emitted as WARN (the doctor status
        # enum is PASS/WARN/FAIL; WARN is the closest "informational
        # but worth noticing" slot) — but the phrasing makes clear
        # this is intentional behaviour, not a failure.
        auto_pick_note = CheckResult(
            "handler_matrix_workspace", "WARN",
            f"multi-workspace tenant: testing against "
            f"{picked.workspaceName!r} "
            f"(role={getattr(picked, 'role', None)!r}); "
            f"pass `--workspace <name>` or `--role <role>` to target others",
        )

    register_default_handlers()
    saved_env = os.environ.get("PIPELINE_WORKSPACE_NAME")
    if auto_pick_note is not None:
        results.append(auto_pick_note)
    try:
        for asset in default_registry.assets():
            handler = default_registry.get(asset)
            if not isinstance(handler, DriftCapable):
                continue
            is_sentinel = asset.value.startswith("sentinel_")
            if is_sentinel:
                if not target_ws:
                    # No Sentinel workspaces to target (Defender-only tenant
                    # or pinned name didn't resolve) — skip rather than
                    # invoking the handler with an ambiguous active workspace.
                    continue
                for ws in target_ws:
                    os.environ["PIPELINE_WORKSPACE_NAME"] = ws.workspaceName
                    check_name = f"handler:{asset.value}"
                    try:
                        items = handler.list_remote()
                        results.append(CheckResult(
                            check_name, "PASS", f"{len(items)} item(s) listed",
                        ))
                    except Exception as exc:
                        results.append(
                            _classify_handler_matrix_failure(check_name, str(exc)),
                        )
                    # Drop the cached provider so the next iteration
                    # re-reads PIPELINE_WORKSPACE_NAME.
                    handler.close()
            else:
                check_name = f"handler:{asset.value}"
                try:
                    items = handler.list_remote()
                    results.append(CheckResult(
                        check_name, "PASS", f"{len(items)} item(s) listed",
                    ))
                except Exception as exc:
                    results.append(
                        _classify_handler_matrix_failure(check_name, str(exc)),
                    )
    finally:
        if saved_env is None:
            os.environ.pop("PIPELINE_WORKSPACE_NAME", None)
        else:
            os.environ["PIPELINE_WORKSPACE_NAME"] = saved_env
        default_registry.close_all()
    return results


# --- Aggregation & rendering ----------------------------------------------


def run_checks(
    *, with_auth: bool = False, with_matrix: bool = False,
) -> list[CheckResult]:
    """Run every check in display order. Pure: no exit calls.

    ``with_matrix=True`` adds the per-handler list_remote smoke (one
    row per registered drift-capable handler). Implies ``with_auth``.
    """
    results: list[CheckResult] = [
        _check_python_version(),
        _check_python_deps(),
        _check_dotenv(),
        _check_auth_env(),
        _check_tenant_yml(),
        _check_detections_dir(),
        _check_detections_parse(),
        _check_git(),
    ]
    if with_auth or with_matrix:
        results.append(_check_token_acquisition())
        results.append(_check_workspace_reachable())
        results.append(_check_sentinel_health())
        results.append(_check_graph_reachable())
    else:
        results.append(CheckResult(
            "token_acquisition", "WARN",
            "skipped — run with --auth or --matrix to test token acquisition",
        ))
    if with_matrix:
        results.extend(_check_handler_matrix())
    return results


def aggregate_exit_code(results: list[CheckResult]) -> int:
    return 1 if any(r.status == "FAIL" for r in results) else 0


_COLORS: dict[Status, str] = {
    "PASS": "green",
    "FAIL": "red",
    "WARN": "yellow",
}


def format_results(
    results: list[CheckResult],
    *,
    json_out: bool = False,
    color: bool | None = None,
) -> str:
    if json_out:
        payload = {
            "exit_code": aggregate_exit_code(results),
            "checks": [asdict(r) for r in results],
        }
        return json.dumps(payload, indent=2)

    use_color = color if color is not None else sys.stdout.isatty()
    lines: list[str] = ["contentops doctor"]
    lines.append("=" * 40)
    for r in results:
        tag = f"[{r.status}]"
        if use_color:
            tag = click.style(tag, fg=_COLORS[r.status], bold=True)
        line = f"  {tag} {r.name}"
        if r.detail:
            line += f"  — {r.detail}"
        lines.append(line)
    counts = {s: sum(1 for r in results if r.status == s) for s in ("PASS", "WARN", "FAIL")}
    lines.append("")
    lines.append(
        f"summary: {counts['PASS']} pass, {counts['WARN']} warn, {counts['FAIL']} fail"
    )
    return "\n".join(lines)


__all__ = [
    "CheckResult",
    "run_checks",
    "format_results",
    "aggregate_exit_code",
    "FixResult",
    "apply_safe_fixes",
]


# ---------------------------------------------------------------------------
# F17: safe autofixes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FixResult:
    """Outcome of one autofix attempt."""
    name: str          # canonical fixer id ('dotenv', 'detections_dir', ...)
    action: str        # human label ('copied .env.example -> .env')
    applied: bool      # True if a mutation actually happened
    detail: str = ""   # extra info for the operator


# Safe = mutation is local-disk only and never touches credentials or rule
# content. Anything risky (credentials, tenant config, YAML payloads) is
# explicitly EXCLUDED here.
_SAFE_FIXERS = ("dotenv", "detections_dir", "python_deps")


def _fix_dotenv(*, dry_run: bool) -> FixResult:
    """If `.env.example` exists and `.env` doesn't, copy it."""
    example = Path(".env.example")
    target = Path(".env")
    if target.is_file():
        return FixResult(
            "dotenv", "no-op (.env already exists)",
            applied=False,
        )
    if not example.is_file():
        return FixResult(
            "dotenv", "no fix (.env.example not present)",
            applied=False,
            detail="commit a .env.example to the repo so doctor --fix can scaffold it",
        )
    if dry_run:
        return FixResult(
            "dotenv", "would copy .env.example -> .env",
            applied=False,
        )
    target.write_bytes(example.read_bytes())
    return FixResult(
        "dotenv", "copied .env.example -> .env",
        applied=True,
        detail="open .env and fill in tenant + client credentials",
    )


def _fix_detections_dir(*, dry_run: bool) -> FixResult:
    """Create detections/ + the canonical per-kind subdirs if missing.

    Subdir names come from the ``Asset`` taxonomy (e.g.
    ``sentinel_analytic``, ``defender_custom_detection``) so a fresh
    checkout gets the *real* layout — not the historical
    ``sentinel``/``defender`` provider folders, which don't match where
    ``contentops new`` and discovery expect rules to live.
    """
    from contentops.core.asset import Asset

    base = Path("detections")
    subs = [a.value for a in Asset]
    if base.is_dir() and all((base / s).is_dir() for s in subs):
        return FixResult(
            "detections_dir", "no-op (already present)",
            applied=False,
        )
    if dry_run:
        return FixResult(
            "detections_dir",
            f"would mkdir detections/ + {len(subs)} kind subdirs",
            applied=False,
        )
    base.mkdir(parents=True, exist_ok=True)
    for s in subs:
        (base / s).mkdir(parents=True, exist_ok=True)
    return FixResult(
        "detections_dir", f"created detections/ + {len(subs)} kind subdirs",
        applied=True,
    )


def _fix_python_deps(*, dry_run: bool) -> FixResult:
    """Install the package + dev extras when imports are missing.

    Only runs from a source checkout (``pyproject.toml`` present) and
    mutates the active environment, so it's gated behind the explicit
    ``--fix`` opt-in like every other fixer. Honors ``--dry-run`` by
    printing the command without running pip.
    """
    import subprocess
    import sys

    if not Path("pyproject.toml").is_file():
        return FixResult(
            "python_deps", "no fix (pyproject.toml not found)",
            applied=False,
            detail="run from the repo root, or pip install the package manually",
        )
    cmd = [sys.executable, "-m", "pip", "install", "-e", ".[dev]"]
    if dry_run:
        return FixResult(
            "python_deps", f"would run: {' '.join(cmd)}",
            applied=False,
        )
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return FixResult(
            "python_deps", "pip install failed to launch",
            applied=False, detail=str(exc),
        )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return FixResult(
            "python_deps", "pip install -e .[dev] failed",
            applied=False,
            detail=tail[-1] if tail else f"exit {proc.returncode}",
        )
    return FixResult(
        "python_deps", "ran pip install -e .[dev]",
        applied=True,
        detail="re-run doctor to confirm imports resolve",
    )


_FIXERS = {
    "dotenv": _fix_dotenv,
    "detections_dir": _fix_detections_dir,
    "python_deps": _fix_python_deps,
}


def apply_safe_fixes(
    results: list[CheckResult], *, dry_run: bool = False,
) -> list[FixResult]:
    """Run autofixers for failed/warned checks in ``_SAFE_FIXERS``.

    Pure-function: walks ``results``, dispatches to the matching
    fixer when the check status is FAIL or WARN, returns the list of
    FixResult objects. The CLI prints + exits.
    """
    out: list[FixResult] = []
    by_name = {r.name: r for r in results}
    for name in _SAFE_FIXERS:
        check = by_name.get(name)
        if check is None or check.status == "PASS":
            continue
        fixer = _FIXERS[name]
        out.append(fixer(dry_run=dry_run))
    return out
