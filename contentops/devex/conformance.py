# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Deployment conformance checker for ContentOps.

Answers the question: "Is my ContentOps install + Azure deployment +
GitHub repo wired correctly, end-to-end, without writing anything?"

Seven layers, each a list of :class:`ConformanceCheck` rows with an
actionable remediation hint on FAIL:

* **L1 — Local install**          Python version, package import, lint
                                  + schema parse, audit chain integrity.
* **L2 — Tenant config**          ``config/tenant.yml`` parses and
                                  carries non-placeholder GUIDs.
* **L3 — OIDC / token**           ``DefaultAzureCredential`` acquires
                                  an ARM + Graph token against the
                                  configured tenant.
* **L4 — Graph permissions**      The App Registration's service
                                  principal has the expected
                                  ``appRoleAssignments`` and OIDC
                                  ``federatedIdentityCredentials``.
* **L5 — Azure RBAC**             For every configured Sentinel
                                  workspace: subscription / RG /
                                  workspace exist, Sentinel is
                                  onboarded.
* **L6 — Functional reach**       Live read-only probes:
                                  ``GET alertRules``, ``GET
                                  detectionRules``, ``POST /query``.
* **L7 — GitHub repo**            (optional, gated by ``GH_TOKEN`` or
                                  ``GITHUB_TOKEN``) required secret
                                  names exist, branch protection
                                  requires the expected checks.

All checks are read-only. No writes are issued against Azure, Graph,
or GitHub. Safe to run against a production tenant.

Configuration: every "expected value" (Graph permissions list, fed
cred subjects, GitHub secret names, etc.) defaults to the
ContentOps recommended posture. Adopters with a different posture
override via ``.contentops-conformance.yml`` at the repo root.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml

logger = logging.getLogger(__name__)


def _az_signed_in() -> bool:
    """Best-effort check that the operator has an active ``az login``.

    Mirrors the same helper in contentops/devex/doctor.py. Kept inline
    rather than imported to avoid coupling conformance to doctor's
    private API surface. Returns False when az is not on PATH, the
    invocation times out, or the command returns non-zero.
    """
    az = shutil.which("az")
    if az is None:
        return False
    try:
        result = subprocess.run(
            [az, "account", "show"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0

Status = Literal["PASS", "FAIL", "SKIP", "INFO"]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConformanceCheck:
    """One row in the conformance report."""

    layer: str          # e.g. "L3"
    name: str           # short identifier, e.g. "arm_token"
    status: Status
    detail: str = ""
    remediation: str = ""


@dataclass
class ConformanceReport:
    checks: list[ConformanceCheck] = field(default_factory=list)
    tenant_name: str = ""
    scope: tuple[str, ...] = ()
    identity_label: str = "write"  # which App Reg this run verified

    def add(self, check: ConformanceCheck) -> None:
        self.checks.append(check)

    @property
    def failed(self) -> list[ConformanceCheck]:
        return [c for c in self.checks if c.status == "FAIL"]

    @property
    def passed(self) -> bool:
        return not self.failed


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


_DEFAULT_GRAPH_APP_ROLES: tuple[str, ...] = (
    # Defender XDR custom detections.
    "CustomDetection.ReadWrite.All",
)

_DEFAULT_GITHUB_CREDENTIALS: tuple[str, ...] = (
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "TENANT_CONFIG_YAML",
)

_DEFAULT_GITHUB_REQUIRED_CHECKS: tuple[str, ...] = (
    "dco",
    "spdx-headers",
    "pytest",
    "cli-smoke",
    "bandit",
    "semgrep",
    "gitleaks",
    "actionlint",
)


@dataclass(frozen=True)
class ConformanceConfig:
    """Per-deployment expectations.

    Defaults match the ContentOps reference deployment. Override per
    fork via ``.contentops-conformance.yml`` at the repo root.
    """

    graph_app_roles: tuple[str, ...] = _DEFAULT_GRAPH_APP_ROLES
    # Graph app-roles that must be ABSENT (separation-of-duties). Empty for
    # the write/deploy identity; set to the write roles for the read
    # identity so conformance asserts least privilege, not just presence.
    forbidden_graph_app_roles: tuple[str, ...] = ()
    # Whether THIS identity is expected to hold Sentinel alert-rule write.
    # True for the deploy identity; False for the read/automation identity
    # (where holding write is an SoD violation, surfaced as L5 FAIL).
    expect_rbac_write: bool = True
    # "write" (deploy) or "read" (automation) — drives the report title +
    # the two profiles applied by ``apply_identity_profile``.
    identity_label: str = "write"
    federated_credential_subjects: tuple[str, ...] = ()
    # Required GitHub credential NAMES — checked as repo secrets OR variables
    # (some, e.g. AZURE_CLIENT_ID, migrated from secrets to vars).
    github_required_credentials: tuple[str, ...] = _DEFAULT_GITHUB_CREDENTIALS
    github_required_checks: tuple[str, ...] = _DEFAULT_GITHUB_REQUIRED_CHECKS
    github_repo: str = ""  # owner/name; if empty, GITHUB_REPOSITORY env var
    # Set when .contentops-conformance.yml existed but failed to parse;
    # surfaced as a non-blocking L1 ``config_parse`` row by run_conformance.
    parse_warning: str | None = None


def load_config(path: Path | None = None) -> ConformanceConfig:
    """Load ``.contentops-conformance.yml`` if present, else defaults."""
    target = path or Path.cwd() / ".contentops-conformance.yml"
    if not target.is_file():
        return ConformanceConfig(
            federated_credential_subjects=_default_fed_creds(),
        )
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        # A broken override file must NOT silently empty
        # ``federated_credential_subjects`` — that would make L4 SKIP the
        # federated-credential check instead of running it against the
        # defaults. Preserve the default subjects + warn loudly.
        logger.warning(
            "conformance config parse error (%s); falling back to defaults "
            "— FIX %s, L4 fed-cred check uses default subjects meanwhile",
            exc, target,
        )
        return ConformanceConfig(
            federated_credential_subjects=_default_fed_creds(),
            parse_warning=f"{type(exc).__name__}: {exc}",
        )
    # Back-compat: the field was renamed github_required_secrets ->
    # github_required_credentials (it validates secrets OR variables). Accept
    # either key from an existing override file.
    gh_creds = raw.get("github_required_credentials")
    if gh_creds is None:
        gh_creds = raw.get("github_required_secrets")
    return ConformanceConfig(
        graph_app_roles=tuple(raw.get("graph_app_roles") or _DEFAULT_GRAPH_APP_ROLES),
        federated_credential_subjects=tuple(
            raw.get("federated_credential_subjects") or _default_fed_creds(),
        ),
        github_required_credentials=tuple(
            gh_creds if gh_creds is not None else _DEFAULT_GITHUB_CREDENTIALS,
        ),
        github_required_checks=tuple(
            raw.get("github_required_checks") if raw.get("github_required_checks") is not None else _DEFAULT_GITHUB_REQUIRED_CHECKS,
        ),
        github_repo=raw.get("github_repo") or os.environ.get("GITHUB_REPOSITORY", ""),
    )


def _default_fed_creds() -> tuple[str, ...]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not repo:
        return ()
    return (
        f"repo:{repo}:ref:refs/heads/main",
        f"repo:{repo}:pull_request",
    )


def apply_identity_profile(config: ConformanceConfig, identity: str) -> ConformanceConfig:
    """Adjust a config's grant expectations for a read vs write identity.

    The single shared App Registration was split for separation of duties:
    a **write** (deploy) identity — Sentinel Contributor +
    ``CustomDetection.ReadWrite.All`` — and a **read** (automation)
    identity — Sentinel/Log-Analytics Reader + ``CustomDetection.Read.All``
    and explicitly NO write. Conformance verifies either by running AS that
    identity (its own OIDC token) with the matching expectation profile, so
    ``conformance.yml`` can check both App Regs in one workflow (one job
    per identity).

    - ``write`` — keep the loaded/default write expectations (preserves any
      ``.contentops-conformance.yml`` ``graph_app_roles`` override).
    - ``read`` — require ``CustomDetection.Read.All``, forbid
      ``CustomDetection.ReadWrite.All`` (least-privilege), and expect NO
      Sentinel write.
    """
    import dataclasses

    if identity == "read":
        return dataclasses.replace(
            config,
            graph_app_roles=("CustomDetection.Read.All",),
            forbidden_graph_app_roles=("CustomDetection.ReadWrite.All",),
            expect_rbac_write=False,
            identity_label="read",
        )
    if identity == "write":
        return dataclasses.replace(config, identity_label="write")
    raise ValueError(f"unknown identity profile: {identity!r} (expected 'read' or 'write')")


_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)
_PLACEHOLDER_GUID = "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# L1 — Local install
# ---------------------------------------------------------------------------


def check_l1_local_install(report: ConformanceReport) -> None:
    layer = "L1"

    # Python version
    v = sys.version_info
    if (v.major, v.minor) >= (3, 12):
        report.add(ConformanceCheck(
            layer, "python_version", "PASS",
            f"{v.major}.{v.minor}.{v.micro}",
        ))
    else:
        report.add(ConformanceCheck(
            layer, "python_version", "FAIL",
            f"need >= 3.12, found {v.major}.{v.minor}.{v.micro}",
            "Install Python 3.12+; see README.md.",
        ))

    # Package importability
    try:
        from contentops.cli import cli  # noqa: F401
        from contentops.core.registry import default_registry  # noqa: F401
        report.add(ConformanceCheck(
            layer, "package_import", "PASS",
            "contentops modules importable",
        ))
    except Exception as exc:
        report.add(ConformanceCheck(
            layer, "package_import", "FAIL",
            f"import failure: {exc}",
            "Run: pip install -e .  (from the repo root)",
        ))

    # Detection envelopes parse (best-effort — works without detections/)
    try:
        from contentops.core.asset import Asset
        from contentops.core.discovery import discover_assets, load_asset
        det_root = Path.cwd() / "detections"
        if not det_root.is_dir():
            report.add(ConformanceCheck(
                layer, "envelopes_parse", "SKIP",
                "no detections/ directory at cwd",
            ))
        else:
            total = 0
            errors = 0
            kinds_seen: set[Asset] = set()
            for p in discover_assets(det_root):
                total += 1
                try:
                    la = load_asset(p)
                    kinds_seen.add(la.envelope.asset)
                except Exception:
                    errors += 1
            if errors:
                report.add(ConformanceCheck(
                    layer, "envelopes_parse", "FAIL",
                    f"{errors}/{total} envelopes failed to parse",
                    "Run: contentops lint --strict   to surface details.",
                ))
            else:
                report.add(ConformanceCheck(
                    layer, "envelopes_parse", "PASS",
                    f"{total} envelopes parsed across {len(kinds_seen)} kinds",
                ))
    except Exception as exc:
        report.add(ConformanceCheck(
            layer, "envelopes_parse", "FAIL",
            f"unexpected: {exc}",
        ))

    # Audit chain integrity (skipped if no audit/)
    try:
        from contentops.audit import verify_chain
        audit_root = Path.cwd()
        if not (audit_root / "audit").is_dir():
            report.add(ConformanceCheck(
                layer, "audit_chain", "SKIP",
                "no audit/ directory at cwd",
            ))
        else:
            result = verify_chain(audit_root)
            if result.breaks:
                report.add(ConformanceCheck(
                    layer, "audit_chain", "FAIL",
                    f"{len(result.breaks)} break(s) across "
                    f"{result.files_checked} file(s)",
                    "Run: contentops audit verify   for break details.",
                ))
            else:
                report.add(ConformanceCheck(
                    layer, "audit_chain", "PASS",
                    f"{result.files_checked} file(s), "
                    f"{result.records_verified} records",
                ))
    except Exception as exc:
        report.add(ConformanceCheck(
            layer, "audit_chain", "FAIL",
            f"unexpected: {exc}",
        ))


# ---------------------------------------------------------------------------
# L2 — Tenant config
# ---------------------------------------------------------------------------


def check_l2_tenant_config(report: ConformanceReport) -> None:
    layer = "L2"
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
    except FileNotFoundError:
        report.add(ConformanceCheck(
            layer, "tenant_yml_present", "FAIL",
            "config/tenant.yml not found",
            "Copy config/tenant.yml.example to config/tenant.yml "
            "and fill in your tenant + workspace GUIDs.",
        ))
        return
    except Exception as exc:
        report.add(ConformanceCheck(
            layer, "tenant_yml_parse", "FAIL",
            f"{type(exc).__name__}: {exc}",
            "Check config/tenant.yml against config/tenant.yml.example.",
        ))
        return

    report.tenant_name = cfg.name
    report.add(ConformanceCheck(
        layer, "tenant_yml_parse", "PASS",
        f"tenant={cfg.name}, sentinel_workspaces={len(cfg.sentinelWorkspaces)}",
    ))

    # Tenant ID looks like a real GUID
    if not _GUID_RE.match(cfg.tenantId or ""):
        report.add(ConformanceCheck(
            layer, "tenant_id_shape", "FAIL",
            f"tenantId={cfg.tenantId!r} is not a GUID",
            "Set tenant.tenantId to the Entra ID tenant GUID.",
        ))
    elif cfg.tenantId == _PLACEHOLDER_GUID:
        report.add(ConformanceCheck(
            layer, "tenant_id_shape", "FAIL",
            "tenantId is the all-zero placeholder",
            "Replace tenant.tenantId with the real Entra ID tenant GUID.",
        ))
    else:
        report.add(ConformanceCheck(
            layer, "tenant_id_shape", "PASS",
            f"tenantId={cfg.tenantId[:8]}…",
        ))

    # Each workspace's subscription is a real GUID
    bad_subs = [
        w for w in cfg.sentinelWorkspaces
        if (not _GUID_RE.match(w.subscriptionId or ""))
        or w.subscriptionId == _PLACEHOLDER_GUID
    ]
    if bad_subs:
        names = ", ".join(w.workspaceName for w in bad_subs)
        report.add(ConformanceCheck(
            layer, "workspace_sub_ids", "FAIL",
            f"placeholder / non-GUID subscriptionId on: {names}",
            "Set tenant.sentinelWorkspaces[].subscriptionId to real GUIDs.",
        ))
    elif cfg.sentinelWorkspaces:
        report.add(ConformanceCheck(
            layer, "workspace_sub_ids", "PASS",
            f"{len(cfg.sentinelWorkspaces)} workspace(s) carry real GUIDs",
        ))
    else:
        report.add(ConformanceCheck(
            layer, "workspace_sub_ids", "INFO",
            "no Sentinel workspaces configured (Defender-only tenant)",
        ))

    # Auth env present. Two valid paths to a working local install
    # (see docs/operations/authentication-setup.md):
    #
    #   Path A: az login as user — DefaultAzureCredential picks up
    #           AzureCliCredential. No env vars required. Adopter on
    #           a security-restricted laptop should be on this path.
    #   Path B: AZURE_TENANT_ID + AZURE_CLIENT_ID env vars (often
    #           paired with AZURE_CLIENT_SECRET) — mirrors CI.
    #
    # Previously this check only knew Path B and flagged Path A users
    # with a misleading FAIL "set env vars". Closes task #34 in the
    # adopter-friction notes.
    missing_env = [
        k for k in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID")
        if not os.environ.get(k)
    ]
    if not missing_env:
        report.add(ConformanceCheck(
            layer, "auth_env", "PASS",
            "AZURE_CLIENT_ID + AZURE_TENANT_ID set (Path B)",
        ))
    elif _az_signed_in():
        report.add(ConformanceCheck(
            layer, "auth_env", "INFO",
            "AZURE_CLIENT_ID/AZURE_TENANT_ID not set but `az login` is "
            "active (Path A); DefaultAzureCredential will use the "
            "AzureCliCredential. No remediation needed for local dev.",
        ))
    else:
        report.add(ConformanceCheck(
            layer, "auth_env", "FAIL",
            f"missing env vars: {', '.join(missing_env)} and no "
            f"active `az login`",
            "Either run `az login` (Path A) or set AZURE_CLIENT_ID + "
            "AZURE_TENANT_ID in your shell (Path B) / CI Variables.",
        ))


# ---------------------------------------------------------------------------
# L3 — OIDC / token acquisition
# ---------------------------------------------------------------------------


def _try_acquire_tokens() -> tuple[Any | None, str | None, str | None]:
    """Return (credential, arm_token_str, graph_token_str) or (None, None, err)."""
    try:
        from contentops.utils.auth import (
            get_arm_access_token,
            get_credential,
            get_graph_access_token,
        )
        cred = get_credential()
        arm = get_arm_access_token(cred)
        graph = get_graph_access_token(cred)
        return (cred, arm.token, graph.token)
    except Exception as exc:
        return (None, None, f"{type(exc).__name__}: {exc}")


# Targeted remediation hints for the AAD error codes operators hit
# most often. Searched as substrings against the failure message —
# whichever code matches first wins. Fallback is the generic hint.
_AAD_HINTS: tuple[tuple[str, str], ...] = (
    (
        "AADSTS7000215",
        "AZURE_CLIENT_SECRET is set to the secret ID (a GUID), not "
        "the secret VALUE. The value is the long opaque string shown "
        "only ONCE at creation time in Entra portal -> App registration "
        "-> Certificates & secrets -> 'Value' column. If you lost it, "
        "generate a new secret and copy the Value column immediately.",
    ),
    (
        "AADSTS700016",
        "AZURE_CLIENT_ID does not match any App Registration in the "
        "tenant. Verify the appId against the App Registration's "
        "'Application (client) ID' in the Entra portal Overview tab.",
    ),
    (
        "AADSTS90002",
        "AZURE_TENANT_ID does not resolve to a tenant. Verify the GUID "
        "matches the 'Tenant ID' in the Entra portal Overview tab.",
    ),
    (
        "AADSTS7000222",
        "The client secret has expired. Generate a fresh one in Entra "
        "portal -> App registration -> Certificates & secrets and "
        "update AZURE_CLIENT_SECRET.",
    ),
    (
        "AADSTS700024",
        "The client assertion (federated credential JWT) is malformed "
        "or expired. In CI, confirm the workflow has 'permissions: "
        "id-token: write' AND the federated credential's subject "
        "matches the current git context (branch / PR / environment).",
    ),
    (
        "AADSTS700213",
        "No federated identity credential on the App Registration "
        "matches the current OIDC subject. Add one whose subject "
        "matches your repo's git context (e.g. "
        "'repo:OWNER/REPO:ref:refs/heads/main').",
    ),
    (
        "AADSTS50034",
        "The signed-in user/principal does not exist in the tenant. "
        "Confirm AZURE_TENANT_ID matches the tenant the App "
        "Registration lives in.",
    ),
    (
        "AADSTS70011",
        "The requested scope was rejected. Confirm the App "
        "Registration has the required API permissions granted AND "
        "admin-consented for the tenant.",
    ),
)


_GENERIC_HINT = (
    "Recommended (CI): configure OIDC federated credentials on the App "
    "Registration — no secret stored anywhere. Local dev: run 'az login'. "
    "Client secret (AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET "
    "in .env) is for LOCAL DEV ONLY — do not set it in CI; OIDC supersedes it."
)


def _remediation_for(err_message: str) -> str:
    """Pick a targeted remediation hint by AAD error code, else generic."""
    if not err_message:
        return _GENERIC_HINT
    for code, hint in _AAD_HINTS:
        if code in err_message:
            return f"{code}: {hint}"
    return _GENERIC_HINT


def check_l3_token(report: ConformanceReport) -> tuple[str | None, str | None]:
    """Returns (arm_token, graph_token) for downstream layers, or (None, None)."""
    layer = "L3"
    cred, _arm, err_or_graph = _try_acquire_tokens()
    if cred is None:
        # Strip the multi-line credential-chain dump down to the first
        # informative line so the table stays scannable; the full
        # diagnostic still surfaces via the targeted hint when an
        # AADSTS code matches.
        first_line = (err_or_graph or "").splitlines()[0][:200]
        report.add(ConformanceCheck(
            layer, "token_acquisition", "FAIL",
            f"DefaultAzureCredential failed: {first_line}",
            _remediation_for(err_or_graph or ""),
        ))
        return (None, None)

    # Re-acquire here so we capture both clean for L4-L6
    from contentops.utils.auth import (
        get_arm_access_token, get_graph_access_token,
    )
    try:
        arm = get_arm_access_token(cred)
        report.add(ConformanceCheck(
            layer, "arm_token", "PASS",
            "acquired",
        ))
    except Exception as exc:
        report.add(ConformanceCheck(
            layer, "arm_token", "FAIL",
            f"{type(exc).__name__}: {exc}",
            "Confirm the SP has 'user_impersonation' on Azure Service Management.",
        ))
        arm = None
    try:
        graph = get_graph_access_token(cred)
        report.add(ConformanceCheck(
            layer, "graph_token", "PASS",
            "acquired",
        ))
    except Exception as exc:
        report.add(ConformanceCheck(
            layer, "graph_token", "FAIL",
            f"{type(exc).__name__}: {exc}",
            "Confirm the SP has 'User.Read' (minimum) on Microsoft Graph.",
        ))
        graph = None

    return (
        arm.token if arm else None,
        graph.token if graph else None,
    )


# Microsoft Graph well-known appRole GUIDs. Maps permission VALUE
# (the canonical name like "CustomDetection.ReadWrite.All") to the
# stable GUID that appears as ``appRoleId`` in
# ``servicePrincipals/{id}/appRoleAssignments`` responses.
#
# Hardcoded because the alternative — fetching Microsoft Graph's own
# service principal to enumerate ``appRoles`` — requires the executing
# identity to hold ``Application.Read.All``. A typical ContentOps SP
# only has ``CustomDetection.ReadWrite.All``, so the dynamic lookup
# 403s and silently drops every assignment from the conformance
# report. Hardcoding lets L4 work with the minimum permission set
# the pipeline actually needs at runtime.
#
# IDs are the APPLICATION-permission appRoleIds (the value that appears
# as ``appRoleId`` in appRoleAssignments — NOT the delegated id).
#
# The two CustomDetection ids were verified 2026-05-28 against the
# Microsoft Graph permissions reference
# (https://learn.microsoft.com/graph/permissions-reference#all-permissions):
#   CustomDetection.ReadWrite.All  app id = e0fd9c8d-…  (confirmed)
#   CustomDetection.Read.All       app id = 673a007a-…  (CORRECTED — the
#       previous value ae39c068-… was wrong; it is not this permission)
# The adjunct read-only ids are the standard well-known Graph app roles.
# To re-verify against a tenant:
#   GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoles
_MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
_WELL_KNOWN_GRAPH_APP_ROLES: dict[str, str] = {
    # Defender XDR custom detections.
    "CustomDetection.ReadWrite.All": "e0fd9c8d-a12e-4cc9-9827-20c8c3cd6fb8",
    "CustomDetection.Read.All": "673a007a-9e0f-4c97-b066-3c0164486909",
    # Useful adjuncts for richer conformance checks.
    "Application.Read.All": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
    "AuditLog.Read.All": "b0afded3-3588-46d8-8b3d-9842eff778da",
    "SecurityAlert.Read.All": "472e4a4d-bb4a-4026-98d1-0330a5b8a5da",
    "SecurityEvents.Read.All": "bf394140-e372-4bf9-a898-299cfc7cc280",
}


# ---------------------------------------------------------------------------
# Permission-introspection helpers (shared by L4 / L5)
# ---------------------------------------------------------------------------


def _decode_jwt_claims(token: str) -> dict:
    """Decode — WITHOUT verifying — the payload of a JWT access token.

    We only ever read our OWN token's claims for an informational preflight;
    the token came from a trusted issuer (Entra ID) and is never used to make
    a trust decision here, so signature verification is unnecessary. Returns
    ``{}`` on any malformed input. Never log the token or the returned claims.
    """
    import base64
    import binascii
    import json

    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore base64 padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, binascii.Error):
        return {}
    return claims if isinstance(claims, dict) else {}


def _action_granted(target: str, actions: list, not_actions: list) -> bool:
    """True when an ARM ``target`` action is covered by ``actions`` and not
    excluded by ``not_actions``, honouring Azure wildcards (e.g. ``*`` or
    ``Microsoft.SecurityInsights/*``)."""
    import fnmatch

    tgt = target.lower()
    covered = any(fnmatch.fnmatchcase(tgt, str(a).lower()) for a in (actions or []))
    if not covered:
        return False
    return not any(
        fnmatch.fnmatchcase(tgt, str(na).lower()) for na in (not_actions or [])
    )


def _check_forbidden_graph_roles(
    report: ConformanceReport,
    layer: str,
    granted: set,
    config: ConformanceConfig,
    client_id: str,
) -> None:
    """Add an L4 least-privilege row when the config forbids any Graph role.

    A read/automation identity must NOT hold write-grade Graph roles
    (e.g. ``CustomDetection.ReadWrite.All``). No-op for the write profile
    (``forbidden_graph_app_roles`` empty), so write behaviour is unchanged.
    """
    if not config.forbidden_graph_app_roles:
        return
    forbidden_present = [r for r in config.forbidden_graph_app_roles if r in granted]
    if forbidden_present:
        report.add(ConformanceCheck(
            layer, "least_privilege", "FAIL",
            f"identity unexpectedly holds write-grade Graph role(s): "
            f"{', '.join(forbidden_present)} — a read/automation identity must not",
            f"Remove the application permission(s) {', '.join(forbidden_present)} "
            f"from appId={client_id} on Microsoft Graph (separation of duties).",
        ))
    else:
        report.add(ConformanceCheck(
            layer, "least_privilege", "PASS",
            f"holds none of the forbidden write-grade Graph role(s) "
            f"({', '.join(config.forbidden_graph_app_roles)}) — least privilege OK",
        ))


# ---------------------------------------------------------------------------
# L4 — Graph permissions
# ---------------------------------------------------------------------------


def check_l4_graph_permissions(
    report: ConformanceReport,
    graph_token: str | None,
    config: ConformanceConfig,
) -> None:
    layer = "L4"
    if not graph_token:
        report.add(ConformanceCheck(
            layer, "graph_perms", "SKIP",
            "skipped — no Graph token (see L3)",
        ))
        return

    client_id = os.environ.get("AZURE_CLIENT_ID")
    if not client_id:
        report.add(ConformanceCheck(
            layer, "graph_perms", "SKIP",
            "AZURE_CLIENT_ID unset — cannot resolve the SP",
        ))
        return

    # Fast path: an app-only (client-credentials) Graph token carries a
    # ``roles`` claim = the application permissions granted to THIS SP on
    # Microsoft Graph. That's the effective grant the deploy will use, so we
    # verify write capability straight from the token — no API call, no
    # Application.Read.All, no pagination. Delegated / ``az login`` user tokens
    # carry ``scp`` instead (no ``roles``); those fall through to the
    # appRoleAssignments API below.
    token_roles = _decode_jwt_claims(graph_token).get("roles") or []
    if token_roles:
        granted = set(token_roles)
        missing = [r for r in config.graph_app_roles if r not in granted]
        if missing:
            report.add(ConformanceCheck(
                layer, "app_role_assignments", "FAIL",
                f"missing on Microsoft Graph (access-token 'roles' claim): "
                f"{', '.join(missing)}",
                f"Grant + admin-consent the missing application permission(s) "
                f"to appId={client_id} on Microsoft Graph.",
            ))
        else:
            report.add(ConformanceCheck(
                layer, "app_role_assignments", "PASS",
                f"all {len(config.graph_app_roles)} required Graph role(s) present "
                f"in the access-token 'roles' claim ({len(granted)} role(s) total)",
            ))
        _check_forbidden_graph_roles(report, layer, granted, config, client_id)
        return

    headers = {
        "Authorization": f"Bearer {graph_token}",
        "Accept": "application/json",
    }
    # ``with`` guarantees the client closes on every exit path — including
    # the 404/403/non-200 early returns below — without relying on a
    # trailing ``finally`` that a future early return could outrun.
    with httpx.Client(
        base_url="https://graph.microsoft.com/v1.0",
        headers=headers,
        timeout=httpx.Timeout(connect=10.0, read=15.0, write=15.0, pool=10.0),
    ) as client:
        # Resolve the SP object id from the appId (client_id).
        sp_resp = client.get(f"/servicePrincipals(appId='{client_id}')")
        if sp_resp.status_code == 404:
            report.add(ConformanceCheck(
                layer, "service_principal", "FAIL",
                f"no service principal with appId={client_id}",
                "Confirm the App Registration exists and the appId matches.",
            ))
            return
        if sp_resp.status_code == 403:
            report.add(ConformanceCheck(
                layer, "service_principal", "SKIP",
                "403 reading /servicePrincipals — caller lacks Application.Read.All",
                "Grant the executing identity Application.Read.All "
                "on Microsoft Graph (or run as the tenant admin) for "
                "L4 to function. Other layers continue regardless.",
            ))
            return
        if sp_resp.status_code != 200:
            report.add(ConformanceCheck(
                layer, "service_principal", "FAIL",
                f"GET /servicePrincipals returned {sp_resp.status_code}",
            ))
            return
        sp = sp_resp.json()
        sp_id = sp.get("id", "")
        report.add(ConformanceCheck(
            layer, "service_principal", "PASS",
            f"objectId={sp_id[:8]}…  displayName={sp.get('displayName','?')}",
        ))

        # appRoleAssignments — application permissions granted to this SP.
        ar_resp = client.get(f"/servicePrincipals/{sp_id}/appRoleAssignments")
        if ar_resp.status_code != 200:
            report.add(ConformanceCheck(
                layer, "app_role_assignments", "FAIL",
                f"GET /appRoleAssignments returned {ar_resp.status_code}",
            ))
        else:
            ar_body = ar_resp.json()
            assignments = list(ar_body.get("value") or [])
            # Follow @odata.nextLink so an SP with >100 assignments is not
            # silently truncated at the default page size.
            next_link = ar_body.get("@odata.nextLink")
            _pages = 0
            while next_link and _pages < 50:
                nr = client.get(next_link)
                if nr.status_code != 200:
                    break
                nb = nr.json()
                assignments.extend(nb.get("value") or [])
                next_link = nb.get("@odata.nextLink")
                _pages += 1
            # Resolve each assignment to a (resource_displayName, role_name)
            # pair using two independent sources:
            #
            #  1. The assignment itself carries ``resourceDisplayName``
            #     — no API call needed.
            #  2. Role name is resolved via the well-known GUID table
            #     for the expected permissions, with the dynamic
            #     ``GET /servicePrincipals/{resourceId}`` lookup as a
            #     fallback (cached per session).
            #
            # The earlier implementation required Application.Read.All
            # on the executing identity, because resolving the role
            # name always went through the dynamic lookup. Typical
            # ContentOps service principals don't have that perm, the
            # lookup 403'd, the role name came back empty, and the
            # whole assignment got silently dropped from the report.
            resource_sp_cache: dict[str, dict] = {}
            # Map resource_displayName -> set of granted role value names.
            granted_by_resource: dict[str, set[str]] = {}

            # Reverse the well-known table so we can look up GUID -> name.
            well_known_guid_to_name: dict[str, str] = {
                guid: name for name, guid in _WELL_KNOWN_GRAPH_APP_ROLES.items()
            }

            for a in assignments:
                role_guid = a.get("appRoleId", "") or ""
                res_id = a.get("resourceId", "")
                # ``resourceDisplayName`` is part of the assignment, so
                # we get the resource name even when the SP can't read
                # the resource SP itself.
                res_name = a.get("resourceDisplayName") or (
                    f"<resourceId={res_id[:8]}…>" if res_id else "<unknown>"
                )

                role_name: str = ""

                # Step 1: well-known table (covers expected defaults).
                if res_name == "Microsoft Graph" and role_guid in well_known_guid_to_name:
                    role_name = well_known_guid_to_name[role_guid]

                # Step 2: dynamic resource-SP lookup, cached. Best-effort:
                # if it 403s, we still recorded the assignment via step 1
                # (or fall through to the raw GUID).
                if not role_name and res_id:
                    if res_id not in resource_sp_cache:
                        rr = client.get(f"/servicePrincipals/{res_id}")
                        if rr.status_code == 200:
                            resource_sp_cache[res_id] = rr.json()
                        else:
                            resource_sp_cache[res_id] = {}
                    res_sp = resource_sp_cache[res_id]
                    role_map = {
                        r.get("id"): r.get("value", "")
                        for r in (res_sp.get("appRoles") or [])
                    }
                    role_name = role_map.get(role_guid, "")

                # Step 3: nothing resolved — surface the GUID so the
                # operator at least sees an assignment exists.
                if not role_name:
                    role_name = f"<unknown role: {role_guid}>"

                granted_by_resource.setdefault(res_name, set()).add(role_name)

            ms_graph_grants = granted_by_resource.get("Microsoft Graph", set())
            missing = [r for r in config.graph_app_roles if r not in ms_graph_grants]

            if not missing:
                report.add(ConformanceCheck(
                    layer, "app_role_assignments", "PASS",
                    f"all {len(config.graph_app_roles)} required Graph "
                    f"role(s) granted ({len(assignments)} total assignment(s) "
                    f"across {len(granted_by_resource)} resource(s))",
                ))
            else:
                # Helpful hint: did the operator grant the same-named
                # permission on a DIFFERENT API by mistake?
                misplaced: list[str] = []
                for needed in missing:
                    for res_name, role_names in granted_by_resource.items():
                        if res_name == "Microsoft Graph":
                            continue
                        if needed in role_names:
                            misplaced.append(f"{needed} found on {res_name}")
                            break
                hint_parts = [
                    f"Grant the missing application permission(s) to "
                    f"appId={client_id} on Microsoft Graph AND admin-consent.",
                ]
                if misplaced:
                    hint_parts.append(
                        "Likely cause: same-named permission was granted on "
                        "a different API: " + "; ".join(misplaced)
                        + ". Remove the wrong-API grant and re-add it under "
                        "Microsoft Graph in the API permissions blade.",
                    )
                # Also surface what IS granted (caps to keep the line legible).
                summary_bits = []
                for res_name, role_names in sorted(granted_by_resource.items()):
                    sample = sorted(role_names)[:3]
                    more = "" if len(role_names) <= 3 else f" (+{len(role_names)-3} more)"
                    summary_bits.append(f"{res_name}: {', '.join(sample)}{more}")
                granted_summary = " | ".join(summary_bits) or "(none)"
                report.add(ConformanceCheck(
                    layer, "app_role_assignments", "FAIL",
                    f"missing on Microsoft Graph: {', '.join(missing)} "
                    f"— granted elsewhere: {granted_summary}",
                    " ".join(hint_parts),
                ))

            _check_forbidden_graph_roles(
                report, layer, ms_graph_grants, config, client_id,
            )

        # Federated identity credentials on the Application (NOT the SP).
        if config.federated_credential_subjects:
            app_resp = client.get(f"/applications(appId='{client_id}')")
            if app_resp.status_code != 200:
                report.add(ConformanceCheck(
                    layer, "federated_credentials", "SKIP",
                    f"GET /applications returned {app_resp.status_code}",
                ))
            else:
                app_id = app_resp.json().get("id", "")
                fc_resp = client.get(
                    f"/applications/{app_id}/federatedIdentityCredentials",
                )
                if fc_resp.status_code != 200:
                    report.add(ConformanceCheck(
                        layer, "federated_credentials", "FAIL",
                        f"GET federatedIdentityCredentials returned "
                        f"{fc_resp.status_code}",
                    ))
                else:
                    configured_subjects = {
                        f.get("subject", "")
                        for f in fc_resp.json().get("value") or []
                    }
                    missing = [
                        s for s in config.federated_credential_subjects
                        if s not in configured_subjects
                    ]
                    if missing:
                        report.add(ConformanceCheck(
                            layer, "federated_credentials", "FAIL",
                            f"missing subjects: {', '.join(missing)}",
                            "Add a federated credential to the App "
                            "Registration with one of the missing subjects.",
                        ))
                    else:
                        report.add(ConformanceCheck(
                            layer, "federated_credentials", "PASS",
                            f"all required subjects configured "
                            f"({len(config.federated_credential_subjects)})",
                        ))
        else:
            report.add(ConformanceCheck(
                layer, "federated_credentials", "SKIP",
                "no expected subjects configured (set GITHUB_REPOSITORY "
                "or .contentops-conformance.yml to enable)",
            ))


# ---------------------------------------------------------------------------
# L5 — Azure RBAC + workspace reachability
# ---------------------------------------------------------------------------


def check_l5_azure_rbac(
    report: ConformanceReport,
    arm_token: str | None,
    config: ConformanceConfig,
) -> None:
    layer = "L5"
    if not arm_token:
        report.add(ConformanceCheck(
            layer, "azure_rbac", "SKIP",
            "skipped — no ARM token (see L3)",
        ))
        return

    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
    except Exception as exc:
        report.add(ConformanceCheck(
            layer, "azure_rbac", "SKIP",
            f"tenant config unloadable: {exc}",
        ))
        return

    if not cfg.sentinelWorkspaces:
        report.add(ConformanceCheck(
            layer, "azure_rbac", "INFO",
            "no Sentinel workspaces configured (Defender-only)",
        ))
        return

    # Write capability is read straight from the ARM token's EFFECTIVE
    # permissions at each workspace scope (the token IS the deploy identity),
    # so no Graph service-principal lookup is needed. Azure RBAC is not encoded
    # in the access token, hence the Authorization/permissions probe below.
    write_action = "Microsoft.SecurityInsights/alertRules/write"
    headers = {"Authorization": f"Bearer {arm_token}"}
    with httpx.Client(
        base_url="https://management.azure.com",
        headers=headers,
        timeout=httpx.Timeout(connect=10.0, read=15.0, write=15.0, pool=10.0),
    ) as client:
        for w in cfg.sentinelWorkspaces:
            tag = f"{w.role}:{w.workspaceName}"
            ws_url = (
                f"/subscriptions/{w.subscriptionId}"
                f"/resourceGroups/{w.resourceGroup}"
                f"/providers/Microsoft.OperationalInsights"
                f"/workspaces/{w.workspaceName}"
                f"?api-version=2022-10-01"
            )
            try:
                r = client.get(ws_url)
            except Exception as exc:
                report.add(ConformanceCheck(
                    layer, f"workspace[{tag}]", "FAIL",
                    f"network: {exc}",
                ))
                continue
            if r.status_code == 200:
                report.add(ConformanceCheck(
                    layer, f"workspace[{tag}]", "PASS",
                    "exists + reachable",
                ))
            elif r.status_code == 403:
                report.add(ConformanceCheck(
                    layer, f"workspace[{tag}]", "FAIL",
                    "403 — caller lacks Reader on the workspace",
                    "Grant the SP at least 'Microsoft Sentinel Reader' "
                    f"on subscription={w.subscriptionId[:8]}… RG={w.resourceGroup}.",
                ))
            elif r.status_code == 404:
                report.add(ConformanceCheck(
                    layer, f"workspace[{tag}]", "FAIL",
                    "404 — sub/RG/workspace combination doesn't exist",
                    "Verify subscriptionId, resourceGroup, workspaceName "
                    "in config/tenant.yml.",
                ))
            else:
                report.add(ConformanceCheck(
                    layer, f"workspace[{tag}]", "FAIL",
                    f"status={r.status_code}",
                ))
                continue

            # Sentinel onboarded?
            onb_url = (
                f"/subscriptions/{w.subscriptionId}"
                f"/resourceGroups/{w.resourceGroup}"
                f"/providers/Microsoft.OperationalInsights"
                f"/workspaces/{w.workspaceName}"
                f"/providers/Microsoft.SecurityInsights"
                f"/onboardingStates/default?api-version=2024-09-01"
            )
            try:
                r2 = client.get(onb_url)
            except Exception:
                continue
            if r2.status_code == 200:
                report.add(ConformanceCheck(
                    layer, f"sentinel_onboarded[{tag}]", "PASS",
                    "Microsoft Sentinel is onboarded",
                ))
            else:
                report.add(ConformanceCheck(
                    layer, f"sentinel_onboarded[{tag}]", "FAIL",
                    f"onboarding probe returned {r2.status_code}",
                    "Run 'contentops bootstrap' or onboard Sentinel via portal.",
                ))

            # Can the deploy identity actually WRITE here? Read the caller's
            # EFFECTIVE permissions at the workspace scope and assert the
            # Sentinel alert-rule write action is granted (honouring role
            # wildcards). The ARM token IS the deploy identity, so this is the
            # permission the next deploy will use — and it catches custom
            # roles a fixed role-ID allowlist would miss. Only run when the
            # workspace itself resolved (200).
            if r.status_code == 200:
                perm_url = (
                    f"/subscriptions/{w.subscriptionId}"
                    f"/resourceGroups/{w.resourceGroup}"
                    f"/providers/Microsoft.OperationalInsights"
                    f"/workspaces/{w.workspaceName}"
                    f"/providers/Microsoft.Authorization/permissions"
                    f"?api-version=2022-04-01"
                )
                try:
                    rp = client.get(perm_url)
                except Exception as exc:  # noqa: BLE001
                    report.add(ConformanceCheck(
                        layer, f"rbac_write[{tag}]", "FAIL",
                        f"permissions query failed: {exc}",
                    ))
                    continue
                if rp.status_code != 200:
                    report.add(ConformanceCheck(
                        layer, f"rbac_write[{tag}]", "FAIL",
                        f"permissions query returned {rp.status_code}",
                        "Grant the SP at least Reader on the scope so "
                        "Microsoft.Authorization/permissions/read succeeds.",
                    ))
                    continue
                perms = rp.json().get("value") or []
                can_write = any(
                    _action_granted(
                        write_action,
                        p.get("actions") or [],
                        p.get("notActions") or [],
                    )
                    for p in perms
                )
                if config.expect_rbac_write:
                    if can_write:
                        report.add(ConformanceCheck(
                            layer, f"rbac_write[{tag}]", "PASS",
                            f"effective permissions include {write_action}",
                        ))
                    else:
                        report.add(ConformanceCheck(
                            layer, f"rbac_write[{tag}]", "FAIL",
                            f"effective permissions do NOT include {write_action}",
                            "Grant 'Microsoft Sentinel Contributor' to the App "
                            f"Registration on RG={w.resourceGroup} (recommended) "
                            "or the workspace scope.",
                        ))
                else:
                    # Read/automation identity: holding write is the SoD
                    # violation, so ABSENCE of write is the PASS condition.
                    if can_write:
                        report.add(ConformanceCheck(
                            layer, f"rbac_write[{tag}]", "FAIL",
                            f"identity unexpectedly HAS {write_action} — a "
                            "read/automation identity must not (separation of duties)",
                            "Remove 'Microsoft Sentinel Contributor' from this App "
                            f"Registration at RG={w.resourceGroup} / workspace scope.",
                        ))
                    else:
                        report.add(ConformanceCheck(
                            layer, f"rbac_write[{tag}]", "PASS",
                            f"correctly lacks {write_action} "
                            "(read identity — least privilege)",
                        ))


# ---------------------------------------------------------------------------
# L6 — Functional reach
# ---------------------------------------------------------------------------


def check_l6_functional_reach(
    report: ConformanceReport,
    arm_token: str | None,
    graph_token: str | None,
) -> None:
    layer = "L6"
    if not arm_token and not graph_token:
        report.add(ConformanceCheck(
            layer, "functional_reach", "SKIP",
            "skipped — no tokens (see L3)",
        ))
        return

    # ARM — list alertRules on each configured workspace.
    if arm_token:
        try:
            from contentops.config import load_tenant_config
            cfg = load_tenant_config()
        except Exception:
            cfg = None
        if cfg and cfg.sentinelWorkspaces:
            arm_client = httpx.Client(
                base_url="https://management.azure.com",
                headers={"Authorization": f"Bearer {arm_token}"},
                timeout=httpx.Timeout(connect=10.0, read=15.0, write=15.0, pool=10.0),
            )
            try:
                for w in cfg.sentinelWorkspaces:
                    tag = f"{w.role}:{w.workspaceName}"
                    url = (
                        f"/subscriptions/{w.subscriptionId}"
                        f"/resourceGroups/{w.resourceGroup}"
                        f"/providers/Microsoft.OperationalInsights"
                        f"/workspaces/{w.workspaceName}"
                        f"/providers/Microsoft.SecurityInsights"
                        f"/alertRules?api-version=2025-07-01-preview"
                    )
                    try:
                        r = arm_client.get(url)
                    except Exception as exc:
                        report.add(ConformanceCheck(
                            layer, f"list_alertRules[{tag}]", "FAIL",
                            f"network: {exc}",
                        ))
                        continue
                    if r.status_code == 200:
                        n = len(r.json().get("value") or [])
                        report.add(ConformanceCheck(
                            layer, f"list_alertRules[{tag}]", "PASS",
                            f"200, {n} rule(s)",
                        ))
                    else:
                        report.add(ConformanceCheck(
                            layer, f"list_alertRules[{tag}]", "FAIL",
                            f"status={r.status_code}",
                            "Grant the SP 'Microsoft Sentinel Reader' "
                            "(or higher) on the workspace.",
                        ))
            finally:
                arm_client.close()

    # Graph — list Defender detectionRules.
    if graph_token:
        graph_client = httpx.Client(
            base_url="https://graph.microsoft.com/beta/security/rules",
            headers={"Authorization": f"Bearer {graph_token}"},
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=15.0, pool=10.0),
        )
        try:
            r = graph_client.get("/detectionRules")
            if r.status_code == 200:
                n = len(r.json().get("value") or [])
                report.add(ConformanceCheck(
                    layer, "list_detectionRules", "PASS",
                    f"200, {n} rule(s)",
                ))
            elif r.status_code == 403:
                report.add(ConformanceCheck(
                    layer, "list_detectionRules", "FAIL",
                    "403 — SP lacks Graph CustomDetection.Read.All",
                    "Grant CustomDetection.Read.All (or ReadWrite.All) "
                    "to the App Registration and admin-consent.",
                ))
            else:
                report.add(ConformanceCheck(
                    layer, "list_detectionRules", "FAIL",
                    f"status={r.status_code}",
                ))
        except Exception as exc:
            report.add(ConformanceCheck(
                layer, "list_detectionRules", "FAIL",
                f"network: {exc}",
            ))
        finally:
            graph_client.close()


# ---------------------------------------------------------------------------
# L7 — GitHub repo conformance (optional)
# ---------------------------------------------------------------------------


def _gh_cli_available() -> bool:
    try:
        r = subprocess.run(
            ["gh", "--version"], capture_output=True, text=True,
            timeout=5, check=False,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _gh_api(path: str) -> tuple[int, Any]:
    """Run ``gh api PATH``. Returns (return_code, parsed_json_or_text)."""
    try:
        r = subprocess.run(
            ["gh", "api", path],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (-1, str(exc))
    if r.returncode != 0:
        return (r.returncode, r.stderr.strip() or r.stdout.strip())
    try:
        return (0, json.loads(r.stdout))
    except Exception:
        return (0, r.stdout)


def check_l7_github(
    report: ConformanceReport, config: ConformanceConfig,
) -> None:
    layer = "L7"
    if not _gh_cli_available():
        report.add(ConformanceCheck(
            layer, "gh_cli", "SKIP",
            "'gh' CLI not on PATH; install + run 'gh auth login' to enable",
        ))
        return

    repo = config.github_repo or os.environ.get("GITHUB_REPOSITORY") or ""
    if not repo:
        report.add(ConformanceCheck(
            layer, "github_repo", "SKIP",
            "no GITHUB_REPOSITORY env var and no github_repo config",
        ))
        return

    # Repo accessibility
    rc, body = _gh_api(f"repos/{repo}")
    if rc != 0:
        report.add(ConformanceCheck(
            layer, "github_repo", "FAIL",
            f"gh api repos/{repo} failed: {body}",
            "Confirm 'gh auth status' shows a token with repo scope.",
        ))
        return
    report.add(ConformanceCheck(
        layer, "github_repo", "PASS",
        f"repo {repo} reachable",
    ))

    # Required secret/variable NAMES exist (values not readable, by design).
    # Check both /actions/secrets and /actions/variables since some values
    # (AZURE_CLIENT_ID, AZURE_TENANT_ID) migrated from secrets to vars.
    names: set[str] = set()
    rc_s, body_s = _gh_api(f"repos/{repo}/actions/secrets")
    rc_v, body_v = _gh_api(f"repos/{repo}/actions/variables")
    if rc_s != 0 and rc_v != 0:
        report.add(ConformanceCheck(
            layer, "github_credentials", "SKIP",
            f"gh api ...secrets failed: {body_s}",
        ))
    else:
        if rc_s == 0:
            names.update(s.get("name", "") for s in (body_s.get("secrets") or []))
        if rc_v == 0:
            names.update(v.get("name", "") for v in (body_v.get("variables") or []))
        missing = [s for s in config.github_required_credentials if s not in names]
        if missing:
            report.add(ConformanceCheck(
                layer, "github_credentials", "FAIL",
                f"missing: {', '.join(missing)}",
                "Add the missing repository secrets/variables via GitHub UI or "
                "'gh secret set <NAME>' / 'gh variable set <NAME>'.",
            ))
        else:
            report.add(ConformanceCheck(
                layer, "github_credentials", "PASS",
                f"all required secret/variable names present "
                f"({len(config.github_required_credentials)})",
            ))

    # Branch protection on main (skipped when github_required_checks is empty)
    if not config.github_required_checks:
        report.add(ConformanceCheck(
            layer, "branch_protection", "SKIP",
            "github_required_checks is empty — branch protection check disabled",
        ))
    else:
        rc, body = _gh_api(f"repos/{repo}/branches/main/protection")
        body_str = str(body)
        if rc != 0 and ("403" in body_str or "not accessible" in body_str.lower()):
            # The caller can't READ branch protection — the endpoint needs
            # admin scope, which the Actions GITHUB_TOKEN cannot be granted
            # (`administration` isn't a settable token permission). That's a
            # token-scope limitation, NOT proof main is unprotected, so SKIP
            # (same posture as the secrets/variables check above) rather than
            # false-FAIL a repo whose protection is configured. Verifying it
            # requires an admin-scoped PAT / GitHub App token. A genuine 404
            # ("Branch not protected") still FAILs below.
            report.add(ConformanceCheck(
                layer, "branch_protection", "SKIP",
                f"branch protection unreadable with this token "
                f"(needs an admin-scoped PAT/App token): {body_str}",
            ))
        elif rc != 0:
            report.add(ConformanceCheck(
                layer, "branch_protection", "FAIL",
                f"no branch protection on main: {body_str}",
                "Enable branch protection on main; require status checks "
                "for: " + ", ".join(config.github_required_checks),
            ))
        else:
            contexts = (
                ((body.get("required_status_checks") or {}).get("contexts")) or []
            )
            missing = [c for c in config.github_required_checks if c not in contexts]
            if missing:
                report.add(ConformanceCheck(
                    layer, "branch_protection", "FAIL",
                    f"main lacks required checks: {', '.join(missing)}",
                    "Add the missing checks to the main branch protection rule.",
                ))
            else:
                report.add(ConformanceCheck(
                    layer, "branch_protection", "PASS",
                f"main requires {len(config.github_required_checks)} checks",
            ))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


_ALL_LAYERS: tuple[str, ...] = ("L1", "L2", "L3", "L4", "L5", "L6", "L7")


def run_conformance(
    *,
    scope: tuple[str, ...] = _ALL_LAYERS,
    config: ConformanceConfig | None = None,
) -> ConformanceReport:
    """Run every layer in ``scope`` and return the combined report.

    Network checks (L3-L7) silently SKIP when their prerequisites are
    absent — e.g. L4 SKIPs without a Graph token, L7 SKIPs without
    the ``gh`` CLI. A SKIP never causes overall failure; only FAIL does.
    """
    cfg = config or load_config()
    report = ConformanceReport(scope=scope, identity_label=cfg.identity_label)
    if "L1" in scope:
        check_l1_local_install(report)
        if cfg.parse_warning:
            report.add(ConformanceCheck(
                "L1", "config_parse", "INFO",
                f".contentops-conformance.yml failed to parse — using built-in "
                f"defaults: {cfg.parse_warning}",
                "Fix the YAML override; conformance fell back to defaults.",
            ))
    if "L2" in scope:
        check_l2_tenant_config(report)
    arm_token: str | None = None
    graph_token: str | None = None
    if "L3" in scope:
        arm_token, graph_token = check_l3_token(report)
    if "L4" in scope:
        check_l4_graph_permissions(report, graph_token, cfg)
    if "L5" in scope:
        check_l5_azure_rbac(report, arm_token, cfg)
    if "L6" in scope:
        check_l6_functional_reach(report, arm_token, graph_token)
    if "L7" in scope:
        check_l7_github(report, cfg)
    return report


_LAYER_TITLES: dict[str, str] = {
    "L1": "Local install",
    "L2": "Tenant config",
    "L3": "OIDC / token",
    "L4": "Microsoft Graph permissions",
    "L5": "Azure RBAC",
    "L6": "Functional reach (read-only)",
    "L7": "GitHub repo",
}


_STATUS_GLYPHS: dict[str, str] = {
    "PASS": "[PASS]",
    "FAIL": "[FAIL]",
    "SKIP": "[SKIP]",
    "INFO": "[INFO]",
}


def render_text(report: ConformanceReport) -> str:
    """Render the report as a plain-text table for terminal output."""
    lines: list[str] = []
    title = "ContentOps deployment conformance"
    bits = []
    if report.tenant_name:
        bits.append(f"tenant={report.tenant_name}")
    if report.identity_label:
        bits.append(f"identity={report.identity_label}")
    if bits:
        title += f" ({', '.join(bits)})"
    lines.append(title)
    lines.append("=" * len(title))
    lines.append("")

    by_layer: dict[str, list[ConformanceCheck]] = {}
    for c in report.checks:
        by_layer.setdefault(c.layer, []).append(c)

    for layer in _ALL_LAYERS:
        if layer not in by_layer:
            continue
        lines.append(f"{layer} — {_LAYER_TITLES.get(layer, layer)}")
        for c in by_layer[layer]:
            glyph = _STATUS_GLYPHS.get(c.status, c.status)
            lines.append(f"  {glyph}  {c.name}: {c.detail}")
            if c.status == "FAIL" and c.remediation:
                # Indent remediation under the failing check.
                lines.append(f"         remediation: {c.remediation}")
        lines.append("")

    fail = len(report.failed)
    pass_n = sum(1 for c in report.checks if c.status == "PASS")
    skip_n = sum(1 for c in report.checks if c.status == "SKIP")
    info_n = sum(1 for c in report.checks if c.status == "INFO")
    lines.append("-" * 60)
    if fail == 0:
        lines.append(
            f"Conformance: PASS  ({pass_n} PASS, "
            f"{skip_n} SKIP, {info_n} INFO)",
        )
    else:
        lines.append(
            f"Conformance: FAIL — {fail} check(s) require action "
            f"({pass_n} PASS, {skip_n} SKIP, {info_n} INFO)",
        )
    return "\n".join(lines) + "\n"


def render_json(report: ConformanceReport) -> str:
    """Render the report as JSON (one row per check)."""
    return json.dumps([
        {
            "layer": c.layer,
            "name": c.name,
            "status": c.status,
            "detail": c.detail,
            "remediation": c.remediation,
        }
        for c in report.checks
    ], indent=2) + "\n"


__all__ = [
    "ConformanceCheck",
    "ConformanceConfig",
    "ConformanceReport",
    "apply_identity_profile",
    "load_config",
    "render_json",
    "render_text",
    "run_conformance",
]
