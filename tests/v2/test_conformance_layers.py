# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Direct unit tests for the conformance layer functions (L3–L7).

Previously only L2 had direct tests; the HTTP-bound layers were exercised
only indirectly via the e2e harness. These tests mock the ARM / Graph
endpoints with respx (same pattern as test_sentinel_pagination.py) and the
``gh`` CLI seam with monkeypatch, so each layer's PASS / FAIL / SKIP / INFO
branches are covered hermetically — including the L4 token-``roles`` fast path,
the L5 effective-permissions write check, and the load_config parse-error
fallback.
"""

from __future__ import annotations

from types import SimpleNamespace

import respx
from httpx import Response

from contentops.devex import conformance as C


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _statuses(report: C.ConformanceReport) -> dict[str, str]:
    return {c.name: c.status for c in report.checks}


def _with_prefix(report: C.ConformanceReport, prefix: str) -> list[C.ConformanceCheck]:
    return [c for c in report.checks if c.name.startswith(prefix)]


def _fake_cfg() -> SimpleNamespace:
    return SimpleNamespace(
        name="t",
        sentinelWorkspaces=[
            SimpleNamespace(
                role="prod", workspaceName="law",
                subscriptionId="sub-1", resourceGroup="rg-1",
            ),
        ],
    )


def _jwt(claims: dict) -> str:
    """Build a fake JWT (header.payload.sig) carrying ``claims``.

    Enough for ``_decode_jwt_claims``, which reads the payload segment
    without verifying the signature.
    """
    import base64
    import json

    payload = (
        base64.urlsafe_b64encode(json.dumps(claims).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    return f"eyJhbGciOiJub25lIn0.{payload}.sig"


# ---------------------------------------------------------------------------
# load_config — 3a regression: parse error must not empty fed-cred subjects
# ---------------------------------------------------------------------------


def test_load_config_parse_error_preserves_default_fed_creds(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    broken = tmp_path / ".contentops-conformance.yml"
    broken.write_text("graph_app_roles: [unterminated\n", encoding="utf-8")

    cfg = C.load_config(path=broken)
    # The broken file must NOT silently clear the fed-cred subjects (which
    # would make L4 SKIP the check) — defaults are preserved.
    assert cfg.federated_credential_subjects == (
        "repo:owner/repo:ref:refs/heads/main",
        "repo:owner/repo:pull_request",
    )


# ---------------------------------------------------------------------------
# L3 — token acquisition
# ---------------------------------------------------------------------------


def test_l3_failure_when_no_credential(monkeypatch) -> None:
    monkeypatch.setattr(
        C, "_try_acquire_tokens",
        lambda: (None, None, "AADSTS700016 application not found"),
    )
    report = C.ConformanceReport()
    arm, graph = C.check_l3_token(report)
    assert (arm, graph) == (None, None)
    assert _statuses(report).get("token_acquisition") == "FAIL"


def test_l3_success_acquires_both_tokens(monkeypatch) -> None:
    fake_cred = SimpleNamespace(
        get_token=lambda *a, **k: SimpleNamespace(token="tok", expires_on=9_999_999_999),
    )
    monkeypatch.setattr(C, "_try_acquire_tokens", lambda: (fake_cred, "x", "y"))
    report = C.ConformanceReport()
    arm, graph = C.check_l3_token(report)
    assert arm == "tok" and graph == "tok"
    st = _statuses(report)
    assert st.get("arm_token") == "PASS"
    assert st.get("graph_token") == "PASS"


# ---------------------------------------------------------------------------
# L4 — Graph permissions (early-return paths; the with-block must not error)
# ---------------------------------------------------------------------------


def test_l4_skips_without_graph_token() -> None:
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, None, C.ConformanceConfig())
    assert _statuses(report).get("graph_perms") == "SKIP"


def test_l4_skips_without_client_id(monkeypatch) -> None:
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, "graph-tok", C.ConformanceConfig())
    assert _statuses(report).get("graph_perms") == "SKIP"


@respx.mock
def test_l4_sp_not_found_fails(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    respx.get(url__regex=r".*/servicePrincipals\(appId=").mock(
        return_value=Response(404, json={}),
    )
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, "graph-tok", C.ConformanceConfig())
    assert _statuses(report).get("service_principal") == "FAIL"


@respx.mock
def test_l4_sp_forbidden_skips(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    respx.get(url__regex=r".*/servicePrincipals\(appId=").mock(
        return_value=Response(403, json={}),
    )
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, "graph-tok", C.ConformanceConfig())
    assert _statuses(report).get("service_principal") == "SKIP"


# ---------------------------------------------------------------------------
# L4 — Defender write via the access-token ``roles`` claim (primary path)
# ---------------------------------------------------------------------------


def test_l4_pass_via_token_roles_claim(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    tok = _jwt({"roles": ["CustomDetection.ReadWrite.All", "SecurityAlert.Read.All"]})
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, tok, C.ConformanceConfig())
    assert _statuses(report).get("app_role_assignments") == "PASS"


def test_l4_fail_via_token_roles_missing(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    tok = _jwt({"roles": ["SecurityAlert.Read.All"]})  # no CustomDetection.ReadWrite.All
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, tok, C.ConformanceConfig())
    assert _statuses(report).get("app_role_assignments") == "FAIL"


@respx.mock
def test_l4_token_without_roles_falls_back_to_api(monkeypatch) -> None:
    # Delegated/user tokens carry ``scp`` not ``roles`` → the appRoleAssignments
    # API path runs (here the SP doesn't resolve → service_principal FAIL).
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    respx.get(url__regex=r".*/servicePrincipals\(appId=").mock(
        return_value=Response(404, json={}),
    )
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(
        report, _jwt({"scp": "user_impersonation"}), C.ConformanceConfig(),
    )
    assert _statuses(report).get("service_principal") == "FAIL"


@respx.mock
def test_l4_approle_pagination_followed(monkeypatch) -> None:
    # No ``roles`` claim → API path; the required role is on the 2nd page.
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    role_guid = C._WELL_KNOWN_GRAPH_APP_ROLES["CustomDetection.ReadWrite.All"]
    next_link = (
        "https://graph.microsoft.com/v1.0/servicePrincipals/sp-1"
        "/appRoleAssignments?$skiptoken=PAGE2"
    )
    respx.get(url__regex=r".*/servicePrincipals\(appId=").mock(
        return_value=Response(200, json={"id": "sp-1"}),
    )
    respx.get(url__regex=r".*/appRoleAssignments$").mock(
        return_value=Response(200, json={"value": [], "@odata.nextLink": next_link}),
    )
    respx.get(url__regex=r".*skiptoken=PAGE2").mock(
        return_value=Response(200, json={"value": [{
            "appRoleId": role_guid, "resourceId": "graph-sp",
            "resourceDisplayName": "Microsoft Graph",
        }]}),
    )
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, _jwt({"scp": "x"}), C.ConformanceConfig())
    assert _statuses(report).get("app_role_assignments") == "PASS"


# ---------------------------------------------------------------------------
# L5 — Azure RBAC: effective-permissions write check
# ---------------------------------------------------------------------------


def _mock_l5_workspace_ok() -> None:
    respx.get(url__regex=r".*/workspaces/law\?api-version=2022-10-01").mock(
        return_value=Response(200, json={}),
    )
    respx.get(url__regex=r".*/onboardingStates/default").mock(
        return_value=Response(200, json={}),
    )


def _mock_l5_permissions(actions: list, not_actions: list | None = None) -> None:
    respx.get(url__regex=r".*/Microsoft\.Authorization/permissions").mock(
        return_value=Response(200, json={
            "value": [{"actions": actions, "notActions": not_actions or []}],
        }),
    )


@respx.mock
def test_l5_write_pass_exact_action(monkeypatch) -> None:
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    _mock_l5_workspace_ok()
    _mock_l5_permissions(["Microsoft.SecurityInsights/alertRules/write"])
    report = C.ConformanceReport()
    C.check_l5_azure_rbac(report, "arm-tok", C.ConformanceConfig())
    rows = _with_prefix(report, "rbac_write[")
    assert rows and rows[0].status == "PASS"


@respx.mock
def test_l5_write_pass_via_wildcard(monkeypatch) -> None:
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    _mock_l5_workspace_ok()
    _mock_l5_permissions(["Microsoft.SecurityInsights/*"])
    report = C.ConformanceReport()
    C.check_l5_azure_rbac(report, "arm-tok", C.ConformanceConfig())
    rows = _with_prefix(report, "rbac_write[")
    assert rows and rows[0].status == "PASS"


@respx.mock
def test_l5_write_fail_when_missing(monkeypatch) -> None:
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    _mock_l5_workspace_ok()
    _mock_l5_permissions(["Microsoft.OperationalInsights/workspaces/read"])
    report = C.ConformanceReport()
    C.check_l5_azure_rbac(report, "arm-tok", C.ConformanceConfig())
    rows = _with_prefix(report, "rbac_write[")
    assert rows and rows[0].status == "FAIL"


@respx.mock
def test_l5_write_fail_when_excluded_by_notactions(monkeypatch) -> None:
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    _mock_l5_workspace_ok()
    _mock_l5_permissions(["*"], ["Microsoft.SecurityInsights/alertRules/write"])
    report = C.ConformanceReport()
    C.check_l5_azure_rbac(report, "arm-tok", C.ConformanceConfig())
    rows = _with_prefix(report, "rbac_write[")
    assert rows and rows[0].status == "FAIL"


# ---------------------------------------------------------------------------
# Dual-identity: apply_identity_profile + read-profile assertions
# ---------------------------------------------------------------------------


def test_apply_identity_profile_read_sets_least_privilege_expectations() -> None:
    cfg = C.apply_identity_profile(C.ConformanceConfig(), "read")
    assert cfg.identity_label == "read"
    assert cfg.graph_app_roles == ("CustomDetection.Read.All",)
    assert cfg.forbidden_graph_app_roles == ("CustomDetection.ReadWrite.All",)
    assert cfg.expect_rbac_write is False


def test_apply_identity_profile_write_preserves_defaults() -> None:
    cfg = C.apply_identity_profile(C.ConformanceConfig(), "write")
    assert cfg.identity_label == "write"
    assert cfg.graph_app_roles == C._DEFAULT_GRAPH_APP_ROLES  # ReadWrite.All
    assert cfg.forbidden_graph_app_roles == ()
    assert cfg.expect_rbac_write is True


def test_apply_identity_profile_unknown_raises() -> None:
    import pytest
    with pytest.raises(ValueError):
        C.apply_identity_profile(C.ConformanceConfig(), "bogus")


def test_apply_identity_profile_read_single_mode_keeps_write_expectations() -> None:
    """identity_mode=single: one shared App Reg for every environment — the
    read leg keeps the write-grade expectations (still verifying the
    automation environment's fed cred + reach) and asserts no
    least-privilege split."""
    cfg = C.apply_identity_profile(
        C.ConformanceConfig(identity_mode="single"), "read",
    )
    assert cfg.identity_label == "read (single-app)"
    assert cfg.graph_app_roles == C._DEFAULT_GRAPH_APP_ROLES  # ReadWrite.All
    assert cfg.forbidden_graph_app_roles == ()
    assert cfg.expect_rbac_write is True


def test_apply_identity_profile_read_single_mode_preserves_role_override() -> None:
    """Single mode keeps a fork's graph_app_roles override on the read leg —
    same behaviour the write leg always had."""
    base = C.ConformanceConfig(
        identity_mode="single",
        graph_app_roles=("CustomDetection.ReadWrite.All", "AuditLog.Read.All"),
    )
    cfg = C.apply_identity_profile(base, "read")
    assert cfg.graph_app_roles == (
        "CustomDetection.ReadWrite.All", "AuditLog.Read.All",
    )


def test_load_config_identity_mode_single(tmp_path) -> None:
    f = tmp_path / ".contentops-conformance.yml"
    f.write_text("identity_mode: single\n", encoding="utf-8")
    cfg = C.load_config(path=f)
    assert cfg.identity_mode == "single"
    assert cfg.parse_warning is None


def test_load_config_identity_mode_defaults_to_split(tmp_path) -> None:
    f = tmp_path / ".contentops-conformance.yml"
    f.write_text(
        "graph_app_roles: [CustomDetection.ReadWrite.All]\n", encoding="utf-8",
    )
    cfg = C.load_config(path=f)
    assert cfg.identity_mode == "split"


def test_load_config_identity_mode_invalid_falls_back_to_split(tmp_path) -> None:
    """A typo'd identity_mode must not silently relax least-privilege — the
    strict split profile applies and the report carries the warning."""
    f = tmp_path / ".contentops-conformance.yml"
    f.write_text("identity_mode: solo\n", encoding="utf-8")
    cfg = C.load_config(path=f)
    assert cfg.identity_mode == "split"
    assert cfg.parse_warning is not None
    read_cfg = C.apply_identity_profile(cfg, "read")
    assert read_cfg.forbidden_graph_app_roles == ("CustomDetection.ReadWrite.All",)


def test_l4_read_profile_passes_with_read_only_and_no_write(monkeypatch) -> None:
    """Read identity with only CustomDetection.Read.All: required present
    (PASS) and the forbidden write role absent (least_privilege PASS)."""
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    read_cfg = C.apply_identity_profile(C.ConformanceConfig(), "read")
    tok = _jwt({"roles": ["CustomDetection.Read.All"]})
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, tok, read_cfg)
    st = _statuses(report)
    assert st.get("app_role_assignments") == "PASS"
    assert st.get("least_privilege") == "PASS"


def test_l4_read_profile_fails_when_holding_write_role(monkeypatch) -> None:
    """Read identity that still holds CustomDetection.ReadWrite.All is an
    SoD violation — least_privilege FAILs even though the required read role
    is present."""
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    read_cfg = C.apply_identity_profile(C.ConformanceConfig(), "read")
    tok = _jwt({"roles": ["CustomDetection.Read.All", "CustomDetection.ReadWrite.All"]})
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, tok, read_cfg)
    st = _statuses(report)
    assert st.get("app_role_assignments") == "PASS"
    assert st.get("least_privilege") == "FAIL"


def test_l4_write_profile_emits_no_least_privilege_row(monkeypatch) -> None:
    """Write profile has no forbidden roles, so the least_privilege row is
    never added (back-compat: write behaviour unchanged)."""
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    tok = _jwt({"roles": ["CustomDetection.ReadWrite.All"]})
    report = C.ConformanceReport()
    C.check_l4_graph_permissions(report, tok, C.ConformanceConfig())
    assert "least_privilege" not in _statuses(report)


@respx.mock
def test_l5_read_profile_passes_when_write_absent(monkeypatch) -> None:
    """Read identity that correctly LACKS alert-rule write → rbac_write PASS
    (inverted polarity vs the write profile)."""
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    _mock_l5_workspace_ok()
    _mock_l5_permissions(["Microsoft.OperationalInsights/workspaces/read"])
    read_cfg = C.apply_identity_profile(C.ConformanceConfig(), "read")
    report = C.ConformanceReport()
    C.check_l5_azure_rbac(report, "arm-tok", read_cfg)
    rows = _with_prefix(report, "rbac_write[")
    assert rows and rows[0].status == "PASS"


@respx.mock
def test_l5_read_profile_fails_when_write_present(monkeypatch) -> None:
    """Read identity that unexpectedly HAS alert-rule write → rbac_write
    FAIL (SoD violation)."""
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    _mock_l5_workspace_ok()
    _mock_l5_permissions(["Microsoft.SecurityInsights/alertRules/write"])
    read_cfg = C.apply_identity_profile(C.ConformanceConfig(), "read")
    report = C.ConformanceReport()
    C.check_l5_azure_rbac(report, "arm-tok", read_cfg)
    rows = _with_prefix(report, "rbac_write[")
    assert rows and rows[0].status == "FAIL"


# ---------------------------------------------------------------------------
# L6 — functional reach (ARM list alertRules)
# ---------------------------------------------------------------------------


@respx.mock
def test_l6_alert_rules_pass(monkeypatch) -> None:
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    respx.get(url__regex=r".*/alertRules").mock(
        return_value=Response(200, json={"value": [{"id": "1"}]}),
    )
    report = C.ConformanceReport()
    C.check_l6_functional_reach(report, "arm-tok", None)
    rows = _with_prefix(report, "list_alertRules[")
    assert rows and rows[0].status == "PASS"


@respx.mock
def test_l6_alert_rules_forbidden_fails(monkeypatch) -> None:
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda: _fake_cfg())
    respx.get(url__regex=r".*/alertRules").mock(return_value=Response(403, json={}))
    report = C.ConformanceReport()
    C.check_l6_functional_reach(report, "arm-tok", None)
    rows = _with_prefix(report, "list_alertRules[")
    assert rows and rows[0].status == "FAIL"


# ---------------------------------------------------------------------------
# L7 — GitHub (gh CLI seam)
# ---------------------------------------------------------------------------


def test_l7_skips_when_gh_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(C, "_gh_cli_available", lambda: False)
    report = C.ConformanceReport()
    C.check_l7_github(report, C.ConformanceConfig())
    assert _statuses(report).get("gh_cli") == "SKIP"


def test_l7_repo_unreachable_fails(monkeypatch) -> None:
    monkeypatch.setattr(C, "_gh_cli_available", lambda: True)
    monkeypatch.setattr(C, "_gh_api", lambda path: (1, "HTTP 404"))
    cfg = C.ConformanceConfig(github_repo="owner/repo")
    report = C.ConformanceReport()
    C.check_l7_github(report, cfg)
    assert _statuses(report).get("github_repo") == "FAIL"


def _l7_gh_api(branch_protection_response):
    """Per-path _gh_api fake: repo reachable, empty secrets/vars, and a
    caller-supplied branch-protection response."""
    def _fake(path: str):
        if "branches/main/protection" in path:
            return branch_protection_response
        if path.endswith("/actions/secrets"):
            return (0, {"secrets": []})
        if path.endswith("/actions/variables"):
            return (0, {"variables": []})
        return (0, {})  # repos/{repo} reachable
    return _fake


def test_l7_branch_protection_403_skips_not_fails(monkeypatch) -> None:
    """A token that can't READ branch protection (403) must SKIP, not FAIL —
    it's a scope limitation, not proof main is unprotected."""
    monkeypatch.setattr(C, "_gh_cli_available", lambda: True)
    monkeypatch.setattr(C, "_gh_api", _l7_gh_api(
        (1, "gh: Resource not accessible by integration (HTTP 403)"),
    ))
    cfg = C.ConformanceConfig(
        github_repo="owner/repo",
        github_required_checks=("pytest",),
        github_required_credentials=(),
    )
    report = C.ConformanceReport()
    C.check_l7_github(report, cfg)
    assert _statuses(report).get("branch_protection") == "SKIP"


def test_l7_branch_protection_404_still_fails(monkeypatch) -> None:
    """A genuine 404 (main really is unprotected) must still FAIL."""
    monkeypatch.setattr(C, "_gh_cli_available", lambda: True)
    monkeypatch.setattr(C, "_gh_api", _l7_gh_api(
        (1, "gh: Branch not protected (HTTP 404)"),
    ))
    cfg = C.ConformanceConfig(
        github_repo="owner/repo",
        github_required_checks=("pytest",),
        github_required_credentials=(),
    )
    report = C.ConformanceReport()
    C.check_l7_github(report, cfg)
    assert _statuses(report).get("branch_protection") == "FAIL"
