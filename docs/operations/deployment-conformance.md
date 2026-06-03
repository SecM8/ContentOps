# Deployment conformance check

One command — `contentops conformance` — answers the question "is my
ContentOps install, my Azure deployment, and my GitHub repo wired
correctly?" with a per-layer PASS / FAIL / SKIP table and an
actionable remediation hint on every failure.

**Read-only by construction.** Every probe is a `GET`,
`OPTIONS`, or `POST` to a read-only query endpoint. No `PUT`, `PATCH`,
or `DELETE` is ever issued against ARM, Graph, or GitHub. Safe to run
against production tenants.

## When to run

- **Day-1 onboarding.** After cloning + installing, before opening a
  PR. Catches missing env vars, placeholder GUIDs, and unconfigured
  Graph permissions in one shot.
- **After rotating credentials.** Confirms the new App Registration
  client secret / federated credential / role assignment actually
  works end-to-end.
- **Before a release.** Last-line check that nothing about the
  deployment has drifted out from under the code.
- **When something is mysteriously broken.** Tells you exactly which
  layer is failing instead of leaving you to grep stack traces.

## The seven layers

Each layer is independent — you can run any subset via
`--scope L1,L2,...` or a range like `--scope L1-L4`.

### L1 — Local install

Verifies the basics that don't need any credentials:

| Check | What it proves |
|---|---|
| `python_version` | `python --version` is ≥ 3.12 |
| `package_import` | `contentops` modules load (no `ImportError`) |
| `envelopes_parse` | `detections/**/*.yml` all parse against the envelope schema (skipped if no `detections/` at cwd) |
| `audit_chain` | `audit/*.jsonl` hash chain verifies (skipped if no `audit/` at cwd) |

A failure here means your install is broken or repo content is malformed.

### L2 — Tenant config

Validates `config/tenant.yml` (or the `PIPELINE_ENV`-aware variant):

| Check | What it proves |
|---|---|
| `tenant_yml_parse` | Pydantic schema validation passes |
| `tenant_id_shape` | `tenant.tenantId` is a real GUID, not the all-zero placeholder |
| `workspace_sub_ids` | every workspace's `subscriptionId` is a real GUID |
| `auth_env` | `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` are set in the environment |

A failure here means the config file is missing, placeholder, or the
shell hasn't picked up the credentials.

### L3 — OIDC / token

Confirms `DefaultAzureCredential` can acquire tokens:

| Check | What it proves |
|---|---|
| `arm_token` | A token for `https://management.azure.com/.default` was issued |
| `graph_token` | A token for `https://graph.microsoft.com/.default` was issued |

Failures here usually mean: wrong `AZURE_TENANT_ID`, deleted App
Registration, federated credential subject doesn't match the current
git context, or `az login` hasn't been run for local development.

### L4 — Microsoft Graph permissions

Probes the App Registration's service principal via Graph:

| Check | What it proves |
|---|---|
| `service_principal` | The SP with `appId == AZURE_CLIENT_ID` exists |
| `app_role_assignments` | Every Graph application permission in `graph_app_roles` (default: `CustomDetection.ReadWrite.All`) is granted **and admin-consented** |
| `federated_credentials` | Every subject in `federated_credential_subjects` (e.g. `repo:OWNER/REPO:ref:refs/heads/main`) is configured on the App Registration |

Failures here pinpoint missing permissions or fed-cred misconfiguration
that would otherwise surface as 401/403s deep in `apply` / `collect`.

> **Prerequisite:** the *executing identity* needs
> `Application.Read.All` on Microsoft Graph to read another SP's
> role assignments. If it doesn't, L4 SKIPs with a clear message
> rather than fails — L5 and L6 continue.

### L5 — Azure RBAC

For each Sentinel workspace in `tenant.yml`:

| Check | What it proves |
|---|---|
| `workspace[role:name]` | Subscription + RG + Log Analytics workspace exist and the SP can read them |
| `sentinel_onboarded[role:name]` | Microsoft Sentinel is onboarded onto the workspace (`onboardingStates/default` returns 200) |

A `403` on the workspace probe usually means the SP lacks
`Microsoft Sentinel Reader` (or higher) on the workspace scope. A
`404` means the GUIDs in `tenant.yml` don't match a real resource.

### L6 — Functional reach (read-only)

End-to-end smoke against the real APIs:

| Check | What it proves |
|---|---|
| `list_alertRules[role:name]` | `GET .../alertRules` returns 200 — proves Sentinel reach + read perm |
| `list_detectionRules` | `GET /beta/security/rules/detectionRules` returns 200 — proves Defender Graph reach + `CustomDetection.Read.All` |

This is the cheapest end-to-end proof that the entire stack is wired.

### L7 — GitHub repo (optional)

Skipped without the `gh` CLI and an authenticated token. When
available:

| Check | What it proves |
|---|---|
| `github_repo` | The repo is reachable with the current token |
| `github_secrets` | Every required secret **name** (default: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `TENANT_CONFIG_YAML`) exists — values are never readable, by design |
| `branch_protection` | The `main` branch protection rule requires the expected checks (default: `dco`, `spdx-headers`, `pytest`, `cli-smoke`, `bandit`, `semgrep`, `gitleaks`, `actionlint`) |

## Output

### Text (default)

```text
ContentOps deployment conformance (tenant=production)
=====================================================

L1 — Local install
  [PASS]  python_version: 3.12.10
  [PASS]  package_import: contentops modules importable
  [PASS]  envelopes_parse: 152 envelopes parsed across 6 kinds
  [PASS]  audit_chain: 10 file(s), 716 records

L2 — Tenant config
  [PASS]  tenant_yml_parse: tenant=production, sentinel_workspaces=2
  [PASS]  tenant_id_shape: tenantId=abcd1234…
  [PASS]  workspace_sub_ids: 2 workspace(s) carry real GUIDs
  [PASS]  auth_env: AZURE_CLIENT_ID + AZURE_TENANT_ID set

L3 — OIDC / token
  [PASS]  arm_token: acquired (expires_on=1731123456)
  [PASS]  graph_token: acquired (expires_on=1731123456)

L4 — Microsoft Graph permissions
  [PASS]  service_principal: objectId=fedc4321…  displayName=ContentOps Pipeline
  [FAIL]  app_role_assignments: missing: CustomDetection.ReadWrite.All
         remediation: Grant the missing Graph application permissions to appId=abcd... AND admin-consent them.
  [PASS]  federated_credentials: all required subjects configured (2)

…

------------------------------------------------------------
Conformance: FAIL — 1 check(s) require action (12 PASS, 0 SKIP, 0 INFO)
```

### JSON (`--format json`)

```json
[
  {
    "layer": "L1",
    "name": "python_version",
    "status": "PASS",
    "detail": "3.12.10",
    "remediation": ""
  },
  {
    "layer": "L4",
    "name": "app_role_assignments",
    "status": "FAIL",
    "detail": "missing: CustomDetection.ReadWrite.All",
    "remediation": "Grant the missing Graph application permissions to appId=... AND admin-consent them."
  }
]
```

## Scheduled in CI

The `.github/workflows/conformance.yml` workflow runs the full check
weekly (Mondays 07:00 UTC) via OIDC against the configured tenant
and opens / comments on a dedup'd pipeline-alert issue if anything
goes red. Also dispatchable manually:

```bash
gh workflow run conformance.yml                            # full scope, fails on FAIL
gh workflow run conformance.yml -f scope=L1-L4             # partial
gh workflow run conformance.yml -f exit-zero=true          # report-only
```

The JSON sidecar (`conformance-report.json`) is uploaded as a
workflow artifact on every run, pass or fail.

## How to invoke

```bash
# Full report (default scope: all 7 layers)
contentops conformance

# Layer subset
contentops conformance --scope L1,L2,L3
contentops conformance --scope L1-L4        # range form

# Write to a file
contentops conformance --out report.txt
contentops conformance --format json --out report.json

# Always exit 0 (useful when piping JSON into a wrapper)
contentops conformance --format json --exit-zero
```

The command exits **0** when every check is PASS, INFO, or SKIP; **1**
when any check is FAIL.

## Read vs write identity (`--identity`)

When you run the [two-App-Reg split](authentication-setup.md) for
separation of duties, conformance verifies **each identity against its own
expectation profile** by running AS that identity (its own OIDC token):

```bash
contentops conformance --identity write   # default: write/deploy expectations
contentops conformance --identity read    # read/automation expectations
```

| Profile | Graph | Azure RBAC |
|---|---|---|
| `write` (default) | requires `CustomDetection.ReadWrite.All` | expects Sentinel **write** (alertRules write) |
| `read` | requires `CustomDetection.Read.All`, **forbids** `CustomDetection.ReadWrite.All` | expects **no** Sentinel write |

L5 enforces the separation: the **read** identity PASSES only if it
*lacks* write (least-privilege confirmed); the **write** identity PASSES
only if write is granted. `conformance.yml` runs both legs in one
workflow — the read leg on the `automation` environment, the write leg on
the `conformance` environment — so a single weekly run validates both App
Registrations.

> **What this proves (and doesn't).** The conformance check is **drift /
> regression detection**: it catches an accidental RBAC or Graph-permission
> change, a missing federated credential, or a misconfigured environment
> before they cost you a red deploy. It is **not** a tamper-evident control
> against a malicious maintainer — the `conformance` environment is
> unattended (no reviewer) and L7 reads the same repo it runs in, so
> someone who can already push to `main` / edit branch protection can also
> influence what it sees. Do not gate a deploy on a conformance leg whose
> environment + federated credential don't yet exist, or that leg SKIPs
> (read) / can't authenticate (write) silently.

## Per-fork expectations

The defaults match the reference ContentOps deployment. Adopters
with a different posture (e.g. additional Graph permissions, a
different branch-protection check set) override via
`.contentops-conformance.yml` at the repo root:

```yaml
# .contentops-conformance.yml
graph_app_roles:
  - CustomDetection.ReadWrite.All
  - AuditLog.Read.All
  - SecurityAlert.Read.All

federated_credential_subjects:
  - "repo:my-org/my-fork:ref:refs/heads/main"
  - "repo:my-org/my-fork:pull_request"
  - "repo:my-org/my-fork:environment:production"

github_required_credentials:   # checked as repo secrets OR variables; legacy key `github_required_secrets` still accepted
  - AZURE_CLIENT_ID
  - AZURE_TENANT_ID
  - TENANT_CONFIG_YAML
  - SLACK_WEBHOOK_URL    # if your fork posts to Slack on deploys

github_required_checks:
  - dco
  - spdx-headers
  - pytest
  - cli-smoke
  - my-custom-policy-check
```

Defaults are documented in `contentops/devex/conformance.py`.

## Prerequisites by layer

| Layer | Needs |
|---|---|
| L1 | A working Python 3.12 install + `pip install -e .` |
| L2 | `config/tenant.yml` present + `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` in the shell |
| L3 | Valid `DefaultAzureCredential` chain (env vars, az login, OIDC, or managed identity) |
| L4 | L3 + the executing identity has `Application.Read.All` on Graph |
| L5 | L3 + at least `Reader` on each configured Sentinel workspace's subscription |
| L6 | L3 + `Microsoft Sentinel Reader` on each workspace + `CustomDetection.Read.All` on Graph |
| L7 | `gh` CLI installed + `gh auth login` complete (token needs `repo` + `admin:repo_hook` scopes for branch-protection reads) |

A layer that's missing its prerequisite reports SKIP, not FAIL. Only
broken-but-should-work conditions FAIL.

## Troubleshooting

**Everything in L3+ FAILs with `DefaultAzureCredential failed`.**
You don't have valid credentials in the current shell. Either
`az login` (local development), set `AZURE_CLIENT_ID` /
`AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET` (service principal), or
ensure the GitHub OIDC federated credential matches the current git
context (CI).

**L4 SKIPs with `403 reading /servicePrincipals`.**
The credentials work but the executing identity can't enumerate
other SPs' role assignments. Either run as a tenant admin or grant
the SP `Application.Read.All` on Microsoft Graph. L5 and L6 continue
regardless.

**L5 FAILs `workspace[...]: 404`.**
The `subscriptionId`, `resourceGroup`, or `workspaceName` in
`tenant.yml` doesn't match a real resource. Double-check with
`az resource show` or the Azure portal.

**L6 FAILs `list_alertRules: 403`.**
The SP exists, the workspace exists, but the SP lacks
`Microsoft Sentinel Reader` (or higher) at the workspace scope. Grant
the role and re-run.

**L7 FAILs `branch_protection: no branch protection on main`.**
Either the rule isn't configured, or the executing token doesn't
have `repo` scope. Configure protection at `Settings → Branches →
Add rule` for `main` with the expected required checks.

## Relationship to other tests

- **`contentops doctor`** — local-only sanity checks (Python, deps,
  env, config parse). Subset of L1 + L2 + a piece of L3. Run on
  every shell session; conformance is the deeper deployment-wide
  check.
- **`pytest tests/e2e/test_deployment_conformance.py`** — pytest
  wrapper around `contentops conformance`. Used by the e2e workflow
  to gate the test session on conformance.
- **`tests/e2e/test_full_capability_matrix.py`** — the CLI capability
  matrix. Exercises every CLI leaf command end-to-end against a
  sandbox. Complementary: conformance verifies the deployment is
  *configured* correctly; the matrix verifies the CLI *behaves*
  correctly.
- **`tests/integration/`** — destructive live tests that CRUD real
  Sentinel + Defender content with the `zz-itest-` prefix. Operator-
  only; community adopters should never need to run these.

## Non-goals

- **Verifying detection content quality.** That's `contentops lint`.
- **Verifying CLI behaviour.** That's the capability matrix.
- **Comprehensive RBAC enumeration.** L5 confirms read access; it
  doesn't enumerate every required-vs-actual role mapping. If you
  need that depth, query `roleAssignments` directly via Graph + ARM
  and compare against your ops runbook.
- **Performance.** Every probe has a tight timeout (10–15s); the
  whole check should complete in under a minute on a healthy
  deployment. If it hangs, your network is the problem, not the
  tooling.
