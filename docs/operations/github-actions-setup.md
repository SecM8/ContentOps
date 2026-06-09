# GitHub Actions setup — Day-1 adopter wiring

> What to configure in your GitHub repo before the workflows can run
> against your Azure tenant. Read this once you've finished
> [`authentication-setup.md`](authentication-setup.md) (App Registration
> + permissions on the Azure side) and want to wire it up on the
> GitHub side.

This is the canonical reference for "which secret / variable / env /
federated credential goes where." If a workflow fails with a
`secret … not set` error, search this doc for the secret name and it
will tell you where it belongs.

## The four pieces, in order

1. **GitHub Actions Variables** — public identifiers (App Reg client
   ID, tenant ID). Set once at repo level.
2. **GitHub Actions Secrets** — sensitive payloads (tenant.yml,
   gitleaks license). Stdin form only.
3. **GitHub Environments** — `production`, `integration`,
   `automation`, optionally `dev`. Each gates one set of workflows
   and pairs with a federated credential on the App Reg.
4. **Federated credentials on the App Reg** — one per environment,
   subject-matched to the environment name.

End-to-end after this, `contentops conformance` L7 should pass.

---

## 1. Variables (not secrets — they're public identifiers)

Open the repo's `Settings → Secrets and variables → Actions → Variables tab`.

| Name | Value | Why a Variable, not a Secret |
|---|---|---|
| `AZURE_CLIENT_ID` | The App Registration's "Application (client) ID" GUID | A client ID by itself authenticates nothing — it just identifies the app. Treating it as a secret leaks the wrong threat model and breaks `${{ vars.AZURE_CLIENT_ID }}` references in workflows. |
| `AZURE_TENANT_ID` | The Entra tenant GUID | Same — tenant IDs are public discovery information. Treat as a Variable. |

The workflows reference these as `${{ vars.AZURE_CLIENT_ID }}` and
`${{ vars.AZURE_TENANT_ID }}` (see `.github/actions/pipeline-setup/action.yml`).

## 2. Secrets

Open `Settings → Secrets and variables → Actions → Secrets tab`.
**Always use the stdin form** — never paste secret values into a
shell history or a `--body` flag.

| Name | What | When required |
|---|---|---|
| `TENANT_CONFIG_YAML` | Contents of `config/tenant.yml` (real GUIDs + workspace names). The composite `pipeline-setup` action materialises this onto disk at job start. | Required for every workflow that touches Azure. Set this first. |
| `TENANT_CONFIG_INTEGRATION_YAML` | Contents of `config/tenant.integration.yml` if you have a separate integration tenant config. | Required only for `promote-to-integration.yml`. Skip unless you have a separate integration tenant. |
| `GITLEAKS_LICENSE` | Your free org license key from https://gitleaks.io/ | Required for `secret-scan.yml` once your repo is org-owned. Adopter shortcut: skip the local pre-commit hook + wait for the license before pushing. |
| `AUTO_PR_TOKEN` | Fine-grained PAT scoped to **this repo only**, **Contents: Read and write + Pull requests: Read and write**. The seven PR-opening workflows (`collect`, `drift`, `kql-schemas-refresh`, `attack-matrix-refresh`, `upstream-watchers`, `lock-unlock`, `emergency-disable`) use it when present and fall back to the built-in `GITHUB_TOKEN` when not. Bonus: PRs opened with a PAT trigger `on: pull_request` CI; PRs opened with `GITHUB_TOKEN` never do. | Only when your org disables `Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"` — the run fails with `GitHub Actions is not permitted to create or approve pull requests`. Skip if that toggle is on. |
| `PUBLIC_MIRROR_PAT` | Fine-grained PAT scoped to the public mirror **only** (`SecM8/ContentOps`), **Contents: Read and write + Workflows: Read and write** (Workflows is required because the sync mirrors `.github/workflows/**` — a fine-grained PAT cannot push workflow files without it) — write-only, no access to the private repo. Not a classic `repo`-scope token. See `OPERATOR_MIRROR.md` for the full rotation procedure. | Only the operator needs this. Adopters don't run mirror sync. |

### Stdin form (PowerShell)

```powershell
# tenant.yml — the most common one
Get-Content config\tenant.yml -Raw | gh secret set TENANT_CONFIG_YAML --repo <org>/<repo>

# gitleaks license — paste the key when prompted
gh secret set GITLEAKS_LICENSE --repo <org>/<repo>

# Verify (lists names + dates, never shows values)
gh secret list --repo <org>/<repo>
```

The `-Raw` flag preserves CRLF/UTF-8 exactly; without it,
`Get-Content` line-by-line pipes can subtly corrupt YAML formatting.

### Stdin form (bash / zsh)

```bash
cat config/tenant.yml | gh secret set TENANT_CONFIG_YAML --repo <org>/<repo>
gh secret set GITLEAKS_LICENSE --repo <org>/<repo>
gh secret list --repo <org>/<repo>
```

## 3. GitHub Environments

Open `Settings → Environments → New environment`. Create the
environments below depending on which workflows you intend to run.
Each environment can carry its own protection rules (required
reviewers, wait timer, deployment branch policy) — those are
optional and orthogonal to the wiring.

### Environments × workflows that need them

| Environment | Required by | What runs there |
|---|---|---|
| `production` | `deploy.yml`, `integration.yml` (the live-tenant integration test) | Apply detection content to production Sentinel workspaces; live-tenant integration test suite. The most-protected environment. |
| `integration` | `integration-deploy.yml`, `promote-to-integration.yml` | Apply content to your integration workspace as a PR-time smoke test; copy prod state into integration for parity testing. Skip if you don't have a separate integration workspace. |
| `automation` | `drift.yml`, `defender-graph-probe.yml`, `silent-rules.yml`, `kql-schemas-refresh.yml` | Read-only cron workflows (drift detection, Defender Graph endpoint probing, silent-rule reporting). Separated from `production` so deploy protections don't slow down nightly automation. |
| `conformance` (optional) | `conformance.yml` (write-identity leg) | Where `contentops conformance` authenticates **as the write identity** to verify its grants. Only needed if you run the dual-identity conformance check (the read leg runs on `automation`). |
| `dev` (optional) | `prune.yml`, `retry-failed.yml` (when invoked with `--env dev`) | If you have a dev tenant workspace, scope dev-targeted runs here. Skip if you don't. |

> **Read/write App Reg split (optional, see
> [`authentication-setup.md`](authentication-setup.md)).** If you run two
> App Registrations for separation of duties, set an
> **environment-scoped** `AZURE_CLIENT_ID` Variable on `automation` = the
> **read** App Reg, and leave the **repo-level** `AZURE_CLIENT_ID` = the
> **write** App Reg (the gated environments above inherit it). With a
> single App Reg, the repo-level Variable serves every environment and you
> can ignore this — but declare `identity_mode: single` in
> `.contentops-conformance.yml` so the conformance read leg verifies the
> shared identity instead of failing its least-privilege checks. See
> [`deployment-conformance.md`](deployment-conformance.md#single-app-registration-deployments-identity_mode-single).

### Per-environment optional protections

These are recommendations, not requirements:

| Setting | `production` | `integration` | `automation` |
|---|---|---|---|
| Required reviewers | At least 1 (gates manual `workflow_dispatch` of `deploy.yml`) | 0 (PR-time smoke test, automated) | 0 (cron, read-only) |
| Wait timer | 0 | 0 | 0 |
| Deployment branch policy | Only `main` | `main` + any branch (PRs need it too) | Only `main` |

## 4. Federated credentials on the App Registration

The OIDC token exchange that lets GitHub Actions auth as your App
Reg requires a matching federated credential on the App Reg. **One
federated credential per environment.**

In the Azure portal: `Entra ID → App registrations → your App Reg → Certificates & secrets → Federated credentials → Add credential`.

For each environment from §3, add one credential with these
subject formats:

| Environment | Federated credential subject | On which App Reg (if split) |
|---|---|---|
| `production` | `repo:<org>/<repo>:environment:production` | write |
| `integration` | `repo:<org>/<repo>:environment:integration` | write |
| `conformance` | `repo:<org>/<repo>:environment:conformance` | write |
| `automation` | `repo:<org>/<repo>:environment:automation` | read |
| `dev` | `repo:<org>/<repo>:environment:dev` | write |

With a **single** App Reg, add every subject above to that one App Reg.
With the **two-App-Reg split**, put the `automation` subject on the read
App Reg and the rest on the write App Reg (right-hand column).

Other fields:
- **Issuer**: `https://token.actions.githubusercontent.com`
- **Audience**: `api://AzureADTokenExchange` (the GitHub default)
- **Name**: free-text; use something readable like
  `github-<repo>-environment-<env>`.

The three names must agree: the GitHub Environment, the
`environment:` field in the workflow yaml, and the
`environment:<name>` segment of the federated credential subject.
If any differ by case or spelling, OIDC token exchange fails with
AADSTS700213.

## 5. Branch protection on `main`

`Settings → Branches → Branch protection rules → Add rule` (name
pattern: `main`). Required status checks (these are GitHub Actions
job names; spelling matters):

- `dco` — Developer Certificate of Origin
- `spdx-headers` — Apache 2.0 license headers
- `bandit` — Python static analysis (security)
- `semgrep` — Python static analysis (style + security)
- `cli-smoke` — CLI imports + smoke tests
- `pytest` — full unit suite
- `gitleaks` — secret scan
- `actionlint` — workflow YAML lint
- `coverage` — MITRE coverage report (informational, not a true gate)
- `production-promotion-check` — gates human-authored promotions

Plus:
- Require linear history — **only on the operator repo.** Forks that
  pull from the public mirror via the merge flow in
  [`upstream-sync.md`](upstream-sync.md) must leave this **off**:
  sync PRs (and especially the one-time
  [unrelated-histories stitch](upstream-sync.md#4-one-time-stitch--fork-with-unrelated-history))
  must land as true merge commits, and linear-history protection
  forces squash/rebase, which destroys the stitch.
- Do not allow force pushes
- Do not allow deletions
- Require signed commits (recommended)
- Require pull request before merging (1+ reviewer)

## 6. Scheduled workflows — re-point the repo-slug gate

Eleven workflows gate their **cron runs** on the operator's repo slug
so nightly automation never fires on the public code-only mirror:

```yaml
if: github.event_name != 'schedule' || github.repository == 'KustoKing/SIEMContent'
```

That gate also skips **your fork**: enable `drift.yml`, `collect.yml`,
`conformance.yml`, etc. and the scheduled runs will queue, evaluate
the gate, and silently no-op. (Manual `workflow_dispatch` runs are
unaffected — which is why a workflow can "work when I click it" yet
never fire on cron.)

One-time fix — replace the slug with your own repo across the
workflow files:

```powershell
# PowerShell, from the repo root
Get-ChildItem .github/workflows/*.yml | ForEach-Object {
  (Get-Content $_ -Raw) -replace 'KustoKing/SIEMContent', '<org>/<repo>' |
    Set-Content $_ -NoNewline
}
```

```bash
# bash / zsh
grep -rl "KustoKing/SIEMContent" .github/workflows/ \
  | xargs sed -i 's#KustoKing/SIEMContent#<org>/<repo>#g'
```

Commit with `--signoff` and push. **Re-apply after any upstream sync
that overwrites workflow files** — the `-X theirs` stitch merge in
[`upstream-sync.md` §4](upstream-sync.md#4-one-time-stitch--fork-with-unrelated-history)
does exactly that.

## 7. Verification — does this work?

After §1–§4 are wired:

```powershell
# Conformance L7 reads GitHub repo settings via gh CLI.
$env:GITHUB_REPOSITORY = "<org>/<repo>"
python -m contentops conformance --scope L7
```

Expected: all four secrets/variables checks pass, all environments
listed exist, all federated credentials present, branch protection
required checks include the eight names above.

If L7 reports any missing pieces, the failure message points at the
exact setting + the `gh` command to fix it.

For the full picture (L1–L7), drop the `--scope` flag.

## Common failure modes + fixes

| Symptom | Root cause | Fix |
|---|---|---|
| `Error: tenant-config-yaml input is empty and config/tenant.yml is missing.` | `TENANT_CONFIG_YAML` secret unset or set on the wrong repo | `Get-Content config\tenant.yml -Raw \| gh secret set TENANT_CONFIG_YAML --repo <org>/<repo>` |
| `AADSTS700213` from azure/login step | Federated credential subject doesn't match the workflow's `environment:` value | Compare the GitHub Environment name, workflow yaml `environment:`, and federated credential `subject` — all three must match exactly. |
| Workflow run says success but skipped everything | Workspace not configured (e.g. no `integration` workspace in `tenant.yml`) | This is graceful skip, not failure — see the workflow's step summary. |
| Scheduled workflow never fires on your fork (manual dispatch works) | Cron runs are gated on the operator repo slug (`github.repository == 'KustoKing/SIEMContent'`) | Re-point the gate to your own `<org>/<repo>` — see [§6](#6-scheduled-workflows--re-point-the-repo-slug-gate). |
| DCO check fails on an upstream-sync PR with commits you didn't author | Upstream mirror commits carry no `Signed-off-by`; an old `dco.yml` predates the mirror-author skip | Sync `dco.yml` from upstream (it skips mirror-authored commits). **Never** `git rebase --signoff` a sync branch — it destroys the stitch merge ([upstream-sync.md §4](upstream-sync.md#4-one-time-stitch--fork-with-unrelated-history)). |
| `GitHub Actions is not permitted to create or approve pull requests` on `collect` / `drift` / other auto-PR workflows | Org (or repo) policy disables PR creation by the built-in `GITHUB_TOKEN` | Preferred: enable `Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"` (if greyed out at repo level, an org admin must enable it at org level first). If the policy is intentional: set the `AUTO_PR_TOKEN` secret (see [§2](#2-secrets)) — the workflows use it automatically. PAT caveats: orgs can hold new fine-grained PATs in a pending state until an admin approves them. PATs **expire** — an expired or revoked PAT is still a non-empty secret, so it does not fall back to `GITHUB_TOKEN`; the PR step fails with `HttpError: Bad credentials`. GitHub emails the token owner ~1 week before expiry. When that arrives: re-issue the PAT and `gh secret set AUTO_PR_TOKEN --repo <org>/<repo>`. To avoid this entirely, set expiration to "No expiration" when creating the fine-grained PAT (if your org policy allows it). A failed run may leave a half-pushed `collect/<run_id>`-style branch behind (the branch push succeeds, the PR creation doesn't) — delete it or ignore it. |
| `gitleaks` fails with "missing license" on org repo | `GITLEAKS_LICENSE` not set | Either set the secret once the license email arrives, OR remove `secret-scan.yml` if your org has GitHub Advanced Security covering the same ground. |
| Workflow can't see secret defined at environment level | The workflow doesn't declare `environment:` matching that env | Either move the secret to repo-level (visible to all workflows), or add `environment: <env>` to the workflow's job-level config. |

## See also

- [`authentication-setup.md`](authentication-setup.md) — the Azure
  side: App Reg creation, Graph permissions, Sentinel RBAC.
- [`tenant-config-modes.md`](tenant-config-modes.md) — different
  tenant-config sourcing modes (committed vs. secret vs. vars+split).
- [`deployment-conformance.md`](deployment-conformance.md) — what L1–L7
  conformance checks actually verify.
- [`docs/quickstart.md`](../quickstart.md) — adopter onboarding flow
  with locked-down-Windows recipes.
