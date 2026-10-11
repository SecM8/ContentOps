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
| `CONTENTOPS_SCHEDULES` *(deployment forks)* | `true` | Opts this repo in to scheduled (cron) runs. Unset leaves scheduled runs inactive. Not sensitive — see [§6](#6-scheduled-workflows--opt-in-with-contentops_schedules); the setting lives in repo configuration and is unaffected by upstream sync. |
| `CONTENTOPS_LAND_VIA_PR` *(ruleset-protected `main`)* | `true` | Switches the three generated-output workflows (`status-refresh.yml`, `coverage.yml`, `report.yml`) from a direct `git push` to `main` to **one rolling pull request each** — fixed branches `status/refresh`, `coverage/refresh`, `report/refresh`, updated in place on every run via the shared `auto-pr` action. Set it when a branch ruleset on `main` requires a pull request or a required workflow: direct pushes are then rejected with `GH013: Repository rule violations found for refs/heads/main`, and no token permission bypasses that. Unset = direct push (the upstream default; upstream `main` is unprotected). Pair it with `AUTO_PR_TOKEN` ([§2](#2-secrets)) so the rolling PRs' required workflows run without a manual *Approve and run*. Not sensitive; lives in repo settings and survives upstream sync. Validation checklist: [`protected-fork-validation.md`](protected-fork-validation.md). |
| `CONTENTOPS_ALERTS_PAGE_SIZE` *(optional)* | `alerts_v2` `$top` page size for `alerts-report.yml`. Default 500. **`999` is validated for a tested workload** and may reduce pagination for busy tenants. Verify the returned alert total after changing it: Graph may silently cap an over-large `$top`, which can drop data. Not sensitive; it's a tuning knob, so a Variable. |

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
| `GITLEAKS_LICENSE` | Your free org license key from https://gitleaks.io/. A repo-level or org-level secret both work: when both exist the repo-level one wins (the Settings UI's "overrides an organization secret" notice is informational, not an error). An organization secret your repo can access is still invisible to the action until the workflow passes it through — `secret-scan.yml` does so with `GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}` under the gitleaks step's `env:`. A repo/org **Variable** is honoured only if you swap in the commented `secrets.GITLEAKS_LICENSE \|\| vars.GITLEAKS_LICENSE` line in that step (the secret wins when both are set; Variables are not masked in logs, so prefer the secret). | Required for `secret-scan.yml` once your repo is org-owned — `gitleaks-action` checks the owner type at runtime and refuses to scan an org repo without a key (v3.0.0 only checks that the key is present; the historical per-repository activation cap is not enforced by it). If your organization also mandates gitleaks as a **required workflow** through a ruleset, that organization-owned workflow has its own licence wiring — removing or disabling `secret-scan.yml` here does not remove the organization rule. Adopter shortcut: skip the local pre-commit hook + wait for the license before pushing. |
| `AUTO_PR_TOKEN` | Fine-grained PAT. **Token contract:** resource owner = your **organization** (not a personal namespace); repository access = **this repo only**; permissions **Contents: Read and write**, **Pull requests: Read and write** (Metadata: Read is implied). Add **Workflows: Read and write** only if a branch this token pushes can change `.github/workflows/*` — an upstream-sync branch does, the generated-output PRs never do. Record the token's **owner, expiry date and rotation procedure** next to the secret. The owner must **not** be the only code owner of the paths the automation writes: a PR author cannot approve their own PR, and `CODEOWNERS` uses the *last* matching pattern — prefer a machine user, or a team member who is not the sole owner (see the comments in [`.github/CODEOWNERS`](../../.github/CODEOWNERS)). The ten PR-opening workflows (`collect`, `drift`, `kql-schemas-refresh`, `attack-matrix-refresh`, `upstream-watchers`, `lock-unlock`, `emergency-disable`, and — in PR-landing mode — `status-refresh`, `coverage`, `report`) use it when present and fall back to the built-in `GITHUB_TOKEN` when the secret is **empty**. The fallback is visible: the `auto-pr` action emits a `::warning::` and a step-summary entry whenever it opens a PR with `GITHUB_TOKEN`. Why it matters: a PAT-opened PR starts its `on: pull_request` workflows automatically; a `GITHUB_TOKEN`-opened PR gets those runs **held for manual approval** (GitHub behaviour since 2026-06; before that they were not created at all), so under a ruleset that requires a workflow to pass, the PR cannot merge until someone with write access clicks *Approve and run* on its Checks tab. | Required when **(a)** your org disables `Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"` — the run fails with `GitHub Actions is not permitted to create or approve pull requests` — **or (b)** a branch ruleset on `main` requires a workflow to pass before merging and you want automation PRs to merge without a manual *Approve and run* every time. Otherwise optional. **Never leave a pending or expired PAT in place:** a non-empty secret is used as-is and fails every auto-PR run with `403 Write access to repository not granted` / `Bad credentials`. Get it approved or renewed, or delete the secret so the `GITHUB_TOKEN` fallback (with its manual step) takes over. |

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
| `production` | `deploy.yml` | Apply detection content to production Sentinel workspaces. The most-protected environment. |
| `integration` | `integration-deploy.yml` (PR-time), `integration.yml` (live test suite, PR label `run-integration` or manual), `promote-to-integration.yml`, `e2e-capability-tests.yml` (live mode) | Apply content to your integration workspace as a PR-time smoke test; run the live-tenant integration tests; copy prod state into integration for parity testing. Skip if you don't have a separate integration workspace. |
| `automation` | `drift.yml` (incl. the PR-time `drift-pr` job), `tuning-impact-preview.yml` (PR-time), `defender-graph-probe.yml`, `silent-rules.yml`, `kql-schemas-refresh.yml` | Read-only workflows (drift detection, suppression blast-radius preview, Defender Graph endpoint probing, silent-rule reporting). Separated from `production` so deploy protections don't slow down nightly automation. |
| `conformance` (optional) | `conformance.yml` (write-identity leg) | Where `contentops conformance` authenticates **as the write identity** to verify its grants. Only needed if you run the dual-identity conformance check (the read leg runs on `automation`). |
| `reporting` | `coverage.yml`, `report.yml` | Where the MITRE coverage layer / badge and the detection inventory report are rendered. Repo-axis only — neither job requests `id-token`, so no federated credential is needed. Create it **unprotected**: both jobs run on pull requests and on push-to-main and must not wait for a reviewer. |
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
| Required reviewers | At least 1 (gates manual `workflow_dispatch` of `deploy.yml`) | 0 for a fully automatic PR smoke test, **or** 1+ with *Prevent self-review* if not every writer should hold the integration identity (see below) | 0 (read-only) |
| Wait timer | 0 | 0 | 0 |
| Deployment branch policy | Only `main` | `main` + PR refs (`refs/pull/*/merge`) | `main` + PR refs (`refs/pull/*/merge`) — `drift-pr` and `tuning-impact-preview` run on PRs |

**PR jobs run the PR's own code.** A pull-request job runs with the
identity of its environment, and it runs before review. So anyone who
can push a branch to this repository can act as that identity. Forks
are excluded: they get no OIDC token, and every credentialed PR job
skips them. Keep these identities small:

- **`integration`:** use a dedicated App Registration whose RBAC covers
  only the integration workspace's resource group, not the production
  write identity. If that is not possible, require a reviewer on the
  environment.
- **`automation`:** use the **read** App Registration (see the split
  note above).

[`SECURITY.md`](../../SECURITY.md#ci-trust-model-for-pull-requests)
has the full trust model.

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
- **Require linear history** only if you do not need upstream-sync merge
  commits. Repositories that pull from the public mirror using the
  procedure in [`upstream-sync.md`](upstream-sync.md) must leave this
  **off**:
  sync PRs (and especially the one-time
  [unrelated-histories stitch](upstream-sync.md#4-one-time-stitch--fork-with-unrelated-history))
  must land as true merge commits, and linear-history protection
  forces squash/rebase, which destroys the stitch.
- Do not allow force pushes
- Do not allow deletions
- Require signed commits (recommended)
- Require pull request before merging (1+ reviewer)

### Rulesets are equivalent — and stricter for automation

Many organizations enforce the same policy through **rulesets**
(`Settings → Rules → Rulesets`, or organization-wide rules you cannot
edit from the repository) instead of a classic branch protection rule.
Two consequences for this pipeline:

- A ruleset that **requires a pull request** or **requires a workflow to
  pass before merging** rejects every direct push to `main` — including
  the pipeline's own `git push origin HEAD:main` in `status-refresh.yml`,
  `coverage.yml` and `report.yml` — with `GH013: Repository rule
  violations found for refs/heads/main`. No token permission bypasses a
  ruleset without a bypass actor (and granting one defeats the policy).
  Set the repo variable `CONTENTOPS_LAND_VIA_PR=true`
  ([§1](#1-variables-not-secrets--theyre-public-identifiers)) so those workflows open rolling PRs
  instead, and set `AUTO_PR_TOKEN` ([§2](#2-secrets)) so the PRs'
  required workflows start automatically.
- Policy and implementation are two layers. Removing or disabling a
  scanner in this repository's YAML (for example `secret-scan.yml`) does
  **not** remove an organization-level required-workflow rule that
  mandates the same scan; change both together or the merge gate stays
  red while CI looks changed.

`contentops conformance` L7 currently reads the classic branch-protection
API only, so on a ruleset-protected `main` it reports the branch as
unprotected. Verify rulesets by hand until the check learns about them:

```bash
gh api repos/<org>/<repo>/rules/branches/main
```

The end-to-end checklist for a fork under such rules is
[`protected-fork-validation.md`](protected-fork-validation.md).

## 6. Scheduled workflows — opt in with `CONTENTOPS_SCHEDULES`

Scheduled workflows are inactive by default on the public code-only
mirror and in deployment forks. This prevents unconfigured repositories
from running tenant-facing automation.

Out of the box this applies to **your fork** too: enable
`drift.yml`, `collect.yml`, `conformance.yml`, etc. and the scheduled
runs will queue, evaluate the opt-in gate, and silently no-op. (Manual
`workflow_dispatch` runs are unaffected — which is why a workflow can
"work when I click it" yet never fire on cron.)

One-time fix — set one repo **variable**. No workflow edits:

```powershell
# PowerShell or bash, from anywhere
gh variable set CONTENTOPS_SCHEDULES --body true -R <org>/<repo>
```

Or in the UI: *Settings → Secrets and variables → Actions → Variables
tab → New repository variable*, name `CONTENTOPS_SCHEDULES`, value
`true`.

Why a variable and not an edit: the variable lives in repo settings,
not in the workflow files, so an upstream sync never overwrites it and
never conflicts on it. Leave it unset in repositories where scheduled
tenant-facing workflows are not configured.

If you previously edited workflow files to enable schedules, restore
the upstream versions and set the variable instead. To confirm it is
set:

```bash
gh variable list -R <org>/<repo>
```

**A manual run proves the workflow, not the cron.** `workflow_dispatch`
bypasses the opt-in gate, so a green manual run says nothing about
whether scheduled runs are eligible. To tell a *policy skip* from a
*broken cron*: a gated scheduled run does appear in the Actions tab, with
every job marked **skipped** (grey) — that is this policy, not a failure.
A cron slot that produces **no run at all** points elsewhere: GitHub
disables schedules after 60 days without repository activity, Actions is
disabled for the repository, or the workflow file on the default branch
has no `schedule:` trigger. After setting the variable, wait for the next
slot ([`workflow-schedule.md`](workflow-schedule.md)) and confirm the run
*executed* (not skipped) before declaring the deployment ready.

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
| `AADSTS700213` from azure/login step | Federated credential subject doesn't match the token's `sub` claim: the environment name differs, or the **subject format** does — repositories created after 2026-07-15 emit `repo:<org>@<org-id>/<repo>@<repo-id>:environment:<env>` instead of `repo:<org>/<repo>:environment:<env>` (verified 2026-10-11; re-check after GitHub platform changes) | Read the subject GitHub actually sent from the error text (`presented assertion subject '<sub>'`) and create the federated credential with exactly that issuer + subject + audience. Compare the GitHub Environment name, workflow yaml `environment:`, and federated credential `subject` — all three must match exactly. See [authentication-setup.md, step 3](authentication-setup.md#step-3-add-an-oidc-federated-credential-for-ci). |
| Workflow run says success but skipped everything | Workspace not configured (e.g. no `integration` workspace in `tenant.yml`) | This is graceful skip, not failure — see the workflow's step summary. |
| Scheduled workflow never fires on your deployment repo (manual dispatch works) | Scheduled runs are inactive until the repo opts in | Set the repo variable `CONTENTOPS_SCHEDULES=true` — see [§6](#6-scheduled-workflows--opt-in-with-contentops_schedules). |
| DCO check fails on an upstream-sync PR with commits you didn't author | Upstream mirror commits carry no `Signed-off-by`; an old `dco.yml` predates the mirror-author skip | Sync `dco.yml` from upstream (it skips mirror-authored commits). **Never** `git rebase --signoff` a sync branch — it destroys the stitch merge ([upstream-sync.md §4](upstream-sync.md#4-one-time-stitch--fork-with-unrelated-history)). |
| `GitHub Actions is not permitted to create or approve pull requests` on `collect` / `drift` / other auto-PR workflows | Org (or repo) policy disables PR creation by the built-in `GITHUB_TOKEN` | Preferred: enable `Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"` (if greyed out at repo level, an org admin must enable it at org level first). If the policy is intentional: set the `AUTO_PR_TOKEN` secret (see [§2](#2-secrets)) — the workflows use it automatically. PAT caveats: orgs can hold new fine-grained PATs in a pending state until an admin approves them. PATs **expire** — an expired or revoked PAT is still a non-empty secret, so it does not fall back to `GITHUB_TOKEN`; the PR step fails with `HttpError: Bad credentials`. GitHub emails the token owner ~1 week before expiry. When that arrives: re-issue the PAT and `gh secret set AUTO_PR_TOKEN --repo <org>/<repo>`. To avoid this entirely, set expiration to "No expiration" when creating the fine-grained PAT (if your org policy allows it). A failed run may leave a half-pushed `collect/<run_id>`-style branch behind (the branch push succeeds, the PR creation doesn't) — delete it or ignore it. |
| `dco` fails on a `collect` / `drift` (or other auto-PR) PR with "missing a Signed-off-by trailer" | A PAT-opened PR (via `AUTO_PR_TOKEN`) is authored by the PAT owner — a real account, not on the `dco.yml` bot bypass list — and the `auto-pr` action's commit needs a sign-off trailer | Fixed upstream: `auto-pr` now passes `signoff: true` to `create-pull-request`, so every automated commit carries the trailer. Make sure your fork has synced that change (`Select-String AUTO_PR_TOKEN .github/actions/auto-pr/action.yml` *and* `Select-String signoff .github/actions/auto-pr/action.yml`). The fix only matters once collect PRs trigger `pull_request` CI, which only happens on the PAT path. |
| `production-promotion-check` rejects *every* rule on your first `collect` ("rejecting N promotion(s) without a fresh lifecycle.promotedAt stamp") | First collect of a **brownfield** tenant (one that already has production rules) imports them all at once; each looks like a new production promotion. The gate has a `chore(collect\|drift):` skip, but an older copy read the `pull_request` merge commit's subject (`Merge … into …`), so the skip never fired | Fixed upstream: the gate now reads the PR head-commit subject via `$HEAD_SHA`, so collect/drift PRs skip the promotion gate as intended (collected content mirrors already-promoted tenant rules — not a human promotion). Sync the fix, then re-run the check (or re-run collect). These rules are stamped going forward by `contentops lifecycle promote`; the initial import is the one-time baseline. |
| `gitleaks` fails with "missing gitleaks license" on org repo | `GITLEAKS_LICENSE` not set — or set but not passed through: the action only reads the `GITLEAKS_LICENSE` env var, so a secret that exists in Settings but is missing from the gitleaks step's `env:` block is invisible to it | Set the secret (repo- or org-level) once the license email arrives, and check that the gitleaks step in `secret-scan.yml` has `GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}` under `env:`. OR remove `secret-scan.yml` if your org has GitHub Advanced Security covering the same ground. |
| `gitleaks` flags `config/tenant.yml` on a Mode A fork (file committed on purpose) | The upstream `.gitleaks.toml` rules target that file because upstream never commits it | Uncomment the `config/tenant\.yml$` entry under `[allowlist] paths` in `.gitleaks.toml` — see [tenant-config-modes.md, Mode A](tenant-config-modes.md#mode-a--committed-tenantyml-private-corp-fork). |
| `remote: error: GH013: Repository rule violations found for refs/heads/main` (`Required workflow '<name>' is not satisfied` / `Changes must be made through a pull request`) on `status-refresh` / `coverage` / `report` | A ruleset on `main` requires a pull request and/or a required workflow; direct pushes are rejected whatever token is used | Set the repo variable `CONTENTOPS_LAND_VIA_PR=true` ([§1](#1-variables-not-secrets--theyre-public-identifiers)) — the three workflows then open rolling PRs via `auto-pr`. Do **not** widen token permissions to work around it; they cannot bypass a ruleset. |
| Automation PR exists but its checks never start (no required-workflow run; PR stays "not mergeable"; runs show *action required*) | The PR was opened with the built-in `GITHUB_TOKEN`: GitHub holds `pull_request` runs from such PRs for manual approval (older behaviour: did not create them). The `auto-pr` step summary says `token fallback: GITHUB_TOKEN` | One-off recovery: open the PR → Checks tab → *Approve and run* (or close and reopen it), then request the code-owner review. Permanent fix: set an **approved** `AUTO_PR_TOKEN` ([§2](#2-secrets)) — PAT-opened PRs start their workflows automatically. |
| `remote: Write access to repository not granted.` / `fatal: unable to access ... 403` from the `auto-pr` push | A **non-empty** `AUTO_PR_TOKEN` that cannot write: still pending organization approval (fine-grained PATs on org repositories can only read public resources until an owner approves them), wrong resource owner or repository access, missing `Contents: Read and write`, or expired / revoked. A 403 alone does not say which | Check those four in that order (the token's page under *Developer settings → Fine-grained tokens* shows approval state and scopes). While the PAT is unusable, **delete the secret** rather than leave it: an empty secret falls back to `GITHUB_TOKEN` (visible warning, manual approve-and-run); a broken one fails every auto-PR run. |
| Automation PR cannot get a code-owner approval ("Review required" never clears, no eligible reviewer) | The PR author — the PAT owner — is the only code owner matched by the **last** `CODEOWNERS` pattern for the written path (e.g. `docs/**` for `docs/status/**`), and authors cannot approve their own PRs | Open the PRs with a machine-user PAT (or let `GITHUB_TOKEN` open them: the author is then a bot), or route the automation-written paths (`docs/status/**`, `coverage/**`, `reports/**`) to a team with another eligible reviewer in your fork's `CODEOWNERS`. Last matching pattern wins — put the override *after* the broader `docs/**` line. |
| `auto-pr` fails at `git stash pop`: `error: Your local changes to the following files would be overwritten by merge: config/tenant.yml` | A tracked file is committed with CRLF line endings while `.gitattributes` says `*.yml text eol=lf` (typical for a Mode A `config/tenant.yml` committed from Windows). Git reports it modified in every fresh checkout, and `create-pull-request`'s stash / reset / pop aborts. Every auto-PR workflow on the fork fails until this is fixed | In the **private** fork only: `git ls-files --eol -- config/tenant.yml` (an `i/crlf` column = needs repair), then `git add --renormalize -- config/tenant.yml` and commit the line-ending-only change — [tenant-config-modes.md, Mode A step 5](tenant-config-modes.md#mode-a--committed-tenantyml-private-corp-fork). Not applicable to Mode B. |
| Conformance **read** leg fails `L4 least_privilege` / `L5 rbac_write` on a deployment that deliberately shares one App Registration | Dual-identity expectations applied to a shared, write-capable identity | Declare `identity_mode: single` in `.contentops-conformance.yml` and accept the documented trade-off ([deployment-conformance.md](deployment-conformance.md#single-app-registration-deployments-identity_mode-single)). Do not relax the split-mode checks globally. |
| Workflow can't see secret defined at environment level | The workflow doesn't declare `environment:` matching that env | Either move the secret to repo-level (visible to all workflows), or add `environment: <env>` to the workflow's job-level config. |

## See also

- [`protected-fork-validation.md`](protected-fork-validation.md) — the
  layered checklist for a deployment fork under organization rulesets
  (PR landing, automation token, required workflows, reviewability,
  line endings, schedules, identity).
- [`authentication-setup.md`](authentication-setup.md) — the Azure
  side: App Reg creation, Graph permissions, Sentinel RBAC.
- [`tenant-config-modes.md`](tenant-config-modes.md) — different
  tenant-config sourcing modes (committed vs. secret vs. vars+split).
- [`deployment-conformance.md`](deployment-conformance.md) — what L1–L7
  conformance checks actually verify.
- [`docs/quickstart.md`](../quickstart.md) — adopter onboarding flow
  with locked-down-Windows recipes.
