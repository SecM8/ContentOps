# Quickstart — get started with ContentOps

There are three valid adopter paths. Pick yours first, then follow the
matching steps. Most local-setup friction comes from running the wrong
path's instructions on a machine that doesn't support them.

## Three adopter personas — pick yours

| Persona | Local Azure auth needed? | What runs locally | What runs in CI |
|---|---|---|---|
| **Author-only** (recommended for restricted devices) | None | `clone`, edit YAML under `detections/`, `python -m contentops lint`, `python -m contentops new`, `python -m contentops doctor` (L1 install check only) | Every Azure call: `apply`, `plan`, `conformance` L3+, drift detection |
| **Local-test** (you have `az login` permissions) | `az login` as your user | Everything above plus `plan --dry-run`, `conformance` end-to-end | Real `apply` (still in CI for audit-trail integrity) |
| **CI-mirror** (you want to reproduce CI exactly) | `.env` with App Registration client secret | Everything above plus real `apply` | Nothing — local matches CI exactly |

Security engineers on locked-down workstations, contractors without
tenant access, and most content authors should pick **Author-only**.
You can ship rules without ever running `az login` on your laptop —
GitHub Actions does every Azure call via OIDC federation. The rest of
this guide is structured so you can stop at Step 4 (lint + push) if
that's your path.

## Prerequisites

- Python 3.12+
- `git`
- A clone of either the public mirror
  (`https://github.com/SecM8/ContentOps`) or your private fork.
- For **Local-test** persona: `az` CLI (`az login` access to the
  target tenant; your user needs `Microsoft Sentinel Contributor` on
  the workspace's resource group).
- For **CI-mirror** persona: An Azure App Registration with OIDC
  federated credentials (and Sentinel RBAC on its service principal).
  See [`docs/operations/authentication-setup.md`](operations/authentication-setup.md).

---

## 1. Clone + Python install (3 min)

```powershell
git clone https://github.com/SecM8/ContentOps.git
cd ContentOps
python -m venv .venv
```

Activate the venv (per platform):

```powershell
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Windows cmd.exe:
.venv\Scripts\activate.bat

# macOS / Linux (bash / zsh):
source .venv/bin/activate
```

If you get an execution-policy error on activation:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then install:

```powershell
python -m pip install -r requirements.txt
python -m pip install -e .
python -m contentops --version
```

We use `python -m pip` (not bare `pip`) and `python -m contentops`
(not bare `contentops`) deliberately. See **"Locked-down corporate
Windows"** below for why — short version: corporate endpoint security
(Device Guard / AV) sometimes blocks pip-installed `.exe` shims but
always allows invocation through Python.

---

## 2. Wire credentials — pick your path

### Author-only persona: skip this step entirely

You don't need Azure credentials. Skip to step 3 and ignore steps 4–7.

### Local-test persona: `az login`

```powershell
az login
az account show     # verify it landed on the right tenant + subscription
```

Then copy the tenant config template:

```powershell
copy config\tenant.yml.example config\tenant.yml
# Edit config/tenant.yml — replace the placeholder GUIDs and names
# with your subscription, resource group, workspace name, location.
```

Your `.env` stays empty or unused — `DefaultAzureCredential` falls
through to `AzureCliCredential` which picks up your `az login` token.

### CI-mirror persona: `.env` with App Reg secret

```powershell
copy .env.example .env
copy config\tenant.yml.example config\tenant.yml
```

Fill `.env` with `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
`AZURE_CLIENT_SECRET`. Fill `config/tenant.yml` with subscription /
RG / workspace details. Both files are gitignored.

### What permissions does the identity need?

Whichever auth path you pick, grant the identity only what you actually
use — the pipeline degrades gracefully (read-only works; read-write works;
the two optional Graph scopes can be omitted). Full detail +
admin-consent steps in
[`operations/authentication-setup.md`](operations/authentication-setup.md#step-2-grant-the-app-registration-its-permissions).

| Surface | Read-only | Read-write (deploy) | Optional? |
|---|---|---|---|
| Microsoft Sentinel (Azure RBAC) | Sentinel **Reader** (+ LA Reader) | Sentinel **Contributor** (+ LA Contributor) | needed only if you manage Sentinel content |
| Defender custom detections (Graph) | `CustomDetection.Read.All` | `CustomDetection.ReadWrite.All` | needed only if you manage Defender detections |
| Advanced hunting schema (Graph) | `ThreatHunting.Read.All` | — | **optional**: omit + set `defender.enabled: false` |
| Security alerts (Graph) | `SecurityAlert.Read.All` | — | **optional**: omit → alert telemetry falls back to Sentinel KQL or goes unused |

- **Only read granted** → `lint` / `collect` / `drift` / `coverage` /
  `report` / `silent-rules` all work; you just can't `apply`.
- **Read-write granted** → deploy works too.
- **No `ThreatHunting` / `SecurityAlert`** → those optional features turn
  off cleanly; nothing else is affected.

---

## 3. Verify the install

Local-only sanity check, no Azure call:

```powershell
python -m contentops doctor
```

L1 checks: Python version, package import, envelope parse, git. All
adopter personas should see green here.

For **Author-only** persona, you're done with setup. Skip to
**Author your first detection** below.

For **Local-test** and **CI-mirror**, run the layered diagnostic:

```powershell
python -m contentops doctor --matrix
python -m contentops conformance
```

The matrix exercises real Azure reads. `conformance` runs L1–L7 in
order with explicit remediation hints on failure.

### Diagnostic decoder — 401 vs 403

When `doctor --matrix` or `conformance` shows an auth failure on a
Sentinel or Graph endpoint, the HTTP status code matters:

| Status | Meaning | Fix |
|---|---|---|
| **401 Unauthorized** | The token itself was rejected. Wrong tenant context, expired, or `DefaultAzureCredential` returned a stale cached identity (SharedTokenCache / VSCode) instead of the one `az login` minted. | First try `$env:AZURE_TOKEN_CREDENTIALS = "dev"` to force the dev-credential chain. If that fixes it, you hit a known credential-chain ordering issue on multi-identity machines. Then verify `az account show` matches `tenant.yml`. |
| **403 Forbidden** | Authenticated successfully, but the identity lacks RBAC on this resource. | Grant `Microsoft Sentinel Contributor` on the workspace's resource group to whichever identity is active — your user on Path A, the App Reg on Path B. RBAC propagation can take 5–15 minutes. |
| **500 / other 5xx** | Service-side issue, often transient. | Retry; if persistent, check Azure Service Health. |

---

## 4. Author your first detection

Scaffold:

```powershell
python -m contentops new sentinel_analytic my-first-rule
```

Edit `detections/sentinel_analytic/my-first-rule.yml`. The scaffold
emits `TODO (METAxxx): ...` placeholders for required authoring
metadata. Replace them as you fill in the rule. Until you move
`status` past `experimental`, the lint stays gentle (warnings only,
no CI block).

Minimum content to make a real rule:

- Non-empty `description` and `attackDescription` (META002/003).
- At least one entry in `tactics` and `techniques` (PAYLOAD003).
- A real `query:` block under `payload`.
- An `owner` email and `runbookUrl`.

> **First time?** A full walkthrough — from "what am I detecting?"
> through to "promoted to production" — lives at
> [`docs/tutorials/your-first-detection.md`](tutorials/your-first-detection.md).
> Use it instead of this section if you want a copy-pasteable
> example with a real KQL query, MITRE tags, and the lifecycle
> promote flow.

---

## 5. Lint locally

Works on all adopter personas — no Azure auth required:

```powershell
python -m contentops lint --strict
```

`lint --strict` is what CI runs; fixing locally means the PR is green
from the first push.

> **Heads up — META002–005 default since PR #241.** A fresh
> `config/tenant.yml` runs the META authoring rules in **lenient**
> mode (warnings, not CI-blocking errors). This matches the
> operational reality that the G24 authoring backlog still exists
> on collected envelopes — adopters shouldn't get blocked the
> moment they configure tenant.yml. Set
> `policy.scaffoldStrict: true` explicitly once your team has
> drained the authoring backlog and wants META002–005 to gate CI.

---

## 6. Preview the plan (Local-test or CI-mirror only)

Static plan — no API calls:

```powershell
python -m contentops plan
```

For a **live preview** that shows what apply will actually do
against the tenant (CREATE / UPDATE / NO-CHANGE / ORPHAN-IN-TENANT),
add `--against-tenant`:

```powershell
python -m contentops plan --against-tenant --role integration
```

Read-only — shows what would change in the tenant, no writes. The
overlay is fail-soft so fork PRs / offline runs still work; the
counts come back as `-` when OIDC isn't available.

---

## 7. Apply

Author-only adopters: open a PR. CI applies on merge to main.

Local-test / CI-mirror adopters can dry-run:

```powershell
python -m contentops apply --dry-run
```

Then real apply:

```powershell
python -m contentops apply
```

---

## 8. Explore what's deployed — visibility commands

The 2026-05-22 sprint cluster added several read-only commands that
help you understand the tenant's coverage and health. None of these
mutate state.

| Command | What it shows |
|---|---|
| `python -m contentops navigator --since 365 --out tmp.json` | A MITRE ATT&CK Navigator layer JSON aggregating three axes (repo envelopes + deployed rules + live alert firings). Upload to https://mitre-attack.github.io/attack-navigator/ to visualise. |
| `python -m contentops coverage --gaps` | Inverse heatmap — which ATT&CK techniques you DON'T cover. |
| `python -m contentops coverage --d3fend` | MITRE D3FEND defensive-axis coverage report (companion to ATT&CK). Reads `metadata.defensiveTechniques: [D3-XXX]`. |
| `python -m contentops silent-rules --since 30` | Rules that fired zero alerts in the lookback window. |
| `python -m contentops auto-disabled-rules --since 7` | Rules **Sentinel itself disabled** (consecutive failures, schema break). Distinct from silent rules. Requires the `SentinelHealth` diagnostic to be enabled on the workspace. |
| `python -m contentops portfolio --with-telemetry --out-csv portfolio.csv` | Flat per-detection report with `alerts_30d`, `incidents_30d`, `closed_fp_30d`, `fp_rate`. |
| `python -m contentops detection-docs regenerate` | Renders every envelope to `docs/detections/<asset>/<id>.md` — browsable per-rule documentation. |

If a step fails, the error message points at the fix — and every
real error you might hit is indexed in
[`docs/troubleshooting.md`](troubleshooting.md).

---

## Locked-down corporate Windows — what to expect

Many corporate Windows machines run Device Guard / Microsoft Defender
Application Control (WDAC) and/or endpoint AV that blocks unsigned
executables, throttles parallel subprocess invocations, and sometimes
blocks specific Rust extension DLLs. The full adopter test we ran in
May 2026 hit every one of these. Here's what you'll see and how to
work through it.

### Device Guard blocks `cryptography._rust` DLL inside venv

**Symptom**:

```
ImportError: DLL load failed while importing _rust:
Your organization used Device Guard to block this app.
```

**Cause**: `azure-identity` depends on `cryptography`, which ships a
Rust-backed extension (`_rust.cp312-win_amd64.pyd`). The DLL inside
your venv's `site-packages` isn't on Device Guard's path allowlist
even though the same DLL elsewhere is allowed.

**Fix options**:
- **Use system Python** (no venv) — IT pre-approved system Python's
  `cryptography` install. Simplest path: `deactivate`, run
  `python -m pip install -e .` against system Python, retry.
- **Ask IT to allowlist** `%USERPROFILE%\.venv\Lib\site-packages\cryptography\hazmat\bindings\_rust*.pyd` paths.
- **Use conda / mamba** instead of pip — different binary layout that
  some Device Guard policies allow.

### `pip.exe` / `contentops.exe` blocked, but `python -m ...` works

Bare console scripts created by `pip install` are pre-approved
executables. Custom shims (`pip.exe` inside a venv, `contentops.exe`
from our package) sometimes aren't. Invocation through the Python
interpreter — `python -m pip`, `python -m contentops` — bypasses the
shim entirely because Python itself is always allowlisted.

This guide uses the `python -m` form throughout for that reason.

### `contentops collect` triggers subprocess throttling

When collecting from the tenant, each handler authenticates via
`AzureCliCredential`, which spawns `az.cmd` as a subprocess. The
default of 4 parallel workers spawns 4 simultaneous `az.cmd`
invocations on cold start. Some Device Guard / AV configurations
throttle this and the credential fails with "Failed to invoke the
Azure CLI."

**Fix**: drop to single-worker for the affected machines:

```powershell
python -m contentops collect --workers 1
```

The first token acquisition is slower but the token then caches and
subsequent handlers reuse it.

### `gitleaks` requires an org license

Gitleaks 8.21+ switched to a model where organizational use requires
a (free) license key from https://gitleaks.io/. The check looks at
the repo's owner; org-owned repos trigger the prompt.

**Recommended path** (lets you proceed today): skip
`pre-commit install` locally for now. The pre-commit gitleaks hook is
optional; CI's `secret-scan.yml` workflow runs gitleaks regardless,
and you can deal with the license when wiring CI. Get the license in
parallel — it usually arrives within hours.

**Alternative**: if your org has GitHub Advanced Security, native
secret scanning covers the same ground and you can remove
`secret-scan.yml` from your fork.

### SSO authorization on GitHub Enterprise Cloud

If your private fork is in a GitHub Enterprise Cloud organization
with SAML SSO, `git push` and `gh repo view` will return **404 Not
Found** (not 403) when your credential exists but isn't authorized
for the org. The 404 looks like the repo doesn't exist — but it does.

**Fix**:

```powershell
gh auth login --hostname github.com --web --scopes "repo,workflow,read:org"
```

Then complete the device-code flow in the browser. If your org uses a
PAT directly, open https://github.com/settings/tokens, find the PAT,
click **Configure SSO** next to it, **Authorize** the org.

---

## Public mirror sync cadence

The public mirror at `https://github.com/SecM8/ContentOps` is
rebuilt nightly from the private operator repo. It ships the **tool,
templates, samples, and docs** — never the operator's real detection
content, `config/tenant.yml`, or `audit/`/`state/` (an allowlist plus a
forbidden-paths safety check enforce that boundary). **You bring your own
detections** under `detections/<kind>/`. If you cloned recently and the
code looks older than expected (CLI banner says `pipeline` rather than
`contentops`, or you see asset kinds beyond the canonical six listed in
CLAUDE.md), the mirror just hadn't synced yet. Pull fresh:

```powershell
git fetch upstream
git pull --ff-only upstream main      # fast-forward your main to the mirror
git push origin main                  # update your fork
```

(Assumes you set up `upstream` as the public mirror remote per the
"Mirror into a private GitHub Enterprise repo" section of the README.)

### New install, update, or full reset

The three sync workflows — **first-time install**, **routine update**, and
a **full pristine reset** — are documented end-to-end in
[`operations/upstream-sync.md`](operations/upstream-sync.md), along with
the remote topology and how to make `upstream` un-pushable.

> **Watch out before a full reset:** `git clean -fdx` deletes
> **gitignored** files too — `config/tenant.yml` and `.venv/`, not just
> build artifacts. `-x` bypasses `.gitignore` **and** `.git/info/exclude`;
> only a command-line `-e` pattern survives. Always dry-run first:
> `git clean -nfdx -e config/tenant.yml -e .venv`, then drop the `-n`. Full
> walkthrough + recovery in
> [`operations/upstream-sync.md`](operations/upstream-sync.md#3-full-reset--pristine-match-to-upstream).

---

## Wiring CI/CD before your first push

Before opening a PR on a fresh fork, you need to configure GitHub
Actions Variables, Secrets, Environments, and federated credentials
on the App Registration. Without these, CI fails at the first
Azure-touching step.

The full setup is in
[`operations/github-actions-setup.md`](operations/github-actions-setup.md)
— it covers every secret/variable/environment with the exact `gh`
commands and federated-credential subjects. **Do this once per fork
before your first push.**

Short version of what you'll wire:

| Type | Name | When required |
|---|---|---|
| Variable | `AZURE_CLIENT_ID` | Always |
| Variable | `AZURE_TENANT_ID` | Always |
| Secret | `TENANT_CONFIG_YAML` | Always (`gh secret set` stdin form) |
| Secret | `GITLEAKS_LICENSE` | When org-owned + license email arrives |
| Environment | `production` | For deploy + live tests |
| Environment | `integration` | If you have a second workspace |
| Environment | `automation` | For cron workflows (drift, silent-rules, defender-graph-probe) |
| Federated credential | one per environment | OIDC subject `repo:<org>/<repo>:environment:<env>` |

## Next steps

- **First real rule, end-to-end:**
  [`docs/tutorials/your-first-detection.md`](tutorials/your-first-detection.md)
  walks the full lifecycle (author → lint → plan → apply →
  verify → promote) with a worked example.
- **Day-to-day operations:** [`docs/OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md)
  covers the daily flow, drift PR handling, and the
  when-things-break decision tree.
- **Hit an error?**
  [`docs/troubleshooting.md`](troubleshooting.md) indexes every
  real error we've encountered (Auth, Config, Lint, Apply, Drift,
  CI gates, Fork-PR limits, Workspace data) with the exact fix
  for each.
- **Unfamiliar term?** [`docs/glossary.md`](glossary.md) defines
  the recurring jargon (envelope, drift PR, scaffoldStrict, D3FEND,
  Navigator layer, env-status gate, etc.).
- **What commands / workflows exist?**
  [`docs/reference/generated-catalog.md`](reference/generated-catalog.md)
  is the code-derived inventory — every command, the
  Action→Function→Script→Workflow traceability matrix, lint rules,
  handlers, and workflows — kept in sync with the code by a CI drift gate.
- **Open a PR** with `detections/sentinel_analytic/my-first-rule.yml`.
  CI runs `lint --strict`, integration-deploy on the integration
  workspace (if configured), gitleaks, codespell, references URL
  check, and the other gates; `deploy.yml` ships to prod on merge.
