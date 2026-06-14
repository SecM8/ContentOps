# ContentOps powered by SecM8

> Security content lifecycle management for Microsoft Sentinel and Microsoft Defender XDR.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](pyproject.toml)
[![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange.svg)](docs/reference/roadmap.md)
[![Code of Conduct](https://img.shields.io/badge/contributor%20covenant-2.1-purple.svg)](CODE_OF_CONDUCT.md)
[![MITRE ATT&CK coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/SecM8/ContentOps/main/coverage/badge.json)](coverage/badge.json)
![Detection inventory](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/SecM8/ContentOps/main/reports/badge.json)

A Python CLI plus GitHub Actions pipeline that manages the full
lifecycle of detection rules across Microsoft Sentinel and
Microsoft Defender XDR from a single repo, single tenant, with Git
as the source of truth. Analysts author lean YAML; the pipeline
validates, lints, plans, applies via ARM REST + Graph beta, watches
for portal-side drift, and writes a hash-chained audit trail of
every write.

> **CLI.** `contentops` is the only entry point after
> `pip install -e .`. Both `contentops <cmd>` and
> `python -m contentops <cmd>` work.

<details>
<summary>ContentOps logo</summary>

```text
   _____            _             _    ____            
  / ____|          | |           | |  / __ \           
 | |     ___  _ __ | |_ ___ _ __ | |_| |  | |_ __  ___ 
 | |    / _ \| '_ \| __/ _ \ '_ \| __| |  | | '_ \/ __|
 | |___| (_) | | | | ||  __/ | | | |_| |__| | |_) \__ \
  \_____\___/|_| |_|\__\___|_| |_|\__|\____/| .__/|___/
                                            | |        
                                            |_|        
```

</details>

---

## What ships in this mirror

`SecM8/ContentOps` is the **public, code-only mirror** of a private
operator repo, rebuilt nightly through an allowlist sync. It ships:

- the **tool** — the `contentops` Python package, its tests, and scripts;
- **worked templates + samples** under `detections/templates/` and
  `detections/samples/` (one per asset kind);
- the **documentation** — everything you need to run the pipeline against
  your own tenant.

It deliberately **never** contains operator content: no real detection
`.yml` rules, no `config/tenant.yml`, no `audit/` or `state/`, no
per-detection pages. The boundary is enforced by an explicit allowlist
**plus** a forbidden-paths safety check that fails the sync if any of
those slip in — see [`.github/sync-allowlist.txt`](.github/sync-allowlist.txt)
and [`.github/workflows/public-sync.yml`](.github/workflows/public-sync.yml).
**Bring your own detection content** under `detections/<kind>/`; the
per-kind `README.md`s explain placement.

---

## Get started

One linear path. ~30 minutes from clone to first scaffolded rule.

```powershell
# 1. Clone + install
git clone https://github.com/SecM8/ContentOps.git
cd ContentOps
python -m venv .venv
# Activate (pick your shell):
.\.venv\Scripts\Activate.ps1       # Windows PowerShell
# source .venv/bin/activate         # macOS / Linux bash
python -m pip install -r requirements.txt
python -m pip install -e .

# 2. Wire credentials. The three adopter personas + locked-down
#    Windows recipes are in docs/quickstart.md; the shortest path
#    on a personal laptop is `az login` (no .env needed).
copy config\tenant.yml.example config\tenant.yml    # tenant + workspace IDs (gitignored)

# 3. Pre-flight + first rule
python -m contentops doctor                          # green = ready (L1 install only)
python -m contentops new sentinel_analytic my-first-rule
notepad detections\sentinel_analytic\my-first-rule.yml
python -m contentops lint --strict                   # PR-time gate, locally
python -m contentops plan --role prod                # read-only diff vs the tenant
```

> `python -m pip` and `python -m contentops` are the recommended
> invocations — they work on locked-down corporate Windows machines
> where Device Guard / WDAC blocks pip-installed `.exe` shims. The
> bare `contentops` console script also works after `pip install -e .`.

### Permissions: grant only what you use

The identity ContentOps authenticates as needs at most four permission
surfaces, and the pipeline **degrades gracefully** — read-only grants work
(everything except deploy), read-write grants enable deploy, and the two
optional Graph scopes can be omitted entirely:

| Surface | Read-only | Read-write | Optional? |
|---|---|---|---|
| Microsoft Sentinel (Azure RBAC) | Sentinel Reader | Sentinel Contributor | only if you manage Sentinel content |
| Defender custom detections (Graph) | `CustomDetection.Read.All` | `CustomDetection.ReadWrite.All` | only if you manage Defender detections |
| Advanced hunting schema (Graph) | `ThreatHunting.Read.All` | — | **optional** (Defender lint schema refresh) |
| Security alerts (Graph) | `SecurityAlert.Read.All` | — | **optional** (alert/MTTR telemetry) |

Full grant + admin-consent steps, and exactly what each surface enables,
are in
[`docs/operations/authentication-setup.md`](docs/operations/authentication-setup.md#step-2-grant-the-app-registration-its-permissions).

When that works, read [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md)
for the daily flow and the when-things-break decision tree.

## Verify your install

One command answers "is everything wired correctly?" — read-only,
safe against production tenants:

```bash
contentops conformance                  # full layered report (L1–L7)
contentops conformance --scope L1,L2    # local install + tenant config only
contentops conformance --format json    # machine-readable sidecar
```

Layers — each printed with PASS / FAIL / SKIP and an actionable
remediation hint on failure:

| Layer | Verifies |
|---|---|
| L1 | Local install: Python, package import, envelope parse, audit chain |
| L2 | Tenant config: `tenant.yml` parses, GUIDs aren't placeholders, auth env set |
| L3 | OIDC / token acquisition (ARM + Graph) via `DefaultAzureCredential` |
| L4 | Microsoft Graph permissions on the App Registration (app role assignments + federated credential subjects) |
| L5 | Azure RBAC: every configured Sentinel workspace exists, RG exists, Sentinel onboarded |
| L6 | Functional reach: `list alertRules`, `list detectionRules`, KQL `print 1` |
| L7 | GitHub repo: required secrets exist, branch protection requires expected checks (skipped without `gh` CLI) |

The full reference, including how to override the expected-permissions
list per-fork via `.contentops-conformance.yml`, lives in
[`docs/operations/deployment-conformance.md`](docs/operations/deployment-conformance.md).

For a separate **non-destructive end-to-end CLI matrix** (every leaf
command exercised against a tmpdir sandbox, three modes:
offline / mocked / live), see
[`docs/operations/e2e-capability-tests.md`](docs/operations/e2e-capability-tests.md).

## Mirror into a private GitHub Enterprise repo

Enterprise adopters typically host the code in their own
**GitHub Enterprise** (GHEC or GHES) org rather than working directly
against the public mirror. The recommended topology is:

- `origin` → your private GHE repo (where you push, run CI, branch-protect)
- `upstream` → `SecM8/ContentOps` (the nightly-rebuilt public mirror)

You only do the import once. After that you periodically fetch from
`upstream` and merge into your `origin/main`.

### Windows PowerShell

```powershell
# 1. Sign in to your GitHub Enterprise host
gh auth login --hostname github.<your-ghe>
gh auth status --hostname github.<your-ghe>

# Optional: clear stale cached Git credentials if pushes 401/403.
# When prompted enter `protocol=https`, `host=github.<your-ghe>`,
# then press Enter twice.
# git credential-manager erase

# 2. Clone the public mirror into a working directory
cd C:\work
git clone https://github.com/SecM8/ContentOps.git contentops
cd contentops

# 3. Re-wire remotes: public becomes upstream, private GHE becomes origin
git remote rename origin upstream
git remote add origin https://github.<your-ghe>/<org>/<repo>.git
git remote -v

# 4. Push main + tags to your private GHE repo
git branch --show-current                          # confirm branch name
git push -u origin main                            # or `master` if that's your default
git push origin --tags
```

### Linux / macOS bash

```bash
# 1. Sign in to your GitHub Enterprise host
gh auth login --hostname github.<your-ghe>
gh auth status --hostname github.<your-ghe>

# If cached creds misbehave, inspect `git config --global credential.helper`
# and clear the relevant entry (osxkeychain, libsecret, store, etc.).

# 2. Clone the public mirror into a working directory
mkdir -p ~/work && cd ~/work
git clone https://github.com/SecM8/ContentOps.git contentops
cd contentops

# 3. Re-wire remotes: public becomes upstream, private GHE becomes origin
git remote rename origin upstream
git remote add origin https://github.<your-ghe>/<org>/<repo>.git
git remote -v

# 4. Push main + tags to your private GHE repo
git branch --show-current                          # confirm branch name
git push -u origin main                            # or `master` if that's your default
git push origin --tags
```

### Pulling updates from upstream

The public mirror is rebuilt nightly, so a weekly sync is usually plenty.
Four workflows, fully documented in
[`docs/operations/upstream-sync.md`](docs/operations/upstream-sync.md):

- **New install** — clone the mirror, rewire remotes, install (the GHE
  import above + [Quickstart step 1](docs/quickstart.md#1-clone--python-install-3-min)).
- **Update (routine)** — fast-forward your `main` to the mirror:

  ```bash
  git fetch upstream
  git pull --ff-only upstream main
  git push origin main
  ```

- **Full reset (pristine)** — force `main` to match the mirror exactly,
  discarding fork-local changes: `git reset --hard upstream/main` then
  `git push --force-with-lease origin main`.
- **One-time stitch (unrelated histories)** — if your repo was not born
  as a clone of the mirror, the first merge fails with
  `fatal: refusing to merge unrelated histories`. Fix once with an
  [`--allow-unrelated-histories` stitch merge](docs/operations/upstream-sync.md#4-one-time-stitch--fork-with-unrelated-history),
  and land that PR as a **true merge commit** — never squash/rebase it.

> **Heads-up: `git clean -fdx` deletes `config/tenant.yml` and `.venv/`.**
> The `-x` flag ignores `.gitignore` **and** `.git/info/exclude`, so it
> removes your gitignored tenant config + virtualenv along with build
> artifacts. If you clean, exclude them and dry-run first:
> `git clean -nfdx -e config/tenant.yml -e .venv`, then drop the `-n`. And
> make the mirror un-pushable: `git remote set-url --push upstream DISABLED`.

See [`docs/quickstart.md`](docs/quickstart.md#sso-authorization-on-github-enterprise-cloud)
if a GHEC org with SAML SSO returns 404 on `git push` or `gh repo view`.

## Reference

Once you're past Day-1, these are the docs to bookmark.

- [`docs/quickstart.md`](docs/quickstart.md) — deploy your first detection in 15 minutes.
- [`docs/glossary.md`](docs/glossary.md) — pipeline vocabulary on one page.
- [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) — daily flow, when-things-break decision tree.
- [`docs/operations/operationalization-paths.md`](docs/operations/operationalization-paths.md) — choose your operating model (local-only / GitOps / hybrid), the workflow maturity ladder, and how to validate each path.
- [`docs/operations/authentication-setup.md`](docs/operations/authentication-setup.md) — App Registration + OIDC first-timer primer.
- [`docs/operations/tenant-config-modes.md`](docs/operations/tenant-config-modes.md) — three tenant-config layouts (committed, secret, vars+secrets).
- [`docs/operations/multi-workspace.md`](docs/operations/multi-workspace.md) — single tenant, N Sentinel workspaces; integration vs. prod.
- [`docs/development/local-testing.md`](docs/development/local-testing.md) — `.env`, RBAC, pre-flight.
- [`docs/development/live-integration-tests.md`](docs/development/live-integration-tests.md) — live Azure validation.
- [`docs/reference/architecture.md`](docs/reference/architecture.md) — handler protocol, envelope schema, hash chain, state file, Mermaid diagrams.
- [`docs/reference/workflows.md`](docs/reference/workflows.md) — index of every GitHub Actions workflow with triggers and runtimes.
- [`docs/reference/generated-catalog.md`](docs/reference/generated-catalog.md) — **code-derived** inventory (drift-gated in CI): every command, the Action→Function→Script→Workflow traceability matrix, lint rules, handlers, workflows, and tests.
- [`docs/reference/feature-catalog.md`](docs/reference/feature-catalog.md) — curated narrative for every CLI command, workflow, and lint rule.
- [`docs/reference/asset-coverage.md`](docs/reference/asset-coverage.md) — six implemented asset kinds.
- [`docs/reference/audit-trail.md`](docs/reference/audit-trail.md) — JSONL schema, query examples, retention.
- [`docs/reference/gap-assessment.md`](docs/reference/gap-assessment.md) — what isn't built yet. Honest.
- [`docs/reference/roadmap.md`](docs/reference/roadmap.md) — proposed features.
- [`DESIGN.md`](DESIGN.md) — full design (contract-with-future-self).
- [`docs/archive/DESIGN.md`](docs/archive/DESIGN.md) — original v1 design, kept for context.

---

## Tech stack

| Layer       | Technology                                    |
|-------------|-----------------------------------------------|
| Language    | Python 3.12+                                  |
| CLI         | Click                                         |
| HTTP        | httpx                                         |
| Validation  | Pydantic v2                                   |
| YAML        | PyYAML (custom block-scalar dumper)           |
| Auth        | azure-identity (DefaultAzureCredential)       |
| CI/CD       | GitHub Actions (OIDC)                         |
| Sentinel    | ARM REST 2025-07-01-preview                   |
| Defender    | Microsoft Graph Security beta                 |

Single tenant. Single-tenant App Registration with OIDC federated
credentials for production; client-secret fallback for local dev.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the local setup, the
DCO sign-off requirement, branch protection, and the status
promotion lifecycle. Community expectations are documented in
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Security reports go
through the private channel in [`SECURITY.md`](SECURITY.md).

---

## License + trademarks

Code is licensed under the [**Apache License 2.0**](LICENSE). You
may use, modify, and redistribute it - including commercially.
A patent grant comes with the license; see Apache 2.0 §3.

The names **ContentOps** and **SecM8** are trademarks of
KustoKing / SecM8 and are NOT licensed under Apache 2.0 (the
license explicitly disclaims trademark rights in §6). You may not
name a fork "ContentOps", use the SecM8 wordmark in marketing, or
imply SecM8 endorsement without permission. See
[`TRADEMARK.md`](TRADEMARK.md) for the full policy.

Attribution is appreciated but not required - see [`NOTICE`](NOTICE).
