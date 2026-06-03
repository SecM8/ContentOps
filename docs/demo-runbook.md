# Demo runbook — ContentOps powered by SecM8 (15–20 min)

A copy-pasteable script for a live demo. Two acts:

- **Act 1 — Fresh clone (≈8 min):** the adopter onboarding story, fully
  offline. No Azure, no tenant — just clone, install, and show the tool +
  the quality gates.
- **Act 2 — Drift loop (≈8 min):** the operational story against a
  *connected* repo (one with a real `config/tenant.yml` + credentials):
  prove live tenant reach, then run the daily **Drift detection** workflow
  so a portal edit is captured as a reviewable **pull request** — plus a
  live pre-flight plan.

> All commands use the `python -m contentops` form (works on locked-down
> Windows). The bare `contentops` console script is equivalent after
> `pip install -e .`. Tenant-specific values (workspace name, role,
> detection counts) are shown as placeholders — substitute your own.

---

## Before the demo (one-time prep, not counted in the 15–20 min)

For **Act 1** (any machine):
- Python 3.12+ and `git` installed.
- **Confirm the public mirror is live, public, and fresh** — don't
  discover a private or stale mirror at `git clone` time, on stage. A
  lightweight reachability + freshness probe (no full clone needed):
  ```powershell
  git ls-remote https://github.com/SecM8/ContentOps.git HEAD
  ```
  Expect one `<sha>\tHEAD` line and exit 0. A `fatal: ... not found` or
  an auth prompt means the mirror is missing or still private — check the
  latest `public-sync.yml` run before going live. Cross-check the SHA is
  recent (the mirror rebuilds nightly): `gh api repos/SecM8/ContentOps/commits/HEAD --jq .commit.committer.date`.
  - *Fallback if the mirror is unavailable:* run Act 1 from a fresh clone
    of the operator repo into a scratch dir instead — the tool, templates,
    and quality gates behave identically. Just don't put the repo URL on
    screen, and skip the "this is the public mirror" line.

For **Act 2** (the connected repo — your private operator repo or a
configured fork):
- `config/tenant.yml` filled in, and credentials working
  (`az login`, or a `.env` with the App Registration secret).
- Confirm it's healthy ahead of time: `python -m contentops doctor --matrix --role prod`
  should be all green (token acquisition + per-handler tenant reads).
  **Do this before the audience is watching** — token acquisition + RBAC
  propagation are the usual day-of surprises.
- Pin two browser tabs on your operator repo: **Actions** (the workflow
  list) and **Pull requests** — Act 2 drives both from the UI.
- Pre-run the **Drift detection** + **Conformance** workflows once so a
  recent green run is on hand as a fallback if a live run is slow.
- Know your prod workspace's role tag (`prod` in the examples below).

Optional polish:
- Two terminals: one in a scratch dir for Act 1, one in the connected
  repo for Act 2.
- Increase font size; `clear` between steps.

---

## Act 1 — Fresh clone (≈8 min)

> Story: "A new adopter gets the tool running and authors a detection,
> with the quality gates catching mistakes — all without touching Azure."

### 1.1 Clone + install (≈3 min)

```powershell
git clone https://github.com/SecM8/ContentOps.git
cd ContentOps
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
python -m contentops --version
```

**Expect:** `ContentOps powered by SecM8 v<version>`.

**Say:** "This is the *public mirror* — it ships the tool, worked
templates, and docs, but never the operator's real detections, tenant
config, or audit trail. You bring your own content."

### 1.2 Pre-flight, offline (≈1 min)

```powershell
python -m contentops doctor
```

**Expect:** **exit 0**, nothing red. Five **PASS** (green) —
`python_version`, `python_deps`, `detections_dir`, `detections_parse`,
`git` — and four **WARN** (yellow), all expected on a fresh offline clone:
`dotenv` (no `.env`), `auth_env` (no Azure creds), `tenant_yml` (no
`config/tenant.yml` yet — only needed for tenant calls), and
`token_acquisition` (skipped unless you pass `--auth`). No Azure call.

**Say:** "`doctor` is the install sanity check. The yellow lines are the
not-yet-configured tenant bits — author-only adopters never need them;
GitHub Actions does every tenant call via OIDC. Notice it still exits
clean: a fresh clone is ready to author against immediately."

### 1.3 The full view — code-derived catalog (≈1 min)

```powershell
python -m contentops --help
# Then open the code-derived inventory:
code docs\reference\generated-catalog.md   # or: type/less the file
```

**Say:** "Every command, handler, lint rule, workflow, and an
Action→Function→Script→Workflow **traceability matrix** are generated
from the live code and drift-gated in CI — the docs can't lie about what
the tool does."

### 1.4 Scaffold a detection (≈1 min)

```powershell
python -m contentops new sentinel_analytic demo-impossible-travel
```

**Expect:** writes `detections/sentinel_analytic/demo-impossible-travel.yml`
from a Pydantic-validated template, with `TODO (METAxxx)` placeholders for
required authoring metadata.

Open the file and show the envelope shape (`id`, `version`, `asset`,
`status`, `metadata`, `payload`).

### 1.5 Lint — the quality gate (≈2 min)

```powershell
python -m contentops lint --strict
```

**Expect:** authoring-metadata findings on the fresh scaffold —
`META001` (`lastValidatedAt` unset), `META004` (`references` empty) and
`META005` (`falsePositives` empty) as **warnings**, plus `META006` /
`META007` (`blindSpots` / `responseActions`) as **info**. It **exits 0**:
these are non-blocking by default — they escalate to CI-blocking *errors*
only when an operator sets `policy.scaffoldStrict: true` in
`config/tenant.yml`. The same lint runs in CI. (`--strict` also prints a
one-line advisory if the optional Kusto.Language KQL wrapper isn't built
locally — harmless; the Python rules above still run.)

**Say:** "Lint is pure-Python and runs with zero Azure access, so a PR is
green from the first push. KQL static checks, payload contract checks,
and authoring-metadata checks all run here. The scaffold ships with the
MITRE mapping and a starter query already filled, so what's left is the
analyst-context fields — fill them in, re-run, and it goes quiet."

*(Optional)* show it passing after you paste in real metadata + a KQL
query, or just describe it.

> **Reset Act 1** when done: `git restore .` / delete the scaffolded file
> so the working tree is clean for the next run.

---

## Act 2 — Drift loop on a live tenant (≈8 min)

> Switch to the **connected repo** (real `config/tenant.yml` + creds).
> Story: "Git is the source of truth. The pipeline continuously proves
> the tenant matches the repo — and shows exactly what changed when it
> doesn't."

### 2.1 Prove live reach (≈1.5 min)

```powershell
python -m contentops doctor --matrix --role prod
```

**Expect:** all green, including `token_acquisition`, `workspace_reachable`,
`graph_reachable`, and a **per-handler matrix** with live counts
(`handler:sentinel_analytic — N item(s)`, `handler:defender_custom_detection
— N`). That's the proof we're really reaching the tenant — read-only.

```powershell
python -m contentops conformance --scope L1,L2
```

**Expect:** L1 (install) + L2 (tenant config parses, GUIDs aren't
placeholders, auth env set) green. (`conformance` with no scope runs the
full L1–L7.)

**Say:** "`doctor --matrix` proves connectivity and shows the live rule
counts. `conformance` verifies the deployment *wiring* end-to-end — install,
config, identity, RBAC, deploy path, drift-readiness, branch protection
(L1–L7). That's pipeline health — distinct from `lint`, which gates
detection-*content* quality."

### 2.2 Drift check — the headline (≈2 min)

```powershell
python -m contentops drift --role prod --no-exit-on-drift
```

**Expect:** a summary line like

```
Drift report — new: 0, changed: 0, in-sync: N
```

**Say:** "Read-only. It pulls every rule from the tenant and compares it
to the YAML in git. `new` = in the tenant but not in git (someone authored
in the portal); `changed` = tuned in the portal; `in-sync` = matches. Zero
drift means the tenant *is* the repo."

> Run this **before** the 2.3 portal edit — it's your clean in-sync
> baseline. (If your tenant carries real pre-existing drift, call it out as
> the honest starting state rather than chasing a zero.)

### 2.3 Induce drift in the portal → catch it as a PR (≈3.5 min — the money shot)

Simulate an analyst tuning a rule **in the portal** (the real source of
drift). Edit one rule's **KQL** and append a harmless no-op line so the
behaviour is unchanged but the content differs from git:

```kql
| where true   // DRIFT-DEMO 2026-06-03
```

Do this on one **Sentinel** analytics rule and (optionally) one **Defender**
custom detection, then **Save** in the portal. (Editing the *query* is the
robust choice — it's always part of the drift comparison, unlike fields that
may be normalised.)

**The production loop — GitHub Actions UI:**
operator repo → **Actions** → **Drift detection** → **Run workflow** (branch
`main`) → **Run**. It reads the live tenant (~1 min) and, when it finds
drift, **opens a pull request** on a `drift/auto-<run_id>` branch.

Then: **Pull requests** → open the new drift PR → **Files changed** → point
at your KQL edit on the Sentinel (and Defender) rule.

**Say:** "A portal edit is now a *reviewable PR*, not a silent divergence.
In production this runs daily — a reviewer accepts the portal change, or
rejects the PR and the next deploy restores git's version. Either way it
never drifts in the dark."

> *(Fast local alternative, no portal needed: edit a local YAML —
> `queryFrequency`, a threshold — then `python -m contentops drift --role
> prod --diff` for the field-level delta, and `git restore` it.)*

### 2.4 Live pre-flight plan (≈2 min)

```powershell
python -m contentops plan --against-tenant --role prod
```

**Expect:** an apply-side overlay:

```
Against-tenant overlay:
  CREATE: 0   UPDATE: 0   NO-CHANGE: N   ORPHAN-IN-TENANT: 0
```

**Say:** "Before merging a PR you see exactly what `apply` would do —
without writing anything. The real deploy happens in CI on merge to main,
via OIDC, and writes a hash-chained audit record per rule."

### 2.5 Coverage + inventory (optional, ≈1 min)

```powershell
python -m contentops coverage          # MITRE ATT&CK heatmap (markdown)
python -m contentops coverage --gaps   # techniques you DON'T cover
```

**Say:** "Coverage and the SOC-grade `report` give the manager view —
ATT&CK posture, gaps, per-detection health — all from the same
source-of-truth envelopes."

---

## Wrap-up — the one-minute pitch

- **Git is the source of truth.** Detections are lean YAML, reviewed via
  PR, deployed by CI — never hand-edited in the portal without a trail.
- **Drift is caught, not discovered later.** Daily drift detection opens a
  PR with a field-level diff; nothing silently diverges.
- **Every write is audited.** A hash-chained, monotonic `audit/*.jsonl`
  records each apply/prune, verified weekly.
- **Safe by construction.** Read-only `plan` / `drift` / `conformance`;
  dry-run-default destructive ops; a per-workspace `purgeAllowed` guard on
  prune; OIDC (no long-lived secrets) for prod deploys.
- **Public/private split.** The public mirror ships the tool + templates +
  docs; your detection content, tenant config, and audit trail never leave
  the private repo — enforced by an allowlist and a forbidden-paths check.

---

## Quick reference — every command in this runbook

| Command | Azure? | What it shows |
|---|---|---|
| `contentops --version` | no | Brand + version |
| `contentops doctor` | no | L1 install health |
| `contentops doctor --matrix --role prod` | reads | Live connectivity + per-handler rule counts |
| `contentops --help` | no | Command surface |
| `contentops new <asset> <id>` | no | Scaffold a detection |
| `contentops lint --strict` | no | KQL + payload + metadata gates (content quality) |
| `contentops conformance --scope L1,L2` | reads | Deployment-*wiring* health (install + config) |
| **Drift detection** workflow (Actions UI) | reads | Reads the tenant; opens a drift PR |
| `contentops drift --role prod --no-exit-on-drift` | reads | Repo ↔ tenant drift summary (local) |
| `contentops drift --role prod --diff` | reads | Field-level diff for CHANGED rules (local) |
| `contentops plan --against-tenant --role prod` | reads | Live CREATE/UPDATE/NO-CHANGE/ORPHAN preview |
| `contentops coverage` / `--gaps` | no | MITRE ATT&CK heatmap / gaps |

> Reset after the demo: `git restore .` in the connected repo, and delete
> any scaffolded file from Act 1. Nothing in this runbook writes to the
> tenant.
