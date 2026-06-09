# Operationalization paths — from clone to operated pipeline

> A decision guide for the detection engineer standing this pipeline
> up for real. The [quickstart](../quickstart.md) gets you to a first
> rule; this page maps the **supported ways to run the pipeline
> day-to-day**, what each path costs, and how to validate that the
> path you picked actually works. Five decisions, one maturity
> ladder, one validation matrix. Pick deliberately — switching later
> is supported but never free.

---

## What "operationalized" means here

The pipeline is operational when all five feedback loops below close
without a human remembering to run them:

| Loop | What closes it |
|---|---|
| **Author → gate** | PR checks: envelope validate + strict KQL lint + plan + version bump ([`validate.yml`](../../.github/workflows/validate.yml)), unit suite + CLI smoke + catalog drift ([`ci.yml`](../../.github/workflows/ci.yml)), DCO, SAST, secret scan, spelling |
| **Merge → deploy** | [`deploy.yml`](../../.github/workflows/deploy.yml) applies changed content to the prod workspace(s) via OIDC, verifies post-apply hashes, writes the audit record |
| **Tenant → git** | Daily [`drift.yml`](../../.github/workflows/drift.yml) compares portal ↔ git and opens a PR on divergence; weekly [`collect.yml`](../../.github/workflows/collect.yml) full snapshot |
| **Telemetry → tuning** | Daily [`alerts-report.yml`](../../.github/workflows/alerts-report.yml) syncs alerts into the PII-free ledger, computes FP-rate / MTTR / silent-rule health, recommends TUNE / CLASSIFY / SILENT per detection |
| **Trust, then verify** | Weekly [`audit-verify.yml`](../../.github/workflows/audit-verify.yml) (hash-chain integrity) + [`conformance.yml`](../../.github/workflows/conformance.yml) (L1–L7 wiring) + daily [`status-refresh.yml`](../../.github/workflows/status-refresh.yml) (status pages) |

Path A below operates only the first loop, by hand. Path B closes
all five. Most teams should converge on Path B and treat A as the
on-ramp / lab mode.

---

## Decision 1 — Repo topology: where does your copy live?

| Option | What it is | Pick when |
|---|---|---|
| **Private fork, public mirror as `upstream`** (recommended) | Import the mirror into your GitHub / GitHub Enterprise org; `origin` = your repo, `upstream` = `SecM8/ContentOps`. Weekly `git pull --ff-only upstream main`. | You will deploy to a real tenant. CI, secrets, branch protection, and detection content live under your org's control. |
| **Direct clone of the public mirror** | Work straight off `SecM8/ContentOps` with no fork. | Evaluation only. You cannot configure secrets or branch protection on a repo you don't own, so Paths B/C are unavailable. |
| **Operator source repo** | The private repo the mirror is rebuilt from nightly. | You are the upstream operator. Adopters never need this. |

Import procedure, remote re-wiring, and the routine/full-reset update
recipes: [`README.md`](../../README.md#mirror-into-a-private-github-enterprise-repo)
and [`upstream-sync.md`](upstream-sync.md).

---

## Decision 2 — Execution model: where do Azure writes happen?

This is the load-bearing choice. The three supported paths:

### Path A — local CLI only (evaluation / lab)

Everything runs from one workstation: `contentops new` → `lint` →
`plan` → `apply`, authenticated as you (`az login`) or as an App
Registration client secret in `.env`. No GitHub Actions involved.

- **Setup**: [quickstart](../quickstart.md) steps 1–3, then
  [`local-testing.md`](../development/local-testing.md) for `.env` +
  RBAC.
- **Good for**: a lab tenant, a one-person evaluation, authoring
  against `detections/samples/`, incident-time forensics on a laptop.
- **What you give up**: no branch protection, no PR review gate, no
  scheduled drift / alert-health / audit-verify, and the audit chain
  is only as durable as the workstation that wrote it. Apply
  failures are recovered by whoever remembers to run
  `contentops retry-failed`.
- **Hard rule**: don't operate a production tenant this way. The
  [Operator Guide don't-do-this list](../OPERATOR_GUIDE.md#dont-do-this-list)
  exists because every entry was once a real incident.

### Path B — full GitOps via GitHub Actions (recommended)

Git is the source of truth and CI is the only writer to production.
Analysts can ship rules without any Azure access at all (the
**Author-only** persona in the
[quickstart personas table](../quickstart.md#three-adopter-personas--pick-yours)):
PRs run the read-only gates, merge to `main` deploys via OIDC
federated credentials, and the cron workflows watch the tenant from
then on.

Setup sequence, in order:

1. **Azure side** — App Registration, Graph permissions, Sentinel
   RBAC, federated credentials:
   [`authentication-setup.md`](authentication-setup.md).
2. **GitHub side** — variables, secrets, environments
   (`production` / `integration` / `automation`), branch protection:
   [`github-actions-setup.md`](github-actions-setup.md).
3. **Tenant config sourcing** — Decision 4 below.
4. **Verify** — `contentops conformance` end-to-end (L1–L7), then
   the maturity ladder below to switch on workflows in order.

Operating cadence once live (what fires when, UTC):
[`workflow-schedule.md`](workflow-schedule.md).

### Path C — hybrid (CI owns prod, engineers own integration)

Path B plus a second Sentinel workspace with `role: integration`.
PR-time [`integration-deploy.yml`](../../.github/workflows/integration-deploy.yml)
applies changed rules to the integration workspace with
`--continue-on-error` — API-level breakage surfaces as a PR comment
before merge instead of a failed prod deploy. Engineers with the
**Local-test** persona iterate against integration locally
(`contentops apply --role integration`); `deploy.yml` remains the
only writer to prod.

- **Extra setup**: a second workspace entry in `tenant.yml`
  ([`multi-workspace.md`](multi-workspace.md)), the `integration`
  GitHub environment + federated credential, optionally
  [`promote-to-integration.yml`](../../.github/workflows/promote-to-integration.yml)
  to mirror prod state into integration
  ([`prod-to-int-mirror.md`](prod-to-int-mirror.md)).
- **Caveat**: Defender XDR is tenant-scoped — there is no
  "integration Defender". `--role integration` skips Defender
  content silently, so `defender_custom_detection` rules get their
  first live exercise at prod deploy time. Budget review attention
  accordingly.

### Side-by-side

| | Path A — local | Path B — GitOps | Path C — hybrid |
|---|---|---|---|
| Azure writes from | workstation | CI only | CI (prod) + workstation (integration) |
| Analyst needs Azure auth | yes | **no** (Author-only) | optional (Local-test) |
| Audit chain custody | laptop | CI + git | CI + git |
| Drift / alert-health / conformance crons | manual | automated | automated |
| Pre-merge live API smoke test | no | no | **yes** (integration workspace) |
| Blast-radius controls | `tenant.yml` safeguards only | + branch protection, environments, reviewer gates | same as B |
| Team size sweet spot | 1 | 2+ | 2+ with a second workspace |
| Suited for | lab / evaluation | production | production with high rule churn |

---

## Decision 3 — Identity: how does the pipeline authenticate?

| Option | Where it lives | Use for |
|---|---|---|
| `az login` (your user) | workstation | Path A / Local-test persona. Needs Sentinel Contributor on the workspace RG. |
| App Reg + client secret in `.env` | workstation, gitignored | CI-mirror persona — reproduce CI behaviour exactly. Rotate like any secret. |
| App Reg + **OIDC federated credentials** | GitHub environments, no stored secret | Paths B/C. One federated credential per environment; subject string must match exactly. |

Grant only what the path uses — the four permission surfaces and
their read-only / read-write split are tabulated in
[`README.md`](../../README.md#permissions-grant-only-what-you-use); grant
+ admin-consent walkthrough in
[`authentication-setup.md`](authentication-setup.md). Teams wanting
separation of duties run **two App Registrations** (read for the
`automation` cron environment, write for `production` /
`integration`) — see the split notes in
[`github-actions-setup.md`](github-actions-setup.md#3-github-environments).

---

## Decision 4 — Tenant config sourcing

`config/tenant.yml` (tenant GUID, workspaces, safeguards) has three
supported layouts — committed to a private fork (**Mode A**),
materialised from the `TENANT_CONFIG_YAML` secret (**Mode B**, this
repo's default), or assembled from per-key vars + secrets (**Mode C**,
documented target, not implemented). Full decision table, switch
procedures, and the `policy.scaffoldStrict` lint toggle:
[`tenant-config-modes.md`](tenant-config-modes.md).

Whatever the mode, the per-workspace safeguards (`writeAllowed`,
`purgeAllowed`, `maxDelete`) ride along in the config — set them
before the first non-dry-run apply, not after the first scare.

---

## Decision 5 — Workspace topology

- **Single prod workspace** — the default; `--role` / `--workspace`
  flags become optional everywhere.
- **Prod + integration** — unlocks Path C. Multi-workspace targeting
  rules: [`multi-workspace.md`](multi-workspace.md).
- **Defender XDR** — tenant-scoped, enabled via the `defender:` block;
  one per tenant regardless of workspace count.

---

## Maturity ladder — switch workflows on in this order

Each stage is independently useful; stop climbing when the next rung
buys you nothing. Workflow triggers + permissions:
[`workflows.md`](../reference/workflows.md).

| Stage | You get | Switch on |
|---|---|---|
| **0 — Evaluate** (Path A) | Confidence the tool works against your tenant | Nothing in CI. Locally: `contentops doctor`, `new`, `lint --strict`, `plan`, `apply --dry-run` |
| **1 — Gate authoring** | Every PR validated; no Azure secrets needed yet (Azure-dependent steps degrade gracefully) | `validate.yml`, `ci.yml`, `dco.yml`, `sast.yml`, `secret-scan.yml`, `spelling.yml`, `coverage.yml` + branch protection ([checklist](github-actions-setup.md#5-branch-protection-on-main)) |
| **2 — Deploy from main** | Merge = deploy; audit chain in CI custody | `deploy.yml`, `production-promotion-check.yml`; Path C adds `integration-deploy.yml` |
| **3 — Operate** | The tenant is watched while you sleep | `drift.yml`, `collect.yml`, `audit-verify.yml`, `conformance.yml`, `status-refresh.yml`, `alerts-report.yml`, `silent-rules.yml`, `report.yml`, `portfolio.yml`, `references-check.yml` |
| **4 — Optimize & watch upstream** | Lint schemas, ATT&CK matrix, and Microsoft catalogs stay fresh; tuning PRs carry blast-radius data | `kql-schemas-refresh.yml`, `attack-matrix-refresh.yml`, `upstream-watchers.yml`, `tuning-impact-preview.yml`, `defender-graph-probe.yml`, `e2e-capability-tests.yml` |
| **Break-glass** (wire at Stage 2, hope never) | Reviewer-gated undo, rapid silence, recovery | `emergency-disable.yml`, `rollback.yml`, `retry-failed.yml`, `lock-unlock.yml`, `prune.yml` (leave `purgeAllowed: false` until the day you need it) |

> **Fork gotcha — Stage 3+ runs on a schedule, and schedules are
> slug-gated.** Eleven workflows gate their cron runs on
> `github.repository == 'KustoKing/SIEMContent'` and silently no-op
> everywhere else, including your fork (manual dispatch still works).
> Re-point the gate to your own `<org>/<repo>` before expecting
> Stage 3/4 to run unattended:
> [`github-actions-setup.md` §6](github-actions-setup.md#6-scheduled-workflows--re-point-the-repo-slug-gate).

> **Org gotcha — Stage 3/4 workflows open PRs, and many orgs block
> that.** If your org disables "Allow GitHub Actions to create and
> approve pull requests", every auto-PR workflow (`collect`, `drift`,
> `kql-schemas-refresh`, …) fails at the PR step with
> `GitHub Actions is not permitted to create or approve pull requests`.
> Either flip the toggle or set the `AUTO_PR_TOKEN` secret — see the
> [secrets table](github-actions-setup.md#2-secrets) and the
> troubleshooting row in `github-actions-setup.md`.

Break-glass drills are rehearsable without an incident:
[`emergency-disable-workflow.md`](../emergency-disable-workflow.md)
and [`rollback-drill.md`](rollback-drill.md).

---

## Validating the path you picked

Run these in order; each is read-only against the tenant. Green at a
given row means everything above it is wired correctly.

| # | Command | Proves | Required for |
|---|---|---|---|
| 1 | `contentops doctor` | Install, deps, `tenant.yml` parse, detections parse | all paths |
| 2 | `contentops conformance --scope L1,L2` | Package + envelope integrity, tenant config sane | all paths |
| 3 | `contentops doctor --auth` (or `conformance --scope L3`) | Token acquisition (ARM + Graph) | A, then B/C via CI |
| 4 | `contentops conformance --scope L4,L5,L6` | Graph app roles, RBAC + workspace reach, functional `list` + KQL | paths that deploy |
| 5 | `contentops conformance --scope L7` | GitHub secrets, environments, branch-protection checks | B, C |
| 6 | `contentops plan --role prod` | Read-only diff against the live tenant | first deploy gate |
| 7 | [`e2e-capability-tests.yml`](../../.github/workflows/e2e-capability-tests.yml) (offline → mocked → live) | Every leaf CLI command end-to-end | B, C (weekly) |
| 8 | [`integration.yml`](../../.github/workflows/integration.yml) (manual, explicit ack) | Live-tenant integration suite | C, pre-prod sign-off |

Layer-by-layer reference and per-fork expected-permissions overrides:
[`deployment-conformance.md`](deployment-conformance.md). The
capability-matrix harness and its three modes:
[`e2e-capability-tests.md`](e2e-capability-tests.md).

---

## Switching paths later

- **A → B**: wire Decisions 3–4 (App Reg + secrets/environments),
  push your detection content, run `conformance` L1–L7, climb the
  ladder from Stage 1. Your local audit files stay valid — the chain
  is append-only wherever it lives.
- **B → C**: add the integration workspace + environment, enable
  `integration-deploy.yml`, optionally seed it from prod via
  [`promote-to-integration.yml`](../../.github/workflows/promote-to-integration.yml).
- **C → B**: disable the integration workflows and remove the
  workspace entry; nothing else changes.
- **Mirror-clone → private fork**: re-wire remotes per
  [`README.md`](../../README.md#mirror-into-a-private-github-enterprise-repo),
  then treat as A → B.

---

## See also

- [`../OPERATOR_GUIDE.md`](../OPERATOR_GUIDE.md) — the daily flow once operational; when-things-break decision trees.
- [`../onboarding.md`](../onboarding.md) — Day-1 analyst setup on an already-operational repo.
- [`workflow-schedule.md`](workflow-schedule.md) — the UTC cron map.
- [`../reference/workflows.md`](../reference/workflows.md) — every workflow's trigger, permissions, runtime.
- [`../reference/architecture.md`](../reference/architecture.md) — handler protocol, envelope schema, audit chain.
- [`../reference/audit-trail.md`](../reference/audit-trail.md) + [`audit-recovery.md`](audit-recovery.md) — the evidence trail you're operating for.
