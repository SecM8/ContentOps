# ContentOps Onboarding for SOC analysts

> Day-1 to first-PR with **ContentOps powered by SecM8** — security
> content lifecycle management for Microsoft Sentinel and Defender
> XDR. For architecture and reference reading, see
> [`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md).

This guide assumes you can read Python and YAML, and have used
`git` from the command line. It does **not** assume you know
Sentinel ARM templates, Graph beta, or this repo's internals.

> The public repository is `SecM8/ContentOps` on GitHub.
> **`contentops` is the only CLI.** Install with `pip install -e .`;
> both `contentops <cmd>` and `python -m contentops <cmd>` work.

> Tenant config: `config/tenant.yml` is gitignored. Copy
> `config/tenant.yml.example` to `config/tenant.yml` and fill in
> your Entra ID tenant + workspace values for local dev. CI workflows
> materialise it from the `TENANT_CONFIG_YAML` secret. The full
> list of supported config-source modes (committed file in private
> forks, secret-driven for public OSS, vars+secrets split) lives in
> [`operations/tenant-config-modes.md`](operations/tenant-config-modes.md).

---

## Day 1 — setup

### 1. Install prerequisites

- Python 3.12 or newer (`python --version`).
- Git.
- A way to authenticate to Azure: either Azure CLI (`az login`) or
  the App Registration credentials your team manages.

Optional but recommended: VS Code + the Python and YAML
extensions.

### 2. Clone the repo

```
git clone https://github.com/SecM8/ContentOps.git
cd ContentOps
```

### 3. Set up the Python venv

```
python -m venv .venv
# PowerShell on Windows:
.\.venv\Scripts\Activate.ps1
# bash/zsh on macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .            # installs the `contentops` CLI
```

Verify:

```
contentops --help
```

### 4. Create your `.env`

You need an Azure App Registration with the right permissions before
filling in `.env`. If you've never created one, walk through
[`operations/authentication-setup.md`](operations/authentication-setup.md)
first — it explains what an App Registration is, what OIDC means,
and the portal steps in order (~10 minutes for a first-timer).

Once the App Reg exists, copy `.env.example` to `.env` and fill in:

```
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...                # if using client-secret auth
AZURE_SUBSCRIPTION_ID=...
```

`.env` is gitignored — never commit it.

Full RBAC + permission detail: [`development/local-testing.md`](development/local-testing.md).

### 5. Create your `config/tenant.yml`

`config/tenant.yml` is gitignored — copy the template and fill in your
Entra ID tenant + workspace values:

```
cp config/tenant.yml.example config/tenant.yml
```

Doctor will *warn* on `tenant_yml` until this file exists — that's
non-blocking, so `doctor` still exits 0 and offline authoring (`new` /
`lint` / `plan`) works without it. The file becomes required once you run
tenant-touching commands or `doctor --auth`. The full
list of supported tenant-config sources (committed file in private
forks, secret-driven for public OSS, vars+secrets split) is in
[`operations/tenant-config-modes.md`](operations/tenant-config-modes.md).

### 6. Pre-flight check

```
contentops doctor
```

You should see green for: python_version, python_deps, dotenv,
auth_env, tenant_yml, detections_dir, detections_parse, git.
`token_acquisition` is skipped by default; pass `--auth` to test it.

If anything is red, **fix that before doing anything else**.
Doctor's output is the first thing the live-test suite checks
([`contentops/cli/commands/test_runner.py`](../contentops/cli/commands/test_runner.py)),
so a green doctor unblocks everything downstream.

### 7. First scaffold + first PR

Pick a kebab-case id and an asset kind:

```
contentops new sentinel_analytic my-first-rule
```

This writes `detections/sentinel_analytic/my-first-rule.yml` from
a Pydantic-validated template. Open the file. There are two
metadata layers to fill:

**Required (parse-time):** `owner`, `runbookUrl`, `severity`,
`tactics`, `techniques`, `expectedAlertsPerDay`, `fpHandling`.
These are non-negotiable; the envelope won't parse without them.

**Authoring (Section T — lint-enforced, often CI-blocking):**
`description`, `attackDescription`, `references`,
`falsePositives`, `blindSpots`, `responseActions`. The scaffold
seeds each with a `TODO (METAxxx)` placeholder; fill them in
before opening the PR. The lint rules (META002-005) escalate to
**errors** when the tenant has `policy.scaffoldStrict` unset or
true, which is the strict-by-default Fortune 500 posture.

Treat the Section T fields as the analyst-context block that
SOC triage will read first. The
[`docs/reference/envelope-schema.md`](reference/envelope-schema.md)
doc is the canonical reference and includes a worked example
translating a FalconForce FalconFriday detection into the
envelope format.

Also set `lifecycleStage: concept` (already in the scaffold) and
bump it as the rule matures: `concept → research → engineering
→ delivery → optimization → feedback`. This is authoring
metadata only — it never gates deploy; `status` does that.

The `payload.query` defaults to a no-op KQL — replace it with the
real KQL.

Validate before pushing:

```
contentops lint
contentops plan --asset sentinel_analytic
```

Both must exit 0. Common reasons a fresh scaffold won't pass lint:

- `KQL001 unbalanced-bracket` — check inline JSON / parens.
- `META002-005` at error severity — fill the Section T fields.
- `META001` warning — bump `lastValidatedAt` once you've validated
  the rule (manual KQL run, fixture replay, dry-run apply).

Create a branch, commit, push, open a PR:

```
git checkout -b add-my-first-rule
git add detections/sentinel_analytic/my-first-rule.yml
git commit -m "Add: my-first-rule sentinel analytic"
git push -u origin add-my-first-rule
```

The PR runs `validate.yml` + `coverage.yml` (validate.yml runs the
lint). Once
green and a reviewer approves, merge to `main`. The `deploy.yml`
workflow runs `contentops apply --changed-since <prev SHA>` and
your rule lands in production.

---

## Day 2 — Alert tracking (optional)

If your tenant has `SecurityAlert.Read.All` granted to the app
registration, you can track alert performance per detection.

### 1. Enable in tenant config

Add to `config/tenant.yml`:

```yaml
  alerts:
    enabled: true
    defenderLookbackDays: 30
    sentinelLookbackDays: 90
    ledgerRetentionDays: 90
    rollupRetentionDays: 365
```

### 2. Sync alerts

```bash
contentops alerts sync           # first run: fetches 30d/90d history
contentops alerts sync           # subsequent: fills from last watermark
contentops alerts sync --backfill  # force full refetch
```

### 3. Generate health report

```bash
contentops alerts health --period 30d --sync-owners
```

This creates `config/owners.yml` with all detection IDs. Edit the
file to assign real owners. The health report shows per-detection
TP/FP rates and recommendations (TUNE, CLASSIFY, SILENT, HEALTHY).

### 4. Unified report

```bash
contentops report --unified
```

Opens `reports/unified.html` — a single report for all audiences
from CEO (posture score) to detection engineers (attention queue).
When a daily rollup store is present (`contentops alerts rollup`),
the Alerts Overview also charts 14-day trends: alert volume,
false-positive rate, and resolution time (MTTR).

### 5. (Optional) Report retention

`reports/` is normal versioned content, so `report.yml` commits the
regenerated reports on push-to-main — your deployment keeps a **durable,
diffable posture history in git** with no setup. (Per-detection telemetry
is kept off the public mirror by the sync allowlist, not gitignore.)

The dated snapshots accumulate one per run; cap how much history is kept
with:

```yaml
  reports:
    retentionDays: 365   # keep ~52 weekly snapshots; 0 = keep everything
```

`contentops report` then prunes dated snapshots older than the window on
each run. Details (how `report.yml` materialises `tenant.yml`, the
`--retention-days` flag, the public-mirror boundary) are in
[`operations/durable-reports.md`](operations/durable-reports.md).

---

## Common analyst tasks

### Edit an existing rule

```
git checkout -b tune-my-rule
# edit detections/sentinel_analytic/my-rule.yml
contentops lint --severity error
contentops plan --asset sentinel_analytic --changed-since origin/main
```

If the rule is GUID-named (e.g. `id: sentinel-<guid>` from a prior
collect), don't rename the id — `metadata.arm_name` keys the
upsert and renaming would create a duplicate. To rename a
collected rule, use `contentops collect --rename-existing` (renames
the file but preserves the id).

### Add a new rule from a Marketplace template

```
contentops new --search-template "brute force"
contentops new --from-template <template-guid> --id <kebab-id>
```

The first command lists candidates; the second materialises the
chosen template into a valid envelope. Edit the YAML (especially
`metadata`), commit, PR.

### Retire a rule

```
contentops disable my-rule-id --reason "Superseded by improved-rule"
```

This sets `status: deprecated` in the YAML. On merge, `apply`
disables the rule remotely (sets `enabled: false`) but does NOT
delete it. To delete, separately:

```
# Remove the YAML in your branch, then on merge:
contentops prune --asset sentinel_analytic --dry-run
# Review the orphans list. If satisfactory, the prune.yml workflow
# can run with --no-dry-run + confirm=CONFIRM.
```

### Investigate a failed deploy

The `deploy.yml` workflow uploads `audit/*.jsonl` as a 90-day
artefact. Download it, then:

```
jq -c 'select(.status=="failed")' audit/<date>.jsonl
```

Each record has `id`, `asset`, `action`, `message` (error text),
`sha`, `actor`. The `sha` points at the commit that produced the
failure — usually the merge commit.

If the failures are transient (5xx from ARM, 429 rate limit):

```
contentops retry-failed
```

If structural (handler validate error, ARM 400): fix the YAML in a
new PR; `deploy.yml` will pick it up on next merge.

Full guide: [`reference/audit-trail.md`](reference/audit-trail.md).

### View MITRE ATT&CK coverage in the Navigator UI

```
contentops navigator --since 365 --out tmp-layer.json
# Open https://mitre-attack.github.io/attack-navigator/
# → "Open Existing Layer" → "Upload from local" → tmp-layer.json
```

The rendered matrix shows each technique scored by the count of
unique rules covering it across three axes (repo envelopes,
deployed rules, live `SecurityAlert` firings). Pair with
`contentops coverage --gaps` (ATT&CK gap report — what you DON'T
cover) and `contentops coverage --d3fend` (defensive-axis D3FEND
report) for the complete coverage picture.

Add `--no-firings` if you want a quick view without hitting the LA
Query API. Add `--no-deployed --no-firings` for a repo-only view
(works offline, useful in PR comments).

### Generate per-detection markdown docs

```
contentops detection-docs regenerate
```

Renders every envelope to `docs/detections/<asset>/<id>.md` plus an
index at `docs/detections/README.md`. The format pulls
`metadata.description`, MITRE tags, false-positive guidance,
response actions, and the KQL preview into a SOC-analyst-readable
shape. Regenerate alongside `contentops catalog regenerate` whenever
you change an envelope — the pytest suite has a drift gate that
fails the PR if you forget.

### Check what your PR would actually change in the tenant

```
contentops plan --against-tenant --role integration
```

Beyond the static `contentops plan`, the `--against-tenant` flag
calls `list_remote()` per workspace and overlays an apply-side
preview:

```
Against-tenant overlay (closes G17):
  CREATE: 3   UPDATE: 12   NO-CHANGE: 142   ORPHAN-IN-TENANT: 1
```

Use this before merging to see exactly what apply will do. Fork-PR
safe: it fails-soft when OIDC isn't available.

### Spot rules Sentinel turned off

```
contentops auto-disabled-rules --since 7
```

Sentinel auto-disables rules after consecutive query failures (table
gone, parser broken, ingest stopped). This command surfaces them
from the `SentinelHealth` diagnostic table. Distinct from
`contentops silent-rules` which finds rules with zero alerts —
silent ≠ disabled.

> Prerequisite: the `SentinelHealth` diagnostic data collection must
> be enabled on the workspace (opt-in since ~2022). Run
> `contentops doctor --auth` first; the `sentinel_health` check
> warns when the diagnostic returns zero rows.

### Resolve a drift PR

The daily `drift.yml` opens a PR named `Auto-drift YYYY-MM-DD` if
the tenant has changed since the last collect. Each entry in the
PR body says:

- `NEW` — exists in tenant, no YAML on disk. Either someone
  authored a rule in the portal (we want to capture it in git), or
  the daily collect is misclassifying (rare; investigate).
- `CHANGED` — exists in both, YAML payload differs from remote.
  Someone tuned a rule in the portal.

For each entry, decide: *should the portal change win, or should
git win?* If portal: merge the drift PR. If git: revert that file
in the drift PR's branch (`git restore detections/...`) and merge
the partial PR; the next deploy will reapply git's version and the
tenant will catch up.

Persistent `CHANGED` on the same rules every day is a handler bug.
(G2 — 46 defender_custom_detection rules that once reported this —
was resolved by unifying the server-field strip logic; see
[`reference/gap-assessment.md`](reference/gap-assessment.md).)

---

## Don't do this

Reasons matter; "don't" is just the headline.

### Don't force-push to `main`

`main` is protected by branch rules. A force-push would rewrite
the audit-chain anchor (`audit/*.jsonl` is committed alongside
deploys) and orphan the SHAs every audit record references. It
also breaks the `--changed-since <prev SHA>` driver in
`deploy.yml`.

### Don't run `contentops apply` against production from a feature branch

The `deploy.yml` workflow is the canonical deploy path. It reads
`config/tenant.yml`, sets up OIDC auth, and writes audit + state.
Local apply against the production tenant from a developer
machine bypasses CODEOWNERS, doesn't get audit-uploaded, and is
not reproducible. If you genuinely need to apply locally for a
sandbox tenant, set `PIPELINE_ENV=<sandbox>` so the right
`config/tenant.<env>.yml` loads.

### Don't commit `.env`

`.gitignore` excludes it. If you accidentally `git add .env`,
`git restore --staged .env` and rotate the secret. (Anything in a
public commit is compromised.)

### Don't manually edit a rule in the portal without a follow-up drift PR

The drift workflow will catch the change overnight, but if you
*know* you tuned something in the portal, open a PR yourself with
the corresponding YAML edit. This keeps git as the source of truth
and avoids the "drift PR sat for a week, someone deployed the old
YAML, your tuning was lost" failure mode.

### Don't pass `--no-audit` or `--skip-deps-check` in CI

These exist for local debugging. Production runs need the audit
trail and the dependency graph. The `deploy.yml` and
`validate.yml` workflows do not pass them; if you find yourself
adding them to a workflow, that's a sign something else is wrong.

### Don't hand-edit `audit/*.jsonl`

The hash chain breaks on tamper. If a record is genuinely wrong
(e.g. an audit was written with `actor=unknown` because GITHUB_ACTOR
wasn't set in some workflow), open a PR adjusting the *workflow*
that produced it; never fix the audit file in place.

`contentops audit verify` runs weekly — broken chains will fire an
alert.

### Don't commit secrets to YAML

Watchlist items, ARM template parameters, automation rule action
inputs — these all sometimes need a secret value. The pattern:
`{{ KEY_VAULT_REF: <vault-name>/<secret-name> }}` placeholder in
git, resolved at apply time by the handler. **Today this is not
fully implemented for every asset kind.** When in doubt, leave
the secret blank in YAML and rely on the portal's "set this
secret here" affordance. Bringing every kind onto the
KEY_VAULT_REF machinery is on the roadmap.

### Don't let `contentops lint` warnings build up

Warnings are not gating by default — the `--fail-on-warn` flag
exists but is off in `validate.yml`'s lint step. That doesn't mean warnings are
fine. `project *` and `evaluate bag_unpack` warnings, in particular,
are easy to ignore and expensive to learn from later. Treat warnings
on a new rule as blockers for that PR even if CI doesn't.

### Don't disable a rule by deleting its YAML

Deleting the file removes it from the prune target list. The next
prune pass will see the live remote rule, fail to find a local
envelope, classify it as an orphan, and delete it. That's a hard
delete, no `enabled: false` softening. Use `contentops disable`
instead — it sets `status: deprecated`, which the apply path
translates into a soft-disable (the rule remains in the tenant,
just turned off).

If you actually want to delete: change the status to `deprecated`,
let the next deploy disable it, *then* delete the YAML and let
prune handle it.

---

## When you're stuck

1. Read [`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md) again — the
   decision-tree section covers most of the first-week stumbling
   blocks.
2. Run `contentops doctor`. Half of "the pipeline isn't working" is
   actually "my .env is stale."
3. Search the `audit/*.jsonl` for the asset id you're worried about.
4. Read the handler under [`contentops/handlers/`](../contentops/handlers/)
   for that asset kind. Each one is 200–400 lines and self-contained.
5. Ask in the SOC team channel. Include: command run, full output,
   `git rev-parse HEAD`.

---

## Contributing from a fork

Some CI checks fall back to a degraded mode on PRs opened from
forks. The cause is GitHub: OIDC tokens are not minted for fork PRs,
so any workflow step that needs Azure / Log Analytics credentials
silently no-ops. This is intentional — we never trust a fork PR
with tenant access — but it means contributors see fewer signals
than the base repo would. Affected today:

- `drift-pr` — skipped on forks. The reviewer doesn't get the
  "this PR's intent vs the live tenant" comment.
- `tuning-impact-preview` — renders the suppression table with `-`
  in the count columns. The diff is still posted; only the
  blast-radius numbers are missing.
- `validate.yml` pre-PR schema refresh — `continue-on-error` falls
  through to the committed baseline. Lint still runs.

What still works on forks:

- All YAML / Python / metadata lint.
- Pytest suite, SAST (bandit + semgrep), DCO check, SPDX check,
  spelling check, references URL check (outbound HTTP only,
  no tenant token).
- `validate` job's structural plan (no API calls — pure parser).

If you need the full signal, rebase your branch into the base repo
and reopen the PR there. We don't force this — the degraded fork
path is good enough for most reviews.

---

## Reading the codebase

If you want to understand *how* the pipeline works, read in this
order:

1. [`reference/architecture.md`](reference/architecture.md) — the
   shape.
2. [`contentops/core/asset.py`](../contentops/core/asset.py) — the
   asset taxonomy (6 kinds).
3. [`contentops/core/envelope.py`](../contentops/core/envelope.py) —
   what's in the YAML and how it parses.
4. [`contentops/core/handler.py`](../contentops/core/handler.py) — the
   handler protocol.
5. One concrete handler — [`contentops/handlers/sentinel_analytic.py`](../contentops/handlers/sentinel_analytic.py)
   is a reasonable choice; it's the most-used kind and exercises
   ETag, hash projection, validate, and apply paths.
6. [`contentops/cli/commands/`](../contentops/cli/commands/) — the
   CLI commands wire everything together (one module per command group).

The handler protocol is small (4 methods, 2 optional drift
methods). Once you've read one handler, the others read like
variations on a theme.
