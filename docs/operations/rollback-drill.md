# Rollback drill

This page is the operator's step-by-step for reverting the tenant to
the detection content at a prior commit. Use it during an incident, a
bad merge, or a regression that shipped to production. Pair with
[`prune.md`](prune.md) when you need a full reset rather than a replay.

## What `rollback` does

`contentops rollback <sha>` materialises `detections/` at the given
git SHA into a temporary tree, then runs every handler's `validate()`
+ `apply()` against that tree.

- **Replay, not delta.** A rule that exists in the tenant today but
  did *not* exist at the rollback SHA is **left alone**. Run
  `contentops prune` afterwards if you want full reset semantics
  (see [§ Full reset](#full-reset-rollback-then-prune) below).
- **Non-destructive on locks.** Envelopes with
  `localCustomization: true` are skipped. `contentops unlock <id>`
  first if you want rollback to overwrite them.
- **Audit-tagged.** Every rollback apply writes audit records whose
  `message` is prefixed `rollback to <full-sha>`, so you can find the
  exact records later with `contentops audit query` (see
  [§ Verify](#verify-via-audit-query)).
- **Skips the dependency check.** The SHA was valid at its merge
  time; re-validating against *today's* dependency graph would refuse
  to replay a rule whose dependency was later removed. That's the
  wrong contract for incident response.
- **Dry-run by default.** You must pass both `--no-dry-run --yes` to
  actually mutate the tenant.

Implementation: [`contentops/rollback.py`](../../contentops/rollback.py),
[`contentops/cli/commands/rollback.py`](../../contentops/cli/commands/rollback.py).

## When to use it

- Production deploy left rules in a broken state (high alert volume,
  KQL regression, mis-tuned severity).
- A merged drift PR accepted a portal-side change that turned out to
  be a mistake.
- An experimental rule was promoted too aggressively and you need it
  back to the prior `status: experimental` envelope.

When **not** to use it:

- A single rule broke and the fix is obvious — edit the YAML, open a
  PR, re-deploy forward. Rollback is for batches.
- The bad change deleted local YAML and you want it back — that's a
  `git revert`, not a rollback (you have nothing to apply).
- You want the tenant to forget rules that exist on disk today —
  that's `prune`.

## CLI

```
contentops rollback <sha>
                  [--asset <kind>] [--rule-id <id>]
                  [--dry-run | --no-dry-run] [--yes]
                  [--no-audit]
                  [--role prod|integration|dev | --workspace <name>]
```

Required: the target SHA (short or full).
Two flags must be set to actually push: `--no-dry-run --yes`.

`--asset` and `--rule-id` narrow the replay; without them every
envelope that existed at the SHA is replayed. **Use them.** Untargeted
rollbacks are how you re-introduce regressions you'd already fixed
forward.

## Rollback via GitHub Actions (`rollback.yml`)

The CLI is the right tool from an operator workstation. For an
auditable, reviewer-gated rollback — especially against
**production** — use the
[`rollback.yml`](../../.github/workflows/rollback.yml) workflow instead.
It is the gated counterpart to the CLI command:

- **Manual dispatch only** (`workflow_dispatch`) — never fires
  automatically.
- **Dry-run by default.** Uncheck `dry_run` *and* type `CONFIRM` to
  apply; either one alone aborts.
- **Reviewer-gated on prod.** The `prod` slug maps to the `production`
  GitHub Environment, whose required-reviewer rule must approve before
  any write. `integration` / `dev` run without that gate.
- **Serialised against deploys.** It shares `deploy.yml`'s concurrency
  group (`deploy-<env>`), so a rollback queues behind — and never races
  — an in-flight deploy of the same env.
- **OIDC, no secrets.** Same federated App Registration as the rest of
  the pipeline (via the `pipeline-setup` composite action).
- **Traceable.** The plan lands in the run summary and `audit/` is
  uploaded as a 90-day artifact, so every replayed write ties back to a
  commit + the approving reviewer.

Inputs: `sha` (required), `env`, optional `asset` / `rule_id` /
`workspace` to narrow the replay, `dry_run`, and `confirm`. The
"narrow it with `--asset` / `--rule-id`" guidance below applies — the
workflow passes those straight through to the CLI.

## Recovery runbook: a deploy left prod broken

The specific incident the gated workflow exists for: `deploy.yml` ran on
a merge to `main`, and either the post-apply verify failed (a
`verified=False` row / non-zero deploy) or a downstream smoke signal
(alert-volume spike, a broken rule paging the SOC) surfaced minutes
later. You need prod back to the last-good content **now**, with an
audit trail.

1. **Find the last-good SHA** — the merge commit *before* the bad
   deploy. `git log --oneline -20 -- detections/`, or open the bad
   deploy's run and read the SHA it deployed; its parent is your target.
2. **Dispatch `rollback.yml` in dry-run** against `prod`
   (`dry_run=true`, the default), `asset` set to the affected kind and
   `rule_id` if a single rule broke. Read the plan in the run summary.
3. **Re-dispatch to apply:** `dry_run=false` + `confirm=CONFIRM`, and
   approve the `production` environment gate when prompted — the second
   pair of eyes is the point; don't route around it under pressure.
4. **Verify:** `contentops audit query rollbacks --since 1h` shows the
   `rollback to <sha>` records; `contentops explain <rule-id>` should
   read `in-sync`. Spot-check one rule in the portal.
5. **Fix forward.** Rollback buys time; it is not the fix. Open a PR
   that corrects the root cause so the next `deploy.yml` carries the
   real fix — otherwise the next merge re-deploys the broken content.

If the workflow itself can't run (Actions outage, broken runner), fall
back to the CLI drill below from an operator workstation holding the
prod App Registration.

## The drill

The minimum-viable rollback. Reads top-to-bottom.

### 1. Identify the SHA you want to roll back to

Usually the merge commit before the bad one. From the repo root:

```
git log --oneline -20
```

Find the last "known good" merge. Copy its short SHA. (Full SHAs work
too; rollback resolves either via `git rev-parse`.)

If the bad change was a single PR, the prior `main` commit is the
target. If multiple PRs, pick the last one before the first bad PR.

### 2. Dry-run against the integration workspace first

Always rehearse against integration before touching prod.

```
contentops rollback <sha> \
  --asset sentinel_analytic \
  --role integration \
  --dry-run
```

This prints a `Rollback plan (N assets)` table and exits 0 without
mutating anything. Read every row. The `update` actions are the rules
that will be PUT back to their SHA-version state.

If the plan is empty (`No assets to rollback.`), the SHA you picked
either has no `detections/` directory or doesn't match the asset
filter — recheck step 1.

If any row shows `status: error-validate`, the YAML at that SHA fails
today's lint/schema. Rollback refuses to apply in that case. You
have two choices:

- Pick a later SHA where the validation passes.
- Fix the SHA's YAML forward (rare; usually means a payload-rule
  tightening happened after the SHA).

### 3. Execute the rollback against integration

```
contentops rollback <sha> \
  --asset sentinel_analytic \
  --role integration \
  --no-dry-run --yes
```

The output ends with `Rollback summary (N assets)` and an
`[audit] wrote N rollback records to audit/<date>.jsonl` line. Read
the per-rule `verified` column — every row should say `ok`. Any
`verified=False` row is a post-apply hash mismatch; investigate with
`contentops sentinel-roundtrip-diff <id>` or
`contentops defender-roundtrip-diff <id>` before promoting to prod.

### 4. Verify in the live tenant

For each rolled-back rule, confirm it looks right:

```
contentops explain <rule-id>
```

This shows the envelope on disk, the last apply SHA from state, the
latest audit record (which should now carry the `rollback to ...`
prefix), and the current drift status (expected: `in-sync`).

Spot-check one rule in the portal too — open it in the Sentinel UI
and verify the KQL/threshold/etc. match what the SHA's YAML says.

### 5. Promote to production

Repeat steps 2-4 with `--role prod`:

```
contentops rollback <sha> --asset sentinel_analytic --role prod --dry-run
contentops rollback <sha> --asset sentinel_analytic --role prod --no-dry-run --yes
contentops explain <rule-id>
```

If your tenant has multiple prod workspaces, run the rollback once
per workspace by name:

```
contentops rollback <sha> --asset sentinel_analytic --workspace law-prod-eu --no-dry-run --yes
contentops rollback <sha> --asset sentinel_analytic --workspace law-prod-us --no-dry-run --yes
```

`--role prod` matching multiple workspaces is rejected for `rollback`
(same as `prune` and `drift`) — replay is a one-workspace-at-a-time
operation.

## Verify via audit query

After the rollback, every record carries the rollback marker. Find
them all in one shot:

```
contentops audit query rollbacks --since 24h
```

Each row shows `(timestamp, asset, id, action, status, workspace,
sha, message)`. The `message` field starts with `rollback to <full-sha>`.

For a per-rule history:

```
contentops audit query timeline <rule-id>
```

Shows every apply/rollback/disable touching that rule. A clean
rollback shows: original apply at SHA, ..., `rollback to <good-sha>`
record.

## Common pitfalls

### "Materialized 0 files from <sha>"

The SHA has no `detections/` directory. Either the SHA is from before
the directory was introduced, or you fat-fingered the SHA. Re-check
with `git ls-tree <sha> detections`.

### Locked envelopes silently skipped

Rollback honours `localCustomization: true`. If the original incident
was a portal-side edit and someone locked the rule to preserve it,
rollback will skip it. Two paths:

```
contentops unlock <rule-id>     # if you want rollback to overwrite
# ...then re-run rollback
```

Or accept that the locked rule keeps its portal-side state — rollback
only handles the unlocked majority and you handle the locked rule
manually.

### Multi-workspace: one workspace at a time

`rollback` only accepts a single workspace per invocation. If you
need to roll back across two prod workspaces, run the command twice
(once per `--workspace <name>`). The audit chain records each
workspace separately so you can confirm both ran.

### Rollback doesn't delete

A rule that the *current* main has but the *rollback SHA* didn't is
**left alone** in the tenant. If you want full pre-SHA semantics, see
the next section.

## Full reset: rollback then prune

For a "make the tenant look exactly like the SHA" scenario:

```
contentops rollback <sha> --no-dry-run --yes        # replays everything at SHA
contentops prune --no-dry-run --yes                 # deletes anything not on disk
```

The order matters. `prune` works against the YAML *currently on disk*
in the working tree, so the working tree must reflect the SHA you
just rolled back to before pruning. Either `git checkout <sha> --
detections/` first, or run `prune` from a worktree pinned at the SHA.

Note: this is a heavy operation. Rehearse it against integration
before pointing it at prod, and read `prune`'s output carefully — the
`--max-deletes` cap (default 25) is there for a reason.

## See also

- [`.github/workflows/rollback.yml`](../../.github/workflows/rollback.yml) — the gated, reviewer-approved rollback workflow.
- [`docs/reference/audit-trail.md`](../reference/audit-trail.md) — JSONL schema, hash-chain integrity, query examples.
- [`docs/operations/prune.md`](prune.md) — the deletion-as-code counterpart.
- [`docs/OPERATOR_GUIDE.md`](../OPERATOR_GUIDE.md) — high-level operator flow.
- [`contentops/rollback.py`](../../contentops/rollback.py) — git plumbing source.
- [`tests/v2/test_rollback.py`](../../tests/v2/test_rollback.py) — unit tests (14 cases).
- [`tests/integration/test_rollback_drill_live.py`](../../tests/integration/test_rollback_drill_live.py) — gated end-to-end drill.
