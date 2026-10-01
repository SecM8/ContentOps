# `contentops state adopt` — adopting an existing tenant

Marks detections that are **already in sync** with the live tenant as
managed, without deploying anything. Read-only against Azure; the only
thing it writes is the per-env state file (`state/<env>/state.json`)
and, with `--push`, the `refs/heads/state/<env>` branch.

## Why the state file matters

The pipeline records every asset it applies in the per-env state file.
That record is what lets:

- the deployments status page (`docs/status/deployments.md`) mark a
  rule `in-sync` rather than `unmanaged`;
- `prune` tell "we deployed this and it has since been deleted from
  git" (orphan) apart from "someone else's rule" (leave alone);
- `undeployed-rules` spot production rules that never reached the
  tenant.

A tenant whose content was deployed before ContentOps tracked state —
or before the state branch was actually pushed (see the
[CHANGELOG](../../CHANGELOG.md) `[Unreleased]` → Fixed entry) — has an
empty state file, so every asset reads as `unmanaged` until the next
apply happens to touch it.

## When to adopt instead of redeploying

The obvious fix is to redeploy everything once (`apply` without
`--changed-since`). On a live production tenant that is usually the
wrong trade:

- **Re-saving a scheduled rule restarts its schedule.** Sentinel
  re-runs the query from the save time, so its lookback window
  overlaps the previous run and the same events can raise a second
  round of alerts — duplicate incidents for the SOC to close.
- **A PUT replaces the rule with exactly what the YAML holds.** Any
  template metadata (`alertRuleTemplateName`, `templateVersion`) the
  YAML does not carry verbatim is overwritten, which can break the
  Content hub link that tells you a newer template version exists.
- **It writes to every rule** for no functional change, and fills the
  audit trail with no-op applies.

`state adopt` gets the same end state — every rule that genuinely
matches the tenant is recorded as managed — without touching Azure.

Redeploy instead when you *want* the tenant to change: rules that
differ from git (`CHANGED`) are never adopted, by design.

## CLI

```
contentops state adopt [--role prod | --workspace NAME] [--asset KIND]
                       [--path detections] [--env ENV]
                       [--dry-run] [--refresh] [--push]
```

1. Runs the same list-and-compare as `contentops drift` (one workspace
   per run; Defender XDR is tenant-level and always compared).
2. If **any** asset kind could not be listed (ARM / Graph error), it
   prints the errors and exits 1 **without touching state**.
3. Every `in-sync` asset is recorded with `status: adopted`, keyed by
   the **local** envelope id (so a rule renamed in the portal, matched
   by ARM name, lands under the id apply and prune use).
4. `changed` / `new` assets are listed as *not adopted (differs from
   tenant)*.
5. Already-managed assets are skipped; `--refresh` re-records them.

Adopt never sets `last_apply_sha` / `last_apply_at` — adoption is not
an apply — and writes no audit records.

Typical first run, locally:

```powershell
contentops state sync pull                 # start from the durable state
contentops state adopt --role prod --dry-run
contentops state adopt --role prod --push  # save + push refs/heads/state/<env>
```

## In CI: `state-adopt.yml`

Manual dispatch only. Inputs: `role` (default `prod`), optional
`workspace`, and `dry_run` (default **true**). It uses the same
`automation` environment and read-only tenant identity as
`collect.yml`, and runs `state sync pull` → `state adopt` →
`state sync push` (the push only when `dry_run` is false).

Dispatch once with `dry_run: true`, read the summary, then dispatch
again with `dry_run: false`. The next `status-refresh.yml` run shows
the adopted rules as `in-sync (adopted)`.

Avoid running it while a deploy is in progress: both pull, modify and
force-push the same state branch, and `state sync` does not lock.

## What to do with the leftovers

- **`CHANGED`** — git and the tenant disagree. Decide which side is
  right: merge the drift PR (tenant wins) or deploy the YAML (git
  wins). Either way the next apply records the rule.
- **`NEW`** — the rule exists only in the tenant. `contentops collect`
  brings it into git; `contentops prune` removes it.
- **Repo-only rules** (not listed at all) were never deployed; the
  next apply creates and records them.
