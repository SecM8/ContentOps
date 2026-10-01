# Team routine — what to look at, and when

The scheduled workflows do the heavy lifting; what they need from the
team is a few minutes of review so their PRs do not pile up. This page
is the whole routine for a deployment fork: one daily check, one weekly
sweep, a lookup table for red checks, and the short list of things
never to do. Schedules are in
[`workflow-schedule.md`](workflow-schedule.md); they only fire on a
fork that has opted in with `CONTENTOPS_SCHEDULES=true`
([`github-actions-setup.md` §6](github-actions-setup.md#6-scheduled-workflows--opt-in-with-contentops_schedules)).

1. [**Daily** — the drift PR (5 min)](#1-daily--the-drift-pr-5-min)
2. [**Weekly** — housekeeping PRs and upstream sync](#2-weekly--housekeeping-prs-and-upstream-sync)
3. [**Red check** — what to do](#3-red-check--what-to-do)
4. [**Never do**](#4-never-do)

---

## 1. Daily — the drift PR (5 min)

`drift.yml` compares the tenant with git every morning and, when they
differ, opens (or refreshes) one PR from a `drift/auto-*` branch. Open
it and decide per rule:

- **The portal change is wanted** (someone tuned a rule in the portal,
  Microsoft updated a template) — **merge the PR**. That accepts the
  portal state into git, so the next deploy does not overwrite it.
- **The portal change is not wanted** — **revert it in the portal**
  and close the PR. Once the tenant matches git again, the next drift
  run no longer reports the rule.

Merging a `drift/*` PR **never deploys**: `deploy.yml` skips any merge
commit from a `drift/auto-*` or `collect/*` branch, because its content
already *is* the tenant. Merging is therefore safe even mid-incident.

No drift PR means the tenant matched git. Unsure whether an entry is
real? See
[OPERATOR_GUIDE → Drift PR opened — is it real?](../OPERATOR_GUIDE.md#drift-pr-opened--is-it-real).

## 2. Weekly — housekeeping PRs and upstream sync

Once a week (Monday afternoon suits the schedule — most weekly jobs
run Monday morning UTC):

- **Merge the housekeeping bot PRs.** `kql-schemas-refresh.yml`
  (`chore(kql-schemas)`), `collect.yml` (`chore(collect)`) and
  `upstream-watchers.yml` each keep exactly one open PR: a new run
  closes its predecessors automatically. Review and merge the one that
  is there; there is nothing to clean up behind it.
- **Merge the upstream-sync PR with "Create a merge commit".** Never
  squash or rebase it — see [Never do](#4-never-do) and
  [`upstream-sync.md` §4](upstream-sync.md#4-one-time-stitch--fork-with-unrelated-history).
- **Glance at [`docs/status/deployments.md`](../status/deployments.md)**
  for failed or unverified deploys since last week. Anything red there
  goes through the table below.

## 3. Red check — what to do

| Symptom | Why | What to do |
|---|---|---|
| `version-bump check failed` on a drift PR | The drift PR imported portal edits under an unchanged `version`. | Recent tool versions bump the version automatically on re-import — sync the tool. Until then, bump `version` in the listed files on the PR branch. See [troubleshooting](../troubleshooting.md#version-bump-check-failed). |
| `Extra inputs are not permitted` on a Defender `status` / `description` | Graph replaced `isEnabled` with `status` and added `description`; older tool versions reject both. | Sync the tool from upstream; no YAML change needed. See [troubleshooting](../troubleshooting.md#extra-inputs-are-not-permitted-on-a-defender-status--description). |
| `could not add label: 'pipeline-alert' not found` | A job with an `upstream` remote sent `gh` to the public mirror instead of your repo (no `GH_REPO`). | Sync the tool from upstream; add `GH_REPO: ${{ github.repository }}` to any fork-local workflow that adds `upstream`. See [troubleshooting](../troubleshooting.md#could-not-add-label-pipeline-alert-not-found). |
| `GitHub Actions is not permitted to create or approve pull requests` | The org disallows PR creation by the built-in `GITHUB_TOKEN`. | Allow it in the org settings, or set the `AUTO_PR_TOKEN` secret — the PR-opening workflows must use it when the setting stays off. See [`github-actions-setup.md`](github-actions-setup.md#common-failure-modes--fixes). |
| `Could not locate all the workspaces in your query` when saving a rule | The rule's query (or a function it calls) reads another workspace by name, e.g. `workspace("law-other")`. The deploy identity cannot see that workspace, so Sentinel refuses the save. | Grant the deploy identity read on that workspace (Log Analytics Reader) **and** Reader on its subscription so the name resolves. If that is not possible, lock the rule (`contentops lock <id>`, i.e. `localCustomization: true`) so deploys leave it alone. |
| Red deploy with `0 asset(s) selected` | An older tool version failed docs-only pushes to `main` that selected nothing to deploy. | Fixed in recent tool versions — sync the tool. Nothing was deployed and nothing needs re-running. |

Anything else: [`troubleshooting.md`](../troubleshooting.md), then the
decision tree in
[OPERATOR_GUIDE → When something breaks](../OPERATOR_GUIDE.md#when-something-breaks--decision-tree).

## 4. Never do

- **Squash-merge (or rebase-merge) an upstream-sync PR.** It flattens
  the merge, the shared history with the mirror is never recorded, and
  the next sync conflicts on everything or fails with
  `refusing to merge unrelated histories`.
- **Run a full redeploy on a live tenant to "make everything
  managed".** `deploy.yml` with an empty `changed_since` re-saves every
  rule. Microsoft runs a scheduled rule immediately when it is created
  or enabled, and recommends "editing and saving" to reset a rule; a
  mass re-save can therefore re-run rules over windows they already
  covered and raise duplicate incidents. Nothing about the detections
  improves. To bring existing rules under management, use
  `contentops state adopt` instead.
- **Hand-edit `audit/*.jsonl`.** The audit trail is hash-chained; a
  manual edit breaks the chain and the weekly `audit-verify.yml` fails.
  Recovery is in [`audit-recovery.md`](audit-recovery.md).

## See also

- [`workflow-schedule.md`](workflow-schedule.md) — when each scheduled workflow runs.
- [`upstream-sync.md`](upstream-sync.md) — keeping a fork in sync with the public mirror.
- [`../OPERATOR_GUIDE.md`](../OPERATOR_GUIDE.md) — day-to-day operator flow.
