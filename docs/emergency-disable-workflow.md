# Emergency disable workflow

`.github/workflows/emergency-disable.yml` is the SOC break-glass path for
silencing a single noisy or false-positive detection rule **fast**.

It opens a pull request that flips one detection envelope's `status:` to
`deprecated`. A human must review and merge the PR. The regular
`deploy.yml` workflow then deploys the change on push to `main`.

## When to use

* A production detection is generating a flood of false positives that
  cannot wait for a normal change-request cycle.
* A detection is alerting on a known-good, time-boxed activity (e.g. a
  scheduled red-team exercise) and must be silenced for the duration.
* You need a clear, auditable record (workflow run + PR + commit) of
  who silenced what, when, and why.

This workflow is **not** for:

* Permanent rule deletion — use a normal PR.
* Bulk disablement — the workflow refuses any change that touches more
  than one file.
* Tuning queries / changing thresholds — submit a normal PR with
  metadata + lint passing.

## Required inputs

| Input      | Required | Notes                                                         |
|------------|----------|---------------------------------------------------------------|
| `rule_id`  | yes      | Envelope `id` of the single rule. Validated against the V2 envelope id regex `^[a-z0-9][a-z0-9-]*[a-z0-9]$`. Wildcards are rejected. |
| `reason`   | yes      | Free-text rationale. Recorded in the YAML `disableReason:` and in the PR body. |
| `confirm`  | yes      | Must be the literal string `DISABLE`. This guards against accidental dispatch. |

## What the workflow does

1. Validates `confirm == "DISABLE"`, `reason` is non-empty, and
   `rule_id` matches the envelope id regex.
2. Checks out `main`, installs deps, configures the bot git identity.
3. Creates branch `emergency-disable/<rule_id>-<run_number>`.
4. Runs `contentops disable <rule_id> --reason "<reason>"`,
   which rewrites exactly one detection YAML's `status:` to
   `deprecated` and appends `disableReason:`.
5. Asserts:
   * a diff was produced under `detections/`,
   * **no** files outside `detections/` were modified,
   * **exactly one** detection file changed (no blast radius).
6. Stages `detections/` only (`git add -- detections`), commits with the
   actor + reason + run id in the message.
7. Pushes the branch and opens a PR labeled `emergency`.
8. Writes an audit summary to the GitHub Actions step summary.

## What the workflow does **not** do

* It does **not** auto-merge. A human must merge the PR.
* It does **not** call `contentops apply` / talk to Azure / Microsoft Graph.
  Deployment happens via the existing `deploy.yml` on push-to-main.
* It does **not** modify anything outside `detections/`.
* It does **not** require `id-token: write` — there is no OIDC step.

## Permissions

```yaml
permissions:
  contents: write           # create branch + commit
  pull-requests: write      # open PR
```

Notably absent (intentional):

* `actions: write`
* `id-token: write`
* `deployments: write`

## Triggers

Only `workflow_dispatch`. There is no `push`, no `pull_request`, no
`pull_request_target`, no `schedule`.

## Concurrency

`group: emergency-disable-${{ inputs.rule_id }}` — two operators
disabling the same rule serialize, two operators disabling different
rules run in parallel.

## Approvals

The workflow itself requires no environment approval, because
GitHub-side approval gates can introduce minutes of delay during an
active incident. Approval happens on the **PR** instead:

* The repo's branch protection on `main` should require at least one
  human review for the `emergency-disable/*` branch pattern.
* Reviewers should confirm the `rule_id`, the diff (single-file YAML
  status change), and the recorded reason.

## Audit trail

Every emergency disable produces:

1. A workflow run with the actor, inputs (visible in the run page) and
   step summary block.
2. A branch `emergency-disable/<rule_id>-<run_number>`.
3. A commit signed by the bot identity, with the actor and run id in
   the commit message body.
4. A PR labeled `emergency` linking back to the run URL.

## Re-enable / rollback

To re-enable a rule that was emergency-disabled:

1. Open a normal PR that flips the YAML's `status:` back to its prior
   value (`production`, `test`, etc.) and removes `disableReason:`.
2. Merge through the normal review process.
3. `deploy.yml` re-deploys on push-to-main.

The emergency workflow does **not** have a re-enable mode by design —
re-enabling should never be a break-glass action.

## Limitations / future hardening

* No expiry / auto-re-enable. Re-enable is a manual normal PR.
* No auto-merge. If the SOC needs sub-2-minute mean-time-to-disable, a
  follow-up PR can re-enable auto-merge once branch protection rules
  for `emergency-disable/*` are documented and enforced (required
  status checks, restricted approvers, dismiss stale reviews).
* Single rule per dispatch. Bulk disablement is intentionally not
  supported; trigger the workflow once per rule.
