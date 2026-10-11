# Protected-fork validation — running the pipeline under organization rulesets

Use this runbook once per deployment fork whose `main` is governed by a
ruleset — pull request required, code-owner review, a required workflow
such as an organization-wide secret scan, no bypass actors, auto-merge
off — and again whenever the token, the ruleset or the GitHub platform
changes. It exists because three outcomes that look alike are different:

| Outcome | Proves | Does **not** prove |
|---|---|---|
| A green workflow run | the code ran | that anything landed on `main` |
| A pull request exists | the branch was pushed and the PR API call succeeded | that its required workflows ran, that anyone can approve it, or that it can merge |
| A mergeable pull request | required workflows ran **on the PR** and an eligible reviewer approved | that the schedule will fire tomorrow, or that Azure authorization is right |

Treat each layer below as its own gate, record the evidence, and label a
check **not verified** when you cannot run it rather than assuming. A
missing prerequisite or a skipped check is not proof that the deployment
is ready.

Settings these checks rely on (all in repo configuration, never in
workflow files, so an upstream sync cannot undo them):

| Control | Where | Reference |
|---|---|---|
| `CONTENTOPS_LAND_VIA_PR=true` | repo Variable | [`github-actions-setup.md` §1](github-actions-setup.md#1-variables-not-secrets--theyre-public-identifiers) |
| `CONTENTOPS_SCHEDULES=true` | repo Variable | [`github-actions-setup.md` §6](github-actions-setup.md#6-scheduled-workflows--opt-in-with-contentops_schedules) |
| `AUTO_PR_TOKEN` | repo Secret | [`github-actions-setup.md` §2](github-actions-setup.md#2-secrets) |
| `GITLEAKS_LICENSE` | repo or org Secret | [`github-actions-setup.md` §2](github-actions-setup.md#2-secrets) |
| `identity_mode` | `.contentops-conformance.yml` | [`deployment-conformance.md`](deployment-conformance.md#single-app-registration-deployments-identity_mode-single) |

Evidence labels used below: **Observed** = seen in a run log, the UI or
an API response you captured; **Not verified** = the check could not be
run (say why, and what the manual fallback is).

---

## 0. Know your rules

```bash
gh api repos/<org>/<repo>/rules/branches/main          # rules in effect on main
gh api repos/<org>/<repo>/branches/main/protection      # classic protection (404 = none)
gh api repos/<org>/<repo>/actions/permissions/workflow  # can_approve_pull_request_reviews
gh variable list -R <org>/<repo>
gh secret list   -R <org>/<repo>                         # names only
gh api repos/<org>/<repo> --jq '{created_at, owner_id: .owner.id, repo_id: .id}'
```

Record: which rules apply (`pull_request`, `required_status_checks`,
`workflows`), whether any bypass actor exists (there should be none), and
the repository creation date (it decides the OIDC subject format, check 8).
`contentops conformance` L7 reads classic protection only, so a ruleset-
protected `main` shows as unprotected there — the API call above is the
authority.

## 1. Licence secret reaches the scanner

**Check.** The secret exists where the workflow can read it *and* the
workflow passes it through: `secret-scan.yml`'s gitleaks step has
`GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}` under `env:`. An
organization secret your repository can access is still invisible to the
action without that line. A repository secret of the same name overrides
the organization one (the UI notice about the override is informational).

**Evidence.** A `secret-scan` run on this repository that completes
without `missing gitleaks license`. If your organization enforces gitleaks
as a *required workflow* from another repository, that workflow has its
own wiring — a green `secret-scan.yml` here does not satisfy it, and
deleting `secret-scan.yml` does not remove the rule.

**Fallback.** Settings → Secrets and variables → Actions shows the names
(never the values) at repo and org level.

## 2. PR-only landing is on

**Check.** `CONTENTOPS_LAND_VIA_PR` is `true`. Dispatch `status-refresh.yml`
(or push a change under `detections/` for `coverage.yml` / `report.yml`)
and confirm the run's step summary says *landing mode: rolling PR*, that a
PR exists on `status/refresh` / `coverage/refresh` / `report/refresh`,
and that **nothing was pushed to `main`**. Run it a second time: the same
PR is updated (the summary says `updated`), no second PR appears.

**Evidence.** The step summary, the PR URL, `git log origin/main` without
a new bot commit. A failing direct push looks like
`GH013: Repository rule violations found for refs/heads/main` — that is
the ruleset doing its job, not a token problem; do not widen permissions.

**Not verified when** the variable is unset (the default direct push is
then still in force; on a ruleset-protected `main` every scheduled
status refresh will fail until it is set).

## 3. Automation token: approved, scoped, owned, expiring

**Check.** `AUTO_PR_TOKEN` is a fine-grained PAT with resource owner =
the organization, access = this repository only, Contents RW, Pull
requests RW (Workflows RW only if it will push workflow-file changes,
e.g. an upstream-sync branch), **approved** by the organization, with a
recorded owner, expiry date and rotation procedure. The owner is not the
sole code owner of `docs/status/**`, `coverage/**` or `reports/**`
(check 5).

**Evidence.** The token page under *Developer settings → Fine-grained
tokens* (approval state, scopes, expiry) plus the `auto-pr` step log line
`token source: AUTO_PR_TOKEN`. A `::warning:: ... token fallback:
GITHUB_TOKEN` means the secret is empty; `remote: Write access to
repository not granted ... 403` means it is present but unusable
(pending approval, wrong owner/repo, missing scope, expired) — delete it
until fixed rather than leave it in place.

**Not verified when** you cannot see the token page (ask the owner for
a screenshot of approval state and expiry).

## 4. Required workflows actually ran on the PR

**Check.** Open the rolling PR from check 2 → *Checks*. The ruleset's
required workflow(s) and the repository's own `pull_request` workflows
must have **run**, not merely be listed. With `AUTO_PR_TOKEN` they start
automatically. With the `GITHUB_TOKEN` fallback GitHub holds them for
approval (*action required*) — a user with write access must click
*Approve and run* (or close and reopen the PR). Whether ruleset-required
workflows follow exactly that approval path is not documented by GitHub;
observe it on your first PR and record what you saw.

**Evidence.** `gh pr checks <number>` listing the required check as
completed, and the PR's merge box no longer saying a required workflow is
missing.

**Not verified when** no PR was produced in check 2 (no diff): make a
harmless change that the workflow regenerates, or wait for the next
scheduled refresh.

## 5. Independent code-owner approval exists for every automation-written path

**Check.** For each path the automation writes — `docs/status/**`,
`coverage/**`, `reports/**` — find the **last** matching `CODEOWNERS`
pattern and its owners. At least one eligible reviewer must be someone
other than the PR author (the PAT owner, or `github-actions[bot]` on the
fallback). Authors cannot approve their own PRs; a team assignment helps
only if another team member exists and has write access.

**Evidence.** The PR's *Reviewers* panel offering an approver who is not
the author; an actual approval on the rolling PR. The fork-local
`CODEOWNERS` excerpt in [`onboarding.md`](../onboarding.md#deployment-forks-under-organization-rulesets)
shows the ordering that works.

## 6. Clean index line endings before `create-pull-request`

**Check.** Every tracked file matches `.gitattributes` (`*.yml text
eol=lf`, etc.) in the *index*, not only in the working tree:

```bash
git ls-files --eol | grep -E 'i/crlf|i/mixed'     # must print nothing
```

A Mode A `config/tenant.yml` committed from Windows is the usual hit. Any
such file makes every `auto-pr` run fail at `git stash pop` with `Your
local changes to the following files would be overwritten by merge`.

**Evidence.** Empty output above, from a fresh clone. Repair only in the
private fork: `git add --renormalize -- <file>` and commit
([`tenant-config-modes.md`, Mode A step 5](tenant-config-modes.md#mode-a--committed-tenantyml-private-corp-fork)).

## 7. Scheduled runs are eligible, and skips are deliberate

**Check.** `CONTENTOPS_SCHEDULES` is `true`, Actions is enabled, the
workflow file on the default branch has its `schedule:` trigger, and the
repository has had activity within 60 days (GitHub disables schedules
otherwise). A manual dispatch bypasses the gate and proves **nothing**
about cron eligibility.

**Evidence.** A *scheduled* (`event: schedule`) run that **executed** — not
one whose jobs are all grey *skipped*:

```bash
gh run list -R <org>/<repo> --workflow status-refresh.yml --event schedule --limit 5
```

A skipped scheduled run with the variable unset is the policy working as
designed; a slot with no run at all is a cron problem.
[`workflow-schedule.md`](workflow-schedule.md) lists the slots.

## 8. Azure identity, in layers

Validate each layer on its own; a green earlier layer says nothing about
the next.

1. **Token exchange (L3).** `azure/login` succeeds in the `automation`,
   `production`, `integration` and `conformance` environments you use.
   `AADSTS700213` means the federated credential's issuer / subject /
   audience do not match the emitted claim. Repositories created after
   2026-07-15 emit `repo:<org>@<org-id>/<repo>@<repo-id>:environment:<env>`,
   older ones `repo:<org>/<repo>:environment:<env>`; the error quotes the
   exact subject — copy it, never derive it
   ([`authentication-setup.md`, step 3](authentication-setup.md#step-3-add-an-oidc-federated-credential-for-ci)).
   Never print or store the token itself.
2. **Graph consent (L4).** `contentops conformance --scope L4` shows the
   application permissions granted *and* admin-consented. On a repository
   using the ID-based subject format, list those subjects explicitly under
   `federated_credential_subjects` in `.contentops-conformance.yml` or L4
   reports them missing ([`deployment-conformance.md`](deployment-conformance.md#protected-fork-notes-verified-2026-10-11)).
3. **Azure RBAC (L5).** Workspace, resource group and Sentinel onboarding
   reachable with the right role per identity. With one shared App
   Registration declare `identity_mode: single` and accept the documented
   trade-off; do not relax the split-mode checks globally.
4. **Workflow behaviour under the ruleset (L7 + this runbook).** PR-triggered
   jobs that use OIDC (`integration-deploy`, `drift-pr`,
   `tuning-impact-preview`) run the PR's code with the environment's
   identity; check the environment's branch policy and reviewer
   requirement so PR-controlled code cannot obtain a shared write-capable
   identity unexpectedly ([`SECURITY.md`](../../SECURITY.md#ci-trust-model-for-pull-requests)).

Environments to inventory from the workflows you enable: `production`,
`integration`, `automation`, `conformance`, `reporting` (no OIDC) and any
you added such as `dev`.

---

## Troubleshooting quick reference

| Symptom | Likely cause / distinguishing check | Operator action |
|---|---|---|
| `missing gitleaks license` | Secret absent or inaccessible, or the `env:` line not present in the workflow | Verify org/repo secret access and the workflow wiring (check 1); confirm your licence entitlement |
| `GH013: Repository rule violations found ... Required workflow '<name>' is not satisfied` on a direct push | The ruleset requires PR-mediated landing | Set `CONTENTOPS_LAND_VIA_PR=true` (check 2); do not increase token permissions as a substitute |
| PR exists but its required workflows never run / show *action required* | PR opened with `GITHUB_TOKEN` (step summary says *token fallback*) | Set an approved `AUTO_PR_TOKEN` (check 3); treat *Approve and run* or close/reopen as recovery only |
| `remote: Write access to repository not granted.` (403) | PAT pending approval, wrong owner/repository, insufficient permissions, or expired — a 403 alone does not say which | Check approval, access, scopes and expiry (check 3); delete the secret until it works |
| PR cannot receive a code-owner approval | Author is the only eligible owner for the last-matching path | Supply an independent eligible reviewer via team ownership, or change the automation identity (check 5) |
| `git stash pop`: local changes would be overwritten (`config/tenant.yml`) | Indexed CRLF conflicts with `eol=lf` attributes | Inspect index line endings; commit a narrowly scoped normalisation in the private fork (check 6) |
| Scheduled workflow skipped | `CONTENTOPS_SCHEDULES` unset, schedules disabled by inactivity, or another job condition | Inspect eligibility (check 7); a manual dispatch does not prove cron activation |
| `AADSTS700213` on `azure/login` | Trust tuple does not match the emitted claims (format or environment) | Verify issuer / subject / audience against the error text and the environment selection (check 8.1) |
| Conformance read leg rejects a shared identity | Dual-profile expectations applied to a write-capable shared identity | Declare `identity_mode: single` and document the trade-off; do not relax dual mode globally (check 8.3) |
| L7 says `main` is unprotected although a ruleset exists | L7 reads classic branch protection only | Record the ruleset from check 0 as the authority; the L7 row is **not verified** for rulesets |

## Sign-off

Keep a dated record per fork: for each of checks 0–8 the evidence
captured, who captured it, and anything **not verified** with its manual
fallback. A fork is ready when every check has evidence — not when the
last workflow run was green.
