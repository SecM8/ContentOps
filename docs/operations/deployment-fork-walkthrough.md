# Deployment fork — from clone to adoption

> The one ordered path for a team that runs ContentOps against a real
> tenant from a **private fork under organization rulesets**: pull
> request required on `main`, code-owner review, often an org-wide
> required workflow such as a secret scan, no bypass actors. Each step
> names the command or workflow dispatch, what you should see, and where
> to look when you do not. Budget half a day including the Azure side.

This page orders the existing references; it does not replace them:

| Need | Page |
|---|---|
| Which secret / variable / environment goes where | [`github-actions-setup.md`](github-actions-setup.md) |
| App Registration, federated credentials, RBAC | [`authentication-setup.md`](authentication-setup.md) |
| The three tenant-config layouts | [`tenant-config-modes.md`](tenant-config-modes.md) |
| Evidence checklist for a ruleset-protected fork | [`protected-fork-validation.md`](protected-fork-validation.md) |
| Recording an existing tenant as managed | [`adopt.md`](adopt.md) |
| Keeping the fork current with upstream | [`upstream-sync.md`](upstream-sync.md) |
| What to look at daily and weekly once live | [`team-routine.md`](team-routine.md) |

---

## 0. Decisions before you start (10 min)

Write these down; the rest of the page assumes them.

- **Tenant config mode.** Mode A (commit `config/tenant.yml` in the
  private fork) is the simplest for a deployment fork; Mode B (the
  `TENANT_CONFIG_YAML` secret) keeps the GUIDs out of git. See
  [`tenant-config-modes.md`](tenant-config-modes.md). In Mode A the
  committed file must have LF line endings
  ([step 6 of the validation runbook](protected-fork-validation.md#6-clean-index-line-endings-before-create-pull-request)).
- **Identity.** One App Registration for read and write
  (`identity_mode: single` in `.contentops-conformance.yml`) or a split
  pair. See [`deployment-conformance.md`](deployment-conformance.md#single-app-registration-deployments-identity_mode-single).
- **Reviewers.** At least two humans with write access. The author of a
  pull request cannot approve it, and that includes the owner of the
  automation token, so automation-written paths must have a reviewer who
  is not that person ([CODEOWNERS guidance](github-actions-setup.md#5-branch-protection-on-main)).
- **Your ruleset.** Know whether `main` requires a pull request, a
  code-owner review, a required workflow, and whether anyone can bypass
  ([validation runbook §0](protected-fork-validation.md#0-know-your-rules)).

---

## 1. Fork and clone (15 min)

1. Create a **private** repository in your organization and import the
   public mirror into it, pushing `main` and the tags. The GitHub
   Enterprise recipe is in the README:
   [Mirror into a private GitHub Enterprise repo](../../README.md#mirror-into-a-private-github-enterprise-repo).
2. Set the remotes: `origin` is your fork, `upstream` is the public
   mirror with push disabled, and `gh` pinned to your fork
   ([`upstream-sync.md` — Remote topology](upstream-sync.md#remote-topology)).
3. Install locally ([Quickstart step 1](../quickstart.md#1-clone--python-install-3-min)).

**Expect:** `python -m contentops doctor` is green at the install layer.
Nothing talks to Azure yet.

---

## 2. Repository settings (20 min)

All of these live in repository settings, not in workflow files, so an
upstream sync can never undo them. Full reference:
[`github-actions-setup.md`](github-actions-setup.md).

| Setting | Kind | Value / note |
|---|---|---|
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` | Variables (repo or per environment) | the App Registration and tenant GUIDs |
| `config/tenant.yml` committed (Mode A) **or** `TENANT_CONFIG_YAML` (Mode B) | file / Secret | one of the two, never both |
| `GITLEAKS_LICENSE` | Secret (repo or org) | required for repositories owned by an organization |
| `CONTENTOPS_SCHEDULES` | Variable | `true`, otherwise every scheduled run skips |
| `CONTENTOPS_LAND_VIA_PR` | Variable | `true` when the ruleset forbids direct pushes to `main`; status, coverage and report then land as rolling pull requests |
| `AUTO_PR_TOKEN` | Secret | fine-grained PAT; see the token contract in [§2 of the setup page](github-actions-setup.md#2-secrets). **Do not add it until it is approved**: a pending or mis-scoped token is non-empty, so the fallback never kicks in and every auto-PR run fails with `403 Write access to repository not granted`. Without it the workflows fall back to `GITHUB_TOKEN`, which works with one extra click per PR (step 4). |
| Environments `production`, `integration`, `automation`, `conformance`, `reporting` | Environments | create them; protection rules are optional |
| `.github/CODEOWNERS` default line | file | name a **team**, not one person, so bot PRs always have an eligible approver |

**Expect:** `gh variable list` and `gh secret list` show the names above
(never the values); the environments exist.

---

## 3. Azure identity (30 min)

Follow [`authentication-setup.md`](authentication-setup.md): App
Registration, one federated credential per GitHub environment, Sentinel
RBAC on each workspace, Graph permissions for Defender. Two things trip
first-timers:

- Repositories created after 2026-07-15 emit the **ID-based** OIDC
  subject (`repo:<org>@<org-id>/<repo>@<repo-id>:environment:<env>`),
  older ones the legacy form. Verify the emitted `sub` claim before you
  type subjects into the App Registration
  ([subject table](authentication-setup.md)).
- Login success is not Graph consent is not RBAC. Each is its own
  failure mode ([validation runbook §8](protected-fork-validation.md#8-azure-identity-in-layers)).

**Expect:** dispatch `conformance.yml`; layers L3 to L7 report PASS or an
explained WARN. L7 reads your ruleset when classic branch protection is
absent.

---

## 4. First collect (30 min)

The tenant already has rules. Bring them into git before deploying
anything.

1. Dispatch `collect.yml`. It snapshots every analytics rule, custom
   detection and watchlist into `detections/<kind>/` and opens a pull
   request on a `collect/<run-id>` branch with a `chore(collect):`
   commit. Resource names and GUIDs are preserved in `metadata.arm_name`
   and `payload.watchlistAlias`, so a later deploy updates the same
   resources rather than creating new ones. Watchlists arrive as
   **definitions without rows**; that is the API's behaviour, not a
   failed collect
   ([why, and the options](../assets/sentinel_watchlist_sas.md#collected-watchlists-carry-no-rows)).
2. **Held checks.** If the PR was opened with `GITHUB_TOKEN`, its
   workflow runs sit in *action required*. Open the Checks tab and
   *Approve and run*. An approved `AUTO_PR_TOKEN` removes this step.
3. **Read the checks**, in this order:
   - *Secret scan.* Collected KQL can contain GUID-shaped public
     constants (Windows audit-policy subcategory IDs are the classic
     case) that trip `generic-api-key`. Bridge with a `.gitleaksignore`
     at the repo root, one `file:rule-id:line` entry per finding, full-line
     `#` comments only, no inline comments. Commit it on the collect
     branch with a `chore(collect):` subject and `--signoff`. The durable
     fix is an allowlist regex in whichever gitleaks config the required
     workflow uses; a `.gitleaksignore` is pinned to line numbers.
   - *Validate.* Warnings (`KQL009` long query, `KQL010` cross-workspace
     read, `KQL101` `| take`, `KQLOVERRIDE001` template tokens such as
     `{{StartTimeISO}}`) do not block; triage them after the merge.
     Errors are content problems: fix the rule in the tenant and re-run
     collect, or fix it in git after the merge and let the deploy carry
     it.
   - *cli-smoke, pytest, DCO, SPDX.* Green or there is a real problem;
     see [troubleshooting](../troubleshooting.md).
4. **Keep the branch current by rebasing**, never with GitHub's *Update
   branch* button. That button adds a merge commit whose subject is
   `Merge branch 'main' into collect/...`; the promotion gate and the
   deploy gate recognise collect PRs by branch name and by the
   `chore(collect):` subject, and a rebase keeps both intact:

   ```bash
   git fetch origin
   git switch collect/<run-id>
   git rebase origin/main
   git push --force-with-lease origin collect/<run-id>
   ```

5. **Merge as a merge commit** after a code-owner approval. The deploy
   gate skips merges from `collect/*` branches, so nothing is written to
   the tenant; the content is already there.

**Expect:** `detections/<kind>/` on `main` holds one file per live rule.
The push to `main` triggers `coverage.yml` and `report.yml` (step 5).

---

## 5. The rolling pull requests (10 min)

With `CONTENTOPS_LAND_VIA_PR=true`, generated output lands as one
pull request per workflow, updated in place on every run:

| Branch | Workflow | When |
|---|---|---|
| `coverage/refresh` | `coverage.yml` | after a push to `main` that touches detections |
| `report/refresh` | `report.yml` | after a push to `main` that touches detections, and Mondays |
| `status/refresh` | `status-refresh.yml` | daily, and on dispatch |

Approve the held runs, get a code-owner approval, merge as a merge
commit. Merging them triggers nothing further: no workflow watches
`coverage/**`, `reports/**` or `docs/status/**`. Leaving them open is
also fine; the next run refreshes the same branch.

---

## 6. Adopt the state (10 min)

The status page would still call every rule `unmanaged`: nothing has
recorded them in the per-environment state. Adoption records the rules
that already match the tenant without redeploying anything
([`adopt.md`](adopt.md)).

1. Dispatch `state-adopt.yml` with role `prod` and **Preview only**
   checked (the default). Read the summary line:

   ```
   Adopt summary (env=production) - would adopt: N, already managed: 0, not adopted (differs): 0 (changed: 0, new: 0), errors: 0
   ```

   `N` should equal the number of collected files. A non-zero
   *differs* means the tenant changed between collect and now: run
   collect again, or decide which side wins
   ([leftovers](adopt.md#what-to-do-with-the-leftovers)).
2. Dispatch again with the checkbox **off**. The summary now says
   `adopted: N` and the run pushes the `state/<env>` branch. That
   branch is outside the ruleset, and the push uses the workflow's own
   token.

**Expect:** `state/production` exists with one commit, `[state] production sync from pipeline`.

---

## 7. Status pages (5 min)

Dispatch `status-refresh.yml`. It pulls the state branch, renders
`docs/status/*.md`, and opens the `status/refresh` pull request. The
deployments page should read `N in-sync · 0 failed · 0 unmanaged · 0 orphan`.
Approve the held runs, review, merge as a merge commit.

The redactor strips tenant GUIDs from these pages; the repo's own secret
scan has a rule that fails if one gets through.

---

## 8. Steady state — what arrives when

| UTC | Workflow | Lands as | Who acts |
|---|---|---|---|
| 04:00 daily | `status-refresh.yml` | `status/refresh` PR | reviewer merges when convenient |
| 04:17 daily | `secret-scan.yml` | check on `main` | nobody, unless red |
| 06:00 daily | `drift.yml` | `drift/auto-…` PR when the tenant and git disagree | reviewer decides: merge (tenant wins) or deploy (git wins) |
| 08:00 daily | `validate.yml` | check on `main` | nobody, unless red |
| Monday 08:00 | `report.yml` | `report/refresh` PR | reviewer merges |
| weekly | `upstream-watchers.yml`, `kql-schemas-refresh.yml` | one PR each | reviewer merges |

Human changes follow the normal flow: branch, edit YAML, PR, review,
merge. A merged human commit that touches `detections/**` deploys to
production through `deploy.yml`; collect and drift merges never do.

Until `AUTO_PR_TOKEN` is approved, every bot-opened PR needs the
*Approve and run* click. Once the token is in place the runs start on
their own and the step summary of each landing run reads
`token source: AUTO_PR_TOKEN`.

Keeping the fork current with upstream is a weekly task:
[`upstream-sync.md` §2b](upstream-sync.md#2b-deployment-fork-under-a-ruleset--sync-by-pull-request).

---

## 9. Evidence to keep

Copy this table into the setup ticket and fill the right-hand column as
you go. The [validation runbook](protected-fork-validation.md) has the
longer form with the *Observed* / *Not verified* labels.

| Step | Evidence |
|---|---|
| 2 | `gh variable list`, `gh secret list`, environment names |
| 3 | conformance run id, L3–L7 results |
| 4 | collect run id, PR number, check results, merge commit |
| 5 | first `coverage/refresh` and `report/refresh` PR numbers |
| 6 | adopt summary line (dry run and real), `state/<env>` commit |
| 7 | `status/refresh` PR number, dashboard totals |
| 8 | the first scheduled run that executed (not skipped) |

---

## Pitfalls seen in the field

| Symptom | Cause | Fix |
|---|---|---|
| Promotion check fails on a collect PR after *Update branch* | head commit became `Merge branch 'main' into collect/...` | rebase instead (step 4); upstream also skips by branch name now |
| Every auto-PR run fails with `403 Write access to repository not granted` | `AUTO_PR_TOKEN` present but pending approval or mis-scoped | delete the secret until it is approved; the `GITHUB_TOKEN` fallback then works |
| `git stash pop` fails inside `create-pull-request` | committed `config/tenant.yml` has CRLF | normalise to LF ([runbook §6](protected-fork-validation.md#6-clean-index-line-endings-before-create-pull-request)) |
| Secret scan flags GUIDs in a collected KQL datatable | public constants matched by `generic-api-key` | `.gitleaksignore` bridge, then an allowlist regex in the scanner config |
| Required workflow never runs on a bot PR | PR opened with `GITHUB_TOKEN`; runs held | *Approve and run*, or an approved `AUTO_PR_TOKEN` |
| Nobody can approve a bot PR | the token owner is the only code owner of that path | route automation paths to a team in CODEOWNERS |
| Scheduled run shows *skipped* | `CONTENTOPS_SCHEDULES` unset | set the variable; a manual dispatch does not prove cron eligibility |
| Sync PR cannot merge | squash or rebase chosen | merge commit only; see [`upstream-sync.md`](upstream-sync.md#2b-deployment-fork-under-a-ruleset--sync-by-pull-request) |
