# Keeping your fork in sync with upstream

For adopters running ContentOps from a **fork of the public mirror**
(`SecM8/ContentOps`). Four workflows, pick the one that matches your
situation:

1. [**New user** — first-time install](#1-new-user--first-time-install)
2. [**Updating user** — routine sync](#2-updating-user--routine-sync)
3. [**Full reset** — pristine match to upstream](#3-full-reset--pristine-match-to-upstream)
4. [**One-time stitch** — fork with unrelated history](#4-one-time-stitch--fork-with-unrelated-history)

Git commands below are identical on PowerShell and bash/zsh; only the
one-time Python install differs per shell (see the new-user path).

## Remote topology

| Remote | Points at | Role |
|---|---|---|
| `origin` | your fork / private GitHub Enterprise repo | where you push, run CI, branch-protect |
| `upstream` | `https://github.com/SecM8/ContentOps` | the nightly-rebuilt public mirror — **read-only for you** |

**Make `upstream` un-pushable** so you can never write to the public
mirror by accident:

```powershell
git remote set-url --push upstream DISABLED
git remote -v        # upstream (push) now shows DISABLED
```

**Pin `gh` to your own repo** wherever an `upstream` remote exists.
With two remotes, the GitHub CLI prefers the one named `upstream`, so
`gh pr list`, `gh issue create`, `gh label create` silently target
`SecM8/ContentOps` instead of your fork. Locally, run
`gh repo set-default <org>/<repo>` once. In a workflow that adds the
remote (e.g. a scheduled sync job), set it on every `gh` step:

```yaml
env:
  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  GH_REPO: ${{ github.repository }}
```

Symptom when it's missing: `could not add label: 'pipeline-alert' not
found` although the label exists in your repo — see
[troubleshooting](../troubleshooting.md#could-not-add-label-pipeline-alert-not-found).

What the mirror ships: the **tool, templates, samples, and docs**. What it
never ships: the operator's real detection content, `config/tenant.yml`,
`audit/`, or `state/` (an allowlist + a forbidden-paths safety check
enforce that boundary). **You bring your own detections** under
`detections/<kind>/` — they live only in your `origin`, never upstream, so
no sync ever touches them.

---

## 1. New user — first-time install

Do this once. The detailed GitHub Enterprise import (rewiring remotes,
pushing to your private org) is in the README's
[Mirror into a private GitHub Enterprise repo](../../README.md#mirror-into-a-private-github-enterprise-repo)
section; the Python install + credential wiring is
[Quickstart step 1–2](../quickstart.md#1-clone--python-install-3-min).

Shortest path:

```powershell
# 1. Clone the public mirror, then rewire remotes (origin = your fork)
git clone https://github.com/SecM8/ContentOps.git contentops
cd contentops
git remote rename origin upstream
git remote add origin <your-fork-or-GHE-url>
git remote set-url --push upstream DISABLED        # belt-and-braces

# 2. Push to your fork
git push -u origin main

# 3. Install (PowerShell shown; see quickstart for bash + locked-down Windows)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

# 4. Wire your tenant config (gitignored — never committed)
copy config\tenant.yml.example config\tenant.yml      # then edit in your GUIDs
```

Then continue with [Quickstart](../quickstart.md) for credentials, your
first detection, and CI wiring.

---

## 2. Updating user — routine sync

The mirror is rebuilt **nightly**, so a **weekly** pull is plenty. Two
shapes of fork, two routines: a fork whose `main` mirrors upstream
fast-forwards (this section); a **deployment fork** that carries its
own tenant config and sits under a ruleset syncs by pull request
([§2b](#2b-deployment-fork-under-a-ruleset--sync-by-pull-request)).

The safe, everyday path for the first shape:

```powershell
git fetch upstream
git switch main
git pull --ff-only upstream main      # fast-forward main to the mirror
git push origin main                  # update your fork
```

`--ff-only` **refuses** if your `main` has diverged, so you never silently
lose local commits. If it refuses, you committed directly on `main`:

- **Recommended:** keep `main` a clean mirror of upstream and do your work
  on feature branches (`git switch -c my-change`). Then `main` always
  fast-forwards.
- **If you must keep commits made on `main`:** `git rebase upstream/main`
  (replay your commits on top) or `git merge upstream/main` (merge
  commit), then `git push origin main`. If you'd rather discard them, use
  the full reset below.
- **If the merge fails with `fatal: refusing to merge unrelated
  histories`:** your fork's history does not descend from the mirror's —
  do the [one-time stitch](#4-one-time-stitch--fork-with-unrelated-history)
  below, once, then come back to this routine.

Your own detections under `detections/<kind>/` are unaffected by an
update — the mirror doesn't carry them, so a fast-forward never overwrites
them.

---

## 2b. Deployment fork under a ruleset — sync by pull request

A deployment fork cannot fast-forward `main`: the ruleset requires a
pull request, and the fork carries files the mirror never has
(`config/tenant.yml` in Mode A, the uncommented allowlist line in
`.gitleaks.toml`, `.contentops-conformance.yml`, a CODEOWNERS default
line that names your team, `docs/status/`, `reports/`). Sync by merge
commit through a PR instead. The whole routine is fifteen minutes and
fits the Monday slot in [`team-routine.md`](team-routine.md#2-weekly--housekeeping-prs-and-upstream-sync).

### Is there anything new?

The mirror is rebuilt nightly as one commit, `chore(mirror): daily public
sync <date>`, and only when upstream changed. Check from your clone:

```bash
git fetch upstream
git log --oneline main..upstream/main               # commits your fork does not have
git diff --stat main...upstream/main                # which files they touch
git diff main...upstream/main -- CHANGELOG.md       # what changed, in words
```

Nothing listed means nothing to do. The CHANGELOG diff is the part to
read: an entry under **Changed** that names a workflow or a repo
variable may need a setting on your side (the settings table in the
[walkthrough §2](deployment-fork-walkthrough.md#2-repository-settings-20-min)),
and an entry under **Fixed** often explains a red check you have been
seeing.

Sync **weekly**, and immediately when the CHANGELOG lists a fix you are
waiting for.

### Merge procedure

```bash
git fetch origin upstream
git switch -c chore/upstream-sync-$(date +%F) origin/main
git merge --no-ff --signoff upstream/main
```

Conflicts are rare and always in a file both sides touched. Resolve by
rule, not by judgement:

| File | Keep |
|---|---|
| anything under `contentops/`, `tests/`, `scripts/`, `.github/workflows/`, `.github/actions/`, `docs/` (except `docs/status/`), `CHANGELOG.md` | **upstream** — if your fork hand-edited a workflow, take upstream's and reproduce the behaviour with a repo variable instead |
| `config/tenant.yml`, `.contentops-conformance.yml`, `catalog-info.yaml`, `docs/status/*`, `reports/*` | **fork** |
| `.gitleaks.toml` | upstream's content, with your uncommented `config/tenant\.yml$` allowlist line kept |
| `.github/CODEOWNERS` | your default line, upstream's block appended |

Then:

```bash
git push -u origin chore/upstream-sync-$(date +%F)
gh pr create --base main --title "chore(sync): upstream $(date +%F)" --body-file sync-body.md
```

Put the CHANGELOG entries you are pulling in, the conflict resolution
and any setting the entries ask for in the PR body. The sync PR runs the
full CI on the merged tree, so every check should be green before
review. Merge it as a **merge commit**; squash or rebase loses the
shared ancestor and the next sync conflicts on everything.

### After the merge

- **Open `collect/*` or `drift/*` pull requests** are now behind `main`.
  Rebase them, never *Update branch*: the button adds a merge commit
  whose subject defeats the gates that recognise bot content
  ([walkthrough §4](deployment-fork-walkthrough.md#4-first-collect-30-min)).

  ```bash
  git fetch origin
  git switch collect/<run-id>
  git rebase origin/main
  git push --force-with-lease origin collect/<run-id>
  ```

  Anyone with a local copy of that branch resets it:
  `git fetch origin && git reset --hard origin/collect/<run-id>`.
- **Rolling pull requests** (`status/refresh`, `coverage/refresh`,
  `report/refresh`) refresh themselves on their next run; nothing to do.
- **Settings** survive the merge untouched. Only act if the CHANGELOG
  entry you pulled asked for a new variable or secret.
- Walk the [validation runbook](protected-fork-validation.md) again only
  when the sync changed a landing workflow, the token or the ruleset.

---

## 3. Full reset — pristine match to upstream

Use this when your `main` has gotten messy and you want it to match the
mirror **exactly**, discarding fork-local changes on `main`.

> **Warning — this discards work.** `reset --hard` drops any local commits
> on `main`, and the optional `git clean` below deletes untracked **and
> gitignored** local files (including `config/tenant.yml` and `.venv/`).
> Make sure anything you care about is on another branch or backed up
> first.

```powershell
git fetch upstream
git switch main
git reset --hard upstream/main
git push --force-with-lease origin main      # rewrites your fork's main — be sure
```

### Optional: a pristine working tree (`git clean`)

`reset --hard` only fixes **tracked** files. To also remove stray
untracked files (build artifacts, old outputs), people reach for
`git clean -fdx` — but **`-x` also deletes gitignored files**, so it will
remove `config/tenant.yml` (your real tenant config) and `.venv/`, not
just `__pycache__/` and `*.egg-info/`.

A common misconception: adding `config/tenant.yml` to `.git/info/exclude`
does **not** protect it. `-x` disables *every* standard ignore source
(`.gitignore`, `core.excludesFile`, **and** `.git/info/exclude`); only a
command-line `-e` pattern survives `-x`. So exclude what you want to keep,
and **dry-run with `-n` first**:

```powershell
git clean -nfdx -e config/tenant.yml -e .venv     # dry-run: lists what WOULD be removed
git clean -fdx  -e config/tenant.yml -e .venv     # execute
```

### Recovery if you lost `config/tenant.yml`

- Re-materialise it from your `TENANT_CONFIG_YAML` GitHub secret, or
- Recreate it from
  [`config/tenant.yml.example`](../../config/tenant.yml.example) and
  re-enter your GUIDs (see
  [tenant-config-modes.md](tenant-config-modes.md)).
- `.venv/` is rebuildable — re-run the install from the new-user path.

---

## 4. One-time stitch — fork with unrelated history

Applies when the first merge from `upstream` fails with:

```text
fatal: refusing to merge unrelated histories
```

This happens when your repo was **not born as a clone of the mirror** —
it was imported file-by-file, seeded from another distribution, or
created before the mirror's current history existed. The mirror's
history is generated by the nightly sync, so the two lineages share no
common ancestor and Git refuses the merge by default.

The fix is a **one-time stitch merge** on a branch, then a PR into your
`main`:

```powershell
git fetch upstream
git switch -c chore/upstream-sync main
git merge --signoff --allow-unrelated-histories -X theirs upstream/main
```

- `--allow-unrelated-histories` permits the one-time join.
- `-X theirs` resolves every conflicting path in upstream's favour.
  **Afterwards, re-apply any fork-local edits it clobbered** as a
  follow-up commit on the same branch. The scheduled-workflow gate is
  no longer one of them: it is opt-in via the repo variable
  `CONTENTOPS_SCHEDULES`, which lives in repo settings and survives
  any merge ([github-actions-setup.md §6](github-actions-setup.md#6-scheduled-workflows--opt-in-with-contentops_schedules)).
  The same holds for PR landing of generated output
  (`CONTENTOPS_LAND_VIA_PR`, [§1](github-actions-setup.md#1-variables-not-secrets--theyre-public-identifiers))
  and the automation token (`AUTO_PR_TOKEN`): configuration, not
  workflow edits. If your fork hand-edited `status-refresh.yml`,
  `coverage.yml` or `report.yml` to open pull requests, take upstream's
  versions and set the variable instead — otherwise every sync conflicts
  on those files.
- `--signoff` signs the merge commit for the DCO gate.

Push the branch (`git push -u origin chore/upstream-sync`) and open a
PR. Two hard requirements when merging it:

1. **Merge it as a true merge commit** ("Create a merge commit" on
   GitHub). A squash or rebase merge flattens the stitch — the shared
   ancestor is never recorded, and the *next* sync fails with
   `refusing to merge unrelated histories` all over again. This also
   means the **"Require linear history" branch protection must be off**
   on a fork that syncs this way (see the note in
   [github-actions-setup.md §5](github-actions-setup.md#5-branch-protection-on-main)).
2. **Do not rebase the branch to fix DCO.** Upstream commits authored
   by the mirror account carry no `Signed-off-by` trailer; the
   `dco.yml` check skips upstream-mirror-authored commits and merge
   commits, so the PR passes as-is. The generic
   `git rebase --signoff` hint in the DCO failure output would rewrite
   the merge and destroy the stitch — never use it on a sync branch.

After the stitch lands, the histories share an ancestor and every
later sync is an ordinary merge — same branch-and-PR loop, no special
flags:

```powershell
git fetch upstream
git switch -c chore/upstream-sync main
git merge --signoff upstream/main
git push -u origin chore/upstream-sync     # PR → true merge commit, as above
```

(The `--ff-only` routine in [§2](#2-updating-user--routine-sync) only
applies while your `main` carries no fork-local commits. A stitched
fork by definition carries them, so the merge-PR loop above is its
steady state.)

---

## Never push to the public mirror

`upstream` is read-only for you. The `set-url --push upstream DISABLED`
guard above makes an accidental `git push upstream` fail fast instead of
attempting to write to `SecM8/ContentOps`. If you ever need to
contribute a change upstream, open a PR on the public mirror — the
operator cherry-picks accepted changes into the private source repo, and
they reappear on the mirror at the next nightly sync.
