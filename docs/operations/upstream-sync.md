# Keeping your fork in sync with upstream

For adopters running ContentOps from a **fork of the public mirror**
(`SecM8/ContentOps`). Three workflows, pick the one that matches your
situation:

1. [**New user** — first-time install](#1-new-user--first-time-install)
2. [**Updating user** — routine sync](#2-updating-user--routine-sync)
3. [**Full reset** — pristine match to upstream](#3-full-reset--pristine-match-to-upstream)

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

The mirror is rebuilt **nightly**, so a **weekly** pull is plenty. This is
the safe, everyday path:

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

Your own detections under `detections/<kind>/` are unaffected by an
update — the mirror doesn't carry them, so a fast-forward never overwrites
them.

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

## Never push to the public mirror

`upstream` is read-only for you. The `set-url --push upstream DISABLED`
guard above makes an accidental `git push upstream` fail fast instead of
attempting to write to `SecM8/ContentOps`. If you ever need to
contribute a change upstream, open a PR on the public mirror — the
operator cherry-picks accepted changes into the private source repo, and
they reappear on the mirror at the next nightly sync.
