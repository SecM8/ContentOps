# Contributing

This repository is **detection-as-code** for Microsoft Sentinel and Microsoft
Defender XDR. Git is the source of truth; every rule change ships through a
pull request that is reviewed, validated, and audited before deployment.

Before you start, please read:

- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community expectations.
- [`LICENSE`](LICENSE) — Apache-2.0 license terms.
- [`TRADEMARK.md`](TRADEMARK.md) — what you can and cannot do with the
  `ContentOps` and `SecM8` names.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability privately.

## Local setup

```powershell
git clone https://github.com/SecM8/ContentOps.git
cd ContentOps
python -m venv .venv
# Activate (PowerShell):
.\.venv\Scripts\Activate.ps1
# Activate (bash / zsh):
# source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e ".[dev]"

# Copy the tenant config template and fill in your Entra ID tenant + workspace IDs.
# config/tenant.yml is gitignored — it must never be committed. (See
# docs/operations/tenant-config-modes.md for the full set of supported
# tenant-config sources, including private-fork and vars+secrets-split
# alternatives.)
copy config\tenant.yml.example config\tenant.yml

# Install local pre-commit hooks (gitleaks, YAML checks).
# NOTE: gitleaks 8.21+ requires a free org license for organizational
# repos. If your repo is org-owned, skip `pre-commit install` for now,
# request the license at https://gitleaks.io/, and wire it as the
# `GITLEAKS_LICENSE` org secret when ready. CI's secret-scan.yml runs
# gitleaks regardless of local hooks.
python -m pip install pre-commit
pre-commit install
```

> **Author-only contributors**: if you only intend to author YAML
> detection content and let CI handle Azure operations, the
> `pip install -e ".[dev]"` step above is the only setup you need.
> Skip `az login` / `.env` entirely. See
> [`docs/quickstart.md`](docs/quickstart.md) §"Three adopter personas".

**Azure authentication.** Before you can run anything that touches the
tenant (`contentops doctor --auth`, `contentops apply`, the live test
suite), you need an Azure App Registration with the right permissions
plus credentials in your `.env`. If you've never set this up, walk
through
[`docs/operations/authentication-setup.md`](docs/operations/authentication-setup.md)
— it explains what an App Registration is, what OIDC means, and the
portal steps in order. Already familiar with Azure auth? The TL;DR
section at the top of that doc has everything you need.

## Sign-off (Developer Certificate of Origin)

All commits must include a `Signed-off-by:` line. This is the
[Developer Certificate of Origin](https://developercertificate.org/)
attestation that you have the right to contribute the change under
this project's license.

```bash
git commit --signoff -m "your message"
# or, set it for the repo:
git config commit.gpgsign true && git config format.signoff true
```

A missing sign-off will be flagged by the DCO check on the pull
request and will block merge until fixed.

## Branch protection requirements (`main`)

Branch protection on `main` MUST be configured manually in repository settings
— GitHub does not allow protected-branch rules to be modified through a PR.
See [Managing a branch protection rule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule).

Recommended settings:

- **Require a pull request before merging** — at least **1 approval**.
- **Require review from Code Owners** — enforces `.github/CODEOWNERS`.
- **Require status checks to pass before merging**, with the following checks
  marked required (these are the GitHub Actions job/workflow names that exist
  on `main` today):
  - `pytest` (job in `.github/workflows/ci.yml`)
  - `cli-smoke` (job in `.github/workflows/ci.yml`)
  - `mitre-attack-coverage` (workflow `.github/workflows/coverage.yml`)
  - `production-promotion-check` (workflow
    `.github/workflows/production-promotion-check.yml`)
- **Require branches to be up to date before merging.**
- **Restrict who can dismiss pull request reviews** — admins only.
- **Do not allow force pushes.**
- **Do not allow deletions.**

CI runs a non-destructive `cli-smoke` job (W4.5-C) that exercises
the CLI's `--help` for the most-used subcommands. It catches
import-time regressions but does **not** replace local linting. Run
`contentops lint` and `contentops doctor` locally before opening a PR.

## Status promotion flow

Every detection envelope carries a `status` field. The promotion lifecycle is:

```
development → testing → production → deprecated
```

Rules:

- Each transition is its own pull request. **One rule per PR is preferred for
  production promotions** so reviewers can focus on a single change.
- Production promotions trigger
  [`production-promotion-check`](.github/workflows/production-promotion-check.yml),
  which posts a sticky PR comment listing every rule whose `status` was
  promoted to `production` (or added directly in `production`).
- An emergency `contentops disable` *workflow* that bypasses normal review
  gates is **deferred** to a follow-up PR. The CLI command
  `contentops disable` exists today and can be invoked manually by an
  on-call operator.

## Local checks before opening a PR

Run these from the repository root before requesting review:

```bash
contentops doctor
contentops lint
python -m pytest tests/v2 -q
contentops coverage --path detections
```

`contentops` is the only CLI entry point. `python -m contentops` is the
equivalent module-path invocation; both work after `pip install -e .`.

For credential-backed Azure validation, see
[Live integration tests](docs/development/live-integration-tests.md);
the page covers `RUN_LIVE_TESTS=1`, the `INTEGRATION_*` env vars, the
production-workspace guard, and PowerShell-vs-bash invocation
gotchas.

A PR that fails any of these locally will fail in CI. Fix issues before
pushing to keep the review queue clean.

The expected baseline on `main` is **all `tests/v2` tests passing**. New work
should preserve that contract.

## Your first PR — end-to-end

If this is your first PR to a GitHub project, here's what happens
after you push your branch. Each step is automatic unless noted.

1. **Push the branch.**

   ```bash
   git checkout -b add-my-first-rule
   git add detections/sentinel_analytic/my-first-rule.yml
   git commit --signoff -m "Add: my-first-rule sentinel analytic"
   git push -u origin add-my-first-rule
   ```

   `--signoff` is the DCO attestation (see [above](#sign-off-developer-certificate-of-origin)).

2. **Open the pull request** on github.com. Target branch: `main`. Use
   the default PR template; describe what the rule detects and why.

3. **CI workflows fire automatically.** You'll see status checks
   appear at the bottom of the PR within ~30 seconds:
   - `dco` — confirms every commit has a `Signed-off-by:` trailer.
   - `spdx-headers` — confirms every Python file has the SPDX header.
   - `validate.yml` — parses every envelope, runs handler `validate()`.
   - `lint.yml` — runs `contentops lint` (KQL + META rules).
   - `coverage.yml` — posts an MITRE ATT&CK coverage delta as a
     comment. Never gates on its own.
   - `cli-smoke` / `pytest` — unit tests + CLI sanity checks.
   - `gitleaks` / `bandit` / `semgrep` — security scans.

   A red check is **blocking** — branch protection won't let the PR
   merge until all required checks are green. Click any failed check
   to read the logs and fix the issue with another commit on the same
   branch; CI re-runs automatically.

4. **Code review.** A CODEOWNERS-listed reviewer leaves comments or
   approves. Resolve comments; reviewer re-approves; merge button
   unblocks.

5. **Merge to `main`.** Use a **squash merge** for clean history (the
   default for this repo). Your branch is then safe to delete.

6. **`deploy.yml` runs against the production tenant.** This is the
   first time your rule actually touches Azure — until merge,
   everything was local/CI-only. The workflow:
   - Reads `config/tenant.yml` from the `TENANT_CONFIG_YAML` secret.
   - Authenticates via OIDC (no client secret).
   - Runs `contentops apply --role prod --changed-since <prev-SHA>`.
   - Writes one audit record per asset to `audit/<date>.jsonl`.
   - Commits the updated audit log + state ref back to `main`.

   Watch the workflow in **Actions** tab. A failure here means the
   rule got through validation but ARM/Graph rejected it — see
   [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md#arm--graph-400-at-apply-time).

7. **Drift PR tomorrow morning.** The daily `drift.yml` workflow
   collects live tenant state and compares to git. Your rule should
   appear as `in-sync` (or not appear at all — drift PRs only list
   differences). If it shows up as `changed`, see
   [`OPERATOR_GUIDE.md` Runbook 4](docs/OPERATOR_GUIDE.md#runbook-4--drift-pr-shows-entries-the-operator-didnt-make).

That's the full loop. After your first PR, runs 2–4 are the daily
cycle and you can ignore the rest.

If a check fails and you don't know why, read the logs first, then
ask in the SOC team channel with: workflow name, failing job, log
excerpt, and your branch name.

## Dependency policy

`pyproject.toml` `[project.dependencies]` is the canonical source of
truth for runtime dependencies. `requirements.txt` is a byte-mirror
maintained alongside it so `pip install -r requirements.txt` (used
by GitHub Actions and the `setup-python@v5` pip cache) keeps working
without duplicating the dependency-resolution logic.

When updating a runtime dependency by hand:

1. Edit the version pin in `pyproject.toml` first.
2. Update `requirements.txt` to the same pin.
3. Commit both in the same change.

Renovate keeps the two in lockstep automatically via the config in
`.github/renovate.json`; the manual policy above only matters for
ad-hoc edits between Renovate runs. `pip-audit` in CI fails the
build if either file carries an unsuppressed advisory, so the worst
case of drift is a noisy CI rather than a silent supply-chain risk.

## Generated content

The repository keeps the **collect / export capability** (the
[`collect.yml`](.github/workflows/collect.yml) workflow exports live tenant
state into `detections/`). Generated export output is the result of that
runtime workflow — **do not commit generated `detections/**` changes as part
of an unrelated PR**. Promote rule changes intentionally, one PR at a time.

## Signed commits

All commits merged to `main` **should** be cryptographically signed and show
GitHub's **Verified** badge.

To enforce this, enable "Require signed commits" under
`Settings → Branches → Branch protection rules → main`. It cannot be
configured through a pull request — a **repository administrator** must
enable it.

### Local setup — SSH signing (recommended)

```bash
# 1. Tell git to sign with SSH using your existing key.
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true

# 2. Upload the same public key to GitHub as a "Signing key"
#    (Settings → SSH and GPG keys → New SSH key → Key type: Signing Key).
```

### Local setup — GPG signing

```bash
# 1. Generate (or import) a GPG key, then tell git about it.
gpg --full-generate-key                         # ed25519 recommended
KEYID=$(gpg --list-secret-keys --keyid-format=long | awk '/^sec/{split($2,a,"/"); print a[2]; exit}')
git config --global user.signingkey "$KEYID"
git config --global commit.gpgsign true

# 2. Export the public key and add it under
#    Settings → SSH and GPG keys → New GPG key.
gpg --armor --export "$KEYID"
```

After setup, verify with `git log --show-signature -1` and confirm the
**Verified** badge appears next to your commit on GitHub.
