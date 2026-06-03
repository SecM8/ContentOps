# Release process

How a tagged release happens, what artefacts it produces, and how
downstream consumers verify them. The implementation lives in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml);
this page is the narrative companion.

## TL;DR

1. Bump `version` in `pyproject.toml`. Open a PR. Merge.
2. Tag the merge commit: `git tag v0.1.1 && git push origin v0.1.1`.
3. `release.yml` fires on the tag push, builds + SBOMs + attests +
   publishes a GitHub Release.

That's it. No human steps in CI; no manual artefact uploads.

## What the workflow produces

For every `v*` tag, the release contains:

| Artefact | Purpose | Consumer verification |
|---|---|---|
| **Source tarball** (`contentops-<v>.tar.gz`) | The signed source distribution | `pip install` from URL; checksum in `sha256` |
| **Wheel** (`contentops-<v>-py3-none-any.whl`) | Installable binary distribution | Same `pip install`; runs offline |
| **CycloneDX SBOM** (`sbom.cdx.json`, schema 1.5) | Software Bill of Materials for the runtime dependency closure | `grype sbom:sbom.cdx.json`, `trivy sbom sbom.cdx.json`, `osv-scanner --sbom=sbom.cdx.json` |
| **Build provenance attestation** (in-toto, attached to all release files) | Cryptographic proof these artefacts were built from this tag on a known GitHub Actions runner | `gh attestation verify <file> --owner KustoKing` |
| **Changelog body** | Bullet list of every non-merge commit since the previous tag, minus auto-audit chore commits | Renders on the GitHub Release page |

The release is marked **prerelease** automatically when the tag
contains `-rc.` or `-beta.` (e.g. `v0.2.0-rc.1`).

## Step-by-step (operator view)

### 1. Decide the version

Versioning is [SemVer 2.0](https://semver.org/):

- `MAJOR` — incompatible CLI/schema break (rare; we'd announce first).
- `MINOR` — new feature, backward-compatible (most releases).
- `PATCH` — bug fix only.
- `-rc.N` / `-beta.N` — pre-release suffix; marked `prerelease` on
  the GitHub Release.

Examples: `v0.1.1` (patch), `v0.2.0` (minor), `v0.2.0-rc.1` (RC).

### 2. Bump `pyproject.toml`

Edit one line:

```
version = "0.1.1"
```

Open a PR, get a review, merge to `main`. The version bump is the
*only* change in this PR — keep it surgical.

Why a PR rather than tagging straight from main: the version bump
goes through the same branch protection (`pytest`, `cli-smoke`,
`dco`, `sast`, `secret-scan`, `mitre-attack-coverage`,
`production-promotion-check`) every other change does. A tag push
isn't gated by branch protection on its own; the PR is what gates.

### 3. Tag

Tag the merge commit, push the tag:

```
git switch main
git pull --ff-only
git tag -a v0.1.1 -m "v0.1.1"
git push origin v0.1.1
```

Annotated tags (`-a`) are the convention — they carry the author and
date, which the GitHub Release surface uses.

### 4. Watch `release.yml`

Open the Actions tab, find the `Release` workflow run triggered by
your tag. It takes ~2 minutes. Steps in order:

1. **Build** — `python -m build` produces `dist/*.tar.gz` and
   `dist/*.whl`.
2. **SBOM** — `cyclonedx-py requirements requirements.txt` generates
   `dist/sbom.cdx.json`. A sanity check refuses to release an SBOM
   with fewer than 6 components (the floor for our runtime deps);
   that fails the build, not the release artefacts.
3. **Attest** — `actions/attest-build-provenance` generates an
   in-toto attestation over every file in `dist/`. The attestation
   is stored on the release and signed by GitHub's
   Sigstore-fulcio chain.
4. **Changelog** — `git log <prev-tag>..<this-tag>` rendered as a
   bullet list. Merge commits and `chore(audit):` entries are
   filtered out so the changelog reads as the human-meaningful
   delta.
5. **Publish** — `softprops/action-gh-release` creates the GitHub
   Release with the rendered changelog as the body and every file
   under `dist/` attached.

### 5. Verify the release (optional, recommended)

A downstream consumer reviewing the release artefacts:

```bash
# Pull the wheel + SBOM + provenance from the release.
gh release download v0.1.1 --repo KustoKing/SIEMContent --pattern '*.whl' --pattern 'sbom*' 

# Verify the wheel was built from this tag.
gh attestation verify contentops-0.1.1-py3-none-any.whl --owner KustoKing

# Scan the SBOM for known advisories.
grype sbom:sbom.cdx.json --output table
osv-scanner --sbom=sbom.cdx.json
```

The attestation verification establishes "this artefact came from a
GitHub Actions runner building from `v0.1.1` of `KustoKing/SIEMContent`".
Combine it with the wheel's checksum to pin a known good artefact in
your downstream lockfile.

## Pre-releases

Tag with an `-rc.N` or `-beta.N` suffix:

```
git tag -a v0.2.0-rc.1 -m "v0.2.0-rc.1"
git push origin v0.2.0-rc.1
```

The workflow auto-marks the release as `prerelease: true`. Pip will
not install a prerelease unless explicitly requested
(`pip install contentops==0.2.0-rc.1` or `--pre`).

Use pre-releases for:

- API surface changes that may need to be rolled back.
- New asset kinds where the handler/state plumbing isn't yet
  exercised against every downstream tenant.
- Anything that touches `audit/` semantics — the hash chain is the
  durable record, and a buggy audit projection is hard to recover
  from after the fact.

## What's NOT in the release

- **Tenant config.** `config/tenant.yml` is gitignored and
  per-deployment; the release ships the example template
  (`config/tenant.yml.example`) only.
- **Detection content.** Detection YAMLs under `detections/` are
  pipeline content, not pipeline source. They're collected per
  tenant; the release ships the pipeline that operates on them.
- **Live audit records.** The `audit/*.jsonl` chain is per-tenant
  and committed separately by the tenant's own CI workflow.

## Cadence and tagging criteria

There is no fixed weekly or monthly schedule for tags. A release happens
when **at least one of these criteria is met**:

1. **Milestone completion** — a phase from the operationalisation roadmap
   (or another tracked initiative) finished and the milestone is worth
   citing. Example: "v0.2.0 — closes G24 metadata backlog + Phase 2
   lifecycle gating."
2. **Security-relevant fix landed** — any bandit/semgrep/pip-audit
   advisory was suppressed or resolved, OR a tenant-config or OIDC
   surface changed in a way external adopters need to know about. These
   ship as patch-level releases.
3. **Externally-visible CLI/schema change** — a new command, a removed
   command, an envelope field rename, or a Pydantic schema bump that
   would force a downstream lint adjustment. Minor or major depending
   on whether the change is back-compat.

**Skip a release for:** internal refactors that don't change the CLI
surface or YAML schema; pure documentation updates; CI workflow changes
that don't affect what's shipped; catalog regenerations.

A long gap between tags is not a problem. A tag that captures three
months of work is more useful to a downstream consumer than three tags
covering one cleanup each.

## GA vs prerelease

| Tag form | Marked prerelease? | When to use |
|---|---|---|
| `v0.2.0` | No (GA) | Routine releases. Default. |
| `v0.2.0-rc.1` | Yes (auto) | Anything that materially changes the apply / drift / state semantics; release notes deserve a soak window. |
| `v0.2.0-beta.1` | Yes (auto) | Defender-beta API surface changes, new asset kinds, or audit-chain schema migrations. |

The workflow auto-detects `-rc.` and `-beta.` and flips the GitHub
Release's `prerelease: true` flag (see `release.yml:104`). Pip will not
install a prerelease unless explicitly requested.

## Pre-tag release checklist

Before `git tag -a v...`, the tag author confirms each of the following:

- [ ] **Lint backlog state** — `contentops lint --strict --path detections/`
  exits 0; or if it doesn't, the residual count is documented in the
  release notes (e.g. "G24 still has 12 rules pending enrichment").
- [ ] **Audit-verify is green** — the latest scheduled `audit-verify.yml`
  run passed; if there's an open chain break, do not tag until recovery
  per [`operations/audit-recovery.md`](../operations/audit-recovery.md).
- [ ] **Drift state** — the latest `drift.yml` morning PR (if any) has
  been triaged. Untriaged drift PRs older than 7 days are a tagging
  blocker.
- [ ] **No suppressed pip-audit advisories** — `SECURITY.md` "Known
  advisories" section either lists every suppression with rationale or
  is empty.
- [ ] **CHANGELOG.md `[Unreleased]` block** has at least one entry under
  Security, Added, Changed, or Fixed since the previous tag. An empty
  Unreleased block is a sign no meaningful change has shipped.
- [ ] **`pyproject.toml` version** matches the tag exactly. Tag is
  annotated (`-a`), not lightweight.

## Tag-author responsibility

The maintainer cutting the tag is responsible for:

1. Running the checklist above (or assigning a co-maintainer to verify).
2. Watching `release.yml` execute end-to-end. If a step fails (SBOM gen,
   in-toto attestation, GitHub Release creation), the partial release
   must be cleaned up before re-tagging — see "Bad release → rollback"
   below.
3. Moving the `[Unreleased]` block in `CHANGELOG.md` to a versioned block
   immediately after the GitHub Release lands.

A second maintainer review is required for any release that bumps the
**major** version or that ships a behaviour-changing schema migration.
Patch and minor releases can ship on a single maintainer's authority.

## Bad release → rollback

If a tagged release is wrong (e.g. a CLI regression slipped through
CI), the right move is **roll forward, not delete the release**.
Deleting a release is observable; consumers may have pinned to it.

Bump again with the fix:

```
# Suppose v0.1.1 had a bug; fix on main, then:
git tag -a v0.1.2 -m "v0.1.2 — fixes regression in <area>"
git push origin v0.1.2
```

For rolling back the *content* of a tenant after a bad deploy (a
distinct concern), see
[`docs/operations/rollback-drill.md`](../operations/rollback-drill.md).

## See also

- [`SECURITY.md`](../../SECURITY.md) — supply-chain hardening,
  pinning, advisory channel.
- [`CHANGELOG.md`](../../CHANGELOG.md) — durable human-curated
  changelog (Keep a Changelog format).
- [`.github/workflows/release.yml`](../../.github/workflows/release.yml) — workflow source.
- [GitHub Releases](https://github.com/KustoKing/SIEMContent/releases) — published artefacts.
