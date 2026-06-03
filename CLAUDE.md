# CLAUDE.md — ContentOps powered by SecM8

> Read this file before writing code or making decisions in this
> repo. Keep it short on purpose — it is auto-loaded into every AI
> agent's context window. For project basics (what it does, tech
> stack, install steps, license) see [README.md](README.md). For
> day-to-day operator flow see [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md).
> For terms that recur in CLI output, runbooks, and PR comments see
> [docs/glossary.md](docs/glossary.md).

## One-line summary

Detection-as-code pipeline for Microsoft Sentinel + Microsoft
Defender XDR. Single tenant. Apache-2.0 with reserved trademarks
(see [TRADEMARK.md](TRADEMARK.md)). Single Click root group:
`contentops`.

## Invariants — break these and CI / production breaks

1. **Brand string is `ContentOps powered by SecM8`** (not `by SecM8`
   — that's the old phrasing). `contentops --version` prints this;
   docs and chat output should match.
2. **CLI: the only entry point is `contentops`.** The historical
   `pipeline` alias was removed; do not reintroduce it (no
   console-script alias in `pyproject.toml`, no `python -m pipeline`
   shim, no deprecation banner). Both `python -m contentops` and the
   `contentops` console script work.
3. **Tenant config: `config/tenant.yml` is gitignored. Never commit
   it.** CI materialises it from the `TENANT_CONFIG_YAML` secret via
   `.github/actions/pipeline-setup/action.yml`. Three supported
   modes documented in
   [`docs/operations/tenant-config-modes.md`](docs/operations/tenant-config-modes.md).
   gitleaks (`.gitleaks.toml` + `.github/workflows/secret-scan.yml`)
   will fail CI if real tenant/subscription GUIDs land in the repo.
4. **SPDX headers** — every new Python file under `contentops/`,
   `scripts/`, or `tests/` must carry both
   `# SPDX-FileCopyrightText: 2026 KustoKing / SecM8` and
   `# SPDX-License-Identifier: Apache-2.0`. CI enforces via
   `scripts/add_spdx_headers.py --check`. Bulk-add with
   `python scripts/add_spdx_headers.py` (idempotent).
5. **DCO** — every commit must carry a `Signed-off-by:` trailer
   (`git commit --signoff`). CI enforces via
   `.github/workflows/dco.yml`. Dependabot, Renovate, and
   github-actions[bot] are allowlisted.
6. **Composite actions have no `secrets` context.** Never put
   `${{ secrets.* }}` literally in `inputs.*.description` strings
   or `run:` heredocs inside `.github/actions/*/action.yml` — the
   GitHub Actions parser fails at load time. Pass secrets through
   inputs from the calling workflow instead. See PR #155.
7. **Catalog regen** — after adding a workflow, CLI command, or
   lint rule, run `contentops catalog regenerate` so
   `docs/reference/generated-catalog.md` matches code. CI gates
   this via `tests/v2/test_catalog.py`.
8. **Asset taxonomy is six kinds** (`contentops/core/asset.py`):
   `sentinel_analytic`, `sentinel_hunting`, `sentinel_watchlist`,
   `sentinel_parser`, `sentinel_data_connector`,
   `defender_custom_detection`. The historical 21 are in git
   history — recoverable but not currently supported. Do not
   propose handlers for them without an explicit ask.
9. **Audit trail is hash-chained + monotonic.** Never edit
   `audit/*.jsonl` by hand. Use `contentops` CLI commands which
   maintain the chain via `contentops/audit/writer.py`. Weekly
   `audit-verify.yml` checks chain integrity.
10. **Git is the source of truth, not `state/state.json`.** State
    is derived and rebuildable; refusing to load it is a recoverable
    error, not a deal-breaker.
11. **Detection content is tracked alongside the code.**
    `detections/<kind>/*.yml` are committed normally, not
    gitignored. A 2026-05-17 PR (#183) briefly added a "bring your
    own" gitignore pattern under an alternative topology; it was
    reverted. Don't re-propose that pattern. Operator-side details
    about how this repo relates to any public release live in
    files not shipped to public consumers.

## Workflow gotchas

- Every PR: `git commit --signoff` always. Branch protection
  requires `dco` + `spdx-headers` + `bandit` + `semgrep` +
  `cli-smoke` + `pytest` + `gitleaks` + `actionlint` to pass.
- Trademark policy: `ContentOps` and `SecM8` are reserved marks
  (Apache 2.0 §6 carve-out). See [TRADEMARK.md](TRADEMARK.md).
- Auto-memory items the agent has already captured live under the
  operator's local `~/.claude/projects/<repo>/memory/` directory —
  consult before re-litigating decisions like "F2 deferred",
  "v1 hard-cut, no migration", or "aggressive cleanup, fail fast".
  (The path is operator-local and not present in the public mirror.)

## Tech stack pointer

[README.md — Tech stack](README.md#tech-stack).
