# `kql_strict` — Kusto.Language strict-lint wrapper

Tiny .NET 8 console app that powers the *optional* semantic layer of
`contentops lint --strict` (closes roadmap entry **F1** / gap-assessment
**G1**). The Python lint runner at
[`contentops/lint/strict.py`](../../contentops/lint/strict.py) invokes
this wrapper via `dotnet kql_strict.dll <kql-file>` and reads tab-
separated diagnostic lines from stdout. When the wrapper is missing,
the runner gracefully degrades to the Python-only policy rules
(KQL101 etc.) and prints a single advisory.

## Building

```bash
# Linux / macOS
bash scripts/build_kql_strict.sh

# Windows (PowerShell)
pwsh scripts/build_kql_strict.ps1
```

Both wrappers run `dotnet publish` into the repo's `tools/` directory
so the resulting `tools/kql_strict.dll` lands where
`contentops.lint.strict._resolve_wrapper()` looks for it.

CI does the same step automatically in `.github/workflows/lint.yml`
and `.github/workflows/validate.yml`.

## Contract

The wrapper reads KQL from stdin (the Python caller in
`contentops/lint/strict.py:run_strict` pipes it in via
`subprocess.run(input=query)`); the positional argument is used as a
file-fallback when stdin isn't redirected (for ad-hoc CLI testing).
Emits one diagnostic per line on stdout:

```
<rule_id>\t<severity>\t<line>\t<message>
```

Where:

- `rule_id` — upstream Kusto.Language code (e.g. `KS204`); falls back
  to `KQL000` when the diagnostic carries no code.
- `severity` — currently always `warning` (see "Severity policy" below).
- `line` — 1-based line number derived from the diagnostic offset.
- `message` — single-line human description (tabs / newlines stripped).

Exit code is `0` on success (any number of diagnostics, including zero)
and `2` only on file-read failure (with detail on stderr). The Python
caller surfaces a `KQL000` warning when the wrapper crashes or times
out — see `contentops/lint/strict.py:run_strict`.

## Schema management

The wrapper enumerates every `schemas*.json` file in
`AppContext.BaseDirectory` (the directory `kql_strict.dll` ships in;
`dotnet publish` copies the JSONs next to the DLL via `<Content>`
entries in `KqlStrict.csproj`). Files are loaded alphabetically in
reverse order (so `schemas_defender.json` is processed *before*
`schemas.json` — first-occurrence wins on table-name conflicts). The
union is merged into a single `Kusto.Language.GlobalState.Default
.WithDatabase(new DatabaseSymbol("SentinelDefender", tables))` and
passed to `ParseAndAnalyze`.

The convention is a two-file split:

| File | Source | Refresh |
|---|---|---|
| `schemas.json` | **Sentinel custom tables** (tenant-specific — custom logs, ASIM normalizers, third-party connectors). | Nightly via `contentops upstream check-schemas`, sourced from `https://api.loganalytics.io/v1/workspaces/<id>/metadata`. |
| `schemas_defender.json` | **Defender XDR tables** (tenant-invariant — same columns for every tenant on the same license tier). | Vendored from Microsoft Learn / Graph Advanced Hunting; rarely changes. Public-mirror adopters reuse this file as-is without needing tenant access. |

When neither file is present the wrapper logs a stderr advisory and
falls back to no-schema mode. When one file is malformed, the
wrapper logs and continues with the others.

### Mode + severity (config-driven, F1.1 PR-I)

`contentops/lint/strict.py` reads `config/lint_strict.yml` and
controls the wrapper invocation accordingly:

- `mode: off` — Python policy rules only (KQL101 still gates `| take`
  / `| limit`); the .NET wrapper isn't even invoked.
- `mode: report` (default) — wrapper runs. Findings emit at
  `warning` severity so lint exits 0 even on `KS204` / `KS142` —
  visible in lint output for operator triage. Onboarding-friendly.
- `mode: block` — wrapper runs with `KQL_STRICT_PROMOTE_SEVERITY=1`.
  Findings emit at the upstream Kusto.Language severity (typically
  `error`). Errors fail `lint --strict`. Flip here once the baseline
  is mature.

The `KQL_STRICT_PROMOTE_SEVERITY=1` env var that PR-G shipped is
still honoured by the wrapper itself — but the canonical control is
now `config/lint_strict.yml: mode`. The Python runner sets the env
var on the wrapper subprocess based on mode; manual env-var
overrides still work for debugging.

### Finding allowlist

The wrapper validates KQL against the vendored Sentinel + Defender
schemas but doesn't model three constructs the operator-side
detection corpus uses heavily:

- **Join-suffix columns** — `SHA1` → `SHA11` after a self-join.
- **Dynamic extend columns** — `parse_json()` output typed via
  Log Analytics suffix conventions (`_s` / `_d` / `_b` / `_g` / `_l`).
- **Invoke-function projections** — `FileProfile()` projects ~15
  well-known columns the wrapper can't see (and the invoke itself
  emits `KS211`).

`config/kql_lint_allowlist.yml` suppresses these false positives.
See [`kql_lint_allowlist.yml.example`](../../config/kql_lint_allowlist.yml.example)
for the canonical shape and the loader at
[`contentops/lint/strict_allowlist.py`](../../contentops/lint/strict_allowlist.py)
for the contract:

- Only `KS142` (column-not-found) and `KS211` (invoke-not-found) can
  be allowlisted. Heuristic rules (`KQL001`-`KQL007`) and the
  strict-mode policy (`KQL101`) stay loud and cannot be suppressed.
- Each entry MUST carry a `reason` field. The loader rejects entries
  missing it so suppressions are always auditable.
- Patterns are Python regex `re.search` matches against the finding
  message — write column names directly without anchoring.
- Malformed entries are skipped with a stderr note; a single bad
  entry doesn't tank the whole file.

To bootstrap on a new tenant, copy the example into place:

```bash
cp config/kql_lint_allowlist.yml.example config/kql_lint_allowlist.yml
```

### Refresh paths

1. **Nightly workflow** — `.github/workflows/kql-schemas-refresh.yml`
   runs at 03:30 UTC. Runs `check-schemas` (Sentinel, LA metadata)
   AND `check-defender-schema` (Defender, Graph
   `runHuntingQuery getschema`) in sequence; one PR per night with
   both files refreshed. Each step honours
   `config/lint_strict.yml`'s per-source `enabled`.
2. **On-demand workflow** — `gh workflow run kql-schemas-refresh.yml`
   triggers the same flow immediately. Useful when an operator just
   added a connector and wants the new tables landed before the
   nightly fires.
3. **Pre-PR refresh** — when `config/lint_strict.yml:
   refresh_on_pr: true`, `validate.yml` runs `contentops upstream
   pre-pr-refresh` after `dotnet publish` and before `lint --strict`.
   Refreshes the published schemas next to `kql_strict.dll` so the
   PR's lint runs against the current tenant state. Best-effort: on
   Graph / LA failure, the published JSONs are unchanged and lint
   falls back to the committed baseline.
4. **Manual local** —
   ```bash
   contentops upstream check-schemas \
       --workspace-id "$PIPELINE_WORKSPACE_ID" \
       --write
   contentops upstream check-defender-schema --write
   git add tools/kql_strict/schemas.json \
       tools/kql_strict/schemas_defender.json docs/whats-new/
   git commit -s -m "chore(kql-schemas): refresh"
   ```
   No flag → dry-run prints the diff. With `--write` updates the
   committed JSON + appends `docs/whats-new/<date>-schemas.md` (or
   `-defender-schemas.md`).

### Schema staleness

If the wrapper reports `KS204 The name 'X' does not refer to any known
table` for a table you know exists, the schema file is stale (or the
table is on a connector that isn't installed on the workspace this
schema was pulled from). Run the manual refresh above to update.

## Why this is opt-in

The `Microsoft.Azure.Kusto.Language` NuGet package isn't reachable from
pure Python. Shipping the wrapper as a separate built artifact keeps
the rest of `contentops` Python-only at rest; only the lint and validate
workflows pay the .NET install cost.
