# Audit trail

> Hash-chained JSONL of every write the pipeline performs against
> the tenant. The records live in the repo at `audit/YYYY-MM-DD.jsonl`;
> CI also uploads the same files as 90-day GitHub Actions artefacts.

Background and architectural rationale: see
[`architecture.md`](architecture.md#audit-trail--the-hash-chain).
Implementation lives in
[`contentops/audit/writer.py`](../../contentops/audit/writer.py).

---

## Schema

One JSON object per line. Determinism: serialised with
`json.dumps(separators=(",", ":"))` and the field order matches the
dataclass definition in
[`contentops/audit/writer.py:27`](../../contentops/audit/writer.py).

```jsonc
{
  "timestamp":      "2026-05-07T09:14:32.481213Z",   // UTC, microseconds
  "asset":          "sentinel_analytic",              // Asset enum value
  "id":             "brute-force-ssh-001",            // envelope id
  "action":         "update",                         // PlanAction.value
  "status":         "success",                        // see below
  "sha":            "<full git sha>",                 // HEAD at apply time
  "actor":          "github-actor-or-USER",           // GITHUB_ACTOR / $USER
  "workflow_run":   "9123456789",                    // GITHUB_RUN_ID or null
  "message":        null,                             // free text on failure
  "metadata_owner": "secops@example.com",             // envelope.metadata.owner
  "prev_hash":      "<sha256 of previous record>",    // chain anchor
  "record_hash":    "<sha256 of this record minus record_hash>"
}
```

### Field reference

| Field | Source | Notes |
|---|---|---|
| `timestamp` | `datetime.now(timezone.utc)` at apply time | Microsecond precision; lexicographically sortable. |
| `asset` | `Asset` enum value | e.g. `sentinel_analytic`. See [`contentops/core/asset.py`](../../contentops/core/asset.py). |
| `id` | `envelope.id` | The on-disk slug, **not** the ARM resource name. |
| `action` | `PlanAction.value` | `create`, `update`, `disable`, `skip`, `noop`, `delete`. |
| `status` | derived | `success` / `failed` / `skipped` (see below). |
| `sha` | `git rev-parse HEAD` | "unknown" if not in a git checkout. |
| `actor` | `GITHUB_ACTOR` → `USER` → `USERNAME` → `"unknown"` | Driver of the run, not the rule owner. |
| `workflow_run` | `GITHUB_RUN_ID` | `null` for local runs. |
| `message` | optional | Filled on failure (truncated error text) or skip (reason). |
| `metadata_owner` | `envelope.metadata.owner` | `null` for legacy envelopes that don't carry metadata. |
| `prev_hash` | chain | First-ever record uses `"0"*64`; first record on a new day pulls from prior day's last record. |
| `record_hash` | computed | SHA-256 of the JSON serialisation of the record with `record_hash` itself removed. |

### Status values

`status` is derived from the per-asset `ActionResult` by
[`_build_audit_record()` in `contentops/cli/commands/apply_support.py`](../../contentops/cli/commands/apply_support.py)
(unified for apply, prune, lifecycle, and rollback):

| Result condition | `status` | Notes |
|---|---|---|
| `result.is_error` (status starts with `error-`) or `verified is False` | `failed` | `message` carries the error or verification detail. |
| `action is PlanAction.SKIP` | `skipped` | `message` carries the skip reason (e.g. `"experimental"`, `"locked"`, `"read-only handler"`). |
| Anything else | `success` | `message` is null for apply; "pruned" for prune. |

### Action values

| Action | When emitted |
|---|---|
| `create` | Apply produced a remote PUT/POST that the handler classifies as a creation. (Most handlers don't differentiate create vs update — they emit `update` as the canonical upsert label.) |
| `update` | Apply produced an upsert PUT/PATCH. |
| `disable` | Apply rewrote the asset with `enabled:false` / `isEnabled:false` (envelope `status: deprecated`). |
| `skip` | Asset skipped: experimental, locked without `--force-overwrite`, read-only handler, prune of a singleton. |
| `noop` | Validation/apply error (envelope didn't reach the wire). |
| `delete` | Prune deleted the orphan. |

---

## Querying the audit trail

The audit directory is `audit/`. One file per UTC day.

### "What changed yesterday?"

PowerShell:

```powershell
$yesterday = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
Get-Content "audit/$yesterday.jsonl" |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.status -eq 'success' } |
  Select-Object timestamp,asset,id,action,actor,sha
```

bash + jq:

```bash
yday=$(date -u -d 'yesterday' +%F)
jq -c 'select(.status=="success") | {timestamp,asset,id,action,actor,sha}' \
  "audit/${yday}.jsonl"
```

### "Who applied rule X across all time?"

```bash
jq -c --arg id "brute-force-ssh-001" \
  'select(.id==$id) | {timestamp,action,status,actor,sha}' \
  audit/*.jsonl
```

```powershell
Get-ChildItem audit/*.jsonl | ForEach-Object { Get-Content $_ } |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.id -eq 'brute-force-ssh-001' } |
  Select-Object timestamp,action,status,actor,sha
```

### "Show me every failed apply for this asset kind"

```bash
jq -c --arg kind "defender_custom_detection" \
  'select(.asset==$kind and .status=="failed") | {timestamp,id,action,message,sha}' \
  audit/*.jsonl
```

```powershell
Get-ChildItem audit/*.jsonl | ForEach-Object { Get-Content $_ } |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.asset -eq 'defender_custom_detection' -and $_.status -eq 'failed' } |
  Select-Object timestamp,id,action,message,sha
```

### "Latest success per envelope id"

```bash
jq -c 'select(.status=="success") | {id, timestamp, sha}' audit/*.jsonl |
  jq -s 'group_by(.id) | map(max_by(.timestamp))' |
  jq -c '.[]'
```

### "Did anyone touch a rule the same day a tenant pricing tier changed?"

Cross-reference `audit/*.jsonl` (this repo) against the Azure
Activity Log query in your portal — the `sha` field gives you the
exact PR; `git show <sha>` shows the diff that produced it.

---

## Verifying the chain

```bash
contentops audit verify
```

Walks every `audit/*.jsonl` file in date order, recomputes each
record's hash, and confirms each `prev_hash` matches the previous
record's `record_hash`. Exit 0 = clean; exit 1 = at least one break,
with file + line number printed.

The check runs weekly on `audit-verify.yml` (Mondays 04:00 UTC) so
silent rewrites are caught even if no human ran the command.

A failure can mean:

- **Tamper** — someone hand-edited a record. The chain after the
  edit is broken because the new line's `prev_hash` no longer
  matches the (now changed) prior `record_hash`.
- **Race** — two `apply` runs interleaved. The writer is
  atomic-rename per batch ([`contentops/audit/writer.py:130`](../../contentops/audit/writer.py)),
  but two concurrent `apply` invocations against the *same repo*
  can still produce a chain where their batches have stale
  `prev_hash` values. The `deploy.yml` workflow uses
  `concurrency.cancel-in-progress: false` precisely to serialise
  on-merge applies.
- **Corruption** — a partial write left an unparseable line. The
  atomic-rename pattern protects against this for the writer; an
  external editor opening the file in append-mode can still fool
  it.

---

## Storage

`audit/` is **gitignored** — it is NOT committed to git. `/audit/` is in
`.gitignore` (added after the 2477-file "git add -A" incident) and is on
the public-mirror forbidden-paths list. The durable copy is the **90-day
CI artefact**; the on-runner `audit/*.jsonl` is ephemeral and rebuilt each
run.

> **Earlier versions of this doc claimed the trail was committed back to
> main and "signed by branch protection." That was never true once `audit/`
> was gitignored — corrected here.** Because `audit/` is not restored
> across runs, each deploy's chain starts fresh from `ZERO_HASH`: the chain
> verified by any single run (and the head attested below) describes THAT
> run's records, not a cumulative ledger.

### CI artefact (90 days)

`deploy.yml`, `prune.yml`, and `retry-failed.yml` each include an
`actions/upload-artifact` step naming `audit/` (and `apply-report.json`)
with `retention-days: 90`. The artefact captures the *exact bytes* the
runner saw at the moment of execution and is downloadable from the GitHub
Actions UI for 90 days after the run. After 90 days it is gone.

### Head-hash attestation (provenance)

`deploy.yml` runs `contentops audit head` after a clean apply to emit a
compact `audit-head.json` ({`head_hash`, `tail_timestamp`,
`records_verified`, `chain_breaks`, `verified`}) and attests it with a
GitHub Artifact Attestation (Sigstore-backed, recorded in the public Rekor
transparency log) in a separate least-privilege job. A third party can
verify which CI run produced a given chain head:

```bash
gh attestation verify audit-head.json --owner KustoKing
```

This is **provenance, not authenticity**: it proves "KustoKing CI run N
produced this head hash," and its durability is bounded by GitHub
retention. It does NOT defend against an attacker who controls
`deploy.yml` execution. See [SECURITY.md](../../SECURITY.md).

### Backups

Out of scope today. Recommended: weekly `git bundle create
audit-bundle.bundle audit/*` to immutable storage. Roadmap proposal
F3 (`contentops rollback`) implicitly creates an additional
state-replay path that can be cross-checked against the audit
trail.

---

## Operator playbook

| Situation | Action |
|---|---|
| `audit-verify.yml` red | Run `contentops audit verify` locally. Inspect the reported file:line. `git log audit/<file>.jsonl` to see who touched it. If the line was hand-edited, restore from a previous SHA. |
| Need to find which run applied a specific change | `jq -c --arg sha <sha> 'select(.sha==$sha)' audit/*.jsonl` |
| Need to scan for unauthorised actors | `jq -c '.actor' audit/*.jsonl \| sort -u`. Unexpected entries are usually local-dev runs from analyst machines (`USER` env var). |
| Tenant pricing tier or quota was hit | `jq -c 'select(.status=="failed" and (.message // "") \| contains("429"))' audit/*.jsonl` |
| Want to replay a failed run | `contentops retry-failed` reads the latest `audit/*.jsonl` and re-applies just the failed entries ([`contentops/cli/commands/lifecycle.py:543`](../../contentops/cli/commands/lifecycle.py)). |

---

## Limitations

- **Drift / collect / lint don't write audit records.** Only
  `apply` and `prune` (operations that touch the wire) emit
  records. Read-only walks aren't audited.
- **`apply --no-audit`** suppresses audit writing (local
  debugging). Don't pass it in CI; the workflows don't.
- **`apply --dry-run`** does not write audit records (correct —
  nothing happened).
- **Audit chain doesn't span tenants.** The chain is per-repo, so
  per-tenant under the single-tenant model. If the repo is ever
  re-pointed at a different tenant, snip `audit/` out and start
  fresh — verify-chain treats `prev_hash="0"*64` as the start
  marker.
- **Records are append-only**. There is no compaction; a noisy
  tenant produces large daily files. A typical apply of 100 assets
  produces ~30 KB.

---

## See also

- [`architecture.md`](architecture.md#audit-trail--the-hash-chain) — narrative.
- [`contentops/audit/writer.py`](../../contentops/audit/writer.py) — implementation, ~230 lines.
- [`feature-catalog.md`](feature-catalog.md) → "State + audit + ops" section.
- [`audit-verify.yml`](../../.github/workflows/audit-verify.yml) — weekly check.
