# Audit chain recovery

When `audit-verify.yml` fails or `contentops audit verify` exits non-zero, the
hash-chained audit trail has detected a break. This runbook walks the operator
through diagnosis and recovery. The chain is load-bearing for compliance — a
sustained break is grounds for halting production deploys until resolved.

## Quick decision

```
contentops audit verify --root .
```

Exit code 0 → chain is intact, no action needed.
Exit code 1 → chain break detected. Read the output for the offending file:line,
then continue with this runbook.

## What "broken" means here

The chain stores three load-bearing fields per record:

- **`prev_hash`** — SHA-256 of the previous record's serialised JSON line.
- **`record_hash`** — SHA-256 of the current record's JSON serialisation with
  `record_hash` removed.
- **`timestamp`** — monotonically advanced ISO 8601 string (within and across
  batches; see [`contentops/audit/writer.py`](../../contentops/audit/writer.py)).

`verify_chain` walks every `audit/*.jsonl` record-by-record and asserts:

1. Each record's `record_hash` matches a fresh SHA-256 of its own (sans-hash) body.
2. Each record's `prev_hash` matches the previous record's `record_hash`.
3. Each record's `timestamp` is `>=` the previous record's timestamp (strict
   non-regression).

A failure on any of the three fires a break. The output names the failing file
and the index within that file.

## Step 1 — Identify the first bad record

```
contentops audit verify --root . 2>&1 | head -30
```

Read the first error line. It will look like one of:

| Output | Meaning |
|---|---|
| `record_hash mismatch at audit/2026-05-16.jsonl#L17` | The record's body was edited after it was written; the recorded hash no longer matches the current serialisation. |
| `prev_hash mismatch at audit/2026-05-16.jsonl#L17` | Some prior record's body changed (or was deleted/inserted), breaking the chain at this point. |
| `timestamp regression at audit/2026-05-16.jsonl#L17` | A record landed earlier than its predecessor — concurrent writes raced, or someone hand-edited the timestamp field. |
| `JSON parse error at audit/2026-05-16.jsonl#L17` | A line is malformed (truncated, mid-write crash, file system corruption). |

The first break is the only one that matters for diagnosis — everything after
the break is downstream noise.

## Step 2 — Classify the break

```
git log -p audit/<file>.jsonl | head -100
```

Look for the commit that introduced the offending line. Then classify:

### Class A — Hand-edit

A human (or a tool that didn't go through `write_records`) modified an audit
record. Common causes: someone tried to "clean up" a failed deploy entry, a
text editor reformatted the JSON, or a sloppy `sed`/`yq` ran against the wrong
file.

**Action:** Do NOT try to recompute hashes by hand. The chain's value is that
it is mechanically verifiable; re-hashing manually destroys that property.
Treat the break as a tampered record and proceed to Step 3 (recover via git
revert).

### Class B — Concurrent write race

Two `contentops apply` runs wrote into the same JSONL with overlapping
timestamps. The `deploy.yml` workflow uses `concurrency: cancel-in-progress:
false` to prevent this from CI, so a Class B break suggests a local
`contentops apply` ran simultaneously with a CI deploy, OR two operators ran
local applies at the same time.

**Action:** Drop the duplicate suffix lines (typically the local run's records
that landed after the CI run's), re-verify, commit the cleanup. Document in
the commit message why the lines were dropped.

### Class C — Mid-write crash / corruption

A line is malformed because a process was killed mid-write or the file system
itself corrupted the file (rare on modern journaled filesystems; more likely
on a flaky network drive).

**Action:** The last partial line can be safely truncated to the previous
newline. Re-verify. If the corruption goes deeper, treat as Class A and
revert.

### Class D — Genuinely valid but timestamp-out-of-order

Pre-2026-05 records that were written before `_monotonic_timestamp` was wired
in (commit landed mid-Phase-3 hardening). These records have plain
`datetime.now()` timestamps with no monotonicity guarantee. `verify_chain`
accepts equal timestamps but rejects strict regression. If a Class D-looking
break is in pre-May-2026 records, it's a real defect from the older writer;
treat as Class A (revert or accept).

## Step 3 — Decide whether to halt production deploys

A chain break does not block production deploys mechanically — `deploy.yml`'s
post-apply step runs `contentops audit verify` and exits 1 on break, so each
new deploy will start to fail. The operator's question is whether to
**proactively halt deploys** until the chain is repaired.

| Class | Halt deploys? |
|---|---|
| A — hand-edit | Yes — until the offending commit is reverted. A tampered chain undermines every record after the break. |
| B — race | No — the duplicate cleanup is fast (minutes). Let the next deploy retry naturally. |
| C — crash/corruption | Yes — pause one deploy cycle, recover the truncated line, then resume. |
| D — pre-monotonic legacy | No — accept the legacy record (no remediation possible); document the date in this runbook. |

For Class A and C, set the deploy workflow to `disabled` on the `production`
environment via GitHub Settings → Environments → production → Pause until the
fix lands.

## Step 4 — Recover via `git revert`

```
git log audit/<file>.jsonl --pretty=oneline | head -10
# Identify the SHA that introduced the offending line.
git revert <bad-sha>
git push origin main
```

If the offending content is part of a larger commit (e.g. a deploy
audit-batch), revert the whole commit. The audit chain is the durable record;
losing one batch's apply records is acceptable. The corresponding live
deployments are unchanged — the audit chain documents history, not state.

Re-run:

```
contentops audit verify --root .
```

The chain should now verify clean.

## Step 5 — Resume production deploys

If you paused the `production` environment in Step 3, re-enable it in GitHub
Settings → Environments → production.

Next merge to `main` runs `deploy.yml` against the recovered tree, and
post-deploy `contentops audit verify` re-checks the chain. A green deploy
confirms recovery.

## Class D — One-off cleanup

If a Class D break is in records older than the `_monotonic_timestamp` commit:

```
# Confirm the break is pre-monotonic.
git log --format='%ci %s' contentops/audit/writer.py | head -10
# Find the date when _monotonic_timestamp was introduced. If the break's
# record predates it, the legacy record can stay; document the date here.
```

No code change is required for Class D — `verify_chain` already accepts equal
timestamps (only strict regression breaks the chain). If verify is failing on
a Class D record, the diagnostic was misclassified — re-read Step 2.

## What NOT to do

- **Do not edit a `audit/*.jsonl` file by hand.** Even reformatting whitespace
  changes `record_hash` and propagates the break to every subsequent record.
  The only safe edit is a full-line truncation of a manifestly broken trailing
  line.
- **Do not recompute and re-write `record_hash` values manually.** The chain's
  forensic value is that re-hashing succeeds only if no fields changed; a
  manual recompute would silently launder a tampered record back into a
  verifiable state. If you need to undo a real change, `git revert` it.
- **Do not delete an entire JSONL file to "start over."** The chain seeds
  across files via the previous tail's hash; deleting a file breaks every
  subsequent file's verification.

## See also

- [`docs/reference/audit-trail.md`](../reference/audit-trail.md) — JSONL schema,
  query examples, retention policy.
- [`contentops/audit/writer.py`](../../contentops/audit/writer.py) — chain
  implementation, including `_monotonic_timestamp` and `verify_chain`.
- [`.github/workflows/audit-verify.yml`](../../.github/workflows/audit-verify.yml)
  — weekly chain integrity check.
- [`docs/OPERATOR_GUIDE.md#audit-chain-break`](../OPERATOR_GUIDE.md) — the short-
  form decision tree this runbook expands on.
