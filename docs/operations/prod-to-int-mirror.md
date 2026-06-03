# Mirroring prod content into integration

> **When to use this.** You want the integration workspace to reflect
> the current production rule set — typically before a content-author
> sprint, after a major detection refresh in prod, or when bootstrapping
> a fresh integration tenant. The workflow wipes integration's rule set
> and re-creates it from prod via `prune` → `collect` → `apply`.

This is a **destructive operation on the integration workspace**. The
production workspace is read-only throughout. Pre-flight, confirm:

- `contentops doctor --matrix` is green for both `--role prod` and
  `--role integration`.
- You hold Microsoft Sentinel Contributor on the integration workspace.
- The integration workspace name in `config/tenant.yml` is correct
  (case-sensitive lookup; `_validate_workspace_uniqueness` will flag
  case-only duplicates).

## The four-step workflow

```powershell
# 1. Wipe every analytic rule on the integration workspace.
#    The --max-deletes cap default is 25 — bulk wipes need an
#    explicit higher value. Audit each delete.
contentops prune --role integration --asset sentinel_analytic
# dry-run output lists the orphans; review then proceed:
contentops prune --role integration --asset sentinel_analytic `
    --no-dry-run --yes --max-deletes 200

# 2. Pull the prod analytics into local YAML. Server-managed fields
#    are stripped by the handler's to_envelope() so diffs stay clean.
contentops collect --role prod --asset sentinel_analytic

# 3. Commit the snapshot. Git remains the source of truth — the local
#    YAMLs under detections/sentinel_analytic/ are what `apply` reads.
git add detections/sentinel_analytic/
git commit -s -m "chore(content): mirror prod -> integration snapshot"

# 4. Deploy the collected rules to the integration workspace.
contentops apply --role integration --asset sentinel_analytic
```

After step 4, the `apply summary` prints one row per rule. Expect a
mix of `create`/`success`/`verified=ok` for rules new to integration
and `update`/`success` for rules that already existed under the same
name.

## Tombstone re-deploys (Microsoft Sentinel's soft-delete window)

If you've **just deleted a rule and try to PUT one back with the same
GUID**, Microsoft Sentinel rejects the PUT with:

```
400 BadRequest: The rule with id '<guid>' was recently deleted.
                You need to allow some time before re-using the same id.
                Please try again later.
```

The soft-delete window is **~24 hours** in practice. This commonly
hits the wipe-then-redeploy workflow because some rules in prod
**share the same GUID** as the integration rules you just pruned
(both came from the same Microsoft Solution / template).

**Recovery path:**

```powershell
# After the wait window has cleared (next morning is usually safe):
contentops retry-failed --role integration
```

`retry-failed` reads the last audit batch, identifies the rules that
came back with `error-409` or `error-400`, and re-attempts only those.
Successful ones are skipped — no duplicate work.

For Windows operators: a Unicode encoding fix lives at CLI entry
since PR #160, so `PYTHONIOENCODING=utf-8` is no longer required. If
you still see a `UnicodeEncodeError`, file an issue.

## Two error classes you'll see

| Error | What it means | Action |
|---|---|---|
| `error-409` "rule was recently deleted" | Soft-delete tombstone hasn't cleared yet | Wait ~24h, then `contentops retry-failed` |
| `error-400` "Failed to run the analytics rule query. One of the tables does not exist." | The rule's KQL references a table that isn't ingested on the integration workspace. **Content issue, not pipeline.** | Either change the query, ingest the table on integration, or accept that this rule can't deploy to integration |
| `error-400` "Read-only property '<x>' cannot be assigned" | Fusion / MLBA / template-bound rules have server-managed fields that the apply path now strips (PR #163) | If you still see this on the *current* main, file an issue — the per-kind allowlist may be missing a field |

## Audit trail

Every prune + apply writes to `audit/<YYYY-MM-DD>.jsonl`. The chain
is SHA-256 hash-linked; tampering with one record invalidates every
record after it.

```powershell
contentops audit verify           # walks the whole chain
contentops audit verify --since 4h # last 4 hours only
```

The weekly `audit-verify.yml` workflow runs the same check every
Monday at 04:00 UTC — chain breaks surface as a red CI badge.

## What this workflow does NOT touch

- **Defender custom detections** — they're tenant-wide, not workspace-
  scoped. Mirroring Sentinel doesn't reach them. Use
  `contentops apply --asset defender_custom_detection` separately.
- **Watchlists, hunting queries, parsers, data connectors** — out of
  scope by default. Pass `--asset <kind>` to mirror those individually,
  or omit `--asset` to mirror everything (read the dry-run output
  carefully — data connectors in particular can have side effects on
  ingestion).
- **The audit and state branches** — those are CI-managed; this
  workflow only writes to the per-day audit file locally. A subsequent
  prod apply via CI handles `state sync push` automatically.

## Reverting a bad mirror

If the mirror lands a regression:

```powershell
# 1. The wipe + apply both wrote audit records — verify integrity first.
contentops audit verify

# 2. Roll back to the SHA before the mirror.
contentops rollback --sha <pre-mirror-sha>            # dry-run by default
contentops rollback --sha <pre-mirror-sha> --no-dry-run --yes
```

`rollback` is non-destructive: rules that exist today but didn't at
the prior SHA are left alone. To get back to an exact pre-mirror
state, follow rollback with a `prune` against the integration
workspace (same shape as step 1 of the mirror).

## See also

- [`docs/OPERATOR_GUIDE.md`](../OPERATOR_GUIDE.md) — top-level operator entry point
- [`docs/development/live-integration-tests.md`](../development/live-integration-tests.md) — running the pytest suite live
- [`contentops/cli/commands/prune.py`](../../contentops/cli/commands/prune.py) — prune internals
- [`contentops/cli/commands/lifecycle.py`](../../contentops/cli/commands/lifecycle.py) — `retry-failed` implementation
