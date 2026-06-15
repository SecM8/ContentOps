# Committed reports + retention

## Reports are versioned by default

`contentops report` (and the `report.yml` workflow) writes the detection
inventory report to `reports/`:

| File | What it is |
|---|---|
| `reports/latest.{html,md,json}` | Rolling current report (replaced each run) |
| `reports/<YYYY-MM-DD>.{html,json}` | Dated snapshots — the week-over-week diff substrate |
| `reports/unified.html` | Optional unified CEO/CISO/SOC report (`--unified`) |
| `reports/badge.json` | Anonymous coverage-% shields.io endpoint |

`reports/` is **not gitignored** — it is normal versioned content (same as
`coverage/`). So on push-to-main, `report.yml`'s "Commit refreshed report"
step commits the regenerated reports back to `main`, and your deployment
gets a **durable, diffable posture history out of the box** — "show me the
inventory + coverage as it stood each week, in git." No setup required.

## The public mirror stays clean — via the allowlist, not gitignore

The detailed report carries live per-detection telemetry (display names,
alert / incident counts, TP/FP %, MTTD, MTTR). That telemetry must not
reach the **public mirror** (`SecM8/ContentOps`). The boundary that
enforces this is the **sync allowlist**, not `.gitignore`:

- `.github/sync-allowlist.txt` lists only `reports/badge.json` under
  `reports/`. `public-sync.yml` copies **only** allowlisted paths into the
  mirror tree, so `latest.*`, the dated snapshots, and `unified.html` are
  dropped — they never reach the mirror.
- `public-sync.yml`'s "forbidden paths" safety check additionally asserts
  `reports/unified.html` and `reports/*-findings.md` are absent from the
  mirror tree (belt-and-braces).

So committing reports in your **private** repo (source or deployment fork)
is safe: the telemetry is versioned where you want it and filtered out of
the one-way public sync. Do **not** re-add a `/reports/*` gitignore to
"protect" reports — it protects nothing (the mirror boundary is the
allowlist) and only stops you and other adopters from keeping a report
history.

## Retention: bounding the committed history

Because reports are committed, the dated snapshots accumulate one pair
(`.html` + `.json`) per run. `reports.retentionDays` in `tenant.yml` caps
that history — on each `contentops report` run, dated snapshots older than
the window are pruned (the deletions are then staged by the workflow's
`git add reports/`).

```yaml
tenant:
  # ...
  reports:
    retentionDays: 365   # keep ~52 weekly snapshots; 0 disables pruning
```

Range `0..3650`. `0` keeps everything (pruning disabled). A missing
`reports:` block is equivalent to "no pruning configured".

Only dated `reports/<YYYY-MM-DD>.{html,json}` files are eligible — the
rolling `latest.*`, `badge.json`, and `unified.html` are never pruned
(they have non-date stems).

### How the workflow reads it

`reports.retentionDays` lives in `tenant.yml`, which is gitignored and
materialised in CI from the `TENANT_CONFIG_YAML` secret. `report.yml`
materialises it (guarded on the secret being present) before the
"Generate report" step, so the prune fires automatically wherever the
secret is configured. On a repo without the secret (e.g. the public
mirror) the materialise step is skipped and the prune is simply a no-op.

### Local / ad-hoc override

`contentops report --retention-days <N>` overrides the tenant.yml value
for a single run (handy locally, or to force-trim history).
`--retention-days 0` disables pruning for that run. Precedence:

1. `--retention-days` (explicit flag)
2. `tenant.yml` → `reports.retentionDays`
3. otherwise: no pruning (keep every dated snapshot)

## See also

- [`alerts-reporting.md`](alerts-reporting.md) — the alert ledger pipeline
  and its own `ledgerRetentionDays` / `rollupRetentionDays` retention.
- [`tenant-config-modes.md`](tenant-config-modes.md) — how `tenant.yml`
  is materialised in CI.
- [`workflow-schedule.md`](workflow-schedule.md) — when `report.yml` runs.
