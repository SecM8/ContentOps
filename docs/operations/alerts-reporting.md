# Alert Tracking and Daily Rollup Reporting

## Overview

The `contentops alerts` command group provides subcommands for
tracking, analysing, and reporting on security alerts across Microsoft
Defender XDR (Graph Security alerts_v2) and Microsoft Sentinel (ARM
incidents).

| Command            | Purpose                                            |
|--------------------|----------------------------------------------------|
| `alerts sync`      | Sync alerts into a persistent PII-free ledger       |
| `alerts collect`   | Fetch raw alerts and write JSON or CSV              |
| `alerts rollup`    | Compute a daily classification rollup (MD/JSON/CSV) |
| `alerts report`    | Compute a multi-day trend report (MD/JSON/HTML)     |

## Data Source Detection

The provider automatically detects the best alert source using a
three-step probe:

1. **Try Graph `alerts_v2`** (`GET /security/alerts_v2?$top=1`).
2. **403** -- `SecurityAlert.Read.All` permission not granted. Falls
   back to Sentinel ARM incidents.
3. **200 + empty** -- probes Sentinel for incidents. If Sentinel has
   data, falls back to ARM (standalone Sentinel, not onboarded into
   Defender XDR). If Sentinel is also empty, uses Graph (tenant may
   simply have no alerts).
4. **200 + results** -- uses Graph.

The chosen source is logged in the run banner:

```
pipeline alerts rollup -- production-tenant
  source         : graph
```

## Prerequisites

### Graph (primary)

Grant the app registration the **SecurityAlert.Read.All** application
permission (admin consent required) in Entra ID. This is the same app
registration used for `CustomDetection.ReadWrite.All`.

### Sentinel (fallback)

No additional permission is needed -- the **Microsoft Sentinel
Contributor** role already required for `contentops apply` / `collect`
covers incident listing via the ARM API.

## CLI Usage

### alerts collect

Fetch raw alerts within a time window:

```bash
# Last 24 hours (default)
contentops alerts collect

# Last 7 days, write to JSON
contentops alerts collect --since 7d --out alerts.json

# Specific time range, CSV output
contentops alerts collect \
  --since 2026-05-14T00:00:00Z \
  --until 2026-05-21T00:00:00Z \
  --out alerts.csv

# Filter by service source and status
contentops alerts collect \
  --since 24h \
  --service-source microsoftDefenderForEndpoint \
  --status resolved
```

**Options:**

| Flag               | Description                                      |
|--------------------|--------------------------------------------------|
| `--since`          | Duration (`24h`, `7d`, `30d`) or ISO 8601        |
| `--until`          | End of window (ISO 8601). Default: now.           |
| `--service-source` | Filter by Graph `serviceSource` (Graph only)      |
| `--status`         | Filter by status (`new`, `inProgress`, `resolved`)|
| `--classification` | Filter by classification                          |
| `--out`            | Output file (`.json` or `.csv`). Omit for stdout. |

### alerts rollup

Compute a daily classification rollup:

```bash
# Yesterday (default)
contentops alerts rollup

# Specific date, write Markdown + JSON
contentops alerts rollup \
  --date 2026-05-20 \
  --out-md reports/rollup.md \
  --out-json reports/rollup.json

# Today
contentops alerts rollup --date today --out-csv reports/rollup.csv
```

**Output includes:**

- Total alerts and resolved count
- Classification breakdown (TP / FP / Benign / Undetermined with %)
- Severity breakdown
- Mean time to close (hours)
- Top titles by volume (with per-title TP/FP/Benign counts, avg close
  time, MITRE techniques)
- Still-open alerts (created on date, not yet resolved)
- Rule effectiveness (alerts per detector/rule with TP/FP rates)

### alerts report

Compute a multi-day trend report:

```bash
# Last 7 days (default)
contentops alerts report

# Last 30 days, JSON output
contentops alerts report --period 30d --format json --out trend.json

# Custom period, Markdown
contentops alerts report --period 14d --out trend.md
```

**Output includes:**

- Daily volumes (total + resolved per day)
- Classification trend (TP/FP ratio per day)
- MTTR trend (mean time to resolve per day)
- Top titles across the period
- Noisiest rules (highest FP rate, minimum 2 alerts)
- Unresolved backlog count

## GitHub Actions (Daily Cron)

The `alerts-report.yml` workflow runs daily at 07:00 UTC and computes
yesterday's rollup:

```yaml
# .github/workflows/alerts-report.yml
on:
  schedule:
    - cron: '0 7 * * *'
  workflow_dispatch:
    inputs:
      date:
        description: 'Target date (YYYY-MM-DD, "yesterday", or "today")'
        default: yesterday
```

The workflow:

1. Checks out the repo, installs dependencies.
2. Authenticates via OIDC (using `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID` secrets).
3. Runs `contentops alerts rollup` with Markdown + JSON output.
4. Uploads the output as a workflow artefact.
5. Writes the Markdown to `GITHUB_STEP_SUMMARY` for inline visibility.

### Required Secrets

| Secret                   | Description                        |
|--------------------------|------------------------------------|
| `AZURE_CLIENT_ID`        | App registration client ID          |
| `AZURE_TENANT_ID`        | Entra ID tenant ID                  |
| `AZURE_SUBSCRIPTION_ID`  | Azure subscription (for OIDC login) |

## Alert Ledger

The alert ledger is a persistent, PII-free JSONL file that stores
minimal alert classification data. All downstream reports (rollup,
health, trend) read from the ledger instead of hitting the API
directly.

### Data Minimisation

The ledger stores only the fields needed for reporting:

| Field               | Description                                      |
|---------------------|--------------------------------------------------|
| `alert_id`          | Dedup key (Graph alert ID / Sentinel incident ID) |
| `rule_display_name` | Detection's `displayName` (stable, not dynamic)   |
| `classification`    | truePositive / falsePositive / benignPositive / undetermined |
| `closed_at`         | ISO 8601 resolution timestamp (null if open)       |
| `severity`          | Alert severity level                               |
| `source`            | `graph` or `sentinel`                              |
| `created_at`        | ISO 8601 creation timestamp                        |
| `rule_id`           | ARM GUID for Sentinel rule matching (not PII)      |

**Intentionally excluded**: assigned_to, description, evidence,
mitre_techniques, incident_id, determination. These fields may
contain PII and are not needed for classification reports.

### alerts sync

Sync alerts from Graph/Sentinel into the local ledger:

```bash
# Normal daily sync (from last watermark to yesterday)
contentops alerts sync

# Full backfill (ignore watermark, fetch max lookback)
contentops alerts sync --backfill

# Custom ledger path
contentops alerts sync --ledger path/to/ledger.jsonl
```

**Smart lookback**:

- **First run**: Fetches 30 days for Defender (Graph), 90 days for
  Sentinel. Creates the ledger and watermark from scratch.
- **Subsequent runs**: Fetches from the last watermark to yesterday
  (today isn't finished). Automatically fills gaps from failed runs.
- **`--backfill`**: Ignores the watermark and fetches the full
  lookback window. Use when the ledger is corrupted or missing.
- **Up-to-date**: When the watermark already covers yesterday, skips
  the API call entirely.

### Tenant Configuration

Enable alert sync in `config/tenant.yml`:

```yaml
tenant:
  alerts:
    enabled: true
    defenderLookbackDays: 30   # max lookback for Graph alerts_v2
    sentinelLookbackDays: 90   # max lookback for Sentinel incidents
    retentionDays: 90          # how long to keep daily rollup entries
```

When the `alerts` block is absent, alert sync is disabled (opt-in).
Set `enabled: false` to explicitly disable.

### Daily Rollup Store

The `rollup` command automatically builds a persistent daily rollup
store (`alerts-reports/daily-rollups.jsonl`) alongside the per-alert
ledger. Each entry stores aggregated counts per (date, rule display
name, detection version):

- Alert count, resolved count
- TP / FP / benign / undetermined counts
- Mean time to close (hours)
- Detection version at rollup time

**Gap filling**: If the workflow failed on previous days, the next
run detects missing dates and builds rollups for them from the
ledger data.

**Idempotency**: Dates that already have rollups are skipped. Running
twice produces the same result.

**Retention**: Entries older than `retentionDays` (default 90, set in
`config/tenant.yml`) are automatically pruned.

**Version tracking**: Each rollup entry records the detection's
`version` field from the envelope. This enables trending: "did
v1.2.0 reduce the FP rate compared to v1.1.0?"

### Three-Tier Data Source Fallback

Commands try data sources in order:

1. **Ledger** (fastest): local JSONL, no API call
2. **Graph/Sentinel API**: requires `SecurityAlert.Read.All` or
   Sentinel Contributor role
3. **Workspace KQL** (widest access): queries `SecurityAlert` +
   `SecurityIncident` tables via the LA API. Requires only `Log
   Analytics Reader` role. Retention up to 730 days.

This means operators without `SecurityAlert.Read.All` still get
alert data from the workspace.

### Ledger-Aware Commands

The `rollup`, `health`, and `report` commands automatically read from
the ledger when it exists. Pass `--ledger` to specify a custom path.
If no ledger exists, they fall back to the previous API-direct
behaviour with a warning.

```bash
# After sync, these read from the ledger (no API credentials needed)
contentops alerts rollup --date yesterday
contentops alerts health --period 30d
contentops alerts report --period 7d
```

## Detection Health

The `alerts health` command connects detection rules to their alert
performance, computing per-detection metrics and actionable
recommendations.

### alerts health

```bash
# Default: 30-day lookback, all detections
contentops alerts health

# Custom period, write to files
contentops alerts health --period 7d \
  --out-md health.md --out-json health.json --out-csv health.csv

# With badge output
contentops alerts health --period 30d \
  --out-md health.md --out-badge health-badge.json
```

**Options:**

| Flag                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `--period`            | Lookback period (`7d`, `30d`, or custom days)     |
| `--path`              | Detections directory (default: `detections`)      |
| `--out-md`            | Output Markdown file                              |
| `--out-json`          | Output JSON file                                  |
| `--out-csv`           | Output CSV file                                   |
| `--out-badge`         | Output shields.io health badge JSON               |
| `--previous-snapshot` | Previous health snapshot for delta computation    |

### Mapping Logic

Each alert is mapped to its originating detection via:

1. **ARM resource ID** (Sentinel): `relatedAnalyticRuleIds` from the
   incident contains the GUID matching `envelope.arm_name`.
2. **Title matching** (Graph / Defender XDR): `alert.title` matches
   `payload.displayName` (case-insensitive).

ARM match takes priority over title match.

### Recommendations

| Recommendation    | Condition                                        |
|-------------------|--------------------------------------------------|
| `TUNE`            | FP rate > 40%                                    |
| `SILENT`          | 0 alerts in period                               |
| `HEALTHY`         | TP rate > 80%                                    |
| `REVIEW`          | Everything else                                  |
| `EXPECTED_SILENT` | Hunting queries (don't fire alerts by design)    |

### Acting on Recommendations

- **TUNE**: Investigate false positives. Add exclusions, tighten the
  query scope, or adjust entity mappings to reduce noise.
- **SILENT**: The rule hasn't fired in the lookback period. Verify the
  data source is ingesting, the rule is enabled, and the query logic
  still matches current telemetry schemas.
- **REVIEW**: The rule is firing but with mixed classification results.
  Review recent incidents to understand the TP/FP distribution.
- **EXPECTED_SILENT**: Hunting queries are designed for analyst-driven
  execution, not automated alerting. No action needed.

### Owner Summary

The report includes a per-owner breakdown showing how many detections
each owner has in each recommendation category. Use this to assign
tuning work to the right team.

### Historical Snapshots

When `--out-json` or `--out-md` is specified, the command also writes
a dated snapshot (`alerts-reports/YYYY-MM-DD-health.json`). On
subsequent runs, it automatically compares against the most recent
previous snapshot and reports changes (new TUNE, resolved TUNE, newly
active detections).

### Report Integration

Add `--with-alerts` to the detection inventory report to include
alert health columns:

```bash
contentops report --with-alerts
```

This adds `Silent Days` and `Recommendation` columns alongside the
existing telemetry, health, and schema-drift enrichment.

## Architecture

```
contentops/alerts/
  __init__.py           Module root
  models.py             Pydantic v2 models (GraphAlert, SentinelIncident, NormalizedAlert)
  provider.py           GraphAlertsProvider with Sentinel ARM fallback
  rollup.py             Daily rollup computation + Markdown/JSON rendering
  report.py             Multi-day trend report computation + rendering
  detection_health.py   Per-detection health engine + recommendations
  health_snapshot.py    JSON snapshot + week-over-week delta
  health_badge.py       shields.io endpoint badge

contentops/cli/commands/alerts.py   Click command group (collect, rollup, report, health)
```

The `NormalizedAlert` model is the unified shape that both Graph and
Sentinel data are mapped into before any computation. This decouples
the rollup/report/health engines from the data source.
