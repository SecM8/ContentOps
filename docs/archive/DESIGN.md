# Detection Pipeline — Design Document

## Overview

Python CLI + GitHub Actions pipeline for CRUD management of detection rules
in Microsoft Sentinel and Microsoft Defender XDR. Single tenant. Git is the
source of truth. Rules stored as lean YAML, deployed via Sentinel ARM API
(2025-07-01-preview) and Microsoft Graph Security Beta API.

---

## Repository Structure

```
detection-pipeline/
│
├── detections/
│   ├── sentinel/                       # Sentinel rules (Scheduled + NRT)
│   │   ├── sentinel-brute-force-001.yml
│   │   └── ...
│   ├── defender/                       # Defender XDR custom detection rules
│   │   ├── defender-encoded-powershell-001.yml
│   │   └── ...
│   └── templates/                      # Reference templates — never deployed
│       ├── sentinel-template.yml
│       └── defender-template.yml
│
├── pipeline/                           # Python package
│   ├── __init__.py
│   ├── cli.py                          # CLI entrypoint (Click)
│   ├── config.py                       # Loads tenant config + environment
│   ├── models.py                       # Pydantic models for rule validation
│   ├── sentinel/
│   │   ├── __init__.py
│   │   ├── client.py                   # Sentinel ARM API client
│   │   ├── deploy.py                   # PUT rules (upsert)
│   │   └── collect.py                  # GET rules → YAML
│   ├── defender/
│   │   ├── __init__.py
│   │   ├── client.py                   # Graph Security Beta API client
│   │   ├── deploy.py                   # POST/PATCH rules
│   │   └── collect.py                  # GET rules → YAML
│   └── utils/
│       ├── __init__.py
│       ├── auth.py                     # OIDC / azure-identity token acquisition
│       ├── diff.py                     # Git diff to find changed rules
│       └── yaml_io.py                  # Load/dump rules, split pipeline fields from payload
│
├── config/
│   └── tenant.yml                      # Single tenant configuration
│
├── .github/
│   └── workflows/
│       ├── validate.yml                # PR: schema validation
│       ├── deploy.yml                  # Merge to main: deploy changed rules
│       └── collect.yml                 # Scheduled/manual: pull live rules
│
├── tests/
│   ├── test_models.py
│   ├── test_sentinel_deploy.py
│   ├── test_defender_deploy.py
│   └── fixtures/
│
├── pyproject.toml
├── requirements.txt
└── DESIGN.md
```

---

## Authentication

### App Registration (Single Tenant)

Single-tenant App Registration with GitHub OIDC federated credentials.
No client secret — GitHub Actions proves identity via OIDC token, Azure
trusts the GitHub issuer.

**Entra ID setup:**
1. App Registration → single tenant
2. Federated credentials → add GitHub Actions as issuer
   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject: `repo:{org}/{repo}:ref:refs/heads/main` (lock to main branch)
   - Audience: `api://AzureADTokenExchange`

**GitHub Secrets:**

| Secret               | Value                                    |
|----------------------|------------------------------------------|
| `AZURE_CLIENT_ID`    | App Registration Application (client) ID |
| `AZURE_TENANT_ID`    | Tenant ID                                |
| `AZURE_SUBSCRIPTION_ID` | Subscription ID (for Sentinel ARM calls) |

No `AZURE_CLIENT_SECRET` — OIDC replaces it.

### Permissions

**Sentinel (ARM API):**
Azure RBAC role assignment on the Log Analytics workspace:
- Role: `Microsoft Sentinel Contributor`
- Scope: `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}`

Token audience: `https://management.azure.com/.default`

**Defender XDR (Graph Beta API):**
Application permission (requires admin consent):
- `CustomDetection.ReadWrite.All`

Token audience: `https://graph.microsoft.com/.default`

### Token Acquisition

```python
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()

# Sentinel
arm_token = credential.get_token("https://management.azure.com/.default")

# Defender
graph_token = credential.get_token("https://graph.microsoft.com/.default")
```

`DefaultAzureCredential` automatically picks up OIDC in GitHub Actions
and falls back to CLI credentials for local development.

---

## Tenant Configuration

`config/tenant.yml` — single file, single tenant.

```yaml
tenant:
  name: production
  tenantId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  sentinel:
    subscriptionId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    resourceGroup: "rg-sentinel"
    workspaceName: "law-sentinel"
  defender:
    enabled: true
```

---

## CLI Commands

```
pipeline validate [--path detections/]
pipeline deploy   [--dry-run] [--force]
pipeline collect  [--output detections/]
pipeline diff
pipeline delete   --id RULE_ID --platform sentinel|defender
```

### validate

1. Load each YAML in `detections/sentinel/` and `detections/defender/`
   (skip any path containing `/templates/`)
2. Validate against Pydantic models:
   - Required fields present
   - Enum values valid (severity, tactics, triggerOperator, etc.)
   - Scheduled rules have queryFrequency/queryPeriod/triggerOperator/triggerThreshold
   - NRT rules do NOT have those four fields
   - Defender rules have at least one impactedAsset
   - Defender `displayName` values unique across all Defender rule files
   - Rule `id` values unique across all rule files
3. Exit 1 on any validation error

### deploy

1. Detect changed files:
   - Default: `git diff HEAD~1..HEAD --name-only -- detections/`
   - With `--force`: all rule files
2. Load each changed YAML, extract `platform`, `status`, and payload
3. Skip rules where `status` is `experimental`
4. For `deprecated` rules: deploy with `enabled: false` (Sentinel) / `isEnabled: false` (Defender)
5. **Sentinel rules:** For each rule, PUT to ARM API
   ```
   PUT .../alertRules/{id}?api-version=2025-07-01-preview
   Body: { "kind": "{kind}", "properties": { ...payload minus kind... } }
   ```
6. **Defender rules:**
   a. GET all existing detection rules (one call)
   b. Build lookup: `displayName → graphId`
   c. **Fail fast if duplicate displayNames found** — log which rules conflict
   d. For each rule:
      - If displayName exists in lookup → PATCH `/detectionRules/{graphId}`
      - If new → POST `/detectionRules`
7. Output summary table: rule ID, platform, action (created/updated/skipped/disabled), status

### collect

1. **Sentinel:** GET all alert rules, filter to kind Scheduled and NRT
2. **Defender:** GET all detection rules
3. Convert each to YAML format:
   - Sentinel: extract `kind` from top level, remaining `properties` become the YAML body
   - Defender: map response fields to YAML structure
   - Generate `id` from existing value or derive from displayName (slugified)
   - Set `version: "0.0.0"` for newly collected rules (signals "not yet versioned")
   - Set `status: production` (it's live, so it's production)
4. Write to `detections/{platform}/`
5. Output: created X new files, updated Y existing files, Z unchanged

### diff

1. Load all local rule files
2. GET all remote rules from both APIs
3. Compare:
   - **Local only:** rule exists in YAML but not deployed
   - **Remote only:** deployed but no YAML file (orphan)
   - **Modified:** both exist but content differs
   - **In sync:** identical
4. Output summary table

### delete

1. For Sentinel: DELETE `.../alertRules/{id}`
2. For Defender: resolve graphId via GET+filter by displayName, then DELETE
3. Optionally remove the local YAML file with `--prune`

---

## GitHub Actions Workflows

### validate.yml — PR gate

```yaml
name: Validate Detection Rules

on:
  pull_request:
    paths: ['detections/**']

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: python -m pipeline validate --path detections/
```

### deploy.yml — Merge to main

```yaml
name: Deploy Detection Rules

on:
  push:
    branches: [main]
    paths: ['detections/**']

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install -r requirements.txt

      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - run: python -m pipeline deploy
        env:
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

### collect.yml — Scheduled / manual

```yaml
name: Collect Detection Rules

on:
  schedule:
    - cron: '0 6 * * 1'
  workflow_dispatch: {}

permissions:
  id-token: write
  contents: write
  pull-requests: write

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install -r requirements.txt

      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - run: python -m pipeline collect --output detections/

      - name: Create PR if changes
        run: |
          git config user.name "github-actions"
          git config user.email "actions@github.com"
          BRANCH="collect/$(date +%Y%m%d-%H%M)"
          git checkout -b "$BRANCH"
          git add detections/
          git diff --cached --quiet || {
            git commit -m "Collected detection rules $(date +%Y-%m-%d)"
            git push -u origin "$BRANCH"
            gh pr create \
              --title "Detection rule sync $(date +%Y-%m-%d)" \
              --body "Auto-collected from live environment"
          }
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Python Dependencies

```
azure-identity          # Token acquisition (OIDC + local dev fallback)
httpx                   # HTTP client
pydantic>=2.0           # Schema validation
pyyaml                  # YAML parsing
click                   # CLI
```

---

## API Request/Response Mapping

### Sentinel: YAML → API

```yaml
# YAML file
sentinel:
  kind: Scheduled
  displayName: "My Rule"
  severity: Medium
  query: "..."
  queryFrequency: PT5M
  ...
```

```python
# Pipeline transforms to:
{
    "kind": "Scheduled",
    "properties": {
        "displayName": "My Rule",
        "severity": "Medium",
        "query": "...",
        "queryFrequency": "PT5M",
        ...
    }
}
```

`kind` is extracted from the payload and placed at the top level.
Everything else goes into `properties`.

### Sentinel: API → YAML (collect)

Reverse the above: pull `kind` out, flatten `properties`, add the four
pipeline fields (`id`, `version`, `platform`, `status`).

### Defender: YAML → API

The `defender:` block maps directly to the Graph API request body.
No transformation needed — submit as JSON.

### Defender: API → YAML (collect)

Strip read-only fields (`createdBy`, `createdDateTime`, `lastModifiedDateTime`,
`lastModifiedBy`, `detectorId`, `lastRunDetails`, `queryCondition.lastModifiedDateTime`,
`schedule.nextRunDateTime`). Add the four pipeline fields.

---

## Error Handling

- **API 4xx:** Log error with rule ID and response body, continue with next rule
- **API 429:** Retry with exponential backoff (max 3 retries)
- **API 5xx:** Retry once, then log and skip
- **Auth failure:** Fail fast, exit 1 (nothing will work without auth)
- **Validation failure:** Exit 1 before any API calls
- **Partial deploy failure:** Complete all rules, then exit 1 with summary of failures

---

## YAML ↔ Payload Helper (yaml_io.py)

Core function the whole pipeline depends on:

```python
def load_rule(path: Path) -> dict:
    """Load YAML, return (pipeline_fields, api_payload)."""
    raw = yaml.safe_load(path.read_text())
    pipeline = {
        "id": raw["id"],
        "version": raw["version"],
        "platform": raw["platform"],
        "status": raw["status"],
    }
    payload = raw[raw["platform"]]  # sentinel: or defender: block
    return pipeline, payload


def to_sentinel_body(payload: dict) -> dict:
    """Convert sentinel payload to ARM API request body."""
    body = copy.deepcopy(payload)
    kind = body.pop("kind")
    return {"kind": kind, "properties": body}


def to_defender_body(payload: dict) -> dict:
    """Defender payload is already the API body."""
    return payload
```

---

## Deployment Status Gating

| Rule status    | Deploy behavior                        |
|----------------|----------------------------------------|
| `experimental` | Skip — not deployed (local dev/test only) |
| `test`         | Deploy — but could gate to a test environment in future |
| `production`   | Deploy                                 |
| `deprecated`   | Disable the rule remotely (`enabled: false` / `isEnabled: false`) |

For v1, `test` and `production` both deploy. `experimental` is skipped.
`deprecated` sets the rule to disabled rather than deleting it — safer for
rollback.

---

## Future Considerations (not in v1)

- KQL syntax validation via Log Analytics dry-run query
- Drift detection on schedule (diff command in CI)
- Slack/Teams notification on deploy results
- Multi-tenant support (tenants.yml with array, parallel deploys)
- Automatic version bump via pre-commit hook or CI step
- Rule dependency ordering
