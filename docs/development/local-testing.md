# Local development and live testing

Use this page for local credentials, RBAC, and pre-flight checks.
For the copy-pasteable live Azure test commands, see
[Live integration tests](live-integration-tests.md). If you haven't
created the Azure App Registration yet, do
[`../operations/authentication-setup.md`](../operations/authentication-setup.md)
first — this page assumes you already have an App Reg with the right
permissions.

`contentops` is the only CLI. Both `contentops <cmd>` (console script)
and `python -m contentops <cmd>` work after `python -m pip install -e .`.
**On locked-down corporate Windows machines, prefer `python -m
contentops <cmd>`** — Device Guard / WDAC sometimes blocks the
pip-installed `.exe` shim but always allows invocation through
Python.

## .env is OPTIONAL for local dev

`DefaultAzureCredential` walks a chain. If you've run `az login` and
your user has `Microsoft Sentinel Contributor` on the workspace, you
do NOT need an `.env` file — the chain falls through to
`AzureCliCredential` which uses your cached `az` token. This is the
recommended local-dev posture for security-conscious adopters: no
client secrets on disk.

`.env` is the right answer when you want to mirror CI's auth path
exactly (App Registration with client secret), or when you don't
have `az login` access from your laptop.

See [`../operations/authentication-setup.md`](../operations/authentication-setup.md)
§"Path A vs Path B" for the trade-off and the diagnostic decoder for
401 / 403 outcomes.

## .env layout (if you go with secrets)

Copy `.env.example` to `.env` (the file is git-ignored) and fill in:

```
# OIDC-style service principal for the integration tenant.
AZURE_TENANT_ID=<aad-tenant-guid>
AZURE_CLIENT_ID=<app-registration-client-id>
AZURE_CLIENT_SECRET=<client-secret>
AZURE_SUBSCRIPTION_ID=<integration-subscription-guid>

# Live-test gates. See docs/development/live-integration-tests.md.
RUN_LIVE_TESTS=1
# Only set this if INTEGRATION_WORKSPACE_NAME matches a prod-role
# workspace in config/tenant.yml AND you intend prod CRUD.
# I_UNDERSTAND_THIS_IS_PRODUCTION=yes

# Integration tenant target — these get plumbed into the
# integration_sentinel_config fixture.
INTEGRATION_SUBSCRIPTION_ID=<integration-sub>
INTEGRATION_RESOURCE_GROUP=rg-sentinel-integration
INTEGRATION_WORKSPACE_NAME=law-sentinel-integration
INTEGRATION_WORKSPACE_LOCATION=westeurope
```

Loaded automatically by `contentops.utils.env.load_env_file()` —
both the CLI and pytest pick it up. Existing `os.environ` values
win over file values, so an inline export overrides the file.

Auth flows through `DefaultAzureCredential`. The service-principal
env vars above work; so does `az login` for local dev. Walk-through
in [Live integration tests → Authentication](live-integration-tests.md#authentication).

## Minimum app-registration permissions

The pipeline manages **six asset kinds** today (see
[`reference/asset-coverage.md`](../reference/asset-coverage.md)).
The roles below cover all six. The historical 21-kind taxonomy
required additional roles (`Logic App Contributor` for playbooks,
`Monitoring Contributor` for workbooks, `ThreatIndicators.ReadWrite.OwnedBy`
for TI indicators); those handlers were removed in the v2 hard-cut
and the corresponding roles are no longer required.

| Surface | Permission | Why |
|---|---|---|
| Sentinel ARM | `Microsoft Sentinel Contributor` on the workspace RG | `sentinel_analytic`, `sentinel_watchlist`, `sentinel_data_connector` |
| Sentinel ARM | `Log Analytics Contributor` on the workspace RG | `sentinel_hunting` + `sentinel_parser` — both live as `savedSearches` on the LA workspace, not under SecurityInsights |
| Microsoft Graph | `CustomDetection.ReadWrite.All` (application, admin consent) | `defender_custom_detection` |

## Copy-pasteable RBAC

```bash
# Resolve the App Registration's service-principal object ID first.
APP_OBJECT_ID=$(az ad sp show --id "$AZURE_CLIENT_ID" --query id -o tsv)

# Sentinel + Log Analytics on the workspace RG
az role assignment create \
  --assignee-object-id "$APP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Contributor" \
  --scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$INTEGRATION_RESOURCE_GROUP

az role assignment create \
  --assignee-object-id "$APP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Contributor" \
  --scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$INTEGRATION_RESOURCE_GROUP

# Microsoft Graph application permissions are granted via the portal
# (App Registration → API permissions → admin consent). See
# docs/operations/authentication-setup.md step 2.
```

## Verify your setup

```
$ contentops doctor --matrix
```

Expected output: every check PASSes; the per-handler matrix shows
**six handler rows** (one per drift-capable asset kind), all `PASS`.
On a multi-workspace tenant the Sentinel handler rows repeat with a
`@<workspaceName>` suffix.

```
contentops doctor --matrix
========================================
  [PASS] python_version  — 3.12.10
  [PASS] python_deps  — httpx, pydantic, yaml, azure.identity, click
  [PASS] dotenv  — loaded /path/to/.env
  [PASS] auth_env  — AZURE_TENANT_ID=set, AZURE_CLIENT_ID=set, AZURE_CLIENT_SECRET=set
  [PASS] tenant_yml  — tenant=production, sentinel=[law-sentinel(prod)]
  [PASS] detections_dir  — ./detections
  [PASS] detections_parse  — 51 parsed, 0 errors
  [PASS] git  — git version 2.x
  [PASS] token_acquisition  — ARM + Graph tokens acquired
  [PASS] workspace_reachable  — workspace=law-sentinel (HTTP 200)
  [PASS] graph_reachable  — Graph beta /security/rules/detectionRules HTTP 200
  [PASS] handler:sentinel_analytic         — 101 item(s) listed
  [PASS] handler:sentinel_hunting          — 38 item(s) listed
  [PASS] handler:sentinel_watchlist        — 5 item(s) listed
  [PASS] handler:sentinel_parser           — 12 item(s) listed
  [PASS] handler:sentinel_data_connector   — 3 item(s) listed
  [PASS] handler:defender_custom_detection — 46 item(s) listed

summary: ~17 pass, 0 warn, 0 fail
```

A `FAIL` row in the doctor matrix usually means the credentials
in `.env` don't have a required role; fix the RBAC, re-run.

In a multi-workspace tenant, set `PIPELINE_WORKSPACE_NAME` before
running `contentops doctor --matrix` to pin which workspace the
matrix probes. `contentops doctor` itself does not expose
`--workspace` / `--role` flags today.

## Running the live integration suite

The end-to-end live suite lives under `tests/integration/` and is
gated by `RUN_LIVE_TESTS=1` plus the `INTEGRATION_*` env vars above.

See [`live-integration-tests.md`](live-integration-tests.md) for
the copy-pasteable PowerShell and bash commands, the production
guard, and the troubleshooting table.

## Tearing down

`tests/integration/conftest.py` registers a session-scope sweep
that walks every alert rule / Defender detection / etc. with the
`zz-itest-` (or `zz_itest_`) prefix and deletes them when pytest
exits. You should not have to clean up by hand. If pytest crashed
before teardown, run `contentops collect --asset sentinel_analytic`
and look for `zz-itest-` envelope ids — `contentops prune` with
the right `--asset` will remove them.

## Common failures

| Symptom | Likely cause | Fix |
|---|---|---|
| `403 Forbidden` on a Sentinel handler | App reg missing Sentinel Contributor | `az role assignment create` per above |
| `403 Forbidden` on Defender custom detection | Graph admin consent not granted | App Registration → API permissions → grant admin consent |
| `INTEGRATION_WORKSPACE_NAME matches a prod-role Sentinel workspace` exit | Production-workspace guard tripped | Point at a non-prod workspace; only set `I_UNDERSTAND_THIS_IS_PRODUCTION=yes` if you really mean it |
| Tests pass locally but fail in CI | OIDC federated credential subject mismatch | Verify the federated credential subject matches the workflow's `repo:org/repo:environment:<env>` claim |
| `ModuleNotFoundError: No module named 'pipeline'` after a `git pull` | Stale `detection-pipeline` editable install metadata from before the rebrand | See [Clearing stale editable-install metadata](live-integration-tests.md#clearing-stale-editable-install-metadata) |
