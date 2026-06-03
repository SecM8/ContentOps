# Live integration test runbook

> Companion to [`local-testing.md`](local-testing.md). That file covers
> `.env`, RBAC, and the per-handler `contentops doctor --matrix` gate.
> This one focuses on **how to actually run the live suite** —
> especially the PowerShell-vs-bash gotchas that bite first-time
> operators.

The integration suite under `tests/integration/` is gated behind
`RUN_LIVE_TESTS=1` and a handful of `INTEGRATION_*` variables. It hits
a real Azure tenant: alert rules are created and deleted, Defender
detections are upserted, ARM `PUT` / `DELETE` calls are issued. The
suite is **opt-in** — running `pytest` without the env vars set just
skips every test in `tests/integration/`.

---

## Purpose and safety

These tests exist to give end-to-end confidence in handler CRUD against
a live Sentinel + Defender XDR tenant — the kind of confidence unit
tests cannot provide because the failure mode the suite catches is "the
upstream API contract changed and our handler now writes a 400."

Read this before your first run:

- **Tests hit real Azure.** Each test creates Sentinel rules, Defender
  custom detections, and watchlist items on a live workspace; they are
  deleted again on teardown.
- **Test resources are namespaced.** Every created envelope id starts
  with `zz-itest-` (or `zz_itest_` for Graph endpoints that reject
  hyphens). The session-scope sweep in
  [`tests/integration/conftest.py`](../../tests/integration/conftest.py)
  walks every matching resource on session exit and deletes it, so
  even a crashed test does not leak.
- **Sentinel analytics are created disabled** (`enabled: false`) where
  the API permits it — they will never fire alerts even if teardown is
  interrupted.
- **Use a non-production integration workspace.** The suite refuses to
  run if `INTEGRATION_WORKSPACE_NAME` matches a `role: prod` workspace
  from `config/tenant.yml`; the production-workspace guard is in
  [`tests/integration/conftest.py`](../../tests/integration/conftest.py)
  and exits with status code 2 by default. See
  [Production-workspace guard](#production-workspace-guard) for the
  override and when (rarely) to use it.

---

## Required environment

Set these in your `.env` (or export inline before invoking pytest):

```dotenv
RUN_LIVE_TESTS=1
INTEGRATION_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
INTEGRATION_RESOURCE_GROUP=rg-sentinel-integration
INTEGRATION_WORKSPACE_NAME=law-sentinel-integration
INTEGRATION_WORKSPACE_LOCATION=westeurope
```

Without `RUN_LIVE_TESTS=1` or any of the three required `INTEGRATION_*`
vars (subscription, resource group, workspace name) every test in
`tests/integration/` is skipped at collection time.

### Authentication

Auth flows through `DefaultAzureCredential`, so any credential source
the Azure SDK recognises works. For local development, the simplest
path is the Azure CLI:

```bash
az login
az account set --subscription "<integration subscription guid>"
az account show
```

If you prefer service-principal auth (the same shape used by CI), set
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` in
`.env` — `DefaultAzureCredential` picks them up. The RBAC matrix for
both modes is in [`local-testing.md`](local-testing.md).

### Production-workspace guard

If `INTEGRATION_WORKSPACE_NAME` matches a **prod-role** workspace from
`config/tenant.yml`, the suite refuses to run and exits with code 2.
Override with:

```dotenv
I_UNDERSTAND_THIS_IS_PRODUCTION=yes
```

Set this only when you genuinely intend to exercise CRUD against the
prod workspace. The guard exists because the suite creates and deletes
resources (with a `zz-itest-` prefix) — leaks against prod are
recoverable but noisy. Do not set the override casually; the common
case is "I pointed the env vars at the wrong workspace" and the right
fix is to update `INTEGRATION_WORKSPACE_NAME`, not the override.

---

## PowerShell commands

PowerShell does **not** honor bash-style inline env vars (`KEY=VAL cmd`)
and does **not** glob `test_sentinel_*_crud.py` the way bash does.
Use these patterns instead.

### Targeted smoke

A single Sentinel analytic CRUD round-trip — the cheapest "is the
tenant reachable and can the analytic handler write?" check:

```powershell
$env:RUN_LIVE_TESTS = "1"
pytest tests/integration/test_sentinel_analytic_crud.py -q
```

Doctor handler matrix only (verifies the live tenant is reachable and
every drift-capable handler can list, without exercising CRUD):

```powershell
$env:RUN_LIVE_TESTS = "1"
pytest tests/integration/test_sentinel_live_full_coverage.py::test_doctor_matrix_no_failures -q
```

### Full integration suite

Use the explicit file list — PowerShell does not expand `*` in pytest
arguments:

```powershell
$env:RUN_LIVE_TESTS = "1"
pytest `
  tests/integration/test_sentinel_alert_kinds_crud.py `
  tests/integration/test_sentinel_analytic_crud.py `
  tests/integration/test_sentinel_extras_crud.py `
  tests/integration/test_sentinel_analytic_scaffold_deploys.py `
  tests/integration/test_sentinel_live_full_coverage.py `
  tests/integration/test_prune_live.py `
  tests/integration/test_collect_live_roundtrip.py `
  tests/integration/test_defender_custom_detection_crud.py `
  -q
```

### Whole directory

PowerShell passes the directory through fine — only file globs break:

```powershell
$env:RUN_LIVE_TESTS = "1"
pytest tests/integration -q
```

---

## Bash commands

Bash supports inline env vars and globs natively:

```bash
RUN_LIVE_TESTS=1 pytest tests/integration/test_sentinel_analytic_crud.py -q
```

Full suite — prefer the explicit file list (mirroring the PowerShell
snippet above) for symmetry, or rely on directory expansion:

```bash
RUN_LIVE_TESTS=1 pytest tests/integration -q
```

Shell globs work in bash but **not in PowerShell** — if you copy a
glob snippet from elsewhere, it is bash-only:

```bash
# bash only — PowerShell will pass the literal string to pytest and 404
RUN_LIVE_TESTS=1 pytest tests/integration/test_sentinel_*_crud.py -q
```

---

## Expected results

A healthy run should pass the live CRUD tests. Optional tenant features
(Workspace Manager, Logic-Apps-Standard playbooks, Graph TI scopes the
app reg is not consented for) may produce **skips** or doctor **WARN**
rows — those are tolerated. **FAIL** rows require investigation; see
[Troubleshooting](#troubleshooting) below.

For reference, the R4 / ContentOps validation run reached
`15 passed / 1 skipped` for the CRUD suite, and the
`test_doctor_matrix_no_failures` smoke passed once
`INTEGRATION_WORKSPACE_NAME` was set to the correct workspace name.
Treat that as historical evidence, not a guarantee — tenant feature
availability changes over time.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `RUN_LIVE_TESTS=1 : The term ... is not recognized` | Bash-style inline env var in PowerShell | Use `$env:RUN_LIVE_TESTS = "1"` first, then `pytest …` |
| `ERROR: file or directory not found: tests/integration/test_sentinel_*_crud.py` | PowerShell does not glob file arguments | List files explicitly with backtick line continuation, or pass the whole `tests/integration` directory |
| All tests reported `SKIPPED` | `RUN_LIVE_TESTS` unset or any required `INTEGRATION_*` var missing | Set `RUN_LIVE_TESTS=1` and the three required `INTEGRATION_*` vars in `.env` or inline |
| Auth/token failure (`DefaultAzureCredential` could not retrieve a token) | No credential source the SDK can see | Run `az login` + `az account set --subscription <id>`, or set `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` |
| Suite exits with `INTEGRATION_WORKSPACE_NAME=... matches a prod-role Sentinel workspace` | Production-workspace guard tripped | Point `INTEGRATION_WORKSPACE_NAME` at a non-prod workspace; only set `I_UNDERSTAND_THIS_IS_PRODUCTION=yes` if you genuinely intend prod CRUD |
| `No Sentinel workspace named ... in tenant ...` | Workspace selector mismatch — name not in `config/tenant.yml` | Verify tenant config; selectors are case-insensitive but require the workspace to exist |
| `PIPELINE_WORKSPACE_NAME is unset and the tenant has N Sentinel workspaces` | Multi-workspace tenant, no selector | `$env:PIPELINE_WORKSPACE_NAME = "<name>"` (PowerShell) / `export PIPELINE_WORKSPACE_NAME=<name>` (bash), or pass `--workspace <name>` / `--role <role>` to commands that support those flags |
| Doctor probes a different workspace than expected | Doctor picks the first prod-role workspace (or first overall) when no selector is set | For doctor matrix checks in a multi-workspace tenant, set `PIPELINE_WORKSPACE_NAME` to the desired workspace name before running `contentops doctor --matrix` |
| Workspace Manager 400 reported as `WARN` | Workspace Manager is an opt-in Sentinel feature; tenants that have not provisioned a manager workspace get 400 from those collections | Acceptable WARN unless Workspace Manager is in scope for this tenant. See `_classify_handler_matrix_failure` in [`contentops/devex/doctor.py`](../../contentops/devex/doctor.py) for the rule |
| ARM `403 Forbidden` on a Sentinel handler | App reg missing Sentinel Contributor on the workspace RG | See the RBAC matrix in [`local-testing.md`](local-testing.md) and re-run `az role assignment create` |
| Graph `403 Forbidden` on Defender custom detection | `CustomDetection.ReadWrite.All` app permission missing admin consent | App Registration → API permissions → grant admin consent |
| `Could not import 'pipeline'` / `ModuleNotFoundError: No module named 'pipeline'` | Stale `detection-pipeline` editable install metadata from before the rebrand | See [Clearing stale editable-install metadata](#clearing-stale-editable-install-metadata) below |
| Tests pass locally but fail in CI | OIDC federated credential subject mismatch | Verify the federated credential subject matches the workflow's `repo:org/repo:environment:<env>` claim |

### Clearing stale editable-install metadata

After the ContentOps rebrand the distribution name in `pyproject.toml`
changed from `detection-pipeline` to `contentops`. The Python *import*
package stayed `pipeline`, but a venv created against the old name can
keep a stale `*.dist-info` directory around that interferes with the
new install. Fresh venvs are unaffected — this only bites existing
working trees.

Bash / macOS / Linux:

```bash
pip uninstall -y detection-pipeline
pip install -e .
```

PowerShell / Windows (the egg-info clean-up is belt-and-braces):

```powershell
python -m pip uninstall -y detection-pipeline
Remove-Item -Recurse -Force .\detection_pipeline.egg-info -ErrorAction SilentlyContinue
python -m pip install -e .
```

Verify with `pip show contentops` — the `Location:` should point at the
current repo, and `Name:` should read `contentops`.

---

## Related docs

- [`local-testing.md`](local-testing.md) — `.env`, RBAC, doctor matrix
  expectations.
- [`../operations/multi-workspace.md`](../operations/multi-workspace.md)
  — workspace selection, `--role` / `--workspace`, OIDC federated
  credentials.
- [`../OPERATOR_GUIDE.md`](../OPERATOR_GUIDE.md) — daily-flow and
  when-things-break decision tree.
