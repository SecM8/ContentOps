# End-to-end capability matrix

A single test that exercises every `contentops` CLI capability against
a tmpdir sandbox, with per-capability PASS / FAIL / SKIP reporting.

Complements:

* `tests/v2/` — unit tests for internals (fast, run on every PR).
* `tests/integration/` — live Azure CRUD smoke (gated by
  `RUN_LIVE_TESTS=1`).

This matrix sits between the two. It answers "does every capability
still work end-to-end after this change?" — a question that's
expensive to answer manually with ~40 CLI leaf commands across six
asset kinds.

## Three modes

| Mode | What runs | What's mocked | Prereqs |
|---|---|---|---|
| `offline` | Local-only commands (`plan`, `lint`, `new`, `audit verify`, `coverage`, `portfolio`, `state` show/forget/sync, `config`, `catalog`, `doctor`, `apply --dry-run`, lifecycle YAML rewrites, `drift-pr-body`, `drift-resolve`, `snapshot-diff`, `restore`, `explain`, `bootstrap --dry-run`). Azure-needing capabilities report `SKIP`. | Nothing — no network calls happen at all. | Python 3.12 + repo checkout. |
| `mocked` (default) | Every capability. Azure-needing commands hit `respx`-stubbed ARM + Graph + OIDC + Log Analytics routes backed by in-memory stores so create/read round-trips. | ARM `alertRules` / `watchlists` / `dataConnectors`, Graph `detectionRules` + extensions, AAD `oauth2/token`, LA `query`. | Same as offline + `respx` (already in `pyproject.toml` dev deps). |
| `live` | Every capability against the **integration** workspace, using the existing `zz-itest-` prefix + production guard in `tests/integration/conftest.py`. | Nothing — real Azure. | OIDC creds, `INTEGRATION_*` env vars, `RUN_LIVE_TESTS=1`. |

## How to invoke

### Locally

```powershell
# Default (mocked)
pwsh scripts/run-capability-tests.ps1

# Offline only (no Azure-needing capabilities)
pwsh scripts/run-capability-tests.ps1 -Mode offline

# Live (writes to the integration workspace)
$env:INTEGRATION_SUBSCRIPTION_ID = "..."
$env:INTEGRATION_RESOURCE_GROUP  = "..."
$env:INTEGRATION_WORKSPACE_NAME  = "..."
pwsh scripts/run-capability-tests.ps1 -Mode live
```

The PowerShell wrapper sets `RUN_E2E=1`, invokes pytest, then renders
the per-capability table from the JSON sidecar.

### Direct pytest (bash / CI)

```bash
RUN_E2E=1 pytest tests/e2e/test_full_capability_matrix.py \
  --mode=mocked --e2e-json=e2e-results.json -q
```

### CI (GitHub Actions)

* PR runs: the `e2e-capability-tests` workflow's `mocked` job fires on
  any PR that touches `contentops/`, `tests/e2e/`, `pyproject.toml`,
  the wrapper script, or the workflow file itself. No OIDC, no
  secrets — fork-safe.
* Live runs: `gh workflow run e2e-capability-tests.yml -f mode=live`
  triggers the `live` job. Uses `pipeline-setup` for OIDC + the
  real `TENANT_CONFIG_YAML` secret, targets the integration role.

## Reading the results

The PowerShell wrapper prints a table on every run:

```text
CAPABILITY                         STATUS    DURATION  MESSAGE
---------------------------------  --------  --------  -----------------
plan                               PASS         142.3 ms
plan.filter_asset                  PASS          89.4 ms
lint.strict                        PASS         210.1 ms
apply.mocked                       SKIP           0.0 ms  not exercised in mode=offline
...

Summary: 35 PASS  |  0 FAIL  |  7 SKIP  (total 42)
```

A `SKIP` is informational — the capability is correctly excluded from
the active mode (e.g., `apply.mocked` SKIPs in offline mode because
it requires the mocked Azure routes). A `FAIL` is the only outcome
that exits non-zero.

The JSON sidecar (`-e2e-json` / `--e2e-json`) carries the same data
as machine-readable rows: `capability`, `status`, `duration_ms`,
`message`. Use it for dashboards or post-hoc analysis.

## Adding a new capability

When a new CLI command lands, the `test_capability_drift_guard` test
(which runs in the regular CI suite, NOT gated by RUN_E2E) fails with:

```text
New CLI commands found without an e2e capability entry:
  my-new-command
```

Three options to fix:

1. **Cover it.** Add a `Capability(...)` entry to
   `tests/e2e/_capabilities.py::CAPABILITIES` plus append the new
   path to `COVERED_LEAVES`. Wire any necessary mock routes by name
   (`oidc_token`, `arm_sentinel`, `graph_defender`, `kql_query`) or
   add a new bundle to `tests/e2e/_mocks.py`.
2. **Mark intentionally uncovered.** Add the path to
   `INTENTIONALLY_UNCOVERED` with a one-line justification. Examples
   already in the registry: `contentops test` (would recurse into
   pytest), Click group container paths (their leaves cover them).
3. **Use a placeholder.** If the command needs a piece of sandbox
   state we don't yet build, add a placeholder key to `Sandbox` /
   `Sandbox.placeholders` in `tests/e2e/conftest.py` and reference
   it via `{name}` in `Capability.cli`.

The drift guard also surfaces stale entries (registered capabilities
that no longer exist in the live Click tree) so a deletion gets the
same treatment.

## Troubleshooting

**`AllMockedAssertionError` / unexpected request URL**
A capability hit an endpoint the loaded bundle doesn't mock. Either
(a) add the URL pattern to the relevant bundle in `_mocks.py`, or
(b) add a new bundle and list it in the capability's
`mock_routes` tuple. Inspect the offending URL from the test
output — the error message includes it.

**`FileNotFoundError: config/tenant.yml`**
The conftest monkeypatches `contentops.config.CONFIG_PATH` to the
sandbox's `tenant.yml`. If you see this on a capability that loads
config, check (a) that the fixture seeded `config/tenant.yml` into
the sandbox root, and (b) that the test depends on the `scoped_env`
fixture (which applies the monkeypatch).

**Hung test on Azure-needing capabilities**
DefaultAzureCredential is probing for IMDS / managed identity even
in mocked mode. The `oidc_token` bundle stubs the IMDS endpoint to
return 400 fast; ensure it's listed in your capability's
`mock_routes`.

**`audit verify` reports breaks**
The sandbox copies the entire `audit/` chain from the real repo to
keep hash continuity. If `audit verify` complains, the source chain
itself is broken — fix that in the repo, the e2e is a passenger.

## Non-goals

* Real OIDC token exchange — only exercised in `live` mode.
* Real ARM throttling / retry behaviour — only exercised in `live`.
* Workspace-specific KQL semantics — only exercised in `live` (the
  KQL mock returns an empty result set; `rule-test` and
  `silent-rules` exercise the surrounding command flow, not the
  KQL engine).
* Re-litigating unit-test coverage. If a regression isn't observable
  from the CLI surface, the unit tests are the right place to
  guard it.
