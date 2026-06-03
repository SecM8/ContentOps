# Test catalog

> Every test file in the repo, what it covers, how to run it, and
> which workflow it gates.
>
> **Looking for the canonical, code-derived list of every test file
> + its function count?** See
> [`generated-catalog.md`](generated-catalog.md#tests), emitted by
> `contentops catalog regenerate` and pinned drift-free in CI. This
> page keeps the curated coverage prose; the generated page is what
> the pipeline guarantees stays in sync with the test layout.

For per-asset live coverage status see
[`asset-coverage.md`](asset-coverage.md). For test conventions and
pre-flight checks see [`docs/development/local-testing.md`](../development/local-testing.md).

---

> ⚠ **Live-test ceremony**
>
> Tests under `tests/integration/` hit a real Azure tenant. They
> only run when **all three** of these are true:
>
> 1. `RUN_LIVE_TESTS=1` is set in the environment
>    ([`tests/integration/conftest.py:42`](../../tests/integration/conftest.py)).
> 2. `INTEGRATION_SUBSCRIPTION_ID`, `INTEGRATION_RESOURCE_GROUP`,
>    and `INTEGRATION_WORKSPACE_NAME` are set
>    ([`conftest.py:92`](../../tests/integration/conftest.py)).
> 3. If `INTEGRATION_WORKSPACE_NAME` matches the workspace declared
>    in `config/tenant.yml`, **`I_UNDERSTAND_THIS_IS_PRODUCTION=yes`**
>    must also be set or the suite refuses to run
>    ([`conftest.py:68`](../../tests/integration/conftest.py)).
>
> Sentinel rules created by live tests are PUT with `enabled: false`
> and named `zz-itest-<timestamp>-<rand>` so an end-of-session sweep
> can clean up stragglers from a crashed test
> ([`conftest.py:38`](../../tests/integration/conftest.py)).
>
> Use `contentops test --live` (CLI wrapper) — it runs `contentops
> doctor --matrix` first and refuses to launch if any check FAILs
> ([`contentops/cli/commands/test_runner.py`](../../contentops/cli/commands/test_runner.py)).
> See [`docs/development/live-integration-tests.md`](../development/live-integration-tests.md)
> for the full PowerShell / bash runbook.

---

## How to run

| Need | Command |
|---|---|
| Just unit tests | `pytest -q --ignore=tests/integration` |
| Just unit tests via the CLI wrapper | `contentops test` |
| One file | `pytest tests/v2/test_drift.py -q` |
| Filter by keyword | `pytest -q -k drift` |
| Live integration suite (local) | set the env vars per [`live-integration-tests.md`](../development/live-integration-tests.md), then `contentops test --live` (or invoke pytest directly per that runbook) |
| Live integration suite (CI) | trigger [`integration.yml`](../../.github/workflows/integration.yml) with `i-know-this-hits-prod=true` |

Local prerequisites for live: `contentops doctor --matrix` must be
green. The doctor checks (Python version, deps, `.env`, auth env
vars, tenant.yml, detections parse, git, token acquisition,
workspace reachability, Graph reachability, per-handler list_remote
matrix) live in [`contentops/devex/doctor.py`](../../contentops/devex/doctor.py).

---

## Unit tests — `tests/v2/`

This is the v2 suite. Most of these run in <1s; the whole suite is
~90 seconds. All are gated by `ci.yml`. The pre-existing v1 tests
under `tests/` (without `v2/`) are listed at the bottom.

### Plan / apply / drift / collect

| Test file | Covers | Gates |
|---|---|---|
| [`test_cli_plan_apply.py`](../../tests/v2/test_cli_plan_apply.py) | The two main commands end-to-end (with mocked handlers); validation errors → exit 1; `--changed-since` filtering. | `ci.yml`, `validate.yml` |
| [`test_apply_verify_analytic.py`](../../tests/v2/test_apply_verify_analytic.py) | Sentinel analytic apply + post-apply hash verify. | `ci.yml` |
| [`test_apply_verify_defender.py`](../../tests/v2/test_apply_verify_defender.py) | Defender custom detection apply path. | `ci.yml` |
| [`test_apply_verify_hunting.py`](../../tests/v2/test_apply_verify_hunting.py) | Sentinel hunting query apply path. | `ci.yml` |
| [`test_apply_verify_watchlist.py`](../../tests/v2/test_apply_verify_watchlist.py) | Watchlist apply + W4.5-B item-count check. | `ci.yml` |
<!-- ``test_apply_verify_automation.py`` + ``test_apply_verify_playbook.py``
rows removed -- the automation + playbook handlers were deleted in the
asset-taxonomy reduction (six supported kinds), and so were their tests. -->
| [`test_drift.py`](../../tests/v2/test_drift.py) | DriftReport classification, `_payloads_match` normalisation, `disambiguate_envelope_ids`. | `ci.yml`, `drift.yml` |
| [`test_drift_roundtrip.py`](../../tests/v2/test_drift_roundtrip.py) | Per-handler `to_envelope` ↔ `apply` round-trip stability. | `ci.yml` |
| [`test_drift_pr_body.py`](../../tests/v2/test_drift_pr_body.py) | Markdown body + label list emitted by `contentops drift-pr-body`. | `ci.yml`, `drift.yml` |
| [`test_collect_roundtrip.py`](../../tests/v2/test_collect_roundtrip.py) | Collect's drift-write → drift detect cycle reports nothing changed. | `ci.yml`, `collect.yml` |
<!-- ``test_operational_filter.py`` row removed -- the test, the
``--include-operational`` flag, and the ``OPERATIONAL_ASSETS`` set
were all deleted in the asset-taxonomy reduction. -->
| [`test_prune.py`](../../tests/v2/test_prune.py) | Orphan detection + max-deletes cap + locked envelope skip + audit chain wiring + read-only NotSupportedError handling. | `ci.yml`, `prune.yml` |

### Discovery / envelope / metadata / state

| Test file | Covers | Gates |
|---|---|---|
| [`test_discovery.py`](../../tests/v2/test_discovery.py) | `discover_assets()` walks YAML, skips `templates/` and `samples/`. | `ci.yml` |
<!-- ``test_envelope_compat.py`` row removed with the asset-taxonomy
reduction (the v1/v2 envelope-compat handlers it exercised are gone). -->
| [`test_metadata.py`](../../tests/v2/test_metadata.py) | `RuleMetadata` Pydantic model: tactic enum, technique regex, severity, runbook URL. | `ci.yml`, `validate.yml` |
<!-- ``test_grandfather_legacy.py`` row removed -- the script
(``scripts/grandfather_legacy.py``) and its test were both deleted
in the v1-legacy hard cut (PR #122/#125). -->
| [`test_remediate_payload001.py`](../../tests/v2/test_remediate_payload001.py) | `scripts/remediate_payload001.py` deletes dangling `templateVersion` lines surgically; idempotent; v1+v2 envelope support. | `ci.yml` |
| [`test_state_file.py`](../../tests/v2/test_state_file.py) | EnvState round-trip, `merge_apply_results`, `state show`, `state forget`. | `ci.yml` |
| [`test_audit.py`](../../tests/v2/test_audit.py) | AuditRecord serialization + write_records appending. | `ci.yml`, `audit-verify.yml` |
| [`test_audit_chain.py`](../../tests/v2/test_audit_chain.py) | verify_chain catches `prev_hash_mismatch`, `record_hash_invalid`, `missing_field` across multi-day chains. | `ci.yml`, `audit-verify.yml` |

### Lint, coverage, compliance, portfolio

| Test file | Covers | Gates |
|---|---|---|
| [`test_lint.py`](../../tests/v2/test_lint.py) | KQL001-KQL007 + `contentops lint` CLI integration. | `ci.yml`, `validate.yml` |
| [`test_coverage.py`](../../tests/v2/test_coverage.py) | MITRE coverage report markdown + JSON shapes. | `ci.yml`, `coverage.yml` |
<!-- ``test_compliance.py`` row removed -- ``pipeline compliance``,
``compliance.yml``, ``compliance/mappings/`` and ``compliance-validate.yml``
were all deleted in the v1-legacy hard cut (PR #146/#147). -->
| [`test_portfolio.py`](../../tests/v2/test_portfolio.py) | Portfolio rows shape + `--cohort` filter + legacy include/exclude. | `ci.yml`, `portfolio.yml` |
| [`test_dependencies.py`](../../tests/v2/test_dependencies.py) | `dependencies.yml` schema + `validate()` violations. | `ci.yml`, `validate.yml` |

### Per-handler unit coverage

| Test file | Covers |
|---|---|
| [`test_analytic_kinds.py`](../../tests/v2/test_analytic_kinds.py) | All Sentinel analytic kinds: Scheduled, NRT, MicrosoftSecurityIncidentCreation, Fusion, MLBA, ThreatIntelligence. |
| [`test_hunting_handler.py`](../../tests/v2/test_hunting_handler.py) | Hunting query handler. |
| [`test_hunting_model.py`](../../tests/v2/test_hunting_model.py) | Hunting Pydantic model — frequency, tactics, KQL field. |
| [`test_watchlist_model.py`](../../tests/v2/test_watchlist_model.py) | Watchlist Pydantic model — itemsSearchKey, contentType. |
| [`test_sentinel_arm_retry.py`](../../tests/v2/test_sentinel_arm_retry.py) | ARM 429 backoff and 5xx retry. |
<!-- ``test_automation_handler.py``, ``test_automation_playbook_drift.py``,
``test_playbook_handler.py``, ``test_sentinel_extras.py`` (x2),
``test_sentinel_singletons.py``, ``test_readonly_handlers.py``, and
``test_defender_ti_indicator.py`` rows removed -- the automation,
playbook, ti_indicator, singleton (settings/onboarding/metadata), and
read-only handlers were all deleted in the asset-taxonomy reduction to
six supported kinds, and so were their tests. -->

### CLI surface

| Test file | Covers |
|---|---|
| [`test_devex_doctor.py`](../../tests/v2/test_devex_doctor.py) | `contentops doctor` checks + format/JSON output + exit codes. |
| [`test_devex_scaffold.py`](../../tests/v2/test_devex_scaffold.py) | `contentops new ASSET ID` for the 5 scaffoldable asset kinds (every kind except `sentinel_data_connector`); rendered YAML parses + lints clean. |
| [`test_disable.py`](../../tests/v2/test_disable.py) | `contentops disable RULE_ID` rewrites status, appends reason, idempotent. |
| [`test_emergency_disable_workflow.py`](../../tests/v2/test_emergency_disable_workflow.py) | `emergency-disable.yml` shape + safety guards. |
| [`test_lock_unlock_retry.py`](../../tests/v2/test_lock_unlock_retry.py) | `contentops lock` / `unlock` / `retry-failed`. |
| [`test_bootstrap_cli.py`](../../tests/v2/test_bootstrap_cli.py) | `contentops bootstrap` idempotence + dry-run. |
<!-- ``test_rewrite.py`` row removed -- ``pipeline rewrite`` and the
test were deleted in the v1-legacy hard cut (PR #146). -->
| [`test_yaml_block_scalar.py`](../../tests/v2/test_yaml_block_scalar.py) | Block-scalar dumper preserves multiline KQL. |
| [`test_slug_arm_name.py`](../../tests/v2/test_slug_arm_name.py) | `displayname_slug()` deterministic; reserved-name handling. |
| [`test_config_envs.py`](../../tests/v2/test_config_envs.py) | `config/tenant[.<env>].yml` resolution + `PIPELINE_ENV` precedence. |
| [`test_git_diff.py`](../../tests/v2/test_git_diff.py) | `--changed-since` driver — git diff including untracked files. |
| [`test_pr_l_chunks.py`](../../tests/v2/test_pr_l_chunks.py) | PR-L commit chunks integration. |
<!-- ``test_legacy_detection_allowlist.py`` row removed -- the legacy-
allowlist gate (``scripts/check_legacy_detection_allowlist.py`` +
``config/legacy_detections_allowlist.txt``) and its test were all
deleted in the v1-legacy hard cut (PR #122/#125). -->
| [`test_production_promotion_detector.py`](../../tests/v2/test_production_promotion_detector.py) | `production-promotion-check.yml` PR script. |
| [`test_registry_and_handler.py`](../../tests/v2/test_registry_and_handler.py) | HandlerRegistry: lazy construction, caching, close_all. |
| [`test_registry_close.py`](../../tests/v2/test_registry_close.py) | Registry `close_all()` is idempotent and exception-tolerant. |

---

## Live integration — `tests/integration/`

These hit a real tenant. See the ceremony callout above.

| Test file | Asset(s) | Live ops |
|---|---|---|
| [`test_sentinel_analytic_crud.py`](../../tests/integration/test_sentinel_analytic_crud.py) | sentinel_analytic | Create, update, hash-verify, disable, delete. |
| [`test_sentinel_alert_kinds_crud.py`](../../tests/integration/test_sentinel_alert_kinds_crud.py) | sentinel_analytic (Fusion / MLBA / MSI / TI alert kinds) | CRUD per kind with the kind-specific projection. |
| [`test_sentinel_extras_crud.py`](../../tests/integration/test_sentinel_extras_crud.py) | sentinel_hunting / sentinel_watchlist / sentinel_workbook / sentinel_automation | Per-asset CRUD + post-apply verification. |
<!-- ``test_sentinel_ti_indicator_crud.py`` row removed -- the
sentinel_ti_indicator handler was deleted in the asset-taxonomy
reduction (six supported kinds), and so was its live CRUD test. -->
| [`test_defender_custom_detection_crud.py`](../../tests/integration/test_defender_custom_detection_crud.py) | defender_custom_detection | Graph beta CRUD; displayName-based upsert. |
| [`test_collect_live_roundtrip.py`](../../tests/integration/test_collect_live_roundtrip.py) | every drift-capable handler | `contentops collect → drift` returns no NEW or CHANGED entries (the round-trip contract). |
<!-- ``test_collect_drift_roundtrip.py`` row removed -- the lower-level
roundtrip test was retired alongside the deleted handlers in the
asset-taxonomy reduction; ``test_collect_live_roundtrip.py`` above
covers the round-trip contract. -->
| [`test_prune_live.py`](../../tests/integration/test_prune_live.py) | every write-capable handler | Create test artefact → prune → verify deleted. Fail-closed if anything else is on disk. |
| [`test_sentinel_live_full_coverage.py`](../../tests/integration/test_sentinel_live_full_coverage.py) | every Sentinel handler | Smoke-tests `list_remote()` / `to_envelope()` succeed for every kind in the live tenant. |
| [`test_sentinel_analytic_scaffold_deploys.py`](../../tests/integration/test_sentinel_analytic_scaffold_deploys.py) | sentinel_analytic (from-template) | Scaffolds via `contentops new --from-template`, deploys to tenant, validates the deploy. |

---

## Documented permission gaps

> The `sentinel_playbook` and `defender_ti_indicator` handlers that
> this section used to document permission gaps for were deleted in
> the asset-taxonomy reduction to six supported kinds, along with
> their `test_apply_verify_playbook.py`, `test_playbook_handler.py`,
> and `test_defender_ti_indicator.py` tests. There are no remaining
> live-coverage permission gaps among the six supported kinds. See
> [`gap-assessment.md`](gap-assessment.md).

---

## Pre-v2 unit tests — `tests/`

These predate the v2 suite layout and exercise the legacy CLI
verbs. They still pass and still gate `ci.yml`.

| Test file | Covers |
|---|---|
| [`test_models.py`](../../tests/test_models.py) | Pydantic models in [`contentops/models.py`](../../contentops/models.py): RuleEnvelope, validate_sentinel_payload, validate_defender_payload. |
<!-- ``test_sentinel_deploy.py`` row removed -- the legacy Sentinel
deploy test was deleted in the asset-taxonomy reduction; the live
apply path is covered by ``tests/integration/`` above. -->
| [`test_defender_deploy.py`](../../tests/test_defender_deploy.py) | v1 deploy Defender path. |
| [`test_yaml_io.py`](../../tests/test_yaml_io.py) | `load_rule()`, `to_sentinel_body()`, `to_defender_body()`. |

These will retire alongside the v1 CLI verbs (`validate` / `deploy` /
`diff` / `delete`), which were removed in R4 of the v1 hard cut. The
v1→v2 verb mapping (`validate`→`plan`, `deploy`→`apply`, `diff`→`drift`,
`delete`→`prune`) is recorded in
[`feature-catalog.md`](feature-catalog.md#removed-v1-commands-post-r4).
