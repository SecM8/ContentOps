# YAML ↔ Python Feature Map

> **Purpose** — This table is a maintainability reference for contributors.
> It maps every `.yml` file category (or individual file) in the repository to
> the Python code that reads, generates, validates, or executes it, plus the
> related Python modules in the same feature flow.
>
> **How to read the flow:** `Feature > Function > Python ← .yml`
>
> **Authoritative inventory:** this YAML→Python map is hand-curated
> narrative kept for explanatory context. The authoritative, drift-gated
> inventory of CLI commands, asset handlers, GitHub Actions workflows, and
> lint rules is generated from code and lives in
> [`docs/reference/generated-catalog.md`](generated-catalog.md). When the
> two disagree, the generated catalog wins.
>
> **Keep this file updated** whenever you:
> - Add a new YAML file or directory under `detections/`, `config/`, or `compliance/`
> - Add or rename a Python handler, command, or config-loader
> - Add or remove a GitHub Actions workflow
>
> Conventions used in the tables:
> - **Direct Python file(s)** — the file that explicitly opens / parses / writes the YAML
> - **Related Python file(s)** — part of the same feature flow but does not open the file directly
> - `Unknown` — relationship has not been verified
> - `Not directly referenced` — the file is consumed by a tool outside this repo (e.g. GitHub Actions runner)

---

## Table of Contents

1. [Detection Rule Files (`detections/`)](#1-detection-rule-files-detections)
   1. [Sentinel Analytic Rules](#11-sentinel-analytic-rules)
   2. [Defender Custom Detections](#12-defender-custom-detections)
   3. [Sentinel Watchlists](#13-sentinel-watchlists)
   4. [Removed asset kinds (asset-taxonomy reduction)](#14-removed-asset-kinds-asset-taxonomy-reduction)
   5. [Templates (Reference, not deployed)](#15-templates-reference-not-deployed)
   6. [Samples (Reference, not deployed)](#16-samples-reference-not-deployed)
2. [Configuration Files (`config/`)](#2-configuration-files-config)
<!-- Section 3 (Compliance Manifests) ToC entry removed -- the
``compliance/mappings/`` directory + ``contentops/compliance/`` module
were deleted in the v1-legacy hard cut (PR #146/#147). The framework-
compliance loop is no longer in scope. -->
4. [GitHub Actions Workflows (`.github/workflows/`)](#4-github-actions-workflows-githubworkflows)
5. [Composite Actions (`.github/actions/`)](#5-composite-actions-githubactions)
6. [Test Fixtures (`tests/fixtures/`)](#6-test-fixtures-testsfixtures)
7. [Missing / Planned YAML Files](#7-missing--planned-yaml-files)
8. [Candidate Files With No Direct In-Repo References](#8-candidate-files-with-no-direct-in-repo-references)
9. [Maintenance Guide](#9-maintenance-guide)

---

## 1. Detection Rule Files (`detections/`)

All YAML files under `detections/` share a common **envelope** parsed by
`contentops/core/envelope.py::parse_envelope`. The envelope declares either a
v1 key (`platform: sentinel|defender`) or a v2 key (`asset: <asset-type>`)
and a `payload:` block. Discovery is handled by
`contentops/core/discovery.py::discover_assets`, which skips the `templates/`
and `samples/` sub-directories.

---

### 1.1 Sentinel Analytic Rules

**Directory:** `detections/sentinel_analytic/` · **101 files**

| Feature | Function / Purpose | YAML Pattern | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|---|
| Sentinel Alert Rules | Define Scheduled or NRT KQL detection rules deployed to Sentinel via ARM `PUT alertRules/{id}` | `asset: sentinel_analytic` or legacy `platform: sentinel` | `contentops/handlers/sentinel_analytic.py` | `contentops/core/envelope.py`, `contentops/core/discovery.py`, `contentops/models.py`, `contentops/providers/sentinel_arm.py` | The handler performs ARM deploy/collect via `SentinelArmProvider`. v1 files use `platform: sentinel`; v2 use `asset: sentinel_analytic`. Both parsed by `parse_envelope`. |
| Plan / Apply | Validate + dry-run / deploy the rule | All files above | `contentops/cli/commands/apply.py` | `contentops/core/registry.py`, `contentops/cli/handler_factories.py`, `contentops/cli/commands/_shared.py` | `plan` validates only; `apply` calls `handler.apply()`. |
| Lint | KQL syntax + payload + metadata checks on `query:` field | All files above | `contentops/lint/runner.py`, `contentops/lint/kql.py` | `contentops/lint/payload.py`, `contentops/lint/metadata_rules.py`, `contentops/lint/strict.py`, `contentops/lint/strict_rules.py` | Triggered by `contentops lint` CLI command and the `validate.yml` workflow (lint-regression job). |
| Collect | Pull live rules from ARM and write YAML to disk | All files above (written) | `contentops/cli/commands/collect.py`, `contentops/cli/commands/collect_support.py` | `contentops/handlers/sentinel_analytic.py`, `contentops/providers/sentinel_arm.py`, `contentops/utils/yaml_io.py` | Collect is orchestrated by the `collect` command, which delegates to the handler's collect path over `SentinelArmProvider`. Only `collect.yml` workflow should legitimately commit these files. |
| Drift detection | Compare YAML state to live ARM state; flag divergence | All files above (read) | `contentops/core/drift.py` | `contentops/drift_suppressions.py`, `contentops/cli/commands/drift.py` | `drift.yml` workflow; suppressions loaded from `detections/drift_suppressions.yml` when present. |
| Coverage report | Map tactic/technique fields to MITRE ATT&CK matrix | All files above (read) | `contentops/coverage/report.py` | `contentops/coverage/gaps.py`, `contentops/cli/commands/coverage.py` | `coverage.yml` workflow; posts sticky PR comment. |
<!-- ``Compliance mapping`` row removed -- ``contentops/compliance/``
+ ``contentops/cli/commands/compliance.py`` were deleted in PR #146/#147. -->
| Lifecycle / Promote | Change `status:` field (e.g. experimental → production) | All files above (read + write) | `contentops/lifecycle.py` | `contentops/cli/commands/lifecycle.py` | `production-promotion-check.yml` posts a summary comment. |
| Explain | Render a human-readable summary of one rule | All files above (read) | `contentops/explain.py` | `contentops/core/dependencies.py` | Reads `detections/dependencies.yml` for prerequisite data if present. |
| Portfolio | Export per-rule metadata to CSV / JSON | All files above (read) | `contentops/portfolio/` | `contentops/cli/commands/portfolio.py` | `portfolio.yml` workflow. |
| Rollback | Re-deploy a prior committed version | All files above (read) | `contentops/rollback.py` | `contentops/cli/commands/rollback.py` | Reads git history. |
<!-- ``Rewrite`` row removed -- ``contentops/rewrite.py`` +
``contentops/cli/commands/rewrite.py`` were deleted in PR #146. -->
| Doctor | Health-check: parse every YAML to verify no errors | All files above (read) | `contentops/devex/doctor.py` | `contentops/core/discovery.py`, `contentops/core/envelope.py` | `contentops doctor` command. |

---

### 1.2 Defender Custom Detections

**Directory:** `detections/defender_custom_detection/` · **46 files**

| Feature | Function / Purpose | YAML Pattern | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|---|
| Defender Custom Detection rules | Define KQL hunting-style detections deployed to Defender XDR via Graph Security Beta `POST/PATCH /detectionRules` | `asset: defender_custom_detection` or legacy `platform: defender` | `contentops/handlers/defender_custom_detection.py` | `contentops/defender/deploy.py`, `contentops/defender/collect.py`, `contentops/defender/client.py`, `contentops/core/envelope.py` | Upsert is by `displayName`; duplicate display names fail fast. |
| Plan / Apply / Collect | Same as Sentinel analytic flow | All files above | `contentops/cli/commands/apply.py`, `contentops/defender/collect.py` | `contentops/cli/handler_factories.py`, `contentops/utils/yaml_io.py` | `collect` writes; `apply` reads + deploys. |
| Lint | KQL syntax checks on `queryCondition.queryText:` | All files above | `contentops/lint/runner.py`, `contentops/lint/kql.py` | `contentops/lint/payload.py` | Defender rules do not have the same cost-lint fields as Sentinel. |
| Drift / Coverage | Same as Sentinel analytic flow | All files above | `contentops/core/drift.py`, `contentops/coverage/report.py` | — | Same pipeline, different handler. (Compliance row dropped -- module deleted in PR #146/#147.) |

---

### 1.3 Sentinel Watchlists

**Directory:** `detections/sentinel_watchlist/` · **5 files**

| File | Function / Purpose | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|
| `autoclose.yml` | Watchlist for auto-closing low-fidelity alerts | `contentops/handlers/sentinel_watchlist.py` | `contentops/handlers/sentinel_watchlist_models.py`, `contentops/providers/sentinel_arm.py` | Deployed via ARM `PUT watchlists/{alias}`. Items synced separately (out of scope today). |
| `entraprivilegedgroups.yml` | Reference table for Entra ID privileged group members | Same as above | Same as above | |
| `honeytokens.yml` | Honeytoken account list (referenced in alert rules) | Same as above | Same as above | |
| `sources-by-sourcetype.yml` | Data-source classification lookup table | Same as above | Same as above | |
| `usernames.yml` | User allowlist / lookup table | Same as above | Same as above | Watchlist item-level sync is deferred (W4.5-B). |

**Shared Python flow for all watchlists:**

| Feature | Direct Python File(s) | Related Python File(s) |
|---|---|---|
| Validate / Plan / Apply | `contentops/handlers/sentinel_watchlist.py`, `contentops/handlers/sentinel_watchlist_models.py` | `contentops/core/discovery.py`, `contentops/core/envelope.py`, `contentops/providers/sentinel_arm.py` |
| Collect | `contentops/cli/commands/collect.py`, `contentops/cli/commands/collect_support.py` | `contentops/handlers/sentinel_watchlist.py`, `contentops/providers/sentinel_arm.py`, `contentops/utils/yaml_io.py` |
| Drift | `contentops/core/drift.py` | `contentops/drift_suppressions.py` |

---

### 1.4 Removed asset kinds (asset-taxonomy reduction)

Earlier revisions of this document described `sentinel_settings`,
`sentinel_onboarding`, and `sentinel_metadata` sections — each with its own
`detections/<kind>/` sub-directory and dedicated handler file. Those asset
kinds (and several others — workbooks, automation/playbooks, bookmarks,
hunts, content packages, TI indicators, source control, incidents) were
**removed in the asset-taxonomy reduction** that narrowed the supported
surface to the six kinds defined in `contentops/core/asset.py`:

- `sentinel_analytic`
- `defender_custom_detection`
- `sentinel_hunting`
- `sentinel_watchlist`
- `sentinel_parser`
- `sentinel_data_connector`

The removed handlers, their `detections/<kind>/` directories, and the example
YAML files are recoverable from git history if a kind needs to be reinstated;
they are out of scope for the current focused product. See
[`docs/reference/generated-catalog.md`](generated-catalog.md) for the
code-generated, drift-gated list of what is actually supported.

---

### 1.5 Templates (Reference, not deployed)

**Directory:** `detections/templates/` · **2 files** — **SKIPPED by `discover_assets()`**

| File | Function / Purpose | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|
| `sentinel-template.yml` | Canonical YAML reference for Sentinel Scheduled/NRT rules | `contentops/devex/scaffold.py` (copied by `contentops new`) | `contentops/core/discovery.py` (`is_skipped_path` returns `True`) | Do **not** rename or move — scaffold reads from `contentops/templates/`. |
| `defender-template.yml` | Canonical YAML reference for Defender custom detections | Same as above | Same as above | Skipped by CI lint and deploy. |

---

### 1.6 Samples (Reference, not deployed)

**Directory:** `detections/samples/` · **2 files** — **SKIPPED by `discover_assets()`**

| File | Function / Purpose | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|
| `sentinel.yml` | Working example of a populated Sentinel rule envelope | `Not directly referenced` | `contentops/core/discovery.py` (`is_skipped_path` returns `True`) | For documentation / contributor guidance only. |
| `defender.yml` | Working example of a populated Defender rule envelope | `Not directly referenced` | Same as above | For documentation / contributor guidance only. |

---

## 2. Configuration Files (`config/`)

| File | Feature | Function / Purpose | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|---|
| `config/tenant.yml` | Tenant configuration | Declares Entra ID tenant ID, Sentinel workspaces (role, subscriptionId, resourceGroup, workspaceName, location), and Defender toggle. Loaded at every CLI command. | `contentops/config.py` (`load_tenant_config`) | `contentops/cli/commands/_shared.py`, `contentops/cli/commands/apply.py`, `contentops/cli/commands/collect.py`, `contentops/cli/handler_factories.py` | Multi-env: `config/tenant.<env>.yml` selected via `PIPELINE_ENV` env var. `.github/actions/pipeline-setup/action.yml` reads it to extract `subscriptionId` for `azure/login`. |
| `config/kql_lint_allowlist.yml` | KQL strict-lint allowlist | Suppresses Kusto.Language wrapper false positives (KS142 column-not-found on join-suffix / dynamic-extend / FileProfile output; KS211 on FileProfile invoke). Restricted to those two rule IDs. Every entry requires a `reason` field. | `contentops/lint/strict_allowlist.py` (`load_allowlist`, `should_suppress`, `ALLOWED_RULES`) | `contentops/lint/strict.py` (`run_strict`) | Missing file → no suppression. Example at `config/kql_lint_allowlist.yml.example`. |

---

<!--
Section 3 (Compliance Manifests) removed. The
``compliance/mappings/nist_csf.yml`` and ``compliance/mappings/iso27001.yml``
files, the ``contentops/compliance/`` module, the ``contentops compliance``
CLI command, and both ``compliance.yml`` / ``compliance-validate.yml``
workflows were all deleted in the v1-legacy hard cut (PR #146/#147).
The framework-compliance loop is no longer generated by the pipeline;
section numbering above is preserved so cross-links still resolve.
-->

## 4. GitHub Actions Workflows (`.github/workflows/`)

These YAML files are consumed directly by the GitHub Actions runner, not by Python. The Python CLI command(s) they invoke are listed under "Python CLI invoked".

| Workflow File | Feature | Trigger | Python CLI Invoked | Notes |
|---|---|---|---|---|
| `ci.yml` | CI gate (tests + security) | PR + push to `main` | `pytest -n auto -q`, `pip-audit` | Also runs `actionlint` (workflow YAML), `contentops doctor`, `contentops plan --dry-run`, and 16 `--help` smoke checks for Phase 2-6 commands. |
| `validate.yml` | Detection rule validation + KQL lint | PR touching `detections/`, `contentops/`, `config/` (PR `validate` job); push to `main` on `detections/**` + nightly cron + dispatch (`lint-regression` job) | `contentops plan`, `contentops lint`, `contentops lint --strict` | Read-only; no Azure auth. Two jobs: the load-bearing PR-path `validate` gate, plus a `lint-regression` job whose cron + push-main triggers catch regressions the PR gate doesn't (force-push, admin merge bypass, lint-rule tightening). The former standalone `lint.yml` was merged in here. |
| `deploy.yml` | Production deploy | Push to `main` (paths: `detections/**`) + `workflow_dispatch` | `contentops apply --role prod` | Uses `pipeline-setup` composite action + OIDC. |
| `collect.yml` | Weekly live snapshot | `schedule` (Mon 06:00 UTC) + `workflow_dispatch` | `contentops collect --full` | Only workflow allowed to commit `detections/`. |
| `drift.yml` | Drift detection | `schedule` (daily) + PR touching `detections/` | `contentops drift --write` (scheduled) / `contentops drift` (PR mode) | Opens a PR on divergence; posts PR comment in PR mode. |
| `coverage.yml` | MITRE ATT&CK coverage | PR touching `detections/` or `contentops/` + `workflow_dispatch` | `contentops coverage` | Posts sticky PR comment. |
<!-- ``compliance.yml`` and ``compliance-validate.yml`` rows removed --
the framework-compliance loop (the ``contentops compliance`` command,
``compliance/mappings/``, both workflows) was deleted in the
v1-legacy hard cut (PR #146/#147). -->
| `portfolio.yml` | Portfolio report | `schedule` (daily 07:00 UTC) + `workflow_dispatch` | `contentops portfolio` | Uploads CSV + JSON artefacts. |
| `integration.yml` | Live integration tests | `workflow_dispatch` + `run-integration` label | `pytest tests/integration/` | Hits real tenant. Requires `RUN_LIVE_TESTS=1` guard. |
| `integration-deploy.yml` | Deploy to integration workspace | PR touching `detections/` + `workflow_dispatch` | `contentops apply --role integration` | Catches broken KQL before merging to `main`. |
| `promote-to-integration.yml` | Prod → integration promotion | `workflow_dispatch` | `contentops collect --role prod`, `contentops apply --role integration` | Full snapshot mirror prod → integration. Collected envelopes are tenant-agnostic, so no tenant-id rewrite step is needed (the v1 `contentops rewrite` step was removed in PR #146 along with the rest of the v1 surface). |
| `emergency-disable.yml` | Break-glass rule disable | `workflow_dispatch` | `contentops disable --id <RULE_ID>` | Opens a PR only; does **not** auto-merge or auto-apply. |
| `lock-unlock.yml` | Rule lock / unlock | `workflow_dispatch` | `contentops lock` / `contentops unlock` | Commits YAML change on a branch, opens PR. |
| `retry-failed.yml` | Retry failed apply records | `workflow_dispatch` | `contentops retry-failed` | Reads audit JSONL to find failed (asset, id) pairs. |
| `prune.yml` | Delete remote orphans | `workflow_dispatch` | `contentops prune` | Dry-run default; requires explicit `--yes` for prod deletion. |
| `production-promotion-check.yml` | Status promotion detection | PR touching `detections/` | `python scripts/detect_production_promotions.py` (read-only) | Posts sticky comment listing rules promoted to `production`. |
| `audit-verify.yml` | Audit chain integrity | `schedule` (Mon 04:00 UTC) + `workflow_dispatch` + PR on `audit/` | `contentops audit verify` | Fails on hash-chain corruption in `audit/*.jsonl`. |
| `release.yml` | GitHub Release creation | Push of `v*` tag | `Not directly referenced` (shell script changelog render) | Builds source tarball + changelog from PR titles. |

---

## 5. Composite Actions (`.github/actions/`)

| File | Feature | Function / Purpose | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|---|
| `.github/actions/pipeline-setup/action.yml` | Shared setup | Checkout + Python install + `pip install -r requirements.txt` + resolve `subscriptionId` from `config/tenant.yml` + `azure/login` OIDC | `contentops/config.py` (inline `python -c` snippet reads `config/tenant.yml`) | `Not directly referenced` (composite action, not Python) | Used by `drift.yml`, `deploy.yml`, `collect.yml`, `prune.yml`, `retry-failed.yml`, `integration.yml`. Not used by `integration-deploy.yml` or `promote-to-integration.yml`. |

---

## 6. Test Fixtures (`tests/fixtures/`)

| File | Feature | Function / Purpose | Direct Python File(s) | Related Python File(s) | Notes |
|---|---|---|---|---|---|
| `tests/fixtures/sentinel_scheduled.yml` | Unit test data | Minimal Sentinel Scheduled rule envelope for YAML I/O tests | `tests/test_yaml_io.py` | `contentops/utils/yaml_io.py` | v1 envelope shape (`platform: sentinel`). |
| `tests/fixtures/sentinel_nrt.yml` | Unit test data | Minimal Sentinel NRT rule envelope for YAML I/O tests | `tests/test_yaml_io.py` | `contentops/models.py` | v1 envelope shape. |
| `tests/fixtures/defender_rule.yml` | Unit test data | Minimal Defender custom detection envelope for YAML I/O tests | `tests/test_yaml_io.py` | `contentops/utils/yaml_io.py`, `contentops/models.py` | v1 envelope shape (`platform: defender`). |

---

## 7. Optional / Absent-by-Default YAML Files

All **six** supported asset kinds now have committed YAML under
`detections/` (see the counts in Section 1 and
`contentops/core/asset.py`), so there are no longer any "implemented but
empty" asset directories to track. What remains here is the set of
**optional flat files** that the pipeline tolerates being absent.

| YAML Dir / File | Asset Type | Handler / Reader Python File | Status / Notes |
|---|---|---|---|
| `detections/drift_suppressions.yml` | n/a (flat file) | `contentops/drift_suppressions.py` | Suppress known benign drift entries. File is **optional** (empty list if absent). Create it under `detections/drift_suppressions.yml` when needed. |
| `detections/dependencies.yml` | n/a (flat file) | `contentops/core/dependencies.py`, `contentops/explain.py` | Declare prerequisite tables, watchlists, parsers, or other detections per rule ID. File is **optional** (tolerant of absence). Create it under `detections/dependencies.yml` when needed. |

> **Removed in the asset-taxonomy reduction (recoverable from git history).**
> Earlier revisions of this section listed handlers such as
> `sentinel_automation`, `sentinel_playbook`, `sentinel_bookmark`,
> `sentinel_content_package`, `sentinel_workbook`, `sentinel_hunt` (distinct
> from `sentinel_hunting`), `sentinel_summary_rule`, `sentinel_settings`,
> `sentinel_onboarding`, `sentinel_metadata`, `sentinel_ti_indicator`, and
> `defender_ti_indicator` as "Handler implemented". **None of those handlers
> exist today** — they were deleted when the taxonomy was reduced to the six
> kinds in `contentops/core/asset.py`. There are no
> `contentops/handlers/sentinel_automation.py` (etc.) files. They can be
> rebuilt from git history if a kind needs to be reinstated.

---

## 8. Candidate Files With No Direct In-Repo References

This is the requested second list: files that were **not directly referenced by
another repository file** in a static scan. This does **not** automatically mean
the file is safe to delete. Several files below are used dynamically (for
example by `pytest`, GitHub, or `importlib.resources`) and therefore do not have
a literal path reference elsewhere.

Scan method used for this list:

- Search every non-`.git` repository file for each candidate's relative path and
  basename.
- For Python files, also search for the dotted module path.
- Treat generated references from this documentation section as non-evidence;
  otherwise documenting a candidate would make it appear referenced.

| File | Category | Current Assessment | Notes / Follow-up |
|---|---|---|---|
| `.github/pull_request_template.md` | GitHub metadata | Externally consumed | Used by GitHub when opening PRs; not expected to be referenced by repo files. |
| `docs/reference/yaml-python-map.md` | Documentation | Standalone documentation | This document is useful but currently not linked from another doc or README. Consider linking it from `README.md` or `docs/reference/feature-catalog.md`. |
| `contentops/templates/defender_custom_detection.yml.tmpl` | Scaffold template | Dynamically consumed | Loaded by `contentops/devex/scaffold.py` via `importlib.resources` using `Asset.value`; no literal filename reference expected. |
| `contentops/templates/sentinel_analytic.yml.tmpl` | Scaffold template | Dynamically consumed | Same template-loading pattern as above. |
| `contentops/templates/sentinel_hunting.yml.tmpl` | Scaffold template | Dynamically consumed | Same template-loading pattern as above. |
| `contentops/templates/sentinel_parser.yml.tmpl` | Scaffold template | Dynamically consumed | Same template-loading pattern as above. |
| `contentops/templates/sentinel_watchlist.yml.tmpl` | Scaffold template | Dynamically consumed | Same template-loading pattern as above. |
| `tests/v2/test_arm_name_matching.py` | Test | Externally discovered by pytest | Not referenced by source files; still used by `pytest` discovery. |
| `tests/v2/test_audit_timestamp_monotonicity.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_cli_help_ascii_safe.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_cli_root_group.py` | Test | Externally discovered by pytest | Same as above. |
<!-- ``tests/v2/test_compliance_metadata_audit.py`` row removed --
the test was deleted alongside ``contentops/compliance/`` in PR #146/#147. -->
| `tests/v2/test_doctor_handler_matrix_classifier.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_doctor_output.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_env_status_filter.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_lint_payload002_slug_truncation.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_migrate_tenant_config.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_multi_workspace_config.py` | Test | Externally discovered by pytest | Same as above. |
| `tests/v2/test_token_auth.py` | Test | Externally discovered by pytest | Same as above. |

**Observation:** no file in this list should be treated as definitely unused
without a feature owner review. The strongest cleanup candidates are the
standalone documentation reports and collected Sentinel metadata YAMLs, but only
if the team confirms they are no longer needed.

---

## 9. Maintenance Guide

### Adding a new detection rule file

1. Choose the correct asset directory (`detections/sentinel_analytic/`,
   `detections/defender_custom_detection/`, etc.).
2. Copy the relevant template from `detections/templates/` or use
   `contentops new --asset <asset> --id <slug>`.
3. Set a **unique `id:` slug** (pattern `^[a-z0-9][a-z0-9-]*[a-z0-9]$`).
4. Update **this table** if you are introducing a new directory or YAML category.

### Adding a new asset type

1. Write a Pydantic payload model + handler (see `contentops/handlers/sentinel_analytic.py` as a reference).
2. Register the handler factory in `contentops/cli/handler_factories.py`.
3. Create the `detections/<asset_type>/` directory and add at least one YAML file.
4. Add the asset value to `contentops/core/asset.py` (the `Asset` enum is
   the single source of truth — the supported taxonomy is currently six
   kinds).
5. Add a row to **Section 1** (Detection Rule Files) of this table.
6. Re-run the direct-reference scan and update **Section 8** if new standalone
   files are introduced.

### Adding a new GitHub Actions workflow

1. Create the workflow YAML under `.github/workflows/`.
2. Add a row to **Section 4** (GitHub Actions Workflows) of this table.
3. If the workflow uses Azure auth, use the `.github/actions/pipeline-setup/action.yml`
   composite action (and update the "Used by" note in **Section 5**).

### Adding a new config file

- New `config/` YAML → add a row to **Section 2** and update `contentops/config.py`.
<!-- The "new compliance/mappings/ YAML" bullet was removed --
the framework-compliance loop was deleted in PR #146/#147. -->


### Keeping detection IDs in sync

The `id:` slug in every detection YAML is the cross-cutting key used by:
- Drift suppressions (`id:` or `displayName:` field)
- Dependencies graph (`assets.<id>:` keys)
- Audit JSONL records
- Portfolio / coverage reports

When renaming a rule, search for the old slug in all of the above locations
before committing.
