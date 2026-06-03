# Detection envelope schema

> Single canonical reference for every field on a v2 detection envelope.
> The Pydantic models in `contentops/core/envelope.py` and
> `contentops/core/metadata.py` are the source of truth; this doc explains
> what each field means, when it's required, and which lint rule guards
> it. Companion to the operator-facing
> [`OPERATOR_GUIDE.md`](../OPERATOR_GUIDE.md) and the more technical
> [`reference/architecture.md`](architecture.md).

## TL;DR — the envelope shape

```yaml
id: my-rule-id                  # kebab-case, len ≥ 2, [a-z0-9-]
version: 0.1.0                  # envelope schema version
asset: sentinel_analytic        # one of the six canonical kinds
status: experimental            # deploy gate — experimental / test / production / deprecated
lifecycleStage: engineering     # authoring gate — concept / research / engineering / delivery / optimization / feedback
metadata:                       # authoring + triage metadata (see section below)
  owner: ...
  ...
payload:                        # ARM / Graph API body — kind-specific
  ...
```

Two orthogonal stage axes:

* **`status`** — *runtime* deploy state. Drives `apply` / `prune` /
  `drift` behaviour. Gated by the deploy filter
  (`integration-deploy.yml` allows `production` / `test` /
  `deprecated`; `deploy.yml` excludes `experimental`).
* **`lifecycleStage`** — *authoring* workflow state. Pure metadata
  for SOC team-lead planning, sprint boards, and the portfolio
  dashboard. Never gates deploy.

A rule can be (and often is) at different positions on the two
axes. `lifecycleStage: engineering` + `status: experimental` is a
rule being drafted but already shadow-deployed for telemetry.
`lifecycleStage: optimization` + `status: production` is a mature
rule under active tuning.

---

## Top-level envelope fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `str` (kebab-case pattern) | yes | Canonical identifier. Mutating after first apply is a breaking change — `apply` addresses rules by this id (mapped to `metadata.arm_name` for collected envelopes). |
| `version` | `str` | yes | Envelope schema version. Defaults to `"0.1.0"` for hand-authored content; collect uses the source rule's `templateVersion` for template-bound rules (Fusion / MLBA / TI), falling back to `"1.0.0"`. |
| `asset` | `Asset` enum | yes | One of: `sentinel_analytic`, `sentinel_hunting`, `sentinel_watchlist`, `sentinel_parser`, `sentinel_data_connector`, `defender_custom_detection`. |
| `status` | `str` | yes | Deploy gate: `experimental` / `test` / `production` / `deprecated`. |
| `lifecycleStage` | `LifecycleStage \| None` | no | Authoring stage: `concept` / `research` / `engineering` / `delivery` / `optimization` / `feedback`. |
| `metadata` | `RuleMetadata \| None` | no at parse time, required by lint --strict | Authoring + triage metadata. See below. |
| `payload` | `dict` | yes | ARM / Graph API body for the asset kind. Validated per-kind by Pydantic models under `contentops/models.py`. |
| `arm_name` | `str \| None` | no | Mirrors `metadata.arm_name` in memory for collected envelopes; ignored on hand-authored content. |

---

## `metadata` block — authoring + triage fields

### Required (lint --strict enforces non-empty)

| Field | Type | Lint rule | Description |
|---|---|---|---|
| `owner` | `str` (email) | parse error if invalid | Single accountable owner email. Multiple owners → use a team alias. |
| `runbookUrl` | `str` (http(s)://) | parse error if invalid | Full triage / response playbook URL. |
| `severity` | `informational \| low \| medium \| high` | parse error if invalid | Operator-facing severity. ARM `severity` lives in payload. |
| `tactics` | `list[Tactic]` (≥ 1) | parse error | MITRE ATT&CK tactic IDs. |
| `techniques` | `list[str]` (T#### or T####.###) | parse error | MITRE ATT&CK technique IDs (validated by regex). The attacker-axis. |
| `defensiveTechniques` | `list[str]` (D3-XXX) | parse error if malformed | MITRE D3FEND defensive technique IDs (optional, default empty). Pairs with `techniques` — `techniques` says "what attacker behaviour does this detect?", `defensiveTechniques` says "what defensive technique does this implement?". Read by `contentops coverage --d3fend`. Bundled curated list at [`contentops/coverage/data/d3fend_techniques.json`](../../contentops/coverage/data/d3fend_techniques.json). |
| `expectedAlertsPerDay` | `int ≥ 0` | parse error | Operator's daily-volume expectation. Drives portfolio noise budget. |
| `fpHandling` | `str` (non-empty) | parse error | Free-text FP triage guidance. Complement to the structured `falsePositives` list. |
| `fpExpectedPerWeek` | `low \| medium \| high \| None` | META009 | Structured FP expectation. Cross-checks against `severity` — a high-severity rule that the author expects to fire many false positives per week is a tuning red flag (META009 surfaces the mismatch). |

### Optional today, lint-warned (backlog meter)

| Field | Type | Lint rule | Severity |
|---|---|---|---|
| `lastValidatedAt` | `str` (ISO 8601 date or timestamp) | META001 | warning when missing/stale (>180d), error when malformed |

### Optional today, Section T — Fortune 500 authoring metadata

These six fields are the FalconFriday-shaped detection metadata.
All Optional / default-empty so existing envelopes parse unchanged.
Lint rules surface gaps; the tenant policy controls whether the
gap is a warning or a CI-blocking error.

| Field | Type | Lint rule | Severity behaviour |
|---|---|---|---|
| `description` | `str \| None` | META002 | warning (lenient, the default since PR #241) / **error (strict)** |
| `attackDescription` | `str \| None` | META003 | warning (lenient) / **error (strict)** |
| `references` | `list[str]` (http(s)://) | META004 | warning (lenient) / **error (strict)** |
| `falsePositives` | `list[str]` | META005 | warning (lenient) / **error (strict)** |
| `blindSpots` | `list[str]` | META006 | info (always) |
| `responseActions` | `list[str]` | META007 | info (always) |

> **`policy.scaffoldStrict` default:** as of PR #241 the default is
> **False** (lenient). Operators with a fresh `config/tenant.yml` get
> warnings for META002–005, not CI-blocking errors. Set
> `policy.scaffoldStrict: true` once your authoring backlog drains to
> upgrade those four rules to errors.

### Reserved / system-managed

| Field | Type | Description |
|---|---|---|
| `cohort` | `str \| None` | Free-form grouping label for prune / retry-failed cohort selection. |
| `arm_name` | `str \| None` | Set by `contentops collect` — preserves the original ARM resource name when the envelope id is a slugified displayName. Hand-authored content can omit. |

---

## `tenant.policy.scaffoldStrict` — the META gate

```yaml
# config/tenant.yml
tenant:
  ...
  policy:
    scaffoldStrict: false   # explicit opt-in to lenient mode
```

| Tenant.yml state | META002-005 severity | CI gate |
|---|---|---|
| `tenant.yml` absent (fresh clone / unit tests / no Azure config) | warning | exit 0 unless `--fail-on-warn` |
| `tenant.yml` present, no `policy:` block | **error** | exit 1 on first META hit |
| `tenant.yml` present, `policy:` present, `scaffoldStrict` unset | **error** | exit 1 on first META hit |
| `tenant.yml` present, `scaffoldStrict: true` | **error** | exit 1 on first META hit |
| `tenant.yml` present, `scaffoldStrict: false` | warning | exit 0 unless `--fail-on-warn` |

**Strict-by-default** for configured tenants is the Fortune 500
contract. The only path to warning-only is explicit
`scaffoldStrict: false` — useful during a bulk content migration
when the team is knowingly running with un-enriched envelopes and
wants CI to pass while the backlog drains. META006-007 stay info
in both modes; "blind spots" and "response actions" are
best-effort content, not CI gates.

---

## Worked example — translating FalconFriday's `0xFF-0582` into an envelope

The FalconFriday detection
[`0xFF-0582-WinRM_Plugin_Lateral_Movement-Windows.md`](https://raw.githubusercontent.com/FalconForceTeam/FalconFriday/refs/heads/main/0xFF-0582-WinRM_Plugin_Lateral_Movement-Windows.md)
fits the new envelope schema:

```yaml
id: winrm-plugin-lateral-movement
version: 0.1.0
asset: sentinel_analytic
status: experimental
lifecycleStage: engineering
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/winrm-plugin-lateral-movement
  severity: high
  tactics: [LateralMovement]
  techniques: [T1021.006]
  expectedAlertsPerDay: 2
  fpHandling: |
    Triage with on-call. WinRM plugin loads from %WINDIR%\System32\WinRM
    are normally driver-related; non-system processes are the signal.

  description: |
    Detects non-system processes loading a WinRM plugin DLL. WinRM
    plugins are typically loaded by WinRM-related system processes;
    other process contexts are anomalous and frequently associated
    with lateral movement via remote PowerShell.

  attackDescription: |
    Attackers leverage WinRM for lateral movement by registering a
    custom plugin that executes attacker-controlled code on remote
    hosts. The plugin DLL is loaded by the target's WinRM service
    process. Other processes loading the same plugin DLL indicate
    side-loading or proxy execution that bypasses native WinRM telemetry.

  references:
    - https://attack.mitre.org/techniques/T1021/006/
    - https://www.falconforce.nl/falconfriday-detecting-winrm-plugin-lateral-movement/

  falsePositives:
    - "WinRM service hardening tools that re-register plugin DLLs from a custom installer process."
    - "EDR agents performing read-only inventory scans of WinRM modules."

  blindSpots:
    - "Misses inline reflection: an attacker loading the plugin via Process Doppelgänging is invisible to module-load telemetry."
    - "Plugin DLLs renamed to mimic system filenames bypass the path-based scope."

  responseActions:
    - "Isolate the source host immediately."
    - "Snapshot LSASS + process tree for forensic review."
    - "Audit recent WinRM listener registrations on the target."
    - "Rotate credentials of the user context the suspect process ran under."

payload:
  kind: Scheduled
  displayName: WinRM Plugin Lateral Movement
  query: |
    DeviceImageLoadEvents
    | where FolderPath endswith @"\WinRM\Plugins\"
    | where InitiatingProcessFileName !~ "wsmprovhost.exe"
    | where InitiatingProcessFileName !~ "svchost.exe"
    | summarize count() by DeviceName, InitiatingProcessFileName, FolderPath
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 0
  severity: High
  tactics: [LateralMovement]
  techniques: [T1021.006]
  enabled: true
```

Every Section T field carries the FalconFriday content; `status`
and `lifecycleStage` are project-specific and operator-set; the
`payload` block is the ARM API surface that `apply` PUTs.

---

## See also

* [`contentops/core/metadata.py`](../../contentops/core/metadata.py) — source-of-truth `RuleMetadata` Pydantic model.
* [`contentops/core/envelope.py`](../../contentops/core/envelope.py) — `EnvelopeV2` and the permissive parse path.
* [`contentops/core/lifecycle_stage.py`](../../contentops/core/lifecycle_stage.py) — `LifecycleStage` Literal.
* [`contentops/lint/metadata_rules.py`](../../contentops/lint/metadata_rules.py) — META001-007 implementations.
* [`docs/operations/tenant-config-modes.md`](../operations/tenant-config-modes.md) — the three ways to materialise `config/tenant.yml`, including the optional `policy:` block.
* [FalconForce / FalconFriday](https://github.com/FalconForceTeam/FalconFriday) — the detection-engineering markdown format the metadata schema is inspired by.
* [Research-driven detection engineering — detect.fyi](https://detect.fyi/a-research-driven-process-applied-to-threat-detection-engineering-inputs-1b7e6fe0412b) — origin of the six-stage lifecycle vocabulary.
