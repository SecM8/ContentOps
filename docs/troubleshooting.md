# Troubleshooting

> **Audience:** anyone hitting an error and looking for the fix.
> Junior or senior; first-week or veteran. Each entry tells you
> **(a)** what the error looks like, **(b)** why it happens,
> **(c)** the exact fix.

Index:

- [Authentication errors](#authentication-errors)
- [Configuration errors](#configuration-errors)
- [Lint + validate errors](#lint--validate-errors)
- [Apply errors](#apply-errors)
- [Drift + collect errors](#drift--collect-errors)
- [CI gate failures](#ci-gate-failures)
- [Fork PR limitations](#fork-pr-limitations)
- [Workspace + tenant data errors](#workspace--tenant-data-errors)

For *known issues with no available fix yet*, see
[`docs/reference/gap-assessment.md`](reference/gap-assessment.md).
For full audit-chain repair, see
[`docs/operations/audit-recovery.md`](operations/audit-recovery.md).

---

## Authentication errors

### `AADSTS7000215: Invalid client secret`

**Looks like:**

```
EnvironmentCredential: Authentication failed: AADSTS7000215:
Invalid client secret provided. Ensure the secret being sent in
the request is the client secret value, not the client secret ID,
for a secret added to app '<guid>'.
```

**Why:** the most common Entra ID papercut. In the Azure Portal
under *App Registrations → your app → Certificates & secrets*, the
table shows two columns that both look copyable:

| Column | What it is | Goes in `.env`? |
|---|---|---|
| **Value** | The actual secret (a random ~40-char string) | ✅ Yes — this is `AZURE_CLIENT_SECRET` |
| **Secret ID** | A GUID identifying the secret entry | ❌ No |

The Value is shown **once** at creation. If you clicked away, it's
gone — you have to create a new client secret.

**Fix:**

1. Azure Portal → App Registrations → your app → Certificates &
   secrets.
2. **New client secret** → name + expiry.
3. Immediately copy the **Value** column (not Secret ID).
4. Paste into `.env` as `AZURE_CLIENT_SECRET=<value>`.
5. Re-run `contentops doctor --matrix`.

**Verify it loaded:**

```powershell
$s = $env:AZURE_CLIENT_SECRET
"len=$($s.Length), prefix=$($s.Substring(0,3))..."
```

A real Value is ~40 characters. A Secret ID is exactly 36 (GUID
`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) — if your length is 36
that's the smoking gun.

> **Don't paste the actual secret in chat / issue trackers / PRs.**

### `AADSTS700213: No matching federated identity record found`

**Looks like (in CI logs):**

```
AADSTS700213: No matching federated identity record found for
presented assertion subject 'repo:ORG/REPO:environment:production'.
```

**Why:** the App Registration's federated credential subject
doesn't match the GitHub OIDC token's subject. GitHub mints the
token with subject `repo:<org>/<repo>:environment:<env-name>` (or
`...:ref:refs/heads/main`, or `...:pull_request`); your App Reg
must have a federated credential entry that exactly matches.

**Fix:**

1. Azure Portal → App Registrations → your app → Certificates &
   secrets → **Federated credentials**.
2. **Add credential** → "GitHub Actions deploying Azure resources".
3. Fill in: org, repo, "Environment" (or "Branch" / "Pull request"
   depending on which workflow triggered the failure).
4. Save. The subject is auto-derived from your inputs — it should
   match the error message verbatim.
5. Re-run the workflow.

Common pitfalls: typos in org/repo, wrong environment name (case
matters), missing entries for both `environment:production` AND
`ref:refs/heads/main` (workflows that fire on both triggers need
both subjects).

### `401` on `workspace_reachable` — token rejected

**Looks like (in `contentops doctor --matrix`):**

```
[FAIL] workspace_reachable — GET alertRules returned 401 —
token rejected as unauthenticated. Check `az account show` tenant
context matches tenant.yml.
```

**Why:** the token was acquired successfully but ARM/LA rejected
it. Either (a) the identity is from a *different* Entra tenant than
the workspace, or (b) `DefaultAzureCredential` returned a stale
cached identity (VSCode account, SharedTokenCache) instead of the
one you authenticated with.

**Fix:**

1. Check the tenant context:
   ```powershell
   az account show --query tenantId
   # compare against config/tenant.yml `tenantId:` field
   ```
2. If they match but the error persists, force the dev-credential
   chain:
   ```powershell
   $env:AZURE_TOKEN_CREDENTIALS = "dev"
   contentops doctor --matrix
   ```
3. If still failing, `az logout` and `az login --tenant <id>`
   explicitly.

### `403` on `workspace_reachable` — RBAC missing

**Looks like:**

```
[FAIL] workspace_reachable — GET alertRules returned 403 —
authenticated but lacks RBAC on this workspace.
```

**Why:** the identity is reaching the workspace correctly but
doesn't have permission to read alert rules.

**Fix:** grant `Microsoft Sentinel Contributor` **and `Log Analytics
Contributor`** on the workspace's resource group to whichever identity
is active (the Log Analytics role is required for hunting queries +
parsers, which deploy as `savedSearches` on the workspace):

- **Path A** (`az login` as user): grant to your user account.
- **Path B** (`.env` with App Reg secret): grant to the App Reg's
  service principal.

```powershell
# Path B example — grant both roles on the workspace RG
az role assignment create `
  --role "Microsoft Sentinel Contributor" `
  --assignee "<App-Reg-objectId-or-clientId>" `
  --scope "/subscriptions/<sub>/resourceGroups/<rg>"

az role assignment create `
  --role "Log Analytics Contributor" `
  --assignee "<App-Reg-objectId-or-clientId>" `
  --scope "/subscriptions/<sub>/resourceGroups/<rg>"
```

Wait 1–2 minutes for RBAC to propagate, then re-run doctor.

### `403` on Graph (`graph_reachable` / Defender handler)

**Looks like:**

```
GET /security/rules/detectionRules returned 403
```

**Why:** the App Registration lacks the `CustomDetection.Read.All`
(or `ReadWrite.All`) Graph application permission, or admin consent
hasn't been granted.

**Fix:**

1. Azure Portal → App Registrations → your app → API permissions.
2. **Add a permission** → Microsoft Graph → **Application
   permissions** → search "CustomDetection" → check
   `CustomDetection.ReadWrite.All`.
3. Click **Grant admin consent for <tenant>**.
4. Wait 1–2 minutes; re-run doctor.

For the navigator / auto-disabled-rules paths that also hit the
Log Analytics Query API, `Microsoft Sentinel Reader` (or
Contributor) on the workspace is enough — those use a different
token audience (`api.loganalytics.io`), not Graph.

---

## Configuration errors

### `Tenant has 2 Sentinel workspaces; specify --role or --workspace`

**Looks like:**

```
error: Tenant has 2 Sentinel workspaces; specify --role or
--workspace. Available: [law-sentinel (prod), SIT-Workspace
(integration)]
```

**Why:** your `config/tenant.yml` lists multiple workspaces; the
command needs to know which one to target.

**Fix:** pass `--role` or `--workspace`:

```powershell
contentops apply --role prod
contentops apply --workspace SIT-Workspace
```

For commands that should iterate every workspace of a role (e.g.
`deploy.yml`), the workflow already passes `--role prod` —
single-workspace local runs are the only place you usually hit
this.

### `detections_dir — not a directory: detections`

**Looks like:**

```
[FAIL] detections_dir — not a directory: detections
[FAIL] detections_parse — detections/ missing
```

**Why:** the doctor check is `cwd`-relative. You're running from
somewhere other than the repo root (commonly the `config/`
subdirectory).

**Fix:**

```powershell
cd <repo-root>     # e.g. cd C:\git\SIEMContent
contentops doctor --matrix
```

Both FAILs become PASSes.

### `config/detections/` appeared after I ran collect

**Why:** you ran `contentops collect --path detections` from
`config/`. The `--path` argument is `cwd`-relative, so collect
created `config/detections/`. The real corpus is at the repo root,
not under `config/`.

**Fix:**

```powershell
cd <repo-root>
Remove-Item -Recurse -Force .\config\detections\
contentops collect --role prod              # uses default --path detections
```

> Run all CLI commands from the repo root. The only files inside
> `config/` should be `tenant.yml`, `lifecycle.yml`,
> `kql_lint_allowlist.yml`, etc. — no `detections/`.

### `gitignored config/tenant.yml` doesn't exist after fresh clone

**Why:** `config/tenant.yml` is gitignored on purpose; it carries
your tenant identifiers.

**Fix:** copy the example and edit:

```powershell
Copy-Item config\tenant.yml.example config\tenant.yml
# Edit: subscriptionId, resourceGroup, workspaceName, tenantId
```

See
[`docs/operations/tenant-config-modes.md`](operations/tenant-config-modes.md)
for the supported modes (single-workspace, multi-workspace,
Defender-only).

---

## Lint + validate errors

### 600+ META002–005 errors on a fresh tenant.yml

**Looks like:**

```
Lint summary: 152 files scanned, 152 with findings, 1176 finding(s) total.
META rules in strict mode (tenant.policy.scaffoldStrict=true).
608 finding(s) at-or-above severity 'error'.
```

**Why:** you set `policy.scaffoldStrict: true` (explicitly or
through an older example file). META002–005 — the authoring fields
`description` / `attackDescription` / `references` /
`falsePositives` — are CI-blocking in strict mode. The G24
authoring backlog (51 production rules without these fields)
hasn't been written yet.

**Fix (default, lenient):** since PR #241 the default is
**lenient**. Set the policy block to false (or remove it entirely):

```yaml
# config/tenant.yml
policy:
  scaffoldStrict: false   # or omit the policy block; both behave the same
```

Re-run: META002–005 become warnings, exit 0.

**Fix (you actually want strict):** keep `scaffoldStrict: true` and
fill in the missing fields. Each envelope needs four paragraphs of
content (description, attackDescription, references[], 
falsePositives[]); see
[`docs/reference/envelope-schema.md`](reference/envelope-schema.md)
for the schema.

### `version-bump check failed`

**Looks like (in CI):**

```
detections/sentinel_analytic/my-rule.yml:
  before: 0.1.0
  after:  0.1.0
  diff:   present
error: file changed without a version bump
```

**Why:** the `scripts/check_version_bump.py` CI gate refuses any
PR that changes an envelope's content without bumping the
`version:` field — silent overwrites would defeat the audit trail.

**Fix:** bump the version in your envelope:

```yaml
# detections/sentinel_analytic/my-rule.yml
id: my-rule
version: 0.1.1   # was 0.1.0
```

Whitespace-only diffs still trip the check — that's intentional
(if the diff doesn't matter, revert the cosmetic edit; otherwise
bump).

### `catalog drift: docs/reference/generated-catalog.md disagrees with the regenerated output`

**Looks like (in CI):**

```
catalog drift: committed docs/reference/generated-catalog.md
disagrees with the regenerated output.
```

**Why:** you added a new CLI command, lint rule, workflow, or
handler without re-running `contentops catalog regenerate`. The
generated catalog is drift-gated to prevent stale references in
docs.

**Fix:**

```powershell
contentops catalog regenerate
git add docs/reference/generated-catalog.md
git commit --amend --no-edit --signoff   # or new commit
git push --force-with-lease
```

### `detection-docs drift: 156 file(s) under docs/detections/ disagree`

**Looks like:**

```
docs/detections/sentinel_analytic/my-rule.md is out of sync with
the envelope.
```

**Why:** you changed an envelope without re-running
`contentops detection-docs regenerate`. Same drift-gate pattern as
the catalog above.

**Fix:**

```powershell
contentops detection-docs regenerate
git add docs/detections/
git commit -m "chore(docs): regenerate detection docs" --signoff
git push
```

### `New CLI commands found without an e2e capability entry`

**Looks like (in CI pytest output):**

```
FAILED tests/e2e/test_capability_drift_guard.py::test_registry_matches_click_tree
  New CLI commands found without an e2e capability entry:
    my-new-command
```

**Why:** you added a Click command but didn't register it in the
e2e capability matrix at `tests/e2e/_capabilities.py`. The matrix
exists to keep new commands from silently bypassing the live
integration test suite.

**Fix:** add the command to `INTENTIONALLY_UNCOVERED` (with a
justification referencing where it's tested instead) OR add a
`Capability(...)` entry to `CAPABILITIES` and append the path to
`COVERED_LEAVES`. See existing entries in the file for the shape.

---

## Apply errors

### `apply` returned `400: Failed to run the analytics rule query. One of the tables does not exist.`

**Looks like:**

```
ERROR contentops.handlers.sentinel_analytic: Failed to deploy
sentinel rule aa-azure-vm-...: 400 {"error":{"code":"BadRequest",
"message":"Failed to run the analytics rule query. One of the
tables does not exist."}}
```

**Why:** the rule's KQL references a table that's available in one
workspace (e.g. prod) but not in another (e.g. integration). Common
when a data connector is enabled in prod but not in integration.

**Fix (three options):**

1. **Enable the connector** on the workspace that's missing it
   (e.g. AzureActivity, SecurityEvent). Permanent fix.
2. **Mark the rule `status: experimental`** locally so integration
   skips it (env-status gate). Prod keeps deploying it.
3. **Leave it.** The rule's existing tenant-side state isn't
   touched by the failed update — drift will report it as
   `in-sync` against the OLD payload. Acceptable for known-bad
   single failures; track in your runbook.

### `verified=False` / `MISMATCH` on a Defender rule

**Looks like:**

```
my-detection  defender_custom_detection  update  success  MISMATCH
```

**Why:** apply succeeded (200 OK on PUT) but the round-trip hash
check failed. The local envelope and the immediate post-PUT GET
produce different content hashes — usually because Defender's
server adds or normalises a field (timestamps, computed IDs).

**Fix — diagnose first:**

```powershell
contentops defender-roundtrip-diff <envelope_id>
```

This shows you exactly which fields differ. If the difference is a
server-managed field that should be stripped, file an issue
against `contentops/handlers/defender_custom_detection.py`'s
`_SERVER_FIELDS` set. The `--raw` flag skips the strip step so you
can see new server-managed fields the codebase doesn't know about
yet.

### `1 error(s)` in apply summary — what's the actual error?

**Looks like:**

```
[summary table — every row PASS except one]
1 error(s).
```

**Why:** the apply summary at the end is per-row; the actual error
text was printed inline during the apply loop. Scroll up in the
output to find the `ERROR contentops.handlers...` line for the
failed row.

**Fix:** if you missed it, the audit log has it:

```powershell
contentops audit query failures --since 1h
```

---

## Drift + collect errors

### `prune --dry-run` finds 0 orphans but I expected some

**Why:** `prune` only flags rules in the **tenant** that don't
appear in your **local YAML**. If your local detections/ already
matches the tenant (e.g. you just ran collect), there's nothing to
prune.

If you wanted to clear the tenant of rules NOT in detections/,
that's what prune does. If you wanted the opposite — clear local
YAMLs that aren't in the tenant — that's `contentops clean` or
manual `rm`.

### `collect --role X` says "all in-sync" but the portal shows newer rules

**Why:** `collect` returns "in-sync" when the local envelope's
hash matches the server's. If a portal user just edited a rule and
your local copy was already correct (matching the post-edit
state), no change shows.

**Fix to force a refresh:**

```powershell
contentops clean --asset sentinel_analytic --yes
contentops collect --role prod --asset sentinel_analytic --full
```

`--clear` does both in one step:

```powershell
contentops collect --role prod --clear
```

---

## CI gate failures

### `codespell` failed on a domain term

**Looks like:**

```
./detections/sentinel_analytic/my-rule.yml:42: tehcnique ==> technique
```

**Why:** typo in author-controlled prose. (If it's a real domain
term, see below.)

**Fix (real typo):** fix the spelling in the YAML and recommit.

**Fix (false positive — legitimate domain term):** add it to
`ignore-words-list` in `.codespellrc`:

```ini
ignore-words-list = iif,te,ans,fpr,...,your-new-term-here
```

### `references-check` reports broken URLs

**Looks like:**

```
broken: 2 of 47 URL(s)
  https://blog.example.com/old-post
    HTTP 404
    in detections/sentinel_analytic/my-rule.yml
```

**Why:** a URL in `metadata.references[]` or `metadata.runbookUrl`
returned 4xx/5xx. The PR-time check (`validate.yml`) flags only
URLs *newly added* in the diff; the weekly full scan
(`references-check.yml`) catches URL rot over time.

**Fix:** update or remove the broken URL. If it's a transient CDN
issue (e.g. login.microsoftonline.com sometimes redirects oddly),
add the substring to the workflow's `--allow` list.

---

## Fork PR limitations

If you opened a PR from a fork (not a branch in `KustoKing/SIEMContent`
itself), some CI checks will skip or render degraded output. This is
**intentional** — GitHub doesn't mint OIDC tokens for fork PRs, so
we can't trust them with tenant credentials.

| Check | Behaviour on fork PR | Why |
|---|---|---|
| `drift-pr` (informational drift comment) | Skipped | OIDC unavailable; cannot query the tenant. |
| `tuning-impact-preview` | Posts comment with `-` for counts | OIDC unavailable; `--no-workspace-query` mode used. |
| Pre-PR schema refresh in `validate.yml` | Falls through to committed baseline | `continue-on-error: true`; lint still runs against the existing schema. |
| `plan --against-tenant` overlay | Not exercised in CI on fork PRs | Same reason. |

What still works on fork PRs:
- All YAML / Python / metadata lint
- Pytest, SAST (bandit + semgrep), DCO, SPDX
- Spelling check, references URL check (outbound HTTP only)
- Structural `validate.yml` plan (no API calls)

**If you need full signal:** push your branch into the base repo
(any maintainer can help with this), reopen the PR there.

---

## Workspace + tenant data errors

### `SentinelHealth` returns 0 rows even though rules are firing

**Why:** `SentinelHealth` is an *opt-in* diagnostic data collection
on the workspace (opt-in since approximately 2022). If it's not
turned on, the table simply has no rows, even though your alert
rules are running normally.

**Verify the diagnostic:**

```powershell
contentops doctor --matrix
# Look for [WARN] sentinel_health — SentinelHealth returned 0 rows...
```

**Fix:** enable the diagnostic per
[https://learn.microsoft.com/en-us/azure/sentinel/health-audit](https://learn.microsoft.com/en-us/azure/sentinel/health-audit).
Azure Portal → Sentinel → Settings → Diagnostic settings → enable
"SentinelHealth". Wait 15–30 minutes for the first rows to appear.

Once enabled, `contentops auto-disabled-rules` will surface real
data instead of empty results.

### `Defender custom detection` skipped on integration apply

**Looks like:**

```
env-status filter (gate=integration): 46 asset(s) skipped (allowed:
['deprecated', 'production', 'test'])
  - detection-of-attempts-to-disable-microsoft-defender (status=production [defender:prod-only])
  ...
```

**Why:** Defender XDR is **tenant-wide** — there's no
"integration" instance of it like there is for Sentinel. The apply
gate marks every `defender_*` envelope as `defender:prod-only` so
they only deploy on `--role prod` runs. By design, not a bug.

**Fix:** none needed. To deploy a Defender custom detection, use
`contentops apply --role prod` (or merge to main and let
`deploy.yml` run).

### Integration deploy succeeded but rules don't appear in the portal

**Why:** Sentinel rules can take 30–60 seconds to surface in the
portal after a successful PUT (caching layer). The audit record
will say `success` immediately; the portal UI lags.

**Fix:** wait, then refresh the portal. If they still don't appear
after 5 minutes:

```powershell
contentops drift --role integration
# Look for 'new' entries — that's what apply created.
# If drift shows 0 new + 0 changed but the portal is empty,
# you've hit a tenant-side caching issue. Try the Azure Sentinel
# REST API directly:
az rest --method GET --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-07-01-preview"
```

---

## Lint error quick-reference

Every lint rule ID `contentops lint` (and `--strict`) can emit, what it
flags, and the one-line fix drawn from the rule's own message. The
**canonical rule list with authoritative severities lives in
[`docs/reference/generated-catalog.md`](reference/generated-catalog.md)**
(the "## Lint rules" section) — that file is code-generated and
drift-gated, so trust it over this table if they ever disagree.

> **Strict-mode escalation:** META002–META005 are emitted at
> `warning` by default (lenient migration mode) but **escalate to
> `error`** when `policy.scaffoldStrict: true` in `config/tenant.yml`,
> so CI blocks. META001 also escalates a *stale* `lastValidatedAt`
> from warning to error under strict mode. META006/META007/META009
> stay `info` in both modes (best-effort content, never gates CI).

| Rule | Severity | What it flags | Fix |
|---|---|---|---|
| `KQL000` | warning | Strict-lint plumbing: the Kusto.Language wrapper failed to invoke / exited non-zero, or an allowlist entry was unparseable; also the channel for wrapper-emitted diagnostics. | Read the appended detail; fix the allowlist entry or rebuild the wrapper (`scripts/build_kql_strict.*`). |
| `KQL001` | error | Unbalanced bracket — an unexpected `)`/`]`/`}` or an opener that's never closed. | Balance the brackets in the KQL. |
| `KQL002` | error | Unterminated string at end of query. | Close the open quote. |
| `KQL003` | error | Query is empty (after stripping comments). | Add a non-empty KQL body. |
| `KQL004` | warning | `project *` — perf risk. | Project explicit columns instead of `*`. |
| `KQL005` | warning | `\| take` without an explicit numeric limit. | Give `take` a numeric argument (or remove it). |
| `KQL006` | warning | `evaluate bag_unpack` can be expensive. | Project explicit columns rather than unpacking the bag. |
| `KQL007` | error | `union *` fans out across all tables. | Enumerate the source tables explicitly. |
| `KQL008` | warning | `externaldata()` references external infrastructure. | Ensure the source URL is approved and auditable. |
| `KQL010` | error | `cluster()` / `workspace()` crosses workspace or cluster scope. | Target only the workspace the detection deploys to; drop the cross-scope call. |
| `KQL101` | error | `\| take` / `\| limit` in a production detection — caps results and masks true rule volume. | Use `top N by <field>` for a bounded set, or remove the operator. |
| `KQLOVERRIDE001` | error | Snippet placeholder is malformed (spaces, missing `.yml`, illegal chars). | Write it as exactly `{{folder/file.yml}}`. |
| `KQLOVERRIDE002` | error | Snippet placeholder path is unsafe (absolute or contains `..`). | Use a relative path under `overrides/`. |
| `KQLOVERRIDE003` | error | Snippet placeholder shares its line with other KQL tokens. | Put `{{...}}` alone on its own line (trailing `//` comment is allowed). |
| `KQLOVERRIDE004` | error | An `overrides/**/*.yml` file is unreadable / not a mapping / missing or non-string `content:`. | Make the file valid YAML with a string `content:` key. |
| `META001` | warning | `metadata.lastValidatedAt` is missing, unparseable, or older than the threshold (180d; 90d for `status: production`). | Set/refresh `lastValidatedAt` to an ISO 8601 date after re-validating the rule. |
| `META002` | warning | `metadata.description` is not set. | Add a one-paragraph summary of what the rule detects. |
| `META003` | warning | `metadata.attackDescription` is not set. | Describe what the attacker actually does (threat context). |
| `META004` | warning | `metadata.references` is empty. | Cite at least one source (CVE, ATT&CK page, advisory, blog). |
| `META005` | warning | `metadata.falsePositives` is empty. | Enumerate at least one known false-positive scenario. |
| `META006` | info | `metadata.blindSpots` is empty. | Optionally document known evasion vectors / detection gaps. |
| `META007` | info | `metadata.responseActions` is empty. | Optionally add 3–7 concise inline triage steps (`runbookUrl` can carry the full playbook). |
| `META008` | error | A `description`/`attackDescription` is still the `TODO (METAxxx)` scaffold placeholder while `status` is past `experimental`. | Fill in the real content before promoting, or move `status` back to `experimental`. |
| `META009` | info | `severity: high` paired with `fpExpectedPerWeek: high` (a likely noise generator). | Tune the query (preferred) or lower severity to `medium`. |
| `PAYLOAD001` | error | `templateVersion` set without `alertRuleTemplateName` — ARM rejects the PUT with HTTP 400. | Add the `alertRuleTemplateName` from the source template, or remove the `templateVersion` line. |
| `PAYLOAD002` | warning | `displayName` produces a slug over the 80-char canonical-id cap (silent truncation). | Shorten the `displayName`, or keep the explicit `id:` already in the envelope. |
| `PAYLOAD003` | warning | MITRE mapping is empty (`tactics`/`techniques` for Sentinel; `mitreTechniques` for Defender). | Map the rule to at least one ATT&CK tactic/technique. |
| `PAYLOAD004` | warning | Defender `alertTemplate.recommendedActions` is null/empty. | Add a short SOC triage hint (or a non-empty string explaining no action is needed). |

---

## Doctor output decoder

What each check from `contentops doctor` verifies and what to do when
it FAILs. The doctor never modifies state; exit code is 1 only when at
least one check is **FAIL** (WARN never fails the run). Add `--fix` to
auto-remediate the three safe checks (`dotenv`, `detections_dir`,
`python_deps`).

The first eight checks always run. The four **auth checks** only run
with `--auth` or `--matrix` (without them, `token_acquisition` is
emitted once as a skipped WARN). The **per-handler matrix** rows only
run with `--matrix` (which implies `--auth`).

| Check | What it verifies | If it FAILs |
|---|---|---|
| `python_version` | Python >= 3.12. | Install / activate Python 3.12+. |
| `python_deps` | Required imports resolve (`httpx`, `pydantic`, `yaml`, `azure.identity`, `click`). | `pip install -e .[dev]` (or `doctor --fix`). |
| `dotenv` | A `.env` was loaded (or none is needed). | WARN only — invoke via `contentops` / `python -m contentops`, or copy `.env.example`. |
| `auth_env` | `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` plus a secret or signed-in `az` CLI. | WARN only — set the env vars or `az login` before running auth/matrix checks. |
| `tenant_yml` | `config/tenant.yml` loads and parses; lists workspaces. | Create `config/tenant.yml` from the example and fix parse errors. |
| `detections_dir` | `detections/` exists (cwd-relative). | Run from the repo root, or `doctor --fix` to scaffold the dirs. |
| `detections_parse` | Every discovered envelope under `detections/` parses. | Fix the YAML in the first reported failing file. |
| `git` | `git` is on PATH and `git --version` works. | WARN only — install git / put it on PATH. |
| `token_acquisition` | *(--auth/--matrix)* ARM **and** Graph tokens can be acquired. | WARN only — fix credentials so both scopes mint tokens. |
| `workspace_reachable` | *(--auth/--matrix)* `GET alertRules` against the target Sentinel workspace returns 200. | 401 → wrong tenant / stale cached identity (`$env:AZURE_TOKEN_CREDENTIALS='dev'`); 403 → grant `Microsoft Sentinel Contributor`. |
| `sentinel_health` | *(--auth/--matrix)* The `SentinelHealth` diagnostic table has rows in the last 24h. | WARN only — enable the SentinelHealth diagnostic so `auto-disabled-rules` works. |
| `graph_reachable` | *(--auth/--matrix)* Graph beta `/security/rules/detectionRules` returns 200. | 403 → grant `CustomDetection.ReadWrite.All`; other codes → check Graph reachability / construction. |
| `handler_matrix_workspace` | *(--matrix, multi-workspace only)* Notes which workspace the matrix tested. | Informational WARN — pass `--workspace <name>` / `--role <role>` to target another. |
| `handler:<asset>` | *(--matrix)* Each drift-capable handler's `list_remote()` returns a page (one row per handler, ×workspace for Sentinel kinds). | 403 → RBAC for that scope; 401 → token/identity (`AZURE_TOKEN_CREDENTIALS='dev'`); Workspace-Manager 400 → feature not provisioned (WARN); else inspect the handler error. |

---

## Still stuck?

- **Audit chain integrity**: see
  [`docs/operations/audit-recovery.md`](operations/audit-recovery.md)
- **Multi-workspace setup**: see
  [`docs/operations/multi-workspace.md`](operations/multi-workspace.md)
- **Authentication paths (A vs B)**: see
  [`docs/operations/authentication-setup.md`](operations/authentication-setup.md)
- **The when-things-break decision tree** (deep ops scenarios): see
  [`docs/OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md#when-something-breaks--decision-tree)

If your error isn't above, open an issue with: command run, full
output (redact secrets!), `git rev-parse HEAD`, and `contentops doctor --matrix` output.
