# Broken analytics: templateVersion without alertRuleTemplateName

**Date discovered:** 2026-05-06 during a live `pipeline apply`
against the production Sentinel workspace.

**Symptom:** ARM returned HTTP 400

```
Invalid data model. [: Invalid Properties for alert rule:
'templateVersion' can only be used if 'alertRuleTemplateName'
is not empty.
```

on 68 of the rule files in `detections/sentinel/` -- every rule
that carries `templateVersion` but no matching
`alertRuleTemplateName`.

## Why it slipped through

Three gates failed in the same way:

1. `pipeline lint` had no payload-level rule for the coupling.
2. `pipeline plan` did not surface payload-validation errors:
   the model accepted the partial coupling and the bad PUT
   only showed up as ARM 400 at apply time.
3. `pipeline apply --dry-run` does not call ARM, so the dry-run
   path passed locally even though a real PUT would 400.

The fix PR adds a lint rule (PAYLOAD001), plan-time validation
in `pipeline.handlers.sentinel_analytic.SentinelAnalyticHandler.validate`,
and an apply-time defence-in-depth scrub. None of those
auto-fix the YAML; the analyst team owns the content.

## How to reproduce the lint output

```
$ pipeline lint --path detections
# 68 PAYLOAD001 findings; exit code 1.
```

## Recommended remediation (per file, manual)

Each affected YAML carries a `templateVersion:` field but no
`alertRuleTemplateName:`. Two valid fixes:

**Option A (preferred): re-attach the original template name.**
Find the template GUID via:

```
pipeline new --search-template "<displayName fragment>"
```

and add it to the YAML payload:

```yaml
payload:
  alertRuleTemplateName: "<template-guid-from-search>"
  templateVersion: "1.0.0"   # leave existing value
```

**Option B: drop the template version.**
If the rule was hand-written and the templateVersion was a
copy-paste artefact, just remove the `templateVersion:` line.

## Affected files

<details><summary>68 files (click to expand)</summary>

| # | Path |
|---|---|
| 1 | `detections/sentinel/AA-Azure Active Directory Hybrid Health AD FS New Server.yml` |
| 2 | `detections/sentinel/AA-Azure Active Directory Hybrid Health AD FS Service Delete.yml` |
| 3 | `detections/sentinel/AA-Azure Active Directory Hybrid Health AD FS Suspicious Application.yml` |
| 4 | `detections/sentinel/AA-Azure VM Run Command operation executed during suspicious login window.yml` |
| 5 | `detections/sentinel/AA-Mass Cloud resource deletions Time Series Anomaly.yml` |
| 6 | `detections/sentinel/AA-New CloudShell User.yml` |
| 7 | `detections/sentinel/AA-Rare subscription-level operations in Azure.yml` |
| 8 | `detections/sentinel/AA-Suspicious granting of permissions to an account.yml` |
| 9 | `detections/sentinel/AA-TI map Email entity to AzureActivity.yml` |
| 10 | `detections/sentinel/AA-TI map IP entity to AzureActivity.yml` |
| 11 | `detections/sentinel/AAD-Account Created and Deleted in Short Timeframe.yml` |
| 12 | `detections/sentinel/AAD-Account created or deleted by non-approved user.yml` |
| 13 | `detections/sentinel/AAD-Admin promotion after Role Management Application Permission Grant.yml` |
| 14 | `detections/sentinel/AAD-Anomalous sign-in location by user account and authenticating application.yml` |
| 15 | `detections/sentinel/AAD-Attempts to sign in to disabled accounts.yml` |
| 16 | `detections/sentinel/AAD-Azure AD Role Management Permission Grant.yml` |
| 17 | `detections/sentinel/AAD-Azure Active Directory PowerShell accessing non-AAD resources.yml` |
| 18 | `detections/sentinel/AAD-Brute force attack against Azure Portal.yml` |
| 19 | `detections/sentinel/AAD-Bulk Changes to Privileged Account Permissions.yml` |
| 20 | `detections/sentinel/AAD-Correlate Unfamiliar sign-in properties and atypical travel alerts.yml` |
| 21 | `detections/sentinel/AAD-Credential added after admin consented to Application.yml` |
| 22 | `detections/sentinel/AAD-Detect PIM Alert Disabling activity.yml` |
| 23 | `detections/sentinel/AAD-External guest invitations by default guest followed by Azure AD powershell signin.yml` |
| 24 | `detections/sentinel/AAD-Failed login attempts to Azure Portal.yml` |
| 25 | `detections/sentinel/AAD-First access credential added to Application or Service Principal where no credential was present.yml` |
| 26 | `detections/sentinel/AAD-MFA disabled for a user.yml` |
| 27 | `detections/sentinel/AAD-Mail.Read Permissions Granted to Application.yml` |
| 28 | `detections/sentinel/AAD-Modified domain federation trust settings.yml` |
| 29 | `detections/sentinel/AAD-New access credential added to Application or Service Principal.yml` |
| 30 | `detections/sentinel/AAD-PIM Elevation Request Rejected.yml` |
| 31 | `detections/sentinel/AAD-Rare application consent.yml` |
| 32 | `detections/sentinel/AAD-Suspicious application consent for offline access.yml` |
| 33 | `detections/sentinel/AAD-Suspicious application consent similar to O365 Attack Toolkit.yml` |
| 34 | `detections/sentinel/AAD-Suspicious application consent similar to PwnAuth.yml` |
| 35 | `detections/sentinel/AAD-TI map Email entity to SigninLogs.yml` |
| 36 | `detections/sentinel/AAD-TI map IP entity to SigninLogs.yml` |
| 37 | `detections/sentinel/AAD-User Assigned Privileged Role.yml` |
| 38 | `detections/sentinel/AAD-User added to Azure Active Directory Privileged Groups.yml` |
| 39 | `detections/sentinel/MS-Anomalous login followed by Teams action.yml` |
| 40 | `detections/sentinel/MS-Azure VM Run Command operations executing a unique powershell script.yml` |
| 41 | `detections/sentinel/MS-DEV-0322 Serv-U related IOCs - July 2021.yml` |
| 42 | `detections/sentinel/MS-Detecting Impossible travel with mailbox permission tampering & Privilege Escalation attempt.yml` |
| 43 | `detections/sentinel/MS-Known Barium IP.yml` |
| 44 | `detections/sentinel/MS-Known IRIDIUM IP.yml` |
| 45 | `detections/sentinel/MS-Known Phosphorus group domains-IP.yml` |
| 46 | `detections/sentinel/MS-Log4j vulnerability exploit aka Log4Shell IP IOC.yml` |
| 47 | `detections/sentinel/MS-Malformed user agent.yml` |
| 48 | `detections/sentinel/MS-Multiple Password Reset by user.yml` |
| 49 | `detections/sentinel/MS-NOBELIUM - Domain and IP IOCs - March 2021.yml` |
| 50 | `detections/sentinel/MS-SOURGUM Actor IOC - July 2021.yml` |
| 51 | `detections/sentinel/MS-Suspicious number of resource creation or deployment activities.yml` |
| 52 | `detections/sentinel/MS-User agent search for log4j exploitation attempt.yml` |
| 53 | `detections/sentinel/MS-Workspace deletion attempt from an infected device.yml` |
| 54 | `detections/sentinel/O365-Exchange AuditLog disabled.yml` |
| 55 | `detections/sentinel/O365-Exchange workflow MailItemsAccessed operation anomaly.yml` |
| 56 | `detections/sentinel/O365-External user added and removed in short timeframe.yml` |
| 57 | `detections/sentinel/O365-Known Manganese IP and UserAgent activity.yml` |
| 58 | `detections/sentinel/O365-Multiple Teams deleted by a single user.yml` |
| 59 | `detections/sentinel/O365-Multiple users email forwarded to same destination.yml` |
| 60 | `detections/sentinel/O365-Office policy tampering.yml` |
| 61 | `detections/sentinel/O365-Possible STRONTIUM attempted credential harvesting - Oct 2020.yml` |
| 62 | `detections/sentinel/O365-Possible STRONTIUM attempted credential harvesting - Sept 2020.yml` |
| 63 | `detections/sentinel/O365-Rare and potentially high-risk Office operations.yml` |
| 64 | `detections/sentinel/O365-SharePointFileOperation via devices with previously unseen user agents.yml` |
| 65 | `detections/sentinel/O365-SharePointFileOperation via previously unseen IPs.yml` |
| 66 | `detections/sentinel/O365-TI map Email entity to OfficeActivity.yml` |
| 67 | `detections/sentinel/O365-TI map IP entity to OfficeActivity.yml` |
| 68 | `detections/sentinel/O365-TI map URL entity to OfficeActivity data.yml` |

</details>

## Why this PR does NOT auto-fix the YAML

Each rule needs analyst review:

- The `alertRuleTemplateName` to add is a Marketplace template
  GUID. Picking the wrong one would silently mis-attribute the
  rule to a different template family.
- Some of these rules may have been hand-written and then the
  `templateVersion`-without-`alertRuleTemplateName` shape baked
  in by accident. For those, dropping the `templateVersion`
  line is correct; adding any template name would be a fiction.

Pipeline code is the right place for the lint rule + scrub.
YAML content is the wrong place for a blanket auto-edit. The
rules listed above are tracked separately by the SOC analytics
team.

## Verification

After this PR merges:

- `pipeline lint --path detections` exits 1 with
  68 PAYLOAD001 findings until the YAML is fixed.
- `pipeline plan --asset sentinel_analytic` fails with a clear
  `templateVersion is set but no alertRuleTemplateName` error,
  rather than a noisy ARM 400 at apply time.
- `pipeline apply` (if anyone bypasses lint + plan) silently
  scrubs `templateVersion` from the body before PUT and emits a
  WARNing log line.
- `pipeline new sentinel_analytic <id>` produces a YAML that
  deploys cleanly against the live workspace, verified by
  `tests/integration/test_sentinel_analytic_scaffold_deploys.py`.

## Resolution: 2026-05-06

The 68 affected files were remediated in PR
"Remediate 68 PAYLOAD001 findings (remove dangling
templateVersion)". Per-file fix was Option B from above: drop the
`templateVersion:` line. Selecting Option A en masse would have
required guessing the original Marketplace template GUID for each
rule, and several of the files were hand-authored with no template
provenance to recover.

The PR was generated by `scripts/remediate_payload001.py`, which
walks `detections/` and surgically deletes any `templateVersion:`
line whose payload lacks `alertRuleTemplateName`. The script is
idempotent and run-once: it drove the diff to exactly 68 files,
68 deletions, 0 additions. The apply-time scrub from the PR #34
fix was already dropping this field before the wire, so the live
workspace behaviour is unchanged -- this PR just brings git into
agreement with what we were already shipping.

`pipeline lint --path detections` now exits 0 with 0 PAYLOAD001
findings. PAYLOAD001 stays in the lint runner so any future
regression is caught at PR time.

This document is kept as historical record of the incident.
