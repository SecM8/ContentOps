<!-- SPDX-FileCopyrightText: 2026 KustoKing / SecM8 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deploying Defender detections that use `FileProfile()`

## TL;DR

A Defender custom detection whose KQL uses `invoke FileProfile(...)` can run
perfectly in **Advanced Hunting** yet fail to deploy through this pipeline with
a generic:

```
400 Bad request. Please check your input.
```

This is **not** a pipeline bug and **not** a problem with `FileProfile` itself.
The Microsoft Graph **beta** `security/rules/detectionRules` save-API validates
the query with a static Kusto parser that has **no schema for `FileProfile`'s
output**. Any column that passes *through* the `invoke` becomes invisible to the
validator, so referencing it downstream is rejected.

Fix: redeclare those columns with `column_ifexists(...)` so the validator can
see them. It's logic-preserving — at runtime the columns resolve to the real
`FileProfile`/event values.

## Two failure modes

1. **Filtering on a `FileProfile` output column** (`GlobalPrevalence`,
   `SignatureState`, `IsCertificateValid`, `IsRootSignerMicrosoft`, `Signer`,
   `GlobalFirstSeen`, …) after the `invoke` → generic `400`.
2. **Entity mappings reference columns the validator can't see** after
   `FileProfile` (+ any join back to the events) → a more specific
   `400 "Entity mappings reference the following column(s) which are not
   projected by the query output: …"`. The columns are present at runtime; the
   parser just can't infer them.

The query runs fine interactively in both cases — only the **save / deploy**
path enforces this. (Microsoft tightened this on the beta surface around
2026-05; rules created earlier keep running but can no longer be updated via the
API until fixed.)

## Deploy blast radius — why this bites in production

Defender XDR is a single tenant-level engine; there is **no integration
Defender workspace** the way Sentinel has `role: integration`. So a
`defender_custom_detection` change lands **first in production** via
`deploy.yml` on merge to `main` — production is the operator's only feedback
channel for it. And the cheaper pre-merge checks structurally cannot see this
class of 400:

- **`contentops rule-test`** runs the rule's KQL against the Log Analytics
  Query API (a Sentinel workspace) — exactly where these queries "run fine".
  It never touches the beta `detectionRules` **save** path, so it cannot
  reproduce the save-validator 400.
- The Defender Graph API has **no ETag / If-Match** concurrency, so the apply
  has no optimistic-concurrency guard either (post-apply content-hash verify
  only).

**Caught at PR time:** two regex lint rules flag the documented triggers as
**warnings** on every PR, so the common case surfaces before merge instead of
on the first prod apply:

- **PAYLOAD005** — a `FileProfile()` output column referenced without a
  `column_ifexists` redeclaration.
- **PAYLOAD006** — an `impactedAssets` entity column not re-projected after
  the `invoke` (the schema-less boundary).

They are heuristics scoped to the FileProfile segment of the query;
`defender-patch-probe --replicate` (below) remains the authoritative check.

## The fix pattern

Right after `invoke FileProfile(...)`, redeclare every column you reference
downstream — and just before the rule's output, redeclare the columns your
`impactedAssets` map plus the required `Timestamp` / `DeviceId` / `ReportId` —
using `column_ifexists("Col", <typed default>)`:

```kql
DeviceImageLoadEvents
| ...
| distinct SHA1
| invoke FileProfile(SHA1, 1000)
| extend GP = column_ifexists("GlobalPrevalence", long(null))   // redeclare for the filter
| where GP >= 50
| join kind=rightanti OrganizationalPrevalence on SHA1
| extend                                                        // redeclare for the mappings + required cols
    Timestamp = column_ifexists("Timestamp", datetime(null)),
    DeviceId = column_ifexists("DeviceId", ""),
    ReportId = column_ifexists("ReportId", ""),
    InitiatingProcessAccountSid = column_ifexists("InitiatingProcessAccountSid", "")
```

Typed defaults that match `FileProfile`'s output (so `column_ifexists` resolves
to the real value at runtime):

| Column | Type / default |
|---|---|
| `GlobalPrevalence` | `long(null)` |
| `GlobalFirstSeen` / `GlobalLastSeen` | `datetime(null)` |
| `IsCertificateValid`, `IsRootSignerMicrosoft` | `bool(null)` |
| `SignatureState`, `Signer`, `Issuer` | `""` |
| `Timestamp` | `datetime(null)` |
| `DeviceId`, `ReportId`, `AccountSid`, `InitiatingProcessAccountSid` | `""` |

No detection logic changes — same filters, same thresholds, same mappings.

## Diagnose / verify with `defender-patch-probe`

A `PATCH` only returns the opaque generic `400`; a **create** returns the
specific reason. The diagnostic clones the rule (renamed, disabled, auto-deleted)
to surface it, and can test a candidate query:

```bash
# Why does this rule fail to deploy?  (reads the live rule; --send required to call the API)
contentops defender-patch-probe <envelope-id> --send --replicate

# Test a candidate query (real mappings + your query) before editing the YAML:
contentops defender-patch-probe <envelope-id> --send --replicate --query-file candidate.kql
```

Read the `clone-create` result:

* `-> 201` — the query (with its mappings) is deployable.
* generic `400 Bad request` — the query is still rejected (a downstream column
  the validator can't see).
* `Entity mappings reference … not projected` — the query validates, but a
  mapped column isn't visible; add it to the final `column_ifexists` `extend`.

Needs `CustomDetection.ReadWrite.All` and a credential (`az login`, OIDC, or a
client secret in `.env`). Clones are created **disabled** and deleted in a
`finally` block.

## Background

See the auto-memory note `reference_defender_save_validates_fileprofile_output`
and PRs #298 (the probe) / #299 + the FileProfile-detections fix PR. Related:
the Kusto.Language parser ships only the ADX schema, so Defender tables and
functions are unknown to it (this is the same root limitation behind the KS142
lint false-positives).
