# `detections/defender_custom_detection/`

Custom detection envelopes for **Microsoft Defender XDR** go here.

Defender custom detections are KQL hunting-style rules that fire alerts
via the Defender XDR pipeline. Deployed via Microsoft Graph **beta**
endpoint at `/security/rules/detectionRules` — the Graph beta surface
is preview-versioned and may change.

## Placement

Each rule is one YAML file:

```
detections/defender_custom_detection/<rule-id>.yml
```

The `<rule-id>` is the canonical envelope id (kebab-case slug). Rule
files are committed in your **deployment fork**; the public mirror
never carries them (its sync allowlist ships only this README).

## Authoring

Scaffold:

```bash
contentops new defender_custom_detection <rule-id>
```

Defender rules are **tenant-scoped** — there's no per-workspace
selector. `apply --role integration` skips Defender content silently
when no integration workspace is configured.

## Enabled state — `status`, not `isEnabled`

Graph beta replaced the `isEnabled` boolean with a `status` enum and
removed `isEnabled` from the resource on 2026-10-01. Author the new
field:

```yaml
payload:
  displayName: Suspicious encoded PowerShell
  description: Why this rule exists and what it catches.   # optional
  status: enabled          # enabled | disabled | autoDisabled
```

| `status` | On apply | On collect |
|---|---|---|
| `enabled` | Sent as-is | Envelope `status: production` |
| `disabled` | Sent as-is | Envelope `status: deprecated` |
| `autoDisabled` | **Not sent** — the live state is left alone | Envelope stays `production`; the payload keeps `status: autoDisabled` so drift shows it |

- `autoDisabled` means Defender switched the rule off after repeated
  run failures. Fix the query, then set `status: enabled` — re-enabling
  is always a deliberate edit, never a side-effect of a deploy.
- Envelope `status: deprecated` always deploys as `status: disabled`,
  whatever the payload says.
- Legacy `isEnabled: true|false` still validates and is translated to
  `status` on apply. It is never sent to Graph. Collect stops writing
  it as soon as Graph returns `status`.
- `description` is hashed for post-apply verification **only when you
  set a non-empty one**. YAML collected before the field existed keeps
  verifying cleanly against rules that carry a portal description.

## Beta API risk

The Graph beta endpoint can change without notice. The
`contentops defender-extensions-probe` workflow watches three adjacent
Graph endpoints (`savedQueries`, `detection-tuning-rules`,
`alert-suppression`) and exits 2 when one becomes available — a signal
that Microsoft may be about to GA the surface. See
[`../../docs/assets/defender_graph_extensions_deferred.md`](../../docs/assets/defender_graph_extensions_deferred.md)
and the "Preview / beta API risk" section of
[`../../docs/reference/asset-coverage.md`](../../docs/reference/asset-coverage.md)
for the operational implications.

## See also

- [`../../docs/reference/asset-coverage.md`](../../docs/reference/asset-coverage.md) — endpoint, RBAC, hash projection, beta-API risk.
- [`../../docs/reference/envelope-schema.md`](../../docs/reference/envelope-schema.md) — canonical YAML shape.
