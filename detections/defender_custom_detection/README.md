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

The `<rule-id>` is the canonical envelope id (kebab-case slug). Files
under this directory are gitignored — they live on your local clone
and never get committed back to this public pipeline repo.

## Authoring

Scaffold:

```bash
contentops new defender_custom_detection <rule-id>
```

Defender rules are **tenant-scoped** — there's no per-workspace
selector. `apply --role integration` skips Defender content silently
when no integration workspace is configured.

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
