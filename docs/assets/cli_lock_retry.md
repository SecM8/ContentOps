# CLI: lock / unlock / retry-failed / --force-overwrite

These commands close two operational gaps the prior CLI didn't have:
the customisation-protection pattern (Sentinel-as-Code Wave 2) and a
targeted retry path after a partial apply failure.

## `contentops lock <id>` / `contentops unlock <id>`

Adds or removes a top-level ``localCustomization: true`` flag on the
envelope:

```yaml
id: my-tuned-rule
version: "1.2.0"
asset: sentinel_analytic
status: production
localCustomization: true        # added by `contentops lock`
metadata: { ... }
payload: { ... }
```

Locked rules are skipped by ``contentops apply`` unless
``--force-overwrite`` is set. Use this when an analyst hand-tunes a
threshold or KQL filter and you don't want a future bulk apply to
flatten the change.

The flag is intentionally outside the strict envelope schema: the
locked file still validates, still plans, still drift-detects — only
the *push* is gated.

```
$ contentops apply --path detections
  skipped (locked — re-run with --force-overwrite to push): my-tuned-rule
  ...

$ contentops apply --path detections --force-overwrite
  update: my-tuned-rule
```

## `contentops retry-failed`

Reads the most recent ``audit/*.jsonl`` file, derives the
(asset, id) pairs whose ``status == failed``, and re-applies just
those.

```
$ contentops retry-failed --dry-run
retrying 3 failed asset(s) from 2026-05-05.jsonl:
  - sentinel_analytic    brute-force-001    (detections/sentinel/...)
  - defender_custom_detection    cred-dump  (detections/defender/...)
  - sentinel_hunting     anomalous-rdp      (detections/sentinel/...)
[dry-run] no API calls made.
```

Fail records that no longer have a matching local YAML are listed but
not retried — typical when a deprecated rule was removed between the
original apply and the retry.

The retry writes its own audit batch, so the chain stays continuous.

## `apply --force-overwrite`

The new flag bypasses the lock check. It does NOT bypass etag
concurrency, validation, or drift detection — those gates still fire.

## Limitations

* Lock state is per-rule, not per-field. There is no "lock just the
  threshold" — if a rule is locked, the entire payload is gated.
* The audit JSONL is partitioned by date; ``retry-failed`` only looks
  at the most recent file. If you want to retry across multiple days,
  re-run ``contentops apply`` against the assets directly.
