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

Each retried rule goes through apply's own per-rule step: snippet
substitution, validation, the monitor-mode skip, then the write, in
apply's order (playbooks before the automation rules that run them).
A rule locked since the failed run is skipped like apply skips it;
``retry-failed --force-overwrite`` retries it anyway.

The retry writes its own audit batch, so the chain stays continuous,
and records its results in the state file (``state/<env>/state.json``)
as apply does.

## `apply --force-overwrite`

The new flag bypasses the lock check. It does NOT bypass etag
concurrency, validation, or drift detection — those gates still fire.

## Disabling a locked rule

`contentops disable` on a locked rule sets its status to `deprecated` and
keeps the lock. Deploy then switches the rule off **as it is in the
tenant**: it reads the tenant's rule, changes only the on/off state and
writes that back (a Defender rule gets a status-only PATCH, a playbook
the Logic App's `disable` action). The query and settings tuned in the
portal are not overwritten by the file. A kind that cannot be switched
off that way (hunting queries, parsers, watchlists, data connectors) is
left alone with a message; switch it off in the portal. With
`--force-overwrite` the file is sent as it is, as for any locked rule.

## Limitations

* Lock state is per-rule, not per-field. There is no "lock just the
  threshold" — if a rule is locked, the entire payload is gated.
* The audit JSONL is partitioned by date; without ``--since`` or
  ``--run-id``, ``retry-failed`` only looks at the most recent file.
  Pass ``--since 2d`` (or a timestamp) to retry across days.
