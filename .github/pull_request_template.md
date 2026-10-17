<!--
  Detection-as-code PR template.

  Drop the sections that don't apply (this is a checklist, not a form),
  but DON'T DELETE the headings — CI parses them.
-->

## Summary

<!-- 1–3 sentences. What and why. -->

## Touched assets

<!-- Tick the asset kinds this PR adds, modifies, or disables. -->

- [ ] sentinel_analytic
- [ ] sentinel_hunting
- [ ] sentinel_watchlist
- [ ] sentinel_data_connector
- [ ] sentinel_parser
- [ ] defender_custom_detection
- [ ] sentinel_automation_rule (suppression / response — see the blast-radius note in `docs/assets/sentinel_automation_rules.md`)
- [ ] sentinel_playbook (`.yml` + `.workflow.json` sidecar — bump `version` for either)
- [ ] pipeline / workflow / docs only

## Plan output

<!--
Run locally and paste, OR rely on the CI plan-prod check to attach it.

    contentops plan --skip-deps-check=false
-->

```
<!-- contentops plan output -->
```

## Audit hash chain

<!-- Confirm chain integrity before merging behaviour-changing PRs. -->

- [ ] `contentops audit verify` reports zero breaks against the current
      `audit/` directory, OR this PR does not write audit records.

## Reviewer notes

<!-- Anything reviewers should look at first: a known limitation, a
     deferred follow-up, an upstream bug we're working around, etc. -->
