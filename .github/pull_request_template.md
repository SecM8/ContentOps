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
- [ ] sentinel_workbook
- [ ] sentinel_automation
- [ ] sentinel_playbook
- [ ] sentinel_data_connector
- [ ] sentinel_solution
- [ ] sentinel_parser
- [ ] sentinel_hunt
- [ ] sentinel_bookmark
- [ ] sentinel_ti_indicator
- [ ] sentinel_summary_rule
- [ ] sentinel_metadata
- [ ] defender_custom_detection
- [ ] defender_tuning_rule
- [ ] defender_suppression_rule
- [ ] defender_saved_query
- [ ] defender_ti_indicator
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
