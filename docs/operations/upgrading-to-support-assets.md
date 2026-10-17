# Upgrading to the support-asset kinds (automation rules, playbooks)

This release adds two asset kinds next to the six detection kinds:
`sentinel_automation_rule` and `sentinel_playbook`. This page is for
an existing fork upgrading the tool. Nothing is deleted or written for
the new kinds until you opt in — but some things change on day one.

## What happens on upgrade with an untouched tenant secret

The new kinds default to **`monitor`** mode *in code*
(`DEFAULT_ASSET_MODES`), not in the example config, so a tenant secret
that pre-dates them is safe:

| Command | Behaviour for the new kinds |
|---|---|
| `collect` / `drift` | **active**: the next scheduled `drift.yml` auto-PR and weekly `collect.yml` will propose every portal automation rule as a new `detections/sentinel_automation_rule/*.yml`. Playbooks are managed-tag only, so no Logic App appears until you adopt it. |
| `lint` | active on the new local files |
| `apply` / `plan` | per-asset skip, `status: monitor`, audited as skipped |
| `prune` | refuses the kind; additionally refuses *any* kind with zero local envelopes but remote items unless `--allow-empty-kind` |
| `doctor --fix` | creates the two empty directories |
| status pages | envelope counts rise after the import merges |

Review the first drift PR, don't rubber-stamp it: a collected
suppression rule is a decision somebody made in the portal.

## The opt-in ladder

1. **Collect on a branch and review.**
   ```bash
   contentops collect --asset sentinel_automation_rule --role prod
   contentops collect --asset sentinel_playbook --role prod --adopt <workflow-name>   # per playbook you want managed
   contentops lint
   ```
   Expired automation rules land as `status: deprecated`; close rules
   without conditions get PAYLOAD014. Fix or deprecate before merging.
2. **Merge.** Git is now the source of truth for those rules.
3. **Flip the kind to `managed`** in the tenant secret:
   ```yaml
   sentinelWorkspaces:
     - role: prod
       ...
       assetModes:
         sentinel_automation_rule: managed
         sentinel_playbook: managed
       playbooksResourceGroup: rg-sentinel-playbooks   # if playbooks live elsewhere
   ```
   `contentops config validate` prints the effective mode table.
4. **Grant the roles** `contentops conformance` lists as missing
   (Logic App Contributor on the playbook RG for the deploy identity;
   Microsoft Sentinel Automation Contributor on that RG for the
   *Azure Security Insights* service principal, Owner-level). The
   pipeline reports these; it never assigns them.
5. Only then consider `purgeAllowed` for prune. Never run `prune` for
   a kind before its first full collect has merged — the empty-kind
   guard refuses anyway.

## Kill switch

If the beta misbehaves in CI, set the repository variable
`CONTENTOPS_DISABLED_KINDS` (comma-separated, e.g.
`sentinel_playbook,sentinel_automation_rule`). The `pipeline-setup`
action exports it; listed kinds are not registered at all, so
collect / drift / apply / prune ignore them while `lint` still checks
local files. `doctor` and `config validate` print it so nobody forgets
it is set. Unknown values fail loud.

## Multi-workspace notes

- Automation rules deploy per workspace, each with its own GUID
  (authored rules: `uuid5(envelope id)`).
- Playbooks follow each workspace's `playbooksResourceGroup`. Two
  workspaces sharing one RG make one idempotent PUT; two workspaces
  with different RGs each get a copy.

## Test pins forks may have extended

If your fork extended any of these, re-sync them with upstream:
`tests/v2/test_lint_coverage.py` (`_NON_KQL_BEARING_ASSETS`,
`_EXPECTED_SEVERITIES`), `test_optional_engines.py`,
`test_devex_scaffold.py`, `test_catalog.py` (regenerate the catalog),
and the prune tests (`--allow-empty-kind`).
