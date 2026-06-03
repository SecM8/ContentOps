# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""End-to-end: scaffold via `contentops new` -> deploy -> assert 200/201 -> prune.

Closes the gap that let the 2026-05-06 production apply hit HTTP 400
on zz-itest-lifecycle (a freshly-scaffolded envelope was missing
suppressionDuration / suppressionEnabled). This test exercises the
exact scaffold code path so any future regression in the template
fails CI before the next prod apply.

Skipped unless RUN_LIVE_TESTS=1 + I_UNDERSTAND_THIS_IS_PRODUCTION=yes
when targeting the workspace declared in config/tenant.yml. Tear-down
runs even on assertion failure.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def test_scaffolded_analytic_deploys_against_live_workspace(
    sentinel_client, integration_id, created_sentinel_rules, tmp_path,
):
    """Scaffold → flip status → PUT → assert 2xx → DELETE.

    The scaffold under test is the *production* template at
    contentops/templates/sentinel_analytic.yml.tmpl invoked through
    the same code path `contentops new` uses.
    """
    from contentops.devex.scaffold import scaffold
    from contentops.utils.yaml_io import to_sentinel_body

    rule_id = integration_id
    out = tmp_path / f"{rule_id}.yml"

    # Step 1: scaffold via the public API the CLI uses.
    scaffold(
        "sentinel_analytic",
        rule_id,
        display_name=rule_id,
        out=out,
        force=False,
    )

    # Step 2: flip status to production + safety: enabled false so
    # this synthetic rule cannot fire alerts during the test window.
    raw = yaml.safe_load(out.read_text(encoding="utf-8"))
    raw["status"] = "production"
    raw["payload"]["enabled"] = False
    out.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    # Step 3: PUT the body to ARM. This is what `contentops apply`
    # would send. If the scaffold is missing any ARM-required
    # field, the PUT will return 400 and the assertion below
    # surfaces a clear error.
    payload = raw["payload"]
    body = to_sentinel_body(payload)
    created_sentinel_rules.append(rule_id)
    response = sentinel_client.put_resource("alertRules", rule_id, body)
    assert response.status_code in (200, 201), (
        f"scaffold-and-deploy failed with HTTP {response.status_code}: "
        f"{response.text}\n"
        f"This means the sentinel_analytic scaffold template is missing "
        f"a required field. See docs/archive/incidents/broken-analytics-2026-05-06.md "
        f"for the ARM contract — every required field on the 2025-07-01-preview "
        f"surface must be in the scaffold."
    )

    # Step 4: read back; verify the displayName landed.
    fetched = sentinel_client.get_resource("alertRules", rule_id)
    assert fetched is not None
    assert fetched["properties"]["displayName"] == rule_id

    # Step 5: prune (DELETE).
    deleted = sentinel_client.delete_resource("alertRules", rule_id)
    assert deleted.status_code in (200, 204), deleted.text
    assert sentinel_client.get_resource("alertRules", rule_id) is None
    created_sentinel_rules.remove(rule_id)
