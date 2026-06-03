# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""V2 CLI package.

Re-exports the root Click `cli` group (defined in `contentops.cli.root`)
so the entry point `pipeline = contentops.cli:cli` keeps working, and
attaches the v2 commands (`plan`, `apply`, …) to that same group.

Import order:

1. ``load_env_file()`` so submodules see ``.env`` values on import.
2. ``from contentops.cli.root import cli`` — bring the empty group into
   this namespace.
3. ``cli.add_command(...)`` for each v2 command.
"""

from contentops.utils.stdio import force_utf8_stdio

# Force UTF-8 stdout / stderr before any click.echo can run. On Windows
# the default cp1252 codepage crashes on `→` and other Unicode chars
# scattered through CLI output. Discovered 2026-05-15.
force_utf8_stdio()

# .env loading is deferred to the cli() entry point in root.py so that
# package imports are side-effect-free (important for tests and tooling).

from contentops.cli.root import cli
from contentops.cli.commands import (
    alerts_group,
    apply_cmd,
    audit_group,
    auto_disabled_rules_cmd,
    bootstrap_cmd,
    catalog_group,
    clean_cmd,
    collect_cmd,
    config_group,
    conformance_cmd,
    coverage_cmd,
    defender_extensions_probe_cmd,
    defender_patch_probe_cmd,
    defender_roundtrip_diff_cmd,
    detection_docs_group,
    disable_cmd,
    doctor_cmd,
    enable_cmd,
    drift_cmd,
    drift_pr_body_cmd,
    drift_resolve_cmd,
    explain_cmd,
    lint_cmd,
    lifecycle_group,
    lock_cmd,
    navigator_cmd,
    new_cmd,
    plan_cmd,
    portfolio_cmd,
    prune_cmd,
    report_cmd,
    restore_cmd,
    retry_failed_cmd,
    rollback_cmd,
    rule_test_cmd,
    sentinel_roundtrip_diff_cmd,
    silent_rules_cmd,
    snapshot_diff_cmd,
    state_group,
    status_group,
    test_cmd,
    tuning_group,
    undeployed_rules_cmd,
    unlock_cmd,
    upstream_group,
)

cli.add_command(plan_cmd)
cli.add_command(apply_cmd)
cli.add_command(drift_cmd)
cli.add_command(drift_pr_body_cmd)
cli.add_command(drift_resolve_cmd)
cli.add_command(disable_cmd)
cli.add_command(enable_cmd)
cli.add_command(lint_cmd)
cli.add_command(coverage_cmd)
cli.add_command(audit_group)
cli.add_command(config_group)
cli.add_command(conformance_cmd)
cli.add_command(portfolio_cmd)
cli.add_command(new_cmd)
cli.add_command(doctor_cmd)
cli.add_command(lock_cmd)
cli.add_command(unlock_cmd)
cli.add_command(retry_failed_cmd)
cli.add_command(bootstrap_cmd)
cli.add_command(catalog_group)
cli.add_command(clean_cmd)
cli.add_command(collect_cmd)
cli.add_command(prune_cmd)
cli.add_command(report_cmd)
cli.add_command(restore_cmd)
cli.add_command(rollback_cmd)
cli.add_command(rule_test_cmd)
cli.add_command(snapshot_diff_cmd)
cli.add_command(explain_cmd)
cli.add_command(test_cmd)
cli.add_command(silent_rules_cmd)
cli.add_command(auto_disabled_rules_cmd)
cli.add_command(undeployed_rules_cmd)
cli.add_command(detection_docs_group)
cli.add_command(tuning_group)
cli.add_command(navigator_cmd)
cli.add_command(defender_extensions_probe_cmd)
cli.add_command(defender_patch_probe_cmd)
cli.add_command(defender_roundtrip_diff_cmd)
cli.add_command(sentinel_roundtrip_diff_cmd)
cli.add_command(lifecycle_group)
cli.add_command(state_group)
cli.add_command(status_group)
cli.add_command(upstream_group)
cli.add_command(alerts_group)

__all__ = ["cli"]
