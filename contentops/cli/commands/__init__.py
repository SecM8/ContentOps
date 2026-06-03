# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""V2 CLI command package.

Originally a single ~4500-line ``commands.py`` module. Split into
focused modules for readability; the public Click symbol surface
(every ``*_cmd`` and ``*_group`` referenced by ``contentops.cli``)
is re-exported here so existing imports keep working unchanged.

Module map:

* ``_shared``           — helpers used by 2+ commands
                          (``_apply_log_levels``, ``_print_run_banner``,
                          ``_format_summary_table``, ``_load_all``,
                          ``_filter_changed_since``,
                          ``_emit_dependency_report``, ``_is_locked``,
                          ``_resolve_single_workspace_or_exit``)
* ``apply``             — ``plan_cmd`` + ``apply_cmd``
* ``drift``             — ``drift_cmd`` + ``drift_resolve_cmd``
                          + ``drift_pr_body_cmd``
* ``prune``             — ``prune_cmd``
* ``collect``           — ``collect_cmd`` + ``clean_cmd``
                          (share ``_clean_local_detections``)
* ``config``            — ``config_group`` + validate / list-workspaces
* ``lifecycle``         — ``disable_cmd`` / ``lock_cmd`` / ``unlock_cmd``
                          / ``retry_failed_cmd`` / ``lifecycle_group``
                          / ``lifecycle_promote_cmd``
* ``audit``             — ``audit_group`` + verify / query subcommands
* ``state``             — ``state_group`` + show / forget / sync
* ``bootstrap``         — ``bootstrap_cmd``
* ``diagnostics``       — ``defender_extensions_probe_cmd``
                          + ``defender_patch_probe_cmd``
                          + ``defender_roundtrip_diff_cmd``
                          + ``explain_cmd``
* ``archive``           — ``restore_cmd`` + ``snapshot_diff_cmd``
* ``silent_rules``      — ``silent_rules_cmd``
* ``rollback``          — ``rollback_cmd``
* ``new``               — ``new_cmd``
* ``lint``              — ``lint_cmd``
* ``coverage``          — ``coverage_cmd``
* ``portfolio``         — ``portfolio_cmd``
* ``doctor``            — ``doctor_cmd``
* ``test_runner``       — ``test_cmd`` (module renamed so pytest
                          doesn't collect this command file as a test)
"""

from contentops.cli.commands._shared import (
    _NOISY_LOGGERS,
    _VERBOSE_ONLY_LOGGERS,
    _apply_log_levels,
    _emit_dependency_report,
    _emit_loose_parse_summary,
    _filter_changed_since,
    _format_summary_table,
    _is_locked,
    _load_all,
    _print_run_banner,
    _resolve_single_workspace_or_exit,
    _skip_if_integration_role_absent,
)
from contentops.cli.commands.alerts import alerts_group
from contentops.cli.commands.apply import apply_cmd, plan_cmd
from contentops.cli.commands.archive import restore_cmd, snapshot_diff_cmd
from contentops.cli.commands.audit import audit_group
from contentops.cli.commands.auto_disabled import auto_disabled_rules_cmd
from contentops.cli.commands.bootstrap import bootstrap_cmd
from contentops.cli.commands.catalog import catalog_group
from contentops.cli.commands.collect import (
    clean_cmd,
    collect_cmd,
)
from contentops.cli.commands.collect_support import _clean_local_detections
from contentops.cli.commands.config import config_group
from contentops.cli.commands.conformance import conformance_cmd
from contentops.cli.commands.coverage import coverage_cmd
from contentops.cli.commands.detection_docs import detection_docs_group
from contentops.cli.commands.diagnostics import (
    defender_extensions_probe_cmd,
    defender_patch_probe_cmd,
    defender_roundtrip_diff_cmd,
    explain_cmd,
    sentinel_roundtrip_diff_cmd,
)
from contentops.cli.commands.doctor import doctor_cmd
from contentops.cli.commands.drift import (
    drift_cmd,
    drift_pr_body_cmd,
    drift_resolve_cmd,
)
from contentops.cli.commands.lifecycle import (
    disable_cmd,
    enable_cmd,
    lifecycle_group,
    lock_cmd,
    retry_failed_cmd,
    unlock_cmd,
)
from contentops.cli.commands.lint import lint_cmd
from contentops.cli.commands.navigator import navigator_cmd
from contentops.cli.commands.new import new_cmd
from contentops.cli.commands.portfolio import portfolio_cmd
from contentops.cli.commands.prune import prune_cmd
from contentops.cli.commands.report import report_cmd
from contentops.cli.commands.rollback import rollback_cmd
from contentops.cli.commands.rule_test import rule_test_cmd
from contentops.cli.commands.silent_rules import silent_rules_cmd
from contentops.cli.commands.state import state_group
from contentops.cli.commands.status import status_group
from contentops.cli.commands.test_runner import test_cmd
from contentops.cli.commands.tuning import tuning_group
from contentops.cli.commands.undeployed import undeployed_rules_cmd
from contentops.cli.commands.upstream import upstream_group

__all__ = [
    # Click commands / groups (the contract contentops/cli/__init__.py imports).
    "alerts_group",
    "apply_cmd",
    "audit_group",
    "auto_disabled_rules_cmd",
    "bootstrap_cmd",
    "catalog_group",
    "clean_cmd",
    "collect_cmd",
    "config_group",
    "conformance_cmd",
    "coverage_cmd",
    "defender_extensions_probe_cmd",
    "defender_patch_probe_cmd",
    "defender_roundtrip_diff_cmd",
    "detection_docs_group",
    "disable_cmd",
    "doctor_cmd",
    "enable_cmd",
    "drift_cmd",
    "drift_pr_body_cmd",
    "drift_resolve_cmd",
    "explain_cmd",
    "lint_cmd",
    "lifecycle_group",
    "lock_cmd",
    "navigator_cmd",
    "new_cmd",
    "plan_cmd",
    "portfolio_cmd",
    "prune_cmd",
    "report_cmd",
    "restore_cmd",
    "retry_failed_cmd",
    "rollback_cmd",
    "rule_test_cmd",
    "sentinel_roundtrip_diff_cmd",
    "silent_rules_cmd",
    "snapshot_diff_cmd",
    "state_group",
    "status_group",
    "test_cmd",
    "tuning_group",
    "undeployed_rules_cmd",
    "unlock_cmd",
    "upstream_group",
    # Internal helpers re-exported for tests.
    "_NOISY_LOGGERS",
    "_VERBOSE_ONLY_LOGGERS",
    "_apply_log_levels",
    "_clean_local_detections",
    "_emit_dependency_report",
    "_emit_loose_parse_summary",
    "_filter_changed_since",
    "_format_summary_table",
    "_is_locked",
    "_load_all",
    "_print_run_banner",
    "_resolve_single_workspace_or_exit",
    "_skip_if_integration_role_absent",
]
