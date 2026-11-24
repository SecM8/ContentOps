# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""The kind kill switch for the live suite.

``CONTENTOPS_DISABLED_KINDS`` switches asset kinds off for the pipeline
(collect, drift, apply, prune, rollback, retry-failed). The live tests
build their own clients, so they apply it themselves: each test module
declares the kinds it writes in ``LIVE_KINDS`` (a tuple for the whole
module, or a dict from test function to tuple), and a test whose kind is
switched off is skipped.

``CONTENTOPS_LIVE_IGNORE_KILL_SWITCH=1`` (``integration.yml`` input
``ignore-kill-switch``) runs it anyway: the Defender shape probe is how
you find out why a kind had to be switched off.
"""

from __future__ import annotations

import os
from types import ModuleType
from typing import Any

from contentops.core.asset import Asset

OVERRIDE_ENV = "CONTENTOPS_LIVE_IGNORE_KILL_SWITCH"

#: What a module that does not declare ``LIVE_KINDS`` is assumed to write.
ALL_KINDS: tuple[str, ...] = tuple(sorted(a.value for a in Asset))


def kinds_for(module: ModuleType | Any, test_name: str) -> tuple[str, ...]:
    """The kinds ``test_name`` in ``module`` writes (all kinds if undeclared)."""
    declared = getattr(module, "LIVE_KINDS", None)
    if declared is None:
        return ALL_KINDS
    if isinstance(declared, dict):
        return tuple(declared.get(test_name, ALL_KINDS))
    return tuple(declared)


def override_set() -> bool:
    return os.environ.get(OVERRIDE_ENV) == "1"


def skip_reason(kinds: tuple[str, ...], disabled: frozenset[str], *, override: bool) -> str | None:
    """Why a test that writes ``kinds`` must not run, or None."""
    if override:
        return None
    switched = sorted(set(kinds) & set(disabled))
    if not switched:
        return None
    return (
        f"CONTENTOPS_DISABLED_KINDS lists {', '.join(switched)}; this live test "
        "writes that kind. Start integration.yml with ignore-kill-switch to run it "
        f"anyway ({OVERRIDE_ENV}=1)."
    )
