# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Config knobs for `contentops lint --strict` (G1 / F1.1 follow-up).

Three knobs control the strict-lint pipeline:

* ``mode`` (global) -- ``off`` / ``report`` / ``block``
    * ``off``   - wrapper isn't invoked; Python KQL101 still runs.
    * ``report`` - wrapper runs; all wrapper findings emit at
      ``warning`` severity so lint exits 0 even on KS204 / KS142.
      Onboarding-friendly default.
    * ``block``  - wrapper runs; findings emit at upstream severity
      so errors fail ``lint --strict``. The strict gate.

* ``sentinel.enabled`` / ``defender.enabled`` (per-source) - controls
  whether each schema source refreshes and whether the wrapper loads
  it. Independent of ``mode``: an operator can disable the Defender
  refresh (e.g. ``ThreatHunting.Read.All`` not granted yet) while
  keeping Sentinel-side checking on.

* ``refresh_on_pr`` - when true, ``validate.yml`` + ``lint.yml``
  fetch fresh schemas before running lint so PR validation reflects
  the current tenant state. Best-effort; falls back to the committed
  baseline on Graph / LA failure.

Loader mirrors ``contentops.lifecycle.load_lifecycle_config`` shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml


StrictMode = Literal["off", "report", "block"]

VALID_MODES: tuple[StrictMode, ...] = ("off", "report", "block")


@dataclass(frozen=True)
class LintStrictConfig:
    """Per-tenant config for the strict-lint pipeline."""

    mode: StrictMode = "report"
    sentinel_enabled: bool = True
    defender_enabled: bool = True
    refresh_on_pr: bool = True
    # Case-insensitive glob patterns for workspace tables to DROP from the
    # refreshed kql_strict schema (`contentops upstream check-schemas`).
    # Operator scratch / test custom-log tables (e.g. ``TestMe_KQL_CL``)
    # would otherwise land in the committed, publicly-mirrored
    # tools/kql_strict/schemas.json. Patterns live in the operator-private
    # config/lint_strict.yml (stripped from the public mirror), so the
    # excluded names never reach adopters.
    schema_exclude_tables: tuple[str, ...] = ()


DEFAULT_CONFIG = LintStrictConfig()
DEFAULT_CONFIG_PATH = Path("config") / "lint_strict.yml"


def load_lint_strict_config(
    path: Path | None = None,
) -> tuple[LintStrictConfig, str | None]:
    """Read ``config/lint_strict.yml`` and return ``(config, info_or_None)``.

    Falls back to defaults on missing / malformed file and returns a
    human-readable info note for the CLI to surface. Mirrors
    ``contentops.lifecycle.load_lifecycle_config``.
    """
    target = path if path is not None else DEFAULT_CONFIG_PATH
    if not target.exists():
        return (
            DEFAULT_CONFIG,
            f"lint_strict: {target} not found; using defaults "
            "(mode=report, sentinel+defender enabled, refresh_on_pr=true).",
        )
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return (
            DEFAULT_CONFIG,
            f"lint_strict: failed to parse {target} ({exc}); using defaults.",
        )
    if not isinstance(data, dict):
        return (
            DEFAULT_CONFIG,
            f"lint_strict: {target} top-level is not a mapping; using defaults.",
        )

    # PyYAML coerces unquoted `off` / `on` / `yes` / `no` / `true` / `false`
    # to bool under YAML 1.1, so `mode: off` arrives here as `False`,
    # not the string `"off"`. Normalise booleans back to mode strings so
    # the natural `mode: off` syntax works without forcing quotes.
    raw_value = data.get("mode")
    if raw_value is False:
        raw_mode = "off"
    elif raw_value is True:
        raw_mode = "on"  # not a valid mode; will fall back to default with info
    elif raw_value is None:
        raw_mode = "report"
    else:
        raw_mode = str(raw_value).lower()
    mode: StrictMode = raw_mode if raw_mode in VALID_MODES else "report"  # type: ignore[assignment]
    info: str | None = None
    if raw_mode not in VALID_MODES:
        info = (
            f"lint_strict: invalid mode {raw_mode!r}; expected one of "
            f"{', '.join(VALID_MODES)}. Defaulting to 'report'."
        )

    sentinel = data.get("sentinel") if isinstance(data.get("sentinel"), dict) else {}
    defender = data.get("defender") if isinstance(data.get("defender"), dict) else {}
    sentinel_enabled = bool(sentinel.get("enabled", True))
    defender_enabled = bool(defender.get("enabled", True))
    refresh_on_pr = bool(data.get("refresh_on_pr", True))

    raw_excludes = data.get("schema_exclude_tables")
    if raw_excludes is None:
        schema_exclude_tables: tuple[str, ...] = ()
    elif isinstance(raw_excludes, (list, tuple)):
        schema_exclude_tables = tuple(
            str(p).strip() for p in raw_excludes if str(p).strip()
        )
    else:
        schema_exclude_tables = ()
        note = "lint_strict: schema_exclude_tables is not a list; ignored."
        info = f"{info} {note}" if info else note

    return (
        LintStrictConfig(
            mode=mode,
            sentinel_enabled=sentinel_enabled,
            defender_enabled=defender_enabled,
            refresh_on_pr=refresh_on_pr,
            schema_exclude_tables=schema_exclude_tables,
        ),
        info,
    )


__all__ = [
    "DEFAULT_CONFIG",
    "DEFAULT_CONFIG_PATH",
    "LintStrictConfig",
    "StrictMode",
    "VALID_MODES",
    "load_lint_strict_config",
]
