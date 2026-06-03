# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Strict-mode lint (F1).

``--strict`` runs two layers, in order:

1. **Built-in Python rules** (``contentops.lint.strict_rules``).
   These always run and encode policy-level checks that go
   beyond the heuristics in ``contentops.lint.kql``. The first
   shipped rule is KQL101 (``| take``/``| limit`` forbidden in
   production detections). New rules drop into the registry
   in ``strict_rules.py`` — see that module for the contract.

2. **Optional Kusto.Language wrapper** (this module). When a
   .NET runtime *and* a wrapper at ``tools/kql_strict.dll`` are
   present, the wrapper is invoked per file and its parser
   diagnostics are appended to the Python findings. The wrapper
   gives semantic-level analysis (column resolution, type
   checks) that pure-Python rules can't do. When it's not
   installed, the CLI prints a single advisory banner once and
   strict mode continues with Python rules only.

The wrapper contract is documented inline below so a follow-up
PR can ship the actual wrapper without further design.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from contentops.lint.kql import LintFinding


# Where the wrapper is expected to live. A follow-up PR will
# author the wrapper itself; for now this path is documented
# but not required to exist.
WRAPPER_RELATIVE = Path("tools") / "kql_strict.dll"

# Env-var override so operators can experiment with non-default
# locations without editing the repo.
_WRAPPER_ENV = "PIPELINE_KQL_STRICT_WRAPPER"
_DOTNET_ENV = "PIPELINE_KQL_STRICT_DOTNET"


# Documented advisory message used in the stub-mode finding. The
# CLI also prints this once at the top of the lint output so
# operators see it even when their files have no other findings.
ADVISORY_MESSAGE = (
    "Kusto.Language semantic checks not installed — strict mode "
    "is running Python policy rules only. To enable deeper "
    "semantic analysis locally: install the .NET 8 SDK and run "
    "`scripts/build_kql_strict.sh` (or `scripts/build_kql_strict.ps1` "
    "on Windows). CI lint + validate workflows publish the wrapper "
    f"automatically. Override the wrapper path with {_WRAPPER_ENV}."
)


def _resolve_wrapper(repo_root: Path) -> Path | None:
    """Locate the strict-lint wrapper. Returns None if not present."""
    override = os.getenv(_WRAPPER_ENV)
    if override:
        p = Path(override)
        return p if p.is_file() else None
    candidate = repo_root / WRAPPER_RELATIVE
    return candidate if candidate.is_file() else None


def _resolve_dotnet() -> str | None:
    """Find a `dotnet` executable. Returns None if not on PATH."""
    override = os.getenv(_DOTNET_ENV)
    if override and Path(override).is_file():
        return override
    return shutil.which("dotnet")


def is_available(*, repo_root: Path | None = None) -> bool:
    """True when both the .NET runtime and the wrapper are present."""
    return (
        _resolve_dotnet() is not None
        and _resolve_wrapper(repo_root or Path.cwd()) is not None
    )


def run_strict(
    file_path: Path, query: str, *, repo_root: Path | None = None,
) -> list[LintFinding]:
    """Run strict lint against one query.

    Always runs the built-in Python rules from
    ``contentops.lint.strict_rules``. Then, if the optional
    Kusto.Language wrapper is installed, invokes it as:

        dotnet <wrapper.dll> <file_path>

    The wrapper reads the KQL from disk (file_path) and prints
    one diagnostic per line:

        KQL000\\t<severity>\\t<line>\\t<message>

    Each diagnostic becomes a LintFinding. Severity is one of
    ``error|warning|info`` (matches the existing finding shape).

    Respects ``config/lint_strict.yml``:
      * ``mode: off``    → skip the wrapper entirely; return only
        the Python rules' findings.
      * ``mode: report`` → run the wrapper; let the wrapper's
        default behaviour ship all findings at ``warning``.
      * ``mode: block``  → set ``KQL_STRICT_PROMOTE_SEVERITY=1``
        on the wrapper env so findings emit at their upstream
        severity.
    """
    import os
    from contentops.lint.strict_allowlist import load_allowlist, should_suppress
    from contentops.lint.strict_config import load_lint_strict_config
    from contentops.lint.strict_rules import run_python_rules

    findings: list[LintFinding] = list(run_python_rules(query))

    config, _info = load_lint_strict_config()
    if config.mode == "off":
        return findings

    repo = repo_root or Path.cwd()
    dotnet = _resolve_dotnet()
    wrapper = _resolve_wrapper(repo)
    if dotnet is None or wrapper is None:
        return findings

    env = os.environ.copy()
    if config.mode == "block":
        env["KQL_STRICT_PROMOTE_SEVERITY"] = "1"
    else:
        env.pop("KQL_STRICT_PROMOTE_SEVERITY", None)

    try:
        result = subprocess.run(
            [dotnet, str(wrapper), str(file_path)],
            input=query, capture_output=True, text=True,
            timeout=30, check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        findings.append(LintFinding(
            "KQL000", "warning",
            f"strict-lint wrapper invocation failed: {exc}",
        ))
        return findings
    if result.returncode != 0 and not result.stdout:
        # Wrapper crashed without diagnostics — surface stderr.
        findings.append(LintFinding(
            "KQL000", "warning",
            f"strict-lint wrapper exited {result.returncode}: "
            f"{(result.stderr or '').strip()[:160]}",
        ))
        return findings
    # Allowlist suppresses wrapper false positives the wrapper can't
    # model (join-suffix columns, dynamic extends, FileProfile() output).
    # See contentops/lint/strict_allowlist.py for the taxonomy + the
    # restricted set of allowlistable rule IDs.
    allowlist, allowlist_notes = load_allowlist()
    # Surface allowlist parse warnings as KQL000 findings so an operator
    # who typos a rule ID, writes a bad regex, or forgets the required
    # `reason` field sees feedback in lint output instead of silently
    # losing the suppression. One warning per skipped entry.
    for note in allowlist_notes:
        findings.append(LintFinding(
            "KQL000", "warning",
            f"kql_lint_allowlist: {note}",
        ))
    for line in result.stdout.splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        rule_id, severity, line_no_str, message = parts
        try:
            line_no = int(line_no_str) or None
        except ValueError:
            line_no = None
        if severity not in ("error", "warning", "info"):
            severity = "warning"
        finding = LintFinding(rule_id or "KQL000", severity, message, line_no)
        if should_suppress(finding, allowlist):
            continue
        findings.append(finding)
    return findings


__all__ = [
    "ADVISORY_MESSAGE",
    "WRAPPER_RELATIVE",
    "is_available",
    "run_strict",
]
