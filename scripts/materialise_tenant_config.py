# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Write a tenant config file from a CI secret, refusing ambiguous setups.

Used by ``.github/actions/pipeline-setup`` and the workflows that inline
the same step. The secret's content is read from an environment variable
(composite actions have no ``secrets`` context; the caller maps the
secret onto an input/env var) and is never printed.

Outcomes:

* file absent, secret set     -> write the secret to the file.
* file absent, secret empty   -> error, unless ``--allow-missing``.
* file present, secret empty  -> use the committed file (Mode A,
  docs/operations/tenant-config-modes.md).
* file present, secret set    -> the two must describe the same config
  (compared as parsed YAML, so formatting differences are fine). If they
  differ, fail: a file that silently wins over the secret would let a
  committed or force-added tenant.yml retarget the run -- including a
  production deploy -- at another subscription or workspace.

Exit codes: 0 ok, 1 refused / missing, 2 usage error.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _parse(text: str) -> tuple[object, str | None]:
    """Return ``(parsed, error)``. Falls back to normalised text when PyYAML
    is unavailable (the e2e step runs before dependencies are installed)."""
    try:
        import yaml
    except ImportError:  # pragma: no cover - exercised only on bare runners
        return "\n".join(line.rstrip() for line in text.strip().splitlines()), None
    try:
        return yaml.safe_load(text), None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        # Location only: the YAML error text can quote the offending content.
        return None, f"not valid YAML{where}"


def materialise(target: Path, secret: str, *, env_var: str, allow_missing: bool) -> int:
    has_secret = bool(secret.strip())
    if not target.is_file():
        if has_secret:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(secret, encoding="utf-8")
            print(f"::notice::Wrote {target} from the {env_var} secret.")
            return 0
        if allow_missing:
            print(f"::notice::{target} is absent and {env_var} is empty; nothing to write.")
            return 0
        print(f"::error::{env_var} is empty and {target} is missing.")
        print(f"Pass the {env_var} secret to this step (template: config/tenant.yml.example).")
        return 1

    if not has_secret:
        print(f"::notice::Using the committed {target} ({env_var} is not set; Mode A).")
        return 0

    committed, committed_err = _parse(target.read_text(encoding="utf-8"))
    supplied, supplied_err = _parse(secret)
    if committed_err is None and supplied_err is None and committed == supplied:
        print(f"::notice::{target} matches the {env_var} secret.")
        return 0

    detail = ""
    if committed_err:
        detail = f" ({target} is {committed_err})"
    elif supplied_err:
        detail = f" (the {env_var} secret is {supplied_err})"
    print(
        f"::error::{target} is present in the checkout AND the {env_var} secret is "
        f"set, and they differ{detail}. Refusing to guess which one should win: a "
        f"committed tenant config silently overriding the secret could retarget this "
        f"run at another subscription or workspace. Use one source only -- remove "
        f"the committed file (Mode B) or stop passing the secret (Mode A). See "
        f"docs/operations/tenant-config-modes.md."
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True, type=Path,
                        help="Config file to write or check (e.g. config/tenant.yml).")
    parser.add_argument("--env-var", required=True,
                        help="Environment variable holding the secret's content.")
    parser.add_argument("--allow-missing", action="store_true",
                        help="Succeed without writing when both the file and the secret are absent.")
    args = parser.parse_args(argv)
    secret = os.environ.get(args.env_var, "")
    return materialise(args.target, secret, env_var=args.env_var,
                       allow_missing=args.allow_missing)


if __name__ == "__main__":
    sys.exit(main())
