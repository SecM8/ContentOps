# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Optional `.env` loading for local development.

Production (GitHub Actions OIDC) does not use a `.env` file — credentials
arrive via federated tokens. The loader is best-effort: missing file or
missing `python-dotenv` is not an error. Process env always wins over
file values, so CI cannot be silently overridden.
"""

from __future__ import annotations

import os
from pathlib import Path


def find_dotenv(start: Path | None = None) -> Path | None:
    """Walk upward from `start` (cwd) looking for a `.env` file.

    Stops at the repo root (directory containing ``pyproject.toml`` or
    ``.git``) to avoid loading credentials from unrelated parent dirs.
    Returns the first match or None.
    """
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        env = candidate / ".env"
        if env.is_file():
            return env
        if (candidate / "pyproject.toml").exists() or (candidate / ".git").exists():
            break
    return None


def load_env_file(path: Path | None = None) -> Path | None:
    """Load environment variables from a `.env` file if one is found.

    Returns the path that was loaded, or None if no file was found or the
    `python-dotenv` dependency is not installed. Existing `os.environ`
    values are never overridden.
    """
    target = path or find_dotenv()
    if target is None:
        return None
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover — dotenv is in deps
        return None
    load_dotenv(dotenv_path=target, override=False)
    os.environ.setdefault("PIPELINE_DOTENV_LOADED", str(target))
    return target


__all__ = ["find_dotenv", "load_env_file"]
