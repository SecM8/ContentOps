# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""`contentops new` — scaffold a valid envelope from a template.

Templates live in `contentops.templates` and are resolved through
`importlib.resources` so this command works after `pip install`.
"""

from __future__ import annotations

import re
from importlib.resources import files
from pathlib import Path
from string import Template

import yaml

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2, parse_envelope


# --- Errors ----------------------------------------------------------------


class ScaffoldError(Exception):
    """Raised when scaffolding fails for a user-fixable reason.

    Carries an `exit_code` so the CLI can surface it consistently.
    """

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# Asset kinds we generate scaffolds for. Mirrors the focused taxonomy
# in ``contentops.core.asset``.
_SUPPORTED: frozenset[Asset] = frozenset({
    Asset.SENTINEL_ANALYTIC,
    Asset.SENTINEL_HUNTING,
    Asset.SENTINEL_WATCHLIST,
    Asset.SENTINEL_PARSER,
    Asset.DEFENDER_CUSTOM_DETECTION,
})


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")


def _resolve_asset(asset: str) -> Asset:
    try:
        return Asset(asset)
    except ValueError as exc:
        valid = ", ".join(a.value for a in _SUPPORTED)
        raise ScaffoldError(
            f"unknown asset {asset!r} — supported scaffolds: {valid}",
            exit_code=2,
        ) from exc


def _template_text(asset: Asset) -> str:
    """Return template text for `asset`, or raise ScaffoldError."""
    name = f"{asset.value}.yml.tmpl"
    res = files("contentops.templates").joinpath(name)
    if not res.is_file():
        raise ScaffoldError(
            f"no template for asset {asset.value!r} (looked for {name})",
            exit_code=2,
        )
    return res.read_text(encoding="utf-8")


def _yaml_safe(value: str) -> str:
    """Escape a string for embedding inside double-quoted YAML."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _default_out_path(asset: Asset, id_: str) -> Path:
    return Path("detections") / asset.value / f"{id_}.yml"


def scaffold(
    asset: str,
    id: str,
    *,
    display_name: str | None = None,
    out: Path | None = None,
    force: bool = False,
) -> Path:
    """Generate a minimal-but-valid envelope file from a template.

    Returns the absolute path to the written file. Raises
    ``ScaffoldError`` on any user-fixable failure (bad id, unsupported
    asset, refusing to overwrite, generated file fails validation).
    """
    parsed = _resolve_asset(asset)
    if parsed not in _SUPPORTED:
        valid = ", ".join(a.value for a in _SUPPORTED)
        raise ScaffoldError(
            f"`contentops new` only scaffolds detection-class assets ({valid}); "
            f"got {asset!r}",
            exit_code=2,
        )

    if not _ID_RE.match(id):
        raise ScaffoldError(
            f"id {id!r} is invalid; must match {_ID_RE.pattern} "
            "(lowercase alnum/hyphen, no leading/trailing hyphen, len >= 2)",
            exit_code=2,
        )

    template_src = _template_text(parsed)
    rendered = Template(template_src).safe_substitute(
        id=id,
        asset=parsed.value,
        display_name=_yaml_safe(display_name or id),
    )

    # Validate before writing so we never produce a broken file on disk.
    try:
        raw = yaml.safe_load(rendered)
    except yaml.YAMLError as exc:
        raise ScaffoldError(f"rendered template is not valid YAML: {exc}") from exc
    try:
        envelope, _ = parse_envelope(raw)
        # Re-validate via the strict EnvelopeV2 to catch any drift.
        EnvelopeV2.model_validate(envelope.model_dump())
    except Exception as exc:  # pragma: no cover — defensive
        raise ScaffoldError(
            f"rendered template failed envelope validation: {exc}"
        ) from exc

    target = out if out is not None else _default_out_path(parsed, id)
    target = Path(target)
    if target.exists() and not force:
        raise ScaffoldError(
            f"refusing to overwrite existing file: {target} (use --force)",
            exit_code=1,
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered, encoding="utf-8")
    return target


__all__ = ["scaffold", "ScaffoldError"]
