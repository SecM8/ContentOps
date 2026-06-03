# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""YAML I/O helpers — load rules, split pipeline fields from payload."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Custom YAML dumper — block scalars for multiline strings, UTF-8 output
# ---------------------------------------------------------------------------


class _BlockDumper(yaml.SafeDumper):
    """SafeDumper that uses literal block style (|) for multiline strings.

    Strings with newlines or longer than ~80 chars come out as ``|``
    (literal block) so collected KQL queries are readable and copy-
    pasteable into the portal editor. Without this PyYAML falls back to
    its default flow style — ``"let X = ...\\n..."`` with ``\\n``
    escapes — which is unusable for review.
    """


def _str_representer(dumper: yaml.Dumper, data: str) -> yaml.ScalarNode:
    """Use block scalar style for multiline / long strings.

    PyYAML refuses to emit literal-block style for strings with trailing
    whitespace on any line, so we strip line-trailing whitespace first
    (the trailing space carries no semantic value in any of the YAML
    payloads we round-trip).
    """
    if "\r" in data:
        data = data.replace("\r\n", "\n").replace("\r", "\n")
    if "\n" in data or len(data) > 80:
        # Strip trailing whitespace per line — PyYAML falls back to quoted
        # style if any line has trailing spaces/tabs
        cleaned = "\n".join(line.rstrip() for line in data.split("\n"))
        # Strip trailing newlines so PyYAML uses |- (no hidden trailing newline)
        cleaned = cleaned.rstrip("\n")
        if "\n" in cleaned:
            return dumper.represent_scalar(
                "tag:yaml.org,2002:str", cleaned, style="|",
            )
        # Single-line but long: leave as default scalar (no folding
        # because we set width=4096 on the dump call).
        return dumper.represent_scalar("tag:yaml.org,2002:str", cleaned)
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_BlockDumper.add_representer(str, _str_representer)


def dump_envelope_yaml(envelope: dict[str, Any]) -> str:
    """Serialise an envelope dict using the block-scalar dumper.

    Used by ``contentops collect`` and ``contentops drift --write`` to
    produce human-readable YAML — multi-line KQL queries come out as
    ``query: |`` literal blocks rather than double-quoted strings with
    ``\\n`` escapes.
    """
    return yaml.dump(
        envelope,
        Dumper=_BlockDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=4096,
    )


def _sanitize_filename(name: str) -> str:
    """Sanitize a displayName into a safe filename (preserving readability)."""
    # Replace characters illegal in filenames
    sanitized = re.sub(r'[<>:"/\\|?*]', "-", name)
    # Collapse multiple spaces/dashes
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


# ---------------------------------------------------------------------------
# Core I/O
# ---------------------------------------------------------------------------


def load_yaml(path: Path, *, default: Any = None) -> Any:
    """Read and ``safe_load`` a YAML file.

    Returns the parsed document, or ``default`` when the file parses to
    ``None`` (empty or comments-only). Centralises the
    ``yaml.safe_load(path.read_text(encoding="utf-8"))`` boilerplate that
    recurs across config loaders. Callers that want falsy-collapse (e.g.
    a top-level list → ``{}``) keep their own ``or {}`` at the call site.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return default if raw is None else raw


def load_rule(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load a YAML rule file and return (pipeline_fields, api_payload)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    pipeline_fields = {
        "id": raw["id"],
        "version": raw["version"],
        "platform": raw["platform"],
        "status": raw["status"],
    }
    payload = raw[raw["platform"]]
    return pipeline_fields, payload


def to_sentinel_body(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert a Sentinel payload to the ARM API request body.

    Extracts `kind` to top level, everything else into `properties`.
    """
    body = copy.deepcopy(payload)
    kind = body.pop("kind")
    return {"kind": kind, "properties": body}


def to_defender_body(payload: dict[str, Any]) -> dict[str, Any]:
    """Defender payload is already the API body — pass through."""
    return payload


def dump_rule(
    path: Path,
    pipeline_fields: dict[str, Any],
    payload: dict[str, Any],
) -> None:
    """Write a rule to a YAML file with block scalars and UTF-8 encoding."""
    data = {
        "id": pipeline_fields["id"],
        "version": pipeline_fields["version"],
        "platform": pipeline_fields["platform"],
        "status": pipeline_fields["status"],
        pipeline_fields["platform"]: payload,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.dump(
            data,
            Dumper=_BlockDumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )


def is_template_path(path: Path) -> bool:
    """Return True if the path is inside a templates directory."""
    return "/templates/" in str(path) or "\\templates\\" in str(path)


def discover_rules(base: Path) -> list[Path]:
    """Discover all deployable rule files under sentinel/ and defender/ dirs.

    Skips any path containing /templates/.
    """
    rules: list[Path] = []
    for platform_dir in ("sentinel", "defender"):
        search_dir = base / platform_dir
        if search_dir.is_dir():
            for yml_path in sorted(search_dir.rglob("*.yml")):
                if not is_template_path(yml_path):
                    rules.append(yml_path)
    return rules
