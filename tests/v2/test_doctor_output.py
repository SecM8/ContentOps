# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pin the ContentOps branding in ``format_results`` text output.

``contentops.devex.doctor.format_results`` renders the doctor report
header. These tests deliberately do NOT snapshot the full doctor
output — that would couple to terminal width, color escapes, and the
exact set of registered checks. They pin only:

* the header line uses the ``contentops doctor`` brand;
* the JSON output schema is unchanged (``exit_code`` + ``checks``,
  with the same per-check keys), so downstream JSON consumers
  (CI, ``doctor --format json``, the ``doctor --fix`` summary)
  cannot break silently when the header is reworded again.
"""

from __future__ import annotations

import json

from contentops.devex.doctor import CheckResult, format_results


def test_text_header_uses_contentops_branding() -> None:
    """Header line is the first thing every operator sees — must use
    the canonical ``contentops`` brand. Casefold-compared so a future
    PR that reformats the header (e.g. title-case ``ContentOps``)
    still satisfies the pin without manual rewording."""
    out = format_results(
        [CheckResult("python_version", "PASS", "3.12.10")],
        json_out=False,
        color=False,
    )
    assert "contentops doctor" in out.casefold(), out


def test_json_schema_unchanged_by_branding_polish() -> None:
    """The JSON output is a stable contract for CI and tooling. The
    header rename touches only the human-readable text path; JSON
    must still be ``{"exit_code": int, "checks": [...]}`` with the
    same per-check keys (``name``, ``status``, ``detail``)."""
    results = [
        CheckResult("python_version", "PASS", "3.12.10"),
        CheckResult("auth_env", "WARN", "AZURE_TENANT_ID=unset"),
    ]
    payload = json.loads(format_results(results, json_out=True))
    assert payload["exit_code"] == 0
    assert isinstance(payload["checks"], list)
    assert {"name", "status", "detail"} <= set(payload["checks"][0])


def test_dotenv_warn_message_mentions_contentops() -> None:
    """The ``dotenv`` WARN detail tells the operator how to load the
    file — must reference the canonical ``contentops`` invocation."""
    from contentops.devex import doctor as doctor_mod

    src = doctor_mod._check_dotenv.__code__.co_consts
    text = " ".join(c for c in src if isinstance(c, str))
    assert "contentops" in text, text
