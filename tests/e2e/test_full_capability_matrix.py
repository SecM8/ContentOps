# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""End-to-end CLI capability matrix.

One pytest case per entry in ``CAPABILITIES``. Each case:

1. Decides PASS / FAIL / SKIP based on the capability's mode set.
2. Loads any declared respx bundles in mocked mode.
3. Substitutes sandbox placeholders into the capability's argv.
4. Invokes the Click CLI via ``CliRunner``.
5. Classifies the result and records it on the session collector.
6. Asserts that the result is not FAIL — the collector's table is the
   human-readable view; pytest's exit code is the machine-readable
   one.

The test is gated by the e2e activation check in conftest. Without
``RUN_E2E=1`` or ``--mode``, every case skips.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from click.testing import CliRunner

from tests.e2e._capabilities import CAPABILITIES, Capability


def _substitute(argv: tuple[str, ...], placeholders: dict[str, str]) -> list[str]:
    """Expand ``{name}`` placeholders in argv from the sandbox map."""
    out: list[str] = []
    for token in argv:
        try:
            out.append(token.format(**placeholders))
        except KeyError as exc:
            raise KeyError(
                f"capability argv refers to unknown placeholder {exc.args[0]!r} "
                f"in token {token!r}; add it to Sandbox.placeholders.",
            ) from exc
    return out


def _classify(result: Any, cap: Capability) -> tuple[str, str]:
    """Return (status, short_message) for the collector."""
    exit_code = result.exit_code
    expected = cap.expect_exit
    if exit_code not in expected:
        # Surface the last 300 chars of output for diagnosis.
        out = (result.stdout or "") + (result.stderr or "" if hasattr(result, "stderr") else "")
        tail = out[-300:].replace("\n", " ").strip()
        return ("FAIL", f"exit={exit_code} (expected {expected}); ...{tail}")
    if cap.expect_substrings:
        out = result.stdout or ""
        for needle in cap.expect_substrings:
            if needle not in out:
                return ("FAIL", f"missing expected substring {needle!r}")
    return ("PASS", "")


@pytest.mark.parametrize(
    "cap",
    CAPABILITIES,
    ids=[c.id for c in CAPABILITIES],
)
def test_capability(
    cap: Capability,
    sandbox,
    mode: str,
    mocked_azure,
    non_destructive_guard,
    scoped_env,
    results_collector,
) -> None:
    if mode not in cap.modes:
        results_collector.record(
            cap.id, "SKIP", 0.0, f"not exercised in mode={mode}",
        )
        pytest.skip(f"capability {cap.id} not in mode={mode}")

    if mode == "mocked" and cap.mock_routes:
        from tests.e2e._mocks import load_bundles
        load_bundles(mocked_azure, cap.mock_routes)

    argv = _substitute(cap.cli, sandbox.placeholders)

    # Import the cli object lazily so the conftest's CONFIG_PATH
    # monkeypatch is already in place.
    from contentops.cli import cli

    runner = CliRunner()
    t0 = time.perf_counter()
    try:
        result = runner.invoke(cli, argv, catch_exceptions=True)
    except Exception as exc:
        duration = (time.perf_counter() - t0) * 1000.0
        results_collector.record(cap.id, "FAIL", duration, f"runner raised: {exc}")
        pytest.fail(f"{cap.id}: runner raised {exc}")
    duration = (time.perf_counter() - t0) * 1000.0

    status, message = _classify(result, cap)
    results_collector.record(cap.id, status, duration, message)

    if status == "FAIL":
        pytest.fail(
            f"{cap.id}: {message}\n"
            f"--- argv ---\n{argv}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- exception ---\n{result.exception}",
        )
