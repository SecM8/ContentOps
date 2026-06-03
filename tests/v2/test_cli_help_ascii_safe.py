# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Click `--help` output must encode to legacy Windows console code pages.

Background: stock Windows consoles default to cp1252 (and cp437 on
older shells / when PYTHONIOENCODING is unset). Help text rendered
with characters outside those code pages -- the original culprits
were the U+2713 / U+2717 check marks in `doctor --matrix` help and
the U+2192 right-arrow in command docstrings -- raised
``UnicodeEncodeError`` on those consoles, leaving operators with a
broken ``contentops doctor --help``.

These tests walk every registered Click command and verify its
``--help`` output round-trips through ``cp1252``, ``cp437``, **and
pure ASCII**. The ASCII check is the strictest of the three: it
catches em-dashes (U+2014, which sneaks through cp1252 because
it's mapped to 0x97), en-dashes (U+2013 -> 0x96), smart quotes,
and anything else outside the 0-127 range. cp437 happens to also
reject most of these, but is a side-effect, not the contract.

Adding a new command that ships non-ASCII help text trips the test
in the same PR that introduces it.
"""

from __future__ import annotations

import click
from click.testing import CliRunner

from contentops.cli import cli


def _walk_commands(group: click.Command, prefix: tuple[str, ...] = ()):
    """Yield (argv, command) for the group and every nested command."""
    yield (list(prefix), group)
    sub = getattr(group, "commands", None)
    if not sub:
        return
    for name in sorted(sub):
        yield from _walk_commands(sub[name], prefix + (name,))


def _help_output(argv: list[str]) -> str:
    result = CliRunner().invoke(cli, [*argv, "--help"])
    assert result.exit_code == 0, (argv, result.output)
    return result.output


_ENCODINGS = ("cp1252", "cp437", "ascii")


def test_root_help_is_windows_console_safe():
    out = _help_output([])
    for enc in _ENCODINGS:
        out.encode(enc)


def test_every_command_help_is_windows_console_safe():
    """Each registered subcommand's --help encodes to cp1252, cp437, and ASCII.

    The ASCII check is the strictest: it catches em-dashes (U+2014,
    which cp1252 *accepts* at 0x97 but mangles on legacy consoles),
    en-dashes (U+2013), smart quotes, and any other codepoint > 127.
    cp437 happens to also reject most of these, but the explicit
    ASCII check makes the contract obvious.

    Failures point at the exact (argv, encoding, codepoint) so the
    diagnosis is "find that character in the source and replace it
    with ASCII".
    """
    bad: list[tuple[str, str, str]] = []
    for argv, _cmd in _walk_commands(cli):
        if not argv:
            continue  # root covered above
        out = _help_output(argv)
        for enc in _ENCODINGS:
            try:
                out.encode(enc)
            except UnicodeEncodeError as exc:
                bad.append((" ".join(argv), enc, f"U+{ord(out[exc.start]):04X}"))
    assert not bad, "non-ASCII chars in --help output: " + "; ".join(
        f"{cmd} ({enc}: {cp})" for cmd, enc, cp in bad
    )


def test_doctor_matrix_help_has_no_check_glyphs():
    """Regression pin for the U+2713 / U+2717 crash in doctor --help."""
    out = _help_output(["doctor"])
    assert "✓" not in out  # check mark
    assert "✗" not in out  # ballot x
    assert "→" not in out  # right arrow
