# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Git diff helper to find changed rule files."""

from __future__ import annotations

import subprocess
from pathlib import Path


def get_changed_files(detections_dir: Path) -> list[Path]:
    """Return rule files changed in the last commit.

    Runs: git diff HEAD~1..HEAD --name-only -- detections/
    """
    result = subprocess.run(
        [
            "git", "diff", "HEAD~1..HEAD",
            "--name-only", "--", str(detections_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    paths: list[Path] = []
    for line in result.stdout.strip().splitlines():
        path = Path(line)
        if path.suffix == ".yml" and path.exists():
            paths.append(path)
    return paths
