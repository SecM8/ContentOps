# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""scripts/materialise_tenant_config.py — a committed tenant.yml never
silently overrides the TENANT_CONFIG_YAML secret.

Mode A (committed file, no secret) and Mode B (secret, no file) keep
working; file + secret must describe the same config.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "materialise_tenant_config", REPO_ROOT / "scripts" / "materialise_tenant_config.py",
)
mtc = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(mtc)

SECRET = """\
tenant:
  name: contoso
  tenantId: 00000000-0000-0000-0000-000000000001
  sentinelWorkspaces:
    - workspaceName: law-prod
      role: prod
"""
# Same content, different formatting / key order.
SECRET_REFORMATTED = """\
tenant:
  tenantId: "00000000-0000-0000-0000-000000000001"
  name: contoso
  sentinelWorkspaces: [{role: prod, workspaceName: law-prod}]
"""
OTHER = SECRET.replace("law-prod", "law-attacker")


def _run(tmp_path: Path, monkeypatch, *, file: str | None, secret: str,
         allow_missing: bool = False) -> tuple[int, Path]:
    target = tmp_path / "config" / "tenant.yml"
    if file is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file, encoding="utf-8")
    monkeypatch.setenv("TENANT_CONFIG_YAML", secret)
    argv = ["--target", str(target), "--env-var", "TENANT_CONFIG_YAML"]
    if allow_missing:
        argv.append("--allow-missing")
    return mtc.main(argv), target


def test_writes_the_secret_when_no_file(tmp_path, monkeypatch, capsys) -> None:
    rc, target = _run(tmp_path, monkeypatch, file=None, secret=SECRET)
    assert rc == 0
    assert target.read_text(encoding="utf-8") == SECRET
    assert "law-prod" not in capsys.readouterr().out


def test_missing_file_and_secret_fails(tmp_path, monkeypatch) -> None:
    rc, target = _run(tmp_path, monkeypatch, file=None, secret="")
    assert rc == 1
    assert not target.exists()


def test_missing_file_and_secret_allowed_when_optional(tmp_path, monkeypatch) -> None:
    rc, target = _run(tmp_path, monkeypatch, file=None, secret="", allow_missing=True)
    assert rc == 0
    assert not target.exists()


def test_committed_file_without_secret_is_mode_a(tmp_path, monkeypatch) -> None:
    rc, target = _run(tmp_path, monkeypatch, file=SECRET, secret="")
    assert rc == 0
    assert target.read_text(encoding="utf-8") == SECRET


def test_committed_file_matching_the_secret_passes(tmp_path, monkeypatch) -> None:
    rc, _ = _run(tmp_path, monkeypatch, file=SECRET_REFORMATTED, secret=SECRET)
    assert rc == 0


def test_committed_file_differing_from_the_secret_fails_loudly(
    tmp_path, monkeypatch, capsys,
) -> None:
    rc, target = _run(tmp_path, monkeypatch, file=OTHER, secret=SECRET)
    out = capsys.readouterr().out
    assert rc == 1
    assert "::error::" in out and "differ" in out
    # Neither config's content is echoed into the log.
    assert "law-prod" not in out and "law-attacker" not in out
    # The committed file is left as-is (the run stops instead).
    assert target.read_text(encoding="utf-8") == OTHER


def test_invalid_yaml_secret_reports_location_only(tmp_path, monkeypatch, capsys) -> None:
    rc, _ = _run(tmp_path, monkeypatch, file=SECRET,
                 secret="tenant: [unclosed, secret-value-xyz\n")
    out = capsys.readouterr().out
    assert rc == 1
    assert "not valid YAML" in out
    assert "secret-value-xyz" not in out


@pytest.mark.parametrize("flag", [[], ["--allow-missing"]])
def test_usage_requires_target_and_env_var(flag) -> None:
    with pytest.raises(SystemExit) as excinfo:
        mtc.main(flag)
    assert excinfo.value.code == 2
