# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""One-shot migrator: legacy single-workspace schema → multi-workspace schema.

Old shape (v2)::

    tenant:
      name: production
      tenantId: ...
      sentinel:
        subscriptionId: ...
        resourceGroup: ...
        workspaceName: ...
        location: westeurope
      defender:
        enabled: true

New shape (v3)::

    tenant:
      name: production
      tenantId: ...
      defender:
        enabled: true
      sentinelWorkspaces:
        - role: prod
          subscriptionId: ...
          resourceGroup: ...
          workspaceName: ...
          location: westeurope

Usage::

    python scripts/migrate_tenant_config.py config/tenant.yml
    python scripts/migrate_tenant_config.py config/tenant.yml --dry-run

The script is idempotent — running it on an already-migrated file is a
no-op (exit 0, no write).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def migrate(raw: dict) -> tuple[dict, bool]:
    """Return (new_doc, changed) tuple.

    ``changed`` is False when the file is already in the new shape.
    """
    tenant = raw.get("tenant")
    if not isinstance(tenant, dict):
        raise ValueError("expected top-level `tenant:` block")

    if "sentinelWorkspaces" in tenant and "sentinel" not in tenant:
        return raw, False  # already migrated

    if "sentinel" not in tenant:
        # No sentinel block at all — also migrated (or never had one).
        tenant.setdefault("sentinelWorkspaces", [])
        return raw, False

    sentinel_block = tenant.pop("sentinel")
    workspace = {
        "role": "prod",
        "subscriptionId": sentinel_block["subscriptionId"],
        "resourceGroup": sentinel_block["resourceGroup"],
        "workspaceName": sentinel_block["workspaceName"],
        "location": sentinel_block.get("location", "westeurope"),
    }
    # Reorder: name, tenantId, defender (if present), sentinelWorkspaces
    new_tenant = {"name": tenant["name"], "tenantId": tenant["tenantId"]}
    if "defender" in tenant:
        new_tenant["defender"] = tenant["defender"]
    new_tenant["sentinelWorkspaces"] = [workspace]
    # Preserve any other unrecognised keys at the end.
    for k, v in tenant.items():
        if k not in {"name", "tenantId", "defender", "sentinelWorkspaces"}:
            new_tenant[k] = v
    return {"tenant": new_tenant}, True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="tenant config YAML to migrate")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the new YAML to stdout instead of writing in place.",
    )
    args = parser.parse_args(argv)

    raw = yaml.safe_load(args.path.read_text(encoding="utf-8"))
    new_doc, changed = migrate(raw)
    rendered = yaml.dump(
        new_doc, default_flow_style=False, sort_keys=False, allow_unicode=True,
    )
    if not changed:
        print(f"{args.path}: already in v3 shape (no change)", file=sys.stderr)
        if args.dry_run:
            sys.stdout.write(rendered)
        return 0
    if args.dry_run:
        sys.stdout.write(rendered)
        print(f"\n# (dry-run — would write to {args.path})", file=sys.stderr)
    else:
        args.path.write_text(rendered, encoding="utf-8")
        print(f"migrated: {args.path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
