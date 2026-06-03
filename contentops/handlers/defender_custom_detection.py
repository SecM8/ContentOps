# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Defender XDR custom detection handler.

Wraps v1's `contentops.defender.deploy`. Defender upserts by displayName,
so this handler relies on a per-apply name→graph-id map built lazily.

Note on concurrency: the Microsoft Graph Security Beta API does NOT
expose ARM-style ``etag`` / ``If-Match`` semantics for detection rules,
so this handler performs **post-apply content-hash verification only**
— the sentinel handlers additionally use ``If-Match`` for optimistic
concurrency control.
"""

from __future__ import annotations

import logging
import re
from typing import Callable

import click

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.defender.client import DefenderClient
from contentops.defender.deploy import build_display_name_map, deploy_defender_rule
from contentops.handlers._verify import compute_content_hash, hash_mismatch_error
from contentops.models import validate_defender_payload
from contentops.utils.yaml_io import to_defender_body

logger = logging.getLogger(__name__)

_SERVER_FIELDS = (
    "id", "createdDateTime", "lastModifiedDateTime",
    "createdBy", "lastModifiedBy", "lastExecutionDateTime",
    # Graph beta returns these on every GET; they're never authored
    # in YAML. Without stripping them, every defender rule shows
    # `changed` in drift forever (G2 in docs/reference/gap-assessment.md).
    "detectorId", "lastRunDetails",
)

# Nested server-set timestamps. Same shape as v1's
# contentops.defender.collect.READ_ONLY_NESTED — kept aligned so the
# v1-collected local YAML and the v2 drift round-trip produce the
# same payload dict.
_SERVER_NESTED_FIELDS: dict[str, frozenset[str]] = {
    "queryCondition": frozenset({"lastModifiedDateTime"}),
    "schedule": frozenset({"nextRunDateTime"}),
}

_HASHED_FIELDS = [
    "displayName",
    "queryCondition.queryText",
    "schedule",
    "actions",
    "detectionAction.alertTemplate.severity",
    "detectionAction.alertTemplate.title",
    "detectionAction.alertTemplate.category",
]


def _strip_server_fields(remote: dict) -> dict:
    """Remove fields the API server-sets and that we never author in YAML.

    Used in two phases that MUST see the same canonical body:

    * Collect (``to_envelope``): produces the YAML payload that goes on
      disk. Stripping these here keeps drift quiet.
    * Apply verify: after a PUT, the server's GET response includes the
      same managed fields refreshed (e.g. ``schedule.nextRunDateTime``
      moves forward every minute). The pre-PUT body we hashed against
      already had them stripped at collect time — so without stripping
      the post-PUT GET too, ``got_hash != sent_hash`` for every rule
      forever, regardless of whether anything actually changed.

    The two strip layers are:
      1. Top-level keys in ``_SERVER_FIELDS`` (id, timestamps, run
         metadata).
      2. Nested keys listed in ``_SERVER_NESTED_FIELDS`` (currently
         ``queryCondition.lastModifiedDateTime`` and
         ``schedule.nextRunDateTime``).
    """
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    for parent, nested in _SERVER_NESTED_FIELDS.items():
        block = cleaned.get(parent)
        if isinstance(block, dict):
            cleaned[parent] = {k: v for k, v in block.items() if k not in nested}
    return cleaned


def _slugify_defender_id(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")
    return f"defender-{slug}" if slug else "defender-unknown"


class DefenderCustomDetectionHandler:
    asset = Asset.DEFENDER_CUSTOM_DETECTION

    def __init__(self, client_factory: Callable[[], DefenderClient | None]) -> None:
        self._client_factory = client_factory
        self._client: DefenderClient | None = None
        self._name_map: dict[str, str] | None = None

    def _client_or_create(self) -> DefenderClient | None:
        if self._client is None:
            self._client = self._client_factory()
        return self._client

    def _name_map_or_build(self, dry_run: bool) -> dict[str, str]:
        """Return the display-name → graph-id map for this apply run.

        Real apply (dry_run=False): always fetched, the map drives the
        update-vs-create decision and the etag-less re-PUT path.

        Dry-run (dry_run=True): O.3 best-effort. Try to fetch so the
        action label distinguishes `create` from `update`. On any
        failure (no auth, transient Graph 5xx, etc.) fall back to an
        empty map so the dry-run still completes — the label just
        defaults to `create` as the pre-O.3 behaviour did. Trading
        ~1 extra Graph API call per Defender handler invocation for
        accurate operator-facing labels.
        """
        if self._name_map is not None:
            return self._name_map
        if dry_run:
            try:
                client = self._client_or_create()
                if client is None:
                    # Factory returned None — legacy dry-run shim.
                    self._name_map = {}
                else:
                    self._name_map = build_display_name_map(client)
            except Exception as exc:
                logger.debug(
                    "dry-run name-map fetch failed (label defaults to "
                    "'create'): %s", exc,
                )
                self._name_map = {}
        else:
            client = self._client_or_create()
            assert client is not None
            self._name_map = build_display_name_map(client)
        return self._name_map

    def validate(self, loaded: LoadedAsset) -> None:
        validate_defender_payload(loaded.payload)

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.SKIP,
                status="planned",
                detail="experimental status — skipped",
            )
        # Without remote state we can't tell create vs update; report UPDATE generically.
        action = PlanAction.DISABLE if loaded.envelope.status == "deprecated" else PlanAction.UPDATE
        return ActionResult(
            asset_id=loaded.envelope.id,
            asset_kind=self.asset.value,
            action=action,
            status="planned",
        )

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.SKIP,
                status="skipped",
                detail="experimental",
            )
        client = None if dry_run else self._client_or_create()
        name_map = self._name_map_or_build(dry_run)

        action_map = {
            "create": PlanAction.CREATE,
            "created": PlanAction.CREATE,
            "update": PlanAction.UPDATE,
            "updated": PlanAction.UPDATE,
            "disabled": PlanAction.DISABLE,
            "skipped": PlanAction.SKIP,
        }

        if dry_run:
            result = deploy_defender_rule(
                client, loaded.envelope.id, loaded.payload,
                loaded.envelope.status, name_map, dry_run=True,
            )
            return ActionResult(
                asset_id=result["id"],
                asset_kind=self.asset.value,
                action=action_map.get(result["action"], PlanAction.UPDATE),
                status=result["result"],
            )

        # Build the body the same way deploy_defender_rule does so the
        # sent-hash matches what actually goes over the wire.
        assert client is not None
        body = to_defender_body(loaded.payload)
        if loaded.envelope.status == "deprecated":
            body["isEnabled"] = False
        display_name = body.get("displayName", "")
        sent_hash = compute_content_hash(body, _HASHED_FIELDS)

        graph_id = name_map.get(display_name)
        if graph_id:
            response = client.update_rule(graph_id, body)
            if response.status_code != 200:
                logger.error(
                    "Failed to update defender rule %s: %s %s",
                    loaded.envelope.id, response.status_code, response.text,
                )
                return ActionResult(
                    asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                    action=PlanAction.UPDATE,
                    status=f"error-{response.status_code}",
                    detail=response.text[:200],
                    verified=False, error=response.text[:200],
                )
            action = PlanAction.DISABLE if loaded.envelope.status == "deprecated" else PlanAction.UPDATE
            click.echo(f"  {action.value}: {loaded.envelope.id} (graph:{graph_id})")
        else:
            response = client.create_rule(body)
            if response.status_code != 201:
                logger.error(
                    "Failed to create defender rule %s: %s %s",
                    loaded.envelope.id, response.status_code, response.text,
                )
                return ActionResult(
                    asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                    action=PlanAction.CREATE,
                    status=f"error-{response.status_code}",
                    detail=response.text[:200],
                    verified=False, error=response.text[:200],
                )
            action = PlanAction.CREATE
            try:
                graph_id = str((response.json() or {}).get("id") or "")
            except ValueError as exc:
                # Graph occasionally returns non-JSON on transient gateway
                # 5xx. Don't silently coerce to "" — the post-apply GET
                # then 404s and reports the wrong root cause ("post-apply
                # GET returned 404"). Log the real failure with a short
                # body excerpt so the operator can triage.
                logger.error(
                    "Defender create returned non-JSON for %s: %s; body=%s",
                    loaded.envelope.id, exc, response.text[:200],
                )
                graph_id = ""
            click.echo(f"  {action.value}: {loaded.envelope.id}")

        # Post-apply content-hash verification.
        remote: dict | None = None
        if graph_id:
            try:
                remote = client.get_rule(graph_id)
            except Exception as exc:  # pragma: no cover — defensive
                err = f"post-apply GET failed: {exc}"
                return ActionResult(
                    asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                    action=action, status="success", detail=err,
                    verified=False, error=err,
                )
        if remote is None:
            err = "post-apply GET returned 404"
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )
        # Strip the same server-managed fields we strip at collect time
        # so the post-apply hash sees the same canonical body the pre-PUT
        # hash was computed over. Without this, every Defender rule
        # reports MISMATCH because schedule.nextRunDateTime moves between
        # PUT and the verifying GET. See `_strip_server_fields` for the
        # rationale.
        got_hash = compute_content_hash(_strip_server_fields(remote), _HASHED_FIELDS)
        if got_hash != sent_hash:
            err = hash_mismatch_error(sent_hash, got_hash)
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )

        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=action, status="success", verified=True,
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def delete(self, remote_id: str) -> ActionResult:
        """DELETE one Defender custom detection by Graph id.

        ``remote_id`` here is the Graph-assigned ``id`` of the rule,
        NOT the displayName-derived envelope id. Prune resolves the
        Graph id via list_remote() before invoking delete.
        """
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        client = self._client_or_create()
        if client is None:
            raise NotSupportedError("defender_custom_detection delete requires a DefenderClient")
        try:
            response = client.delete_rule(remote_id)
        except Exception as exc:  # pragma: no cover
            return delete_result_from_exception(remote_id, self.asset, exc)
        return delete_result_from_response(remote_id, self.asset, response)

    # --- Drift support -------------------------------------------------

    def list_remote(self) -> list[dict]:
        client = self._client_or_create()
        if client is None:
            return []
        return client.list_rules()

    def to_envelope(self, remote: dict) -> dict | None:
        from contentops.utils.slug import displayname_slug

        display_name = remote.get("displayName")
        if not display_name:
            return None
        # Same strip the apply path uses for hash verification — keeps
        # collect-time YAML and post-apply GET projections aligned. See
        # `_strip_server_fields` for the full list (top-level server
        # fields like id/timestamps plus nested ones like
        # schedule.nextRunDateTime / queryCondition.lastModifiedDateTime).
        payload = _strip_server_fields(remote)
        is_enabled = remote.get("isEnabled", True)
        graph_id = str(remote.get("id") or "")
        envelope_id = displayname_slug(display_name, fallback_id=graph_id)
        if not envelope_id:
            return None
        envelope: dict = {
            "id": envelope_id,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.DEFENDER_CUSTOM_DETECTION.value,
            "status": "production" if is_enabled else "deprecated",
            "metadata": {"arm_name": graph_id} if graph_id else {},
            "payload": payload,
        }
        return envelope
