# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel watchlist handler — ARM upsert via SentinelArmProvider.

This is the v2-native handler that exercises the full new architecture
(envelope → loaded asset → handler → provider → ARM).

Post-apply verification (W4.5-A + W4.5-B):

* Envelope verification (W4.5-A): re-fetch the watchlist resource and
  compare a hash projection of stable envelope fields.
* Item-count verification (W4.5-B): when the payload includes
  ``rawContent``, additionally GET the ``watchlistItems`` sub-resource
  and assert the actual remote item count matches the count of data
  rows derived from ``rawContent`` (header + ``numberOfLinesToSkip``
  excluded, blank lines ignored).

Cell-level item content equality is intentionally NOT checked yet —
ARM normalizes watchlist items in ways that are not stable enough for
hash comparison without false positives. Count-based ingestion
verification is a deliberate first step; full item hashing is a later
hardening pass.
"""

from __future__ import annotations

import logging
from typing import Callable

import click

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.handlers._verify import (
    ETAG_CONFLICT_MESSAGE,
    compute_content_hash,
    extract_etag,
    hash_mismatch_error,
)
from contentops.handlers.sentinel_watchlist_models import (
    SentinelWatchlistPayload,
    to_watchlist_arm_body,
)
from contentops.providers.sentinel_arm import SentinelArmProvider

logger = logging.getLogger(__name__)

WATCHLIST_RESOURCE = "watchlists"


def _alias_to_envelope_id(alias: str) -> str | None:
    """Slug a watchlist alias to a lowercase envelope id.

    Watchlist aliases in Sentinel can be mixed case (CamelCase is
    common in production); the envelope id regex is lowercase only.
    Slugging here keeps the round-trip stable while preserving the
    original alias on the payload's ``watchlistAlias`` field for the
    apply path.
    """
    import re as _re
    slug = _re.sub(r"[^a-z0-9]+", "-", alias.lower()).strip("-")
    if len(slug) < 2:
        return None
    if not _re.match(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$", slug):
        return None
    return slug

_HASHED_FIELDS = [
    "properties.displayName",
    "properties.itemsSearchKey",
    "properties.provider",
    "properties.contentType",
]

# Server-managed fields stripped before round-trip diff so the
# diagnostic shows the same canonical view ``apply`` would hash. The
# inline strip in ``to_envelope`` mirrors this set; keeping it module-
# level lets the new ``sentinel-roundtrip-diff`` diagnostic share the
# definition.
_SERVER_FIELDS = ("etag", "type", "systemData")
_SERVER_PROPERTY_FIELDS: dict[str, frozenset[str]] = {
    "properties": frozenset({
        "etag", "created", "updated", "createdBy", "updatedBy",
        "watchlistId", "tenantId", "watchlistAlias", "isDeleted",
        "provisioningState",
        # ``itemsCount`` is server-computed after item ingestion;
        # ``numberOfLinesToSkip`` is operator-authored but the
        # to_envelope path drops the ``== 0`` no-op default.
        # Including both here makes the strip set the canonical
        # description of "ARM-managed, not authored" so any future
        # _HASHED_FIELDS addition can't silently produce false
        # positives. Found in PR #142 review (M2).
        "itemsCount", "numberOfLinesToSkip",
    }),
}


def _strip_server_fields(remote: dict) -> dict:
    """Return ``remote`` with server-managed fields removed (defensive copy)."""
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    for parent, nested in _SERVER_PROPERTY_FIELDS.items():
        block = cleaned.get(parent)
        if isinstance(block, dict):
            cleaned[parent] = {k: v for k, v in block.items() if k not in nested}
    return cleaned


def _expected_item_count(raw_content: str, number_of_lines_to_skip: int = 0) -> int:
    """Compute expected watchlist item count from inline ``rawContent``.

    Rules (mirroring ARM watchlist ingestion semantics):
      * Split on newlines.
      * Drop the first ``number_of_lines_to_skip`` lines unconditionally
        (these are file preamble lines, e.g. comments).
      * The next non-blank line is the header row and is not an item.
      * Remaining lines are data rows; blank / whitespace-only lines are
        ignored (ARM does not ingest empty CSV rows).
    """
    if not raw_content:
        return 0
    lines = raw_content.splitlines()
    if number_of_lines_to_skip > 0:
        lines = lines[number_of_lines_to_skip:]
    # Drop a single header row (the first non-blank line after skips).
    header_dropped = False
    data_rows = 0
    for line in lines:
        if not line.strip():
            continue
        if not header_dropped:
            header_dropped = True
            continue
        data_rows += 1
    return data_rows


def _item_count_mismatch_error(expected: int, actual: int) -> str:
    return (
        f"post-apply item-count mismatch: expected={expected} actual={actual} "
        "(rawContent rows vs. remote watchlistItems)"
    )


def _item_fetch_error(detail: str) -> str:
    return f"post-apply watchlistItems GET failed: {detail}"


class SentinelWatchlistHandler:
    asset = Asset.SENTINEL_WATCHLIST

    def __init__(self, provider_factory: Callable[[], SentinelArmProvider | None]) -> None:
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    def validate(self, loaded: LoadedAsset) -> None:
        SentinelWatchlistPayload(**loaded.payload)

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.SKIP,
                status="planned",
                detail="experimental status — skipped",
            )
        # Watchlists do not have an enabled flag; deprecated => DELETE intent
        # is left to a separate `prune` workflow per DESIGN §8.
        if loaded.envelope.status == "deprecated":
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.SKIP,
                status="planned",
                detail="deprecated watchlists are not deleted by deploy; use `prune`",
            )
        return ActionResult(
            asset_id=loaded.envelope.id,
            asset_kind=self.asset.value,
            action=PlanAction.UPDATE,
            status="planned",
        )

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        plan = self.plan(loaded)
        if plan.action is PlanAction.SKIP:
            click.echo(f"  skipped ({plan.detail}): {loaded.envelope.id}")
            return ActionResult(
                asset_id=plan.asset_id, asset_kind=plan.asset_kind,
                action=plan.action, status="skipped", detail=plan.detail,
            )

        # Guard: a watchlist with neither inline rawContent nor a sasUri
        # has nothing to ingest. Schema-time validation accepts this
        # shape (because that's what comes back from a collect GET — the
        # API doesn't echo the CSV body), but applying it would PUT a
        # content-less watchlist which is never the intent. Skip with a
        # clear message rather than calling the API.
        raw = loaded.payload.get("rawContent")
        sas = loaded.payload.get("sasUri")
        if not raw and not sas:
            err = (
                "watchlist has neither rawContent nor sasUri set. "
                "This envelope was almost certainly produced by `contentops collect` "
                "(the API doesn't return CSV bodies on GET, so collected watchlists "
                "are intentionally not deployable). To deploy, populate rawContent "
                "with the CSV body or sasUri with a SAS-protected blob URL."
            )
            click.echo(f"  skipped (no-content): {loaded.envelope.id}", err=True)
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="skipped", detail=err,
            )

        body = to_watchlist_arm_body(loaded.payload)
        # Honour the original alias on collected envelopes; otherwise
        # the envelope id (slugified lowercase) is the alias.
        watchlist_name = loaded.payload.get("watchlistAlias") or loaded.envelope.id
        if dry_run:
            click.echo(f"  [DRY-RUN] Would PUT watchlist: {watchlist_name}")
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="dry-run",
            )

        provider = self._provider_or_create()
        if provider is None:
            # H-5: was ``assert provider is not None``; assertions are
            # stripped under ``python -O`` and silently turn live-apply
            # misconfigurations into AttributeErrors on the next line.
            # Match the explicit raise in sentinel_analytic.apply().
            raise RuntimeError(
                f"sentinel_watchlist {loaded.envelope.id!r}: "
                "SentinelArmProvider factory returned None during a "
                "non-dry-run apply. Check auth / tenant config — this is "
                "a misconfiguration, not a per-rule error."
            )

        # GET first to capture etag for optimistic concurrency.
        # ``extract_etag`` is the shared helper that handles both
        # top-level and properties-nested placements; see _verify.py.
        existing = provider.get_resource(WATCHLIST_RESOURCE, watchlist_name)
        etag: str | None = extract_etag(existing)

        sent_hash = compute_content_hash(body, _HASHED_FIELDS)
        headers = {"If-Match": etag} if etag else None
        response = provider.request(
            "PUT",
            provider.resource_url(WATCHLIST_RESOURCE, watchlist_name),
            json=body, headers=headers,
        )

        if response.status_code == 412:
            click.echo(f"  etag-conflict: {loaded.envelope.id}", err=True)
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="error-412",
                detail=ETAG_CONFLICT_MESSAGE,
                verified=False, error=ETAG_CONFLICT_MESSAGE,
            )

        if response.status_code not in (200, 201):
            logger.error(
                "Failed to deploy watchlist %s: %s %s",
                loaded.envelope.id, response.status_code, response.text,
            )
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status=f"error-{response.status_code}",
                detail=response.text[:200],
                verified=False, error=response.text[:200],
            )

        action = PlanAction.CREATE if response.status_code == 201 else PlanAction.UPDATE
        click.echo(f"  {action.value}: {loaded.envelope.id}")

        verified_remote = provider.get_resource(WATCHLIST_RESOURCE, watchlist_name)
        if verified_remote is None:
            err = "post-apply GET returned 404"
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )
        got_hash = compute_content_hash(verified_remote, _HASHED_FIELDS)
        if got_hash != sent_hash:
            err = hash_mismatch_error(sent_hash, got_hash)
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )

        # W4.5-B: item-count verification. Only meaningful when we sent
        # inline rawContent; SAS-URI sourced watchlists are deferred and
        # remote-only items (manually added) are not in scope here.
        raw_content = loaded.payload.get("rawContent")
        if raw_content:
            expected = _expected_item_count(
                raw_content,
                int(loaded.payload.get("numberOfLinesToSkip") or 0),
            )
            try:
                items_response = provider.request(
                    "GET",
                    provider.resource_url(
                        f"{WATCHLIST_RESOURCE}/{watchlist_name}/watchlistItems"
                    ),
                )
            except Exception as exc:  # pragma: no cover - defensive
                err = _item_fetch_error(str(exc))
                return ActionResult(
                    asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                    action=action, status="success", detail=err,
                    verified=False, error=err,
                )
            if items_response.status_code != 200:
                err = _item_fetch_error(
                    f"{items_response.status_code} {items_response.text[:160]}"
                )
                return ActionResult(
                    asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                    action=action, status="success", detail=err,
                    verified=False, error=err,
                )
            try:
                items_payload = items_response.json()
            except ValueError as exc:
                err = _item_fetch_error(f"invalid JSON: {exc}")
                return ActionResult(
                    asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                    action=action, status="success", detail=err,
                    verified=False, error=err,
                )
            actual = len(items_payload.get("value") or [])
            if actual != expected:
                err = _item_count_mismatch_error(expected, actual)
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
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def delete(self, remote_id: str) -> ActionResult:
        """DELETE one watchlist by alias (envelope.id == ARM resource name)."""
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        provider = self._provider_or_create()
        if provider is None:
            raise NotSupportedError("sentinel_watchlist delete requires a SentinelArmProvider")
        try:
            response = provider.delete_resource(WATCHLIST_RESOURCE, remote_id)
        except Exception as exc:  # pragma: no cover
            return delete_result_from_exception(remote_id, self.asset, exc)
        return delete_result_from_response(remote_id, self.asset, response)

    # --- Drift support -------------------------------------------------

    def list_remote(self) -> list[dict]:
        provider = self._provider_or_create()
        if provider is None:
            return []
        return provider.list_resource(WATCHLIST_RESOURCE)

    def to_envelope(self, remote: dict) -> dict | None:
        name = remote.get("name")
        if not name:
            return None
        properties: dict = dict(remote.get("properties") or {})

        # The watchlist *list* endpoint omits rawContent (size optimisation);
        # to get the full body we GET the individual resource. Catch only
        # the no-tenant-config case (test context); network/auth failures
        # used to be silently coerced to "no change", which let a
        # transient ARM 5xx hide a real divergence — they now propagate
        # so drift surfaces the error rather than reporting a clean diff
        # against truncated data.
        if "rawContent" not in properties or not properties.get("rawContent"):
            try:
                provider = self._provider_or_create()
            except FileNotFoundError:
                # No tenant.yml — unit-test context. Skip the full fetch
                # and use whatever the list-endpoint gave us.
                provider = None
            if provider is not None:
                full = provider.get_resource(WATCHLIST_RESOURCE, name)
                if full is not None:
                    properties = dict(full.get("properties") or {})

        for k in (
            "etag", "created", "updated", "createdBy", "updatedBy",
            "watchlistId", "tenantId", "watchlistAlias", "isDeleted",
            "provisioningState",
            # ``sasUri`` is the operator's one-time upload URL for the
            # large-watchlist SAS path (docs/assets/sentinel_watchlist_sas.md).
            # ARM returns it on subsequent GETs; collecting and committing
            # it would leak a write-capable, time-limited credential into
            # the repo. The upload URL is re-derivable at deploy time
            # from the watchlist source path, so dropping it here is safe.
            "sasUri",
        ):
            properties.pop(k, None)
        if properties.get("numberOfLinesToSkip") == 0:
            properties.pop("numberOfLinesToSkip", None)

        # Watchlist aliases in production are commonly CamelCase
        # (AutoClose, EntraPrivilegedGroups, ...) but the envelope id
        # regex is lowercase-only. Slug to lowercase + hyphens for the
        # envelope id, AND preserve the original alias in the payload
        # under ``watchlistAlias`` so applying re-creates the right
        # remote name. Round-trip via drift compares envelope ids
        # (deterministic) without needing the original case.
        envelope_id = _alias_to_envelope_id(name)
        if envelope_id is None:
            return None
        if envelope_id != name:
            properties.setdefault("watchlistAlias", name)

        return {
            "id": envelope_id,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.SENTINEL_WATCHLIST.value,
            "status": "production",
            "payload": properties,
        }
