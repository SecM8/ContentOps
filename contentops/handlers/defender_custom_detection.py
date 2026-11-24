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
import time
from typing import Callable

import click

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.defender import rule_compare, rule_status
from contentops.defender.client import DefenderClient
from contentops.defender.deploy import (
    alert_title,
    build_rule_index,
    deploy_defender_rule,
    record_graph_id,
    resolve_graph_id,
    title_conflict_message,
)
from contentops.defender.rule_shape import to_current_shape
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

# Kept for ``contentops defender-roundtrip-diff`` only. Apply no longer
# decides "changed or not" on these seven paths: it compares field by
# field through ``contentops.defender.rule_compare``.
_HASHED_FIELDS = [
    "displayName",
    "queryCondition.queryText",
    "schedule",
    "actions",
    "detectionAction.alertTemplate.severity",
    "detectionAction.alertTemplate.title",
    "detectionAction.alertTemplate.category",
]

# Keeps its historical prefix: run summaries and operators search for it.
_MISMATCH_PREFIX = "post-apply hash mismatch"

# A dry run reads every selected rule once. Graph allows about 100
# requests a minute on this endpoint, so the reads are paced.
_DRY_RUN_READ_DELAY_S = 0.7


class ReadOnlyDefenderClient:
    """The reads of a ``DefenderClient``; every write raises.

    A dry run compares against the tenant through this wrapper, so no
    code path of a dry run can create, change or delete a rule.
    """

    def __init__(self, client: DefenderClient) -> None:
        self._client = client

    def list_rules(self) -> list[dict]:
        return self._client.list_rules()

    def get_rule(self, graph_id: str) -> dict | None:
        return self._client.get_rule(graph_id)

    def _refuse(self, *_args: object, **_kwargs: object) -> None:
        raise PermissionError("a dry run does not write to the tenant")

    create_rule = update_rule = delete_rule = _refuse


def _names(fields: tuple[str, ...] | list[str]) -> str:
    return ", ".join(fields)


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


# Post-apply verification: Graph's detectionRules read path can lag a
# successful write by seconds. Six attempts five seconds apart bounds
# the wait at ~25s per changed rule; unchanged rules never get here.
_VERIFY_ATTEMPTS = 6
_VERIFY_DELAY_S = 5.0


class DefenderCustomDetectionHandler:
    asset = Asset.DEFENDER_CUSTOM_DETECTION

    def __init__(self, client_factory: Callable[[], DefenderClient | None]) -> None:
        self._client_factory = client_factory
        self._client: DefenderClient | None = None
        self._name_map: dict[str, str] | None = None
        # Graph ids that exist remotely, from the same list call as
        # ``_name_map``; lets apply match by ``metadata.arm_name``.
        self._graph_ids: set[str] = set()
        # Alert title -> Graph id from the same list call; finds a rule a
        # deploy created and the file renamed before collect recorded its id.
        self._titles: dict[str, str] = {}
        # True when a dry run could not list the tenant's rules (no
        # client, a failing call). The map is then empty because nothing
        # was read, not because the tenant has no rule.
        self._tenant_unread = False

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
                    self._tenant_unread = True
                else:
                    self._name_map, self._graph_ids = build_rule_index(client, titles=self._titles)
            except Exception as exc:
                logger.debug(
                    "dry-run name-map fetch failed (label defaults to "
                    "'create'): %s", exc,
                )
                self._name_map = {}
                self._tenant_unread = True
        else:
            client = self._client_or_create()
            assert client is not None
            self._name_map, self._graph_ids = build_rule_index(client, titles=self._titles)
        return self._name_map

    def validate(self, loaded: LoadedAsset) -> None:
        # The file as written, then what would be sent. The second check
        # alone would miss a blank duration next to a legacy period (the
        # projection leaves a blank key out), the first alone would not
        # see a request that is invalid once the ignored keys are gone.
        validate_defender_payload(loaded.payload)
        validate_defender_payload(to_current_shape(loaded.payload))

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

    def _dry_run(self, loaded: LoadedAsset, body: dict, display_name: str) -> ActionResult:
        """Say what a deploy of ``loaded`` would do, without writing.

        Uses the same body, the same rule lookup and the same comparison
        as a real deploy, through a client that cannot write. When the
        tenant cannot be read (no credentials, a failing call) the answer
        falls back to the label alone, as before.
        """
        deprecated = loaded.envelope.status == "deprecated"
        name_map = self._name_map_or_build(True)
        graph_id = resolve_graph_id(
            display_name, name_map,
            arm_name=loaded.envelope.arm_name, graph_ids=self._graph_ids,
        )

        def answer(action: PlanAction, text: str, detail: str = "") -> ActionResult:
            suffix = f" ({detail})" if detail else ""
            click.echo(f"  [DRY-RUN] {text} defender rule: {loaded.envelope.id} ({display_name}){suffix}")
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="dry-run", detail=detail,
            )

        if self._tenant_unread:
            # Nothing was read, so nothing is known about this rule. The
            # label stays "create" as before; the detail keeps it out of
            # the count of rules the tenant was found not to have.
            return answer(
                PlanAction.CREATE, "Not compared:",
                "not compared: the tenant's rules could not be read",
            )
        if not graph_id:
            taken = self._titles.get(alert_title(loaded.payload))
            if taken:
                return answer(
                    PlanAction.CREATE, "Would not create",
                    title_conflict_message(alert_title(loaded.payload), taken),
                )
            return answer(PlanAction.CREATE, "Would create")
        changing = PlanAction.DISABLE if deprecated else PlanAction.UPDATE
        existing: dict | None = None
        try:
            client = self._client_or_create()
            if client is not None:
                time.sleep(_DRY_RUN_READ_DELAY_S)
                existing = ReadOnlyDefenderClient(client).get_rule(graph_id)
        except Exception as exc:
            logger.debug("dry-run read of %s failed: %s", loaded.envelope.id, exc)
        if existing is None:
            return answer(changing, "Would update", "not compared: the rule could not be read")
        diff = rule_compare.diff_rule(body, _strip_server_fields(existing))
        status_same = "status" not in body or rule_status.rule_status(existing) == body["status"]
        notes = []
        if diff.changed:
            notes.append(f"fields: {_names(diff.changed)}")
        if not status_same:
            notes.append("status")
        if diff.not_cleared:
            notes.append(f"empty in the file, filled in the tenant, left as it is: {_names(diff.not_cleared)}")
        if not diff.changed and status_same:
            return answer(PlanAction.NOOP, "No change for", "; ".join(notes))
        return answer(changing, "Would update", "; ".join(notes))

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.SKIP,
                status="skipped",
                detail="experimental",
            )
        # One body for the dry run, the write and both comparisons, built
        # the way every Defender write builds it.
        body = to_defender_body(
            loaded.payload, deprecated=loaded.envelope.status == "deprecated",
        )
        display_name = body.get("displayName", "")
        if dry_run:
            return self._dry_run(loaded, body, display_name)

        client = self._client_or_create()
        assert client is not None
        name_map = self._name_map_or_build(False)

        def failed(action: PlanAction, err: str) -> ActionResult:
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )

        # Match by the Graph id collect recorded (``metadata.arm_name``)
        # before displayName: matching on displayName alone POSTed a second
        # rule whenever the YAML renamed one.
        graph_id = resolve_graph_id(
            display_name, name_map,
            arm_name=loaded.envelope.arm_name, graph_ids=self._graph_ids,
        )
        taken = "" if graph_id else self._titles.get(alert_title(loaded.payload), "")
        if taken:
            # Graph would refuse the create (409); say why and how to fix
            # it instead of sending it. The rule with that title is not
            # taken over: another file may own it.
            err = title_conflict_message(alert_title(loaded.payload), taken)
            click.echo(f"  error: {loaded.envelope.id}: {err}", err=True)
            return failed(PlanAction.CREATE, err)
        before: dict | None = None
        intended: tuple[str, ...] = ()
        note = ""
        if graph_id:
            # Push only when the rule actually differs. Re-PATCHing an
            # unchanged rule is needless and, for content collected from the
            # tenant, 400s under Microsoft's tightened beta save-validator
            # (e.g. `invoke FileProfile()` rules that run fine but can no
            # longer be re-saved as-is). The comparison is the one the
            # post-apply check uses. The enabled state is not part of it,
            # so an enable/disable flip (e.g. ``status: deprecated``) is
            # guarded explicitly. A body without ``status``
            # (``autoDisabled`` authored) leaves the remote state alone.
            existing = client.get_rule(graph_id)
            if existing is not None:
                before = _strip_server_fields(existing)
                diff = rule_compare.diff_rule(body, before)
                intended = diff.changed
                if diff.not_cleared:
                    note = (
                        "empty in the file, filled in the tenant, left as it is: "
                        f"{_names(diff.not_cleared)}"
                    )
                if not diff.changed and (
                    "status" not in body
                    or rule_status.rule_status(existing) == body["status"]
                ):
                    click.echo(f"  no-change: {loaded.envelope.id} (graph:{graph_id})")
                    return ActionResult(
                        asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                        action=PlanAction.NOOP, status="success",
                        detail="; ".join(part for part in ("unchanged; update skipped", note) if part),
                        verified=True,
                    )
            # An update never sends an empty value over a filled one: in
            # a PATCH that can mean "clear" (a scope written as null would
            # broaden the rule to every device). Where the file is empty
            # and the tenant is not, the tenant's own value is sent back.
            patch_body = (
                rule_compare.keep_tenant_values(body, before, intended)
                if before is not None else body
            )
            response = client.update_rule(graph_id, patch_body)
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
            record_graph_id(display_name, graph_id, name_map, self._graph_ids)
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
            if graph_id:
                # A second YAML with this displayName later in the run
                # must PATCH this rule, not POST another.
                record_graph_id(display_name, graph_id, name_map, self._graph_ids)
            click.echo(f"  {action.value}: {loaded.envelope.id}")

        # Post-apply check: the tenant must hold what the file says. Graph
        # acknowledges a POST/PATCH before its read path converges (observed
        # 2026-10-18: the verifying GET returned the pre-PATCH displayName),
        # so a stale read is retried a bounded number of times before it is
        # reported as a mismatch.
        #
        # The enabled state is checked next to the content, with the same
        # rule as the pre-write comparison: a body that sets no ``status``
        # leaves the remote state alone. Without it a disable would count
        # as verified on the first read even when the rule still shows as
        # enabled.
        remote: dict | None = None
        after: dict = {}
        still_differs: tuple[str, ...] = ()
        status_ok = True
        for attempt in range(1, _VERIFY_ATTEMPTS + 1):
            if not graph_id:
                break
            try:
                remote = client.get_rule(graph_id)
            except Exception as exc:  # pragma: no cover — defensive
                return failed(action, f"post-apply GET failed: {exc}")
            if remote is not None:
                # Server-managed fields (timestamps, the next run time)
                # are stripped as at collect time; they move on their own.
                after = _strip_server_fields(remote)
                still_differs = rule_compare.diff_rule(body, after).changed
                status_ok = (
                    "status" not in body
                    or rule_status.rule_status(remote) == body["status"]
                )
                if not still_differs and status_ok:
                    break
            if attempt < _VERIFY_ATTEMPTS:
                logger.info(
                    "Defender post-apply read for %s not yet converged (attempt %d/%d); retrying in %ss",
                    loaded.envelope.id, attempt, _VERIFY_ATTEMPTS, _VERIFY_DELAY_S,
                )
                time.sleep(_VERIFY_DELAY_S)
        if remote is None:
            return failed(action, "post-apply GET returned 404")
        if still_differs:
            return failed(action, f"{_MISMATCH_PREFIX}: fields differ: {_names(still_differs)}")
        if not status_ok:
            return failed(
                action,
                f"post-apply status mismatch: sent={body['status']} "
                f"got={rule_status.rule_status(remote)}",
            )
        if before is not None:
            # Nothing else may change: a field this update did not set out
            # to change must be the same before and after, the old keys of
            # scope and actions included while the tenant returns them.
            unexpected = rule_compare.unexpected_changes(before, after, intended)
            if unexpected:
                return failed(
                    action,
                    f"{_MISMATCH_PREFIX}: changed without being sent: {_names(unexpected)}",
                )

        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=action, status="success", detail=note, verified=True,
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
        status = rule_status.rule_status(remote)
        if "status" in payload:
            # Graph still echoes the deprecated boolean during the
            # transition; ``status`` carries the same information, so
            # collected YAML stops writing the removed field.
            payload.pop("isEnabled", None)
        graph_id = str(remote.get("id") or "")
        envelope_id = displayname_slug(display_name, fallback_id=graph_id)
        if not envelope_id:
            return None
        envelope: dict = {
            "id": envelope_id,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.DEFENDER_CUSTOM_DETECTION.value,
            # ``autoDisabled`` stays ``production``: Defender switched it
            # off, not the author. The payload keeps ``status:
            # autoDisabled`` so drift and the status report surface it.
            "status": "deprecated" if status == "disabled" else "production",
            "metadata": {"arm_name": graph_id} if graph_id else {},
            "payload": payload,
        }
        return envelope
