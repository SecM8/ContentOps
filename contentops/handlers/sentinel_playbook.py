# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel playbook handler — Consumption Logic Apps via SentinelArmProvider.

A "playbook" is a Logic App workflow that Sentinel automation rules can
call. Logic Apps live OUTSIDE the ``Microsoft.SecurityInsights``
namespace, in the workspace's ``effective_playbooks_resource_group``::

    /subscriptions/{sub}/resourceGroups/{playbooks-rg}
        /providers/Microsoft.Logic/workflows/{name}?api-version=2019-05-01
        /providers/Microsoft.Web/connections/{name}?api-version=2016-06-01

Apply order inside one playbook: every declared connection first
(GET etag → PUT → GET-back check), then the workflow. Any connection
failure aborts BEFORE the workflow PUT so a half-deployed playbook never
references a missing connection. On CREATE the result carries the
managed identity's ``principalId`` and the roles still missing from
``roleAssignments`` as ready-to-run ``az`` commands — the pipeline
verifies roles, it never assigns them.

Discovery is managed-tag only: ``list_remote`` asks ARM for Logic Apps
in the playbook RG tagged ``contentops-managed=true``. Workflows built
outside ContentOps are invisible to drift and prune until an operator
adopts them (``contentops collect --asset sentinel_playbook --adopt
<name>``), which stamps the tag.

Verification is structural (``_playbook_projection``): Logic Apps
normalises definitions heavily on PUT, so ``verified=True`` means "the
deployed workflow has the same triggers / actions / action types /
connections / identity / state we sent", not byte equality — changes
inside an action's ``inputs`` are not detected.
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
    compute_projection_hash,
    extract_etag,
    hash_mismatch_error,
)
from contentops.handlers.sentinel_playbook_models import (
    CONNECTIONS,
    LOGIC_API_VERSION,
    LOGIC_NAMESPACE,
    MANAGED_TAG,
    MANAGED_TAG_VALUE,
    MAX_ENVELOPE_ID_LEN,
    PLAYBOOK_TAG,
    RESOURCES_API_VERSION,
    ROLE_ASSIGNMENTS_API_VERSION,
    WEB_API_VERSION,
    WEB_NAMESPACE,
    WORKFLOWS,
    PlaybookConnection,
    RoleAssignmentDecl,
    SentinelPlaybookPayload,
    canonical_connections_param,
    connection_arm_name,
    connections_from_remote,
    to_connection_arm_body,
    to_workflow_arm_body,
)
from contentops.providers.sentinel_arm import SentinelArmProvider
from contentops.utils.slug import displayname_slug

logger = logging.getLogger(__name__)

_SERVER_FIELDS = ("id", "type", "etag", "systemData")
_SERVER_PROPERTY_FIELDS = (
    "provisioningState", "createdTime", "changedTime", "version",
    "accessEndpoint", "endpointsConfiguration", "sku",
    "integrationServiceEnvironment", "integrationAccount",
)
_SERVER_IDENTITY_FIELDS = ("principalId", "tenantId")


def _strip_server_fields(remote: dict) -> dict:
    """Return ``remote`` without server-managed fields (pure copy)."""
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    block = cleaned.get("properties")
    if isinstance(block, dict):
        cleaned["properties"] = {
            k: v for k, v in block.items() if k not in _SERVER_PROPERTY_FIELDS
        }
    identity = cleaned.get("identity")
    if isinstance(identity, dict):
        cleaned["identity"] = {
            k: v for k, v in identity.items() if k not in _SERVER_IDENTITY_FIELDS
        }
    return cleaned


def _playbook_projection(body: dict) -> dict:
    """Structural projection of a Logic Apps workflow (see module docstring)."""
    props = body.get("properties") or {}
    definition = props.get("definition") or {}
    triggers = definition.get("triggers") or {}
    actions = definition.get("actions") or {}
    params = props.get("parameters") or {}
    conns = ((params.get("$connections") or {}).get("value")) or {}

    def _action_types(actions_dict: dict) -> list[str]:
        return sorted(
            str(v.get("type") or "") for v in actions_dict.values() if isinstance(v, dict)
        )

    def _connection_apis(conn_dict: dict) -> list[str]:
        out: list[str] = []
        for ref in conn_dict.values():
            if isinstance(ref, dict) and ref.get("id"):
                out.append(str(ref["id"]).rsplit("/", 1)[-1].lower())
        return sorted(out)

    identity = body.get("identity") or {}
    return {
        "location": (body.get("location") or "").lower() or None,
        "state": props.get("state"),
        "identityType": identity.get("type") if isinstance(identity, dict) else None,
        "triggerNames": sorted(str(k) for k in triggers.keys()),
        "actionNames": sorted(str(k) for k in actions.keys()),
        "actionTypes": _action_types(actions),
        "connectionApis": _connection_apis(conns),
    }


def az_role_assignment_command(principal_id: str, role: str, scope: str) -> str:
    return (
        f"az role assignment create --assignee-object-id {principal_id} "
        f"--assignee-principal-type ServicePrincipal --role \"{role}\" "
        f"--scope {scope}"
    )


class SentinelPlaybookHandler:
    asset = Asset.SENTINEL_PLAYBOOK

    def __init__(
        self,
        provider_factory: Callable[[], SentinelArmProvider | None],
        *,
        tenant_id: str | None = None,
    ) -> None:
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None
        self._tenant_id = tenant_id

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    # --- URLs -------------------------------------------------------------

    def _rg(self, provider: SentinelArmProvider) -> str:
        return provider.config.effective_playbooks_resource_group

    def _workflow_url(self, provider: SentinelArmProvider, name: str | None = None) -> str:
        return provider.resource_group_resource_url(
            self._rg(provider), LOGIC_NAMESPACE, WORKFLOWS, name,
            api_version=LOGIC_API_VERSION,
        )

    def _connection_url(self, provider: SentinelArmProvider, name: str | None = None) -> str:
        return provider.resource_group_resource_url(
            self._rg(provider), WEB_NAMESPACE, CONNECTIONS, name,
            api_version=WEB_API_VERSION,
        )

    def _scope_id(self, provider: SentinelArmProvider, scope: str) -> str:
        if scope == "workspace":
            return provider.loganalytics_workspace_path
        if scope == "playbookResourceGroup":
            return (
                f"/subscriptions/{provider.config.subscriptionId}"
                f"/resourceGroups/{self._rg(provider)}"
            )
        return scope

    # --- Handler protocol -------------------------------------------------

    def validate(self, loaded: LoadedAsset) -> None:
        if len(loaded.envelope.id) > MAX_ENVELOPE_ID_LEN:
            raise ValueError(
                f"sentinel_playbook id {loaded.envelope.id!r} is longer than "
                f"{MAX_ENVELOPE_ID_LEN} chars (Logic App + connection name cap)"
            )
        SentinelPlaybookPayload(**loaded.payload)

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned",
                detail="experimental status — skipped",
            )
        if loaded.envelope.status == "deprecated":
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned",
                detail="deprecated playbooks are not deleted by deploy; use `prune`",
            )
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="planned",
        )

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        plan = self.plan(loaded)
        if plan.action is PlanAction.SKIP:
            click.echo(f"  skipped ({plan.detail}): {loaded.envelope.id}")
            return ActionResult(
                asset_id=plan.asset_id, asset_kind=plan.asset_kind,
                action=plan.action, status="skipped", detail=plan.detail,
            )

        payload = SentinelPlaybookPayload(**loaded.payload)
        envelope_id = loaded.envelope.id
        if dry_run:
            click.echo(
                f"  [DRY-RUN] Would PUT {len(payload.connections)} connection(s) "
                f"then Logic App workflow: {envelope_id}"
            )
            return ActionResult(
                asset_id=envelope_id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="dry-run",
            )

        provider = self._provider_or_create()
        assert provider is not None
        cfg = provider.config
        location = payload.location or cfg.location
        workflow_name = loaded.envelope.arm_name or envelope_id

        # 1. Connections, in declared order; abort before the workflow PUT
        #    on the first failure.
        connection_refs: dict[str, dict] = {}
        for conn in payload.connections:
            ref, failure = self._apply_connection(
                provider, conn, envelope_id=envelope_id, location=location,
            )
            if failure is not None:
                return failure
            assert ref is not None
            connection_refs[conn.name] = ref

        # 2. Workflow.
        body = to_workflow_arm_body(payload, location=location, connection_refs=connection_refs)
        url = self._workflow_url(provider, workflow_name)
        existing_resp = provider.request("GET", url)
        existing = existing_resp.json() if existing_resp.status_code == 200 else None
        etag = extract_etag(existing)

        sent_hash = compute_projection_hash(_playbook_projection(body))
        headers = {"If-Match": etag} if etag else None
        response = provider.request("PUT", url, json=body, headers=headers)

        if response.status_code == 412:
            click.echo(f"  etag-conflict: {envelope_id}", err=True)
            return ActionResult(
                asset_id=envelope_id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="error-412",
                detail=ETAG_CONFLICT_MESSAGE, verified=False, error=ETAG_CONFLICT_MESSAGE,
            )
        if response.status_code not in (200, 201):
            logger.error(
                "Failed to deploy playbook %s: %s %s",
                envelope_id, response.status_code, response.text,
            )
            return ActionResult(
                asset_id=envelope_id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status=f"error-{response.status_code}",
                detail=response.text[:200], verified=False, error=response.text[:200],
            )

        action = PlanAction.CREATE if existing is None else PlanAction.UPDATE
        click.echo(f"  {action.value}: {envelope_id}")

        verify_resp = provider.request("GET", url)
        if verify_resp.status_code != 200:
            err = f"post-apply GET returned {verify_resp.status_code}"
            return ActionResult(
                asset_id=envelope_id, asset_kind=self.asset.value,
                action=action, status="success", detail=err, verified=False, error=err,
            )
        verified_remote = verify_resp.json()
        got_hash = compute_projection_hash(_playbook_projection(verified_remote))
        if got_hash != sent_hash:
            err = hash_mismatch_error(sent_hash, got_hash)
            return ActionResult(
                asset_id=envelope_id, asset_kind=self.asset.value,
                action=action, status="success", detail=err, verified=False, error=err,
            )

        # 3. Managed-identity roles: verify + report, never assign.
        extra: dict = {"arm_name": workflow_name}
        detail = ""
        principal_id = ((verified_remote.get("identity") or {}).get("principalId"))
        if principal_id:
            extra["principalId"] = principal_id
            missing, unverifiable = self._verify_role_assignments(
                provider, principal_id, payload.roleAssignments,
            )
            if missing:
                extra["missingRoleAssignments"] = missing
                detail = (
                    "managed identity is missing declared role(s); grant them "
                    "(needs Owner / User Access Administrator):\n    "
                    + "\n    ".join(missing)
                )
            elif unverifiable:
                detail = (
                    "could not read role assignments for the managed identity "
                    "(403); verify the declared roles manually"
                )
            elif payload.roleAssignments:
                detail = "declared role assignments present"
        return ActionResult(
            asset_id=envelope_id, asset_kind=self.asset.value,
            action=action, status="success", verified=True, detail=detail, extra=extra,
        )

    def _apply_connection(
        self,
        provider: SentinelArmProvider,
        conn: PlaybookConnection,
        *,
        envelope_id: str,
        location: str,
    ) -> tuple[dict | None, ActionResult | None]:
        """PUT one API connection; return ``(ref, None)`` or ``(None, failure)``."""
        name = connection_arm_name(envelope_id, conn)
        url = self._connection_url(provider, name)
        body = to_connection_arm_body(
            conn, envelope_id=envelope_id, location=location,
            subscription_id=provider.config.subscriptionId,
        )
        existing_resp = provider.request("GET", url)
        etag = extract_etag(existing_resp.json()) if existing_resp.status_code == 200 else None
        headers = {"If-Match": etag} if etag else None
        response = provider.request("PUT", url, json=body, headers=headers)

        def _fail(status: str, message: str) -> ActionResult:
            msg = f"connection {conn.name!r}: {message}"
            click.echo(f"  error: {envelope_id}: {msg}", err=True)
            return ActionResult(
                asset_id=envelope_id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status=status,
                detail=msg[:200], verified=False, error=msg[:200],
            )

        if response.status_code == 412:
            return None, _fail("error-412", ETAG_CONFLICT_MESSAGE)
        if response.status_code not in (200, 201):
            return None, _fail(f"error-{response.status_code}", response.text[:150])

        verify_resp = provider.request("GET", url)
        if verify_resp.status_code != 200:
            return None, _fail("error-verify", f"post-apply GET returned {verify_resp.status_code}")
        remote = verify_resp.json()
        props = remote.get("properties") or {}
        api_id = str((props.get("api") or {}).get("id") or "")
        if not api_id.lower().endswith(f"/managedapis/{conn.effective_api_name}"):
            return None, _fail("error-verify", f"api id mismatch: {api_id!r}")
        if conn.effective_auth_mode == "alternative":
            auth_ok = props.get("parameterValueType") == "Alternative"
        else:
            auth_ok = (props.get("parameterValueSet") or {}).get("name") == "managedIdentityAuth"
        if not auth_ok:
            return None, _fail("error-verify", "connection is not managed-identity authenticated")
        connection_id = remote.get("id") or url.split("?", 1)[0]
        return {
            "connectionId": connection_id,
            "connectionName": name,
            "id": api_id,
        }, None

    def _verify_role_assignments(
        self,
        provider: SentinelArmProvider,
        principal_id: str,
        decls: list[RoleAssignmentDecl],
    ) -> tuple[list[str], bool]:
        """Return ``(missing az commands, unverifiable)``."""
        missing: list[str] = []
        unverifiable = False
        for decl in decls:
            scope = self._scope_id(provider, decl.scope)
            url = (
                f"{scope}/providers/Microsoft.Authorization/roleAssignments"
                f"?api-version={ROLE_ASSIGNMENTS_API_VERSION}"
                f"&$filter=principalId eq '{principal_id}'"
            )
            try:
                resp = provider.request("GET", url)
            except Exception as exc:  # noqa: BLE001 — reported, never fatal
                logger.warning("role assignment check failed for %s: %s", scope, exc)
                unverifiable = True
                continue
            if resp.status_code != 200:
                unverifiable = True
                continue
            wanted = decl.role_definition_id
            present = False
            for item in resp.json().get("value", []) or []:
                rdid = str((item.get("properties") or {}).get("roleDefinitionId") or "")
                if rdid.lower().endswith(wanted.lower()):
                    present = True
                    break
            if not present:
                missing.append(az_role_assignment_command(principal_id, decl.role, scope))
        return missing, unverifiable

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def delete(self, remote_id: str) -> ActionResult:
        """DELETE one playbook (workflow) and the connections it created.

        Only connections tagged ``contentops-playbook=<remote_id>`` are
        removed; untagged connections are never touched. Connection
        delete failures are appended to ``detail`` without flipping a
        successful workflow delete to error.
        """
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        provider = self._provider_or_create()
        if provider is None:
            raise NotSupportedError("sentinel_playbook delete requires a SentinelArmProvider")
        try:
            response = provider.request("DELETE", self._workflow_url(provider, remote_id))
        except Exception as exc:  # pragma: no cover
            return delete_result_from_exception(remote_id, self.asset, exc)
        result = delete_result_from_response(remote_id, self.asset, response)
        if result.is_error:
            return result
        notes: list[str] = []
        try:
            tagged = provider.list_resource_group_resources(
                self._rg(provider),
                filter_expr=f"tagName eq '{PLAYBOOK_TAG}' and tagValue eq '{remote_id}'",
                resource_type=f"{WEB_NAMESPACE}/{CONNECTIONS}",
                api_version=RESOURCES_API_VERSION,
            )
        except Exception as exc:  # noqa: BLE001
            notes.append(f"could not list connections: {exc}")
            tagged = []
        for item in tagged:
            cname = item.get("name")
            if not cname:
                continue
            try:
                cresp = provider.request("DELETE", self._connection_url(provider, cname))
            except Exception as exc:  # noqa: BLE001
                notes.append(f"connection {cname}: {exc}")
                continue
            if cresp.status_code not in (200, 204, 404):
                notes.append(f"connection {cname}: HTTP {cresp.status_code}")
            else:
                notes.append(f"connection {cname}: deleted")
        if notes:
            result.detail = f"{result.detail}; " + "; ".join(notes)
        return result

    # --- Adoption ---------------------------------------------------------

    def adopt(self, workflow_name: str) -> dict:
        """Stamp the managed tag on an existing Logic App so it becomes
        visible to collect / drift / prune. Returns the updated workflow.
        An explicit, audited write the operator requested by name."""
        provider = self._provider_or_create()
        if provider is None:
            raise ValueError("adopt requires a SentinelArmProvider")
        url = self._workflow_url(provider, workflow_name)
        current = provider.request("GET", url)
        current.raise_for_status()
        remote = current.json()
        tags = dict(remote.get("tags") or {})
        tags[MANAGED_TAG] = MANAGED_TAG_VALUE
        patched = provider.request("PATCH", url, json={"tags": tags})
        patched.raise_for_status()
        after = provider.request("GET", url)
        after.raise_for_status()
        return after.json()

    # --- Drift support -------------------------------------------------

    def list_remote(self) -> list[dict]:
        provider = self._provider_or_create()
        if provider is None:
            return []
        # Tag filter server-side; resource type client-side — ARM rejects
        # the two combined in one $filter (400).
        summaries = provider.list_resource_group_resources(
            self._rg(provider),
            filter_expr=f"tagName eq '{MANAGED_TAG}' and tagValue eq '{MANAGED_TAG_VALUE}'",
            resource_type=f"{LOGIC_NAMESPACE}/{WORKFLOWS}",
            api_version=RESOURCES_API_VERSION,
        )
        out: list[dict] = []
        for summary in summaries:
            name = summary.get("name")
            if not name:
                continue
            resp = provider.request("GET", self._workflow_url(provider, str(name)))
            if resp.status_code != 200:
                logger.warning("playbook %s: GET returned %s", name, resp.status_code)
                continue
            out.append(resp.json())
        return out

    def to_envelope(self, remote: dict) -> dict | None:
        name = remote.get("name")
        if not name:
            return None
        cleaned = _strip_server_fields(remote)
        properties: dict = dict(cleaned.get("properties") or {})
        definition = properties.get("definition")
        if not isinstance(definition, dict):
            return None
        connections = connections_from_remote(remote)
        if connections is None:
            logger.warning(
                "Skipping playbook %r — a connection is not managed-identity shaped; "
                "convert it in the designer, then `collect --asset sentinel_playbook`",
                name,
            )
            return None

        env_id = displayname_slug(str(name), fallback_id=str(name))
        if not env_id:
            return None

        definition = dict(definition)
        params_decl = dict(definition.get("parameters") or {})
        if params_decl.get("$connections") == canonical_connections_param():
            params_decl.pop("$connections")
        if params_decl:
            definition["parameters"] = params_decl
        else:
            definition.pop("parameters", None)

        parameters = {
            k: v for k, v in (properties.get("parameters") or {}).items()
            if k != "$connections"
        }
        tags = {
            k: v for k, v in (cleaned.get("tags") or {}).items()
            if k != MANAGED_TAG
        }
        identity = cleaned.get("identity") or {}

        payload: dict = {
            "state": properties.get("state", "Enabled"),
        }
        location = cleaned.get("location")
        if location:
            payload["location"] = location
        if isinstance(identity, dict) and identity.get("type"):
            payload["identity"] = identity["type"]
        if tags:
            payload["tags"] = tags
        if connections:
            payload["connections"] = connections
        payload["definition"] = definition
        if parameters:
            payload["parameters"] = parameters

        return {
            "id": env_id,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.SENTINEL_PLAYBOOK.value,
            "status": "production",
            "metadata": {"arm_name": str(name)},
            "payload": payload,
        }
