# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pydantic payload model + ARM body builders for ``sentinel_playbook``.

A playbook is a Consumption Logic App (``Microsoft.Logic/workflows``)
plus one ``Microsoft.Web/connections`` per connector it uses. On disk::

    detections/sentinel_playbook/<id>.yml            # envelope
    detections/sentinel_playbook/<id>.workflow.json  # designer export, verbatim

The envelope references the sidecar with ``definitionFile:``; the
loader (``contentops.core.discovery.load_asset``) inlines it as
``payload.definition`` so handlers always see the definition in memory,
and the writers (collect / drift / ``contentops new``) split it back out
through :func:`split_sidecars`.

Connections are declared, never pasted: ``connections: [{name, apiName,
authMode}]``. Every connection is managed-identity authenticated — no
secrets, no OAuth consent tokens, no ``$connections`` values on disk.
The handler PUTs the connections first and rewrites ``$connections`` to
the deployed ids. Connectors that only work with interactive OAuth
consent are rejected at validate time.

``roleAssignments`` declares the Azure roles the playbook's managed
identity needs; the pipeline verifies and reports them after apply (and
in conformance) but never assigns them — that is a human, Owner-level
step kept outside the deploy identity on purpose.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

LOGIC_NAMESPACE = "Microsoft.Logic"
WORKFLOWS = "workflows"
LOGIC_API_VERSION = "2019-05-01"
WEB_NAMESPACE = "Microsoft.Web"
CONNECTIONS = "connections"
WEB_API_VERSION = "2016-06-01"
ROLE_ASSIGNMENTS_API_VERSION = "2022-04-01"
RESOURCES_API_VERSION = "2021-04-01"

# Tag stamped on every workflow + connection this pipeline deploys. The
# playbook handler only ever lists / prunes tagged workflows, so Logic
# Apps built outside ContentOps in the same RG are invisible to it.
MANAGED_TAG = "contentops-managed"
MANAGED_TAG_VALUE = "true"
# Stamped on connections: value = owning playbook's envelope id, so
# delete can remove exactly the connections a playbook created.
PLAYBOOK_TAG = "contentops-playbook"

DEFAULT_STATE = "Enabled"
SIDECAR_SUFFIX = ".workflow.json"
# Logic App names are capped at 80 chars; connection names are
# ``<envelope id>-<connection name>`` so leave room.
MAX_ENVELOPE_ID_LEN = 64

AuthMode = Literal["alternative", "parameterValueSet"]

# Connectors that only work with interactive OAuth consent (a human
# signs in). They cannot be deployed from CI with a managed identity.
OAUTH_ONLY_APIS: frozenset[str] = frozenset({
    "office365", "office365users", "outlook", "teams", "sharepointonline",
    "onedriveforbusiness", "excelonlinebusiness", "planner", "todo",
    "office365groups", "onedrive", "dynamicscrmonline",
})

# Connectors known to support managed-identity auth and the ARM shape
# their connection needs. ``alternative`` = ``parameterValueType:
# Alternative`` (documented for the Sentinel connector); the rest use
# the ``parameterValueSet: {name: managedIdentityAuth}`` form. Unknown
# connectors must set ``authMode`` explicitly in the envelope.
MANAGED_IDENTITY_APIS: dict[str, AuthMode] = {
    "azuresentinel": "alternative",
    "azuremonitorlogs": "parameterValueSet",
    "keyvault": "parameterValueSet",
    "azureblob": "parameterValueSet",
    "azurequeues": "parameterValueSet",
    "azuretables": "parameterValueSet",
    "servicebus": "parameterValueSet",
    "azureeventgridpublish": "parameterValueSet",
    "azureloganalyticsdatacollector": "parameterValueSet",
}

# Well-known Azure built-in roles a playbook identity typically needs.
# Name -> role definition GUID (subscription-independent).
WELL_KNOWN_ROLES: dict[str, str] = {
    "Microsoft Sentinel Reader": "8d289c81-5878-46d4-8554-54e1e3d8b5cb",
    "Microsoft Sentinel Responder": "3e150937-b8fe-4cfb-8069-0eaf05ecd056",
    "Microsoft Sentinel Contributor": "ab8e14d6-4a74-4a29-9ba8-549422addade",
    "Log Analytics Reader": "73c42c96-874c-492b-b04d-ab87d138a893",
    "Log Analytics Contributor": "92aaf0da-9dab-42b6-94a3-d43ce8d16293",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
}
# Role the Azure Security Insights service principal needs on the
# playbook RG for automation rules to run playbooks. Reported by
# conformance, never assigned by the pipeline.
SENTINEL_AUTOMATION_CONTRIBUTOR_ROLE_ID = "f4c81013-99ee-4d62-a7ee-b3f1f648599a"

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_CONNECTION_REF_RE = re.compile(r"parameters\('\$connections'\)\['([^']+)'\]")
_CONNECTION_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

ScopeKeyword = Literal["workspace", "playbookResourceGroup"]


class PlaybookConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Key inside ``$connections`` (what the definition references).
    name: str = Field(pattern=_CONNECTION_NAME_RE.pattern)
    # managedApis connector name; defaults to ``name``.
    apiName: str | None = None
    # The only supported mode; spelled out so intent is explicit in YAML.
    auth: Literal["managedIdentity"] = "managedIdentity"
    authMode: AuthMode | None = None
    displayName: str | None = None
    # ARM name override; default ``<envelope id>-<name>``.
    connectionName: str | None = None

    @property
    def effective_api_name(self) -> str:
        return (self.apiName or self.name).lower()

    @property
    def effective_auth_mode(self) -> AuthMode:
        if self.authMode is not None:
            return self.authMode
        return MANAGED_IDENTITY_APIS[self.effective_api_name]

    @model_validator(mode="after")
    def _deployable_from_ci(self) -> "PlaybookConnection":
        api = self.effective_api_name
        if api in OAUTH_ONLY_APIS:
            raise ValueError(
                f"connection {self.name!r} uses connector {api!r}, which only "
                "supports interactive OAuth consent and cannot be deployed from CI "
                "with a managed identity. Use a managed-identity capable connector "
                "(e.g. azuresentinel, keyvault, servicebus) or an HTTP action."
            )
        if self.authMode is None and api not in MANAGED_IDENTITY_APIS:
            raise ValueError(
                f"connection {self.name!r}: connector {api!r} is not in the known "
                "managed-identity table; set `authMode: alternative` or "
                "`authMode: parameterValueSet` explicitly. Known: "
                f"{sorted(MANAGED_IDENTITY_APIS)}"
            )
        return self


class RoleAssignmentDecl(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Well-known role name or a role-definition GUID.
    role: str = Field(min_length=1)
    # ``workspace`` | ``playbookResourceGroup`` | full ARM scope id.
    scope: str = "workspace"

    @property
    def role_definition_id(self) -> str:
        if _GUID_RE.match(self.role):
            return self.role.lower()
        return WELL_KNOWN_ROLES[self.role]

    @model_validator(mode="after")
    def _known_role_and_scope(self) -> "RoleAssignmentDecl":
        if not _GUID_RE.match(self.role) and self.role not in WELL_KNOWN_ROLES:
            raise ValueError(
                f"roleAssignments: unknown role {self.role!r}; use a role-definition "
                f"GUID or one of {sorted(WELL_KNOWN_ROLES)}"
            )
        if self.scope not in ("workspace", "playbookResourceGroup") and not (
            self.scope.lower().startswith("/subscriptions/")
        ):
            raise ValueError(
                f"roleAssignments: scope {self.scope!r} must be 'workspace', "
                "'playbookResourceGroup', or a full ARM scope id"
            )
        return self


class SentinelPlaybookPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    location: str | None = None
    state: Literal["Enabled", "Disabled"] = DEFAULT_STATE
    identity: Literal["SystemAssigned"] = "SystemAssigned"
    tags: dict[str, str] = Field(default_factory=dict)
    connections: list[PlaybookConnection] = Field(default_factory=list)
    roleAssignments: list[RoleAssignmentDecl] = Field(default_factory=list)
    # Pointer to the sidecar on disk. In memory the loader has already
    # inlined it into ``definition``; the handler ignores this field.
    definitionFile: str | None = None
    definition: dict[str, Any] | None = None
    # Workflow parameter VALUES, never ``$connections`` (handler-owned).
    parameters: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _consistent(self) -> "SentinelPlaybookPayload":
        if self.definition is None:
            if self.definitionFile:
                raise ValueError(
                    f"definitionFile {self.definitionFile!r} was not inlined — "
                    "the sidecar is missing or the payload was built without "
                    "contentops.core.discovery.load_asset"
                )
            raise ValueError(
                "playbook payload needs `definitionFile: <id>.workflow.json` "
                "(designer export next to the envelope) or an inline `definition:`"
            )
        if self.definitionFile is not None and not _is_bare_sidecar_name(self.definitionFile):
            raise ValueError(
                f"definitionFile {self.definitionFile!r} must be a bare file name "
                f"ending in {SIDECAR_SUFFIX} (no directories)"
            )
        for key in ("triggers", "actions"):
            if not isinstance(self.definition.get(key), dict):
                raise ValueError(f"definition.{key} must be a mapping")
        names = [c.name for c in self.connections]
        if len(names) != len(set(names)):
            raise ValueError(f"connection names must be unique, got {names}")
        if "$connections" in self.parameters:
            raise ValueError(
                "payload.parameters must not contain `$connections`; declare "
                "connections under `connections:` and the handler builds it"
            )
        referenced = set(referenced_connection_names(self.definition))
        declared = set(names)
        undeclared = sorted(referenced - declared)
        if undeclared:
            raise ValueError(
                f"definition references $connections {undeclared} that are not "
                f"declared under `connections:` (declared: {sorted(declared)})"
            )
        return self


def _is_bare_sidecar_name(value: str) -> bool:
    return (
        value.endswith(SIDECAR_SUFFIX)
        and "/" not in value
        and "\\" not in value
        and value not in (".", "..")
        and len(value) > len(SIDECAR_SUFFIX)
    )


def sidecar_name(envelope_id: str) -> str:
    return f"{envelope_id}{SIDECAR_SUFFIX}"


def referenced_connection_names(definition: dict) -> list[str]:
    """Connection keys the definition reads from ``$connections``."""
    text = json.dumps(definition, default=str)
    seen: list[str] = []
    for name in _CONNECTION_REF_RE.findall(text):
        if name not in seen:
            seen.append(name)
    return seen


def managed_api_id(subscription_id: str, location: str, api_name: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/providers/Microsoft.Web"
        f"/locations/{location}/managedApis/{api_name}"
    )


def connection_arm_name(envelope_id: str, conn: PlaybookConnection) -> str:
    return conn.connectionName or f"{envelope_id}-{conn.name}"


def to_connection_arm_body(
    conn: PlaybookConnection, *, envelope_id: str, location: str, subscription_id: str,
) -> dict:
    """ARM body for one managed-identity ``Microsoft.Web/connections``."""
    props: dict[str, Any] = {
        "displayName": conn.displayName or conn.name,
        "api": {"id": managed_api_id(subscription_id, location, conn.effective_api_name)},
    }
    if conn.effective_auth_mode == "alternative":
        props["parameterValueType"] = "Alternative"
    else:
        props["parameterValueSet"] = {"name": "managedIdentityAuth", "values": {}}
    return {
        "location": location,
        "kind": "V1",
        "tags": {MANAGED_TAG: MANAGED_TAG_VALUE, PLAYBOOK_TAG: envelope_id},
        "properties": props,
    }


def canonical_connections_param() -> dict:
    """The ``$connections`` parameter declaration the handler injects into
    the definition when the author left it out."""
    return {"defaultValue": {}, "type": "Object"}


def to_workflow_arm_body(
    payload: SentinelPlaybookPayload,
    *,
    location: str,
    connection_refs: dict[str, dict],
) -> dict:
    """ARM body for the Consumption workflow.

    ``connection_refs`` is ``{connection name: {connectionId,
    connectionName, id}}`` for the connections already deployed.
    """
    definition = dict(payload.definition or {})
    params_decl = dict(definition.get("parameters") or {})
    if connection_refs and "$connections" not in params_decl:
        params_decl["$connections"] = canonical_connections_param()
    if params_decl:
        definition["parameters"] = params_decl
    parameters: dict[str, Any] = dict(payload.parameters)
    if connection_refs:
        parameters["$connections"] = {"value": connection_refs}
    properties: dict[str, Any] = {
        "state": payload.state,
        "definition": definition,
    }
    if parameters:
        properties["parameters"] = parameters
    return {
        "location": location,
        "identity": {"type": payload.identity},
        "tags": {**payload.tags, MANAGED_TAG: MANAGED_TAG_VALUE},
        "properties": properties,
    }


def is_managed_workflow(remote: dict) -> bool:
    tags = remote.get("tags") or {}
    return isinstance(tags, dict) and str(tags.get(MANAGED_TAG, "")).lower() == MANAGED_TAG_VALUE


def connections_from_remote(remote_workflow: dict) -> list[dict] | None:
    """Reverse ``$connections`` into ``connections:`` declarations.

    Returns None when a connection's auth can't be known to be managed
    identity from the workflow alone — the caller then GETs the
    connection resource to decide (or skips the workflow).
    """
    props = remote_workflow.get("properties") or {}
    params = props.get("parameters") or {}
    conns = ((params.get("$connections") or {}).get("value")) or {}
    out: list[dict] = []
    for name, ref in conns.items():
        if not isinstance(ref, dict):
            return None
        api_id = str(ref.get("id") or "")
        api_name = api_id.rsplit("/", 1)[-1].lower() if api_id else name.lower()
        entry: dict[str, Any] = {"name": name}
        if api_name != name.lower():
            entry["apiName"] = api_name
        conn_name = str(ref.get("connectionName") or "")
        default_conn_name = f"{remote_workflow.get('name')}-{name}"
        if conn_name and conn_name != default_conn_name:
            entry["connectionName"] = conn_name
        out.append(entry)
    return out


def split_sidecars(envelope: dict) -> tuple[dict, dict[str, str]]:
    """Move an inline ``payload.definition`` into a sidecar.

    Returns ``(envelope_on_disk, {sidecar file name: text})``. The
    envelope keeps ``definitionFile`` and loses ``definition``; the
    sidecar is the definition as 2-space-indented, key-sorted JSON with
    a trailing newline (stable diffs across collect runs).
    """
    out = dict(envelope)
    payload = dict(out.get("payload") or {})
    definition = payload.pop("definition", None)
    files: dict[str, str] = {}
    if isinstance(definition, dict):
        name = payload.get("definitionFile") or sidecar_name(str(out.get("id", "")))
        payload["definitionFile"] = name
        files[name] = json.dumps(definition, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    out["payload"] = payload
    return out, files


__all__ = [
    "CONNECTIONS",
    "LOGIC_API_VERSION",
    "LOGIC_NAMESPACE",
    "MANAGED_IDENTITY_APIS",
    "MANAGED_TAG",
    "MANAGED_TAG_VALUE",
    "MAX_ENVELOPE_ID_LEN",
    "OAUTH_ONLY_APIS",
    "PLAYBOOK_TAG",
    "RESOURCES_API_VERSION",
    "ROLE_ASSIGNMENTS_API_VERSION",
    "SENTINEL_AUTOMATION_CONTRIBUTOR_ROLE_ID",
    "SIDECAR_SUFFIX",
    "WEB_API_VERSION",
    "WEB_NAMESPACE",
    "WELL_KNOWN_ROLES",
    "WORKFLOWS",
    "PlaybookConnection",
    "RoleAssignmentDecl",
    "SentinelPlaybookPayload",
    "canonical_connections_param",
    "connection_arm_name",
    "connections_from_remote",
    "is_managed_workflow",
    "managed_api_id",
    "referenced_connection_names",
    "sidecar_name",
    "split_sidecars",
    "to_connection_arm_body",
    "to_workflow_arm_body",
]
