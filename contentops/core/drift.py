# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Drift detection — fetch remote state and emit YAML for new/changed assets.

This is the data layer the `contentops drift` CLI command builds on.

A handler opts in to drift detection by implementing two methods on top of
the standard Handler protocol:

    list_remote() -> list[dict]
        Returns the raw API objects for every asset of this kind in the
        remote tenant.

    to_envelope(remote: dict) -> dict | None
        Converts one raw remote object into a v2 envelope dict (the same
        shape that lives in YAML on disk). Returning None signals the
        item should be skipped (e.g. it's a built-in / Microsoft-shipped
        rule that we don't want to round-trip into git).

The drift engine then writes envelopes for any asset that:
  * exists remote but not in local YAML (NEW)
  * exists in both but the YAML payload differs from the exported one
    (CHANGED)
"""

from __future__ import annotations

import logging
from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Protocol, runtime_checkable

import yaml

from contentops.core.asset import Asset
from contentops.core.discovery import discover_assets, load_asset
from contentops.utils.yaml_io import dump_envelope_yaml

logger = logging.getLogger(__name__)


@runtime_checkable
class DriftCapable(Protocol):
    """Optional handler extension for `contentops drift`."""

    asset: Asset

    def list_remote(self) -> list[dict]: ...

    def to_envelope(self, remote: dict) -> dict | None: ...


@dataclass
class DriftEntry:
    asset: Asset
    asset_id: str
    kind: str  # "new" | "changed" | "in-sync" | "error"
    envelope: dict | None = None  # full v2 envelope to write (None for in-sync/error)
    local_path: Path | None = None  # set when kind == "changed"
    # Populated when ``kind == "error"`` — the exception message that
    # blocked drift from checking this asset kind. Operators see a
    # report that distinguishes "checked, no drift" from "couldn't
    # check" instead of the latter silently looking clean.
    error: str | None = None


@dataclass
class DriftReport:
    entries: list[DriftEntry] = field(default_factory=list)

    @property
    def new(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "new"]

    @property
    def changed(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "changed"]

    @property
    def in_sync(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "in-sync"]

    @property
    def errors(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "error"]

    def has_drift(self) -> bool:
        return bool(self.new) or bool(self.changed)

    def has_errors(self) -> bool:
        return bool(self.errors)


# What a file may leave out or hold beyond what the tenant returns.
#
# A collected file holds every field the tenant returns, so for it these
# sets change nothing. A file written by hand (``contentops new``) holds
# what its author declared: it leaves the fields below to the service,
# and it carries fields a deploy sends that the tenant never returns.
# Without these sets every authored object was "changed" right after a
# successful deploy, and importing the report emptied a watchlist.
#
# Fields the service fills in: only the tenant has them when the file
# leaves them out, and that alone is not drift.
_SERVICE_FILLED: dict[Asset, frozenset[str]] = {
    Asset.SENTINEL_ANALYTIC: frozenset({"incidentConfiguration"}),
    Asset.SENTINEL_WATCHLIST: frozenset({
        "sourceType", "watchlistCategory", "watchlistKind", "watchlistType",
    }),
    Asset.SENTINEL_PLAYBOOK: frozenset({"identity", "location"}),
    # Dotted paths name nested fields.
    Asset.DEFENDER_CUSTOM_DETECTION: frozenset({
        "schedule.lookback",
        "detectionAction.alertTemplate.eventGroupingKind",
        "detectionAction.incidentConfiguration",
    }),
}
# Fields a deploy sends that the tenant never returns. The import keeps
# them from the file; they are not compared.
_DEPLOY_ONLY: dict[Asset, frozenset[str]] = {
    Asset.SENTINEL_WATCHLIST: frozenset({
        "rawContent", "sasUri", "contentType", "numberOfLinesToSkip",
    }),
    Asset.SENTINEL_PLAYBOOK: frozenset({"roleAssignments"}),
}
# Top-level envelope keys the tenant knows nothing about; the import
# keeps them from the file.
_ENVELOPE_KEYS_FROM_TENANT = frozenset({"id", "version", "asset", "status", "metadata", "payload"})


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _drop_empty(value: Any) -> Any:
    """``value`` with every key whose value is empty removed, at any
    depth: for drift an empty value and an absent key are the same."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            v = _drop_empty(v)
            if not _is_empty(v):
                out[k] = v
        return out
    if isinstance(value, list):
        return [_drop_empty(v) for v in value]
    return value


def _without_default_label_type(payload: dict) -> dict:
    """Automation rules: the tenant returns each label with ``labelType:
    User``, the default, which a file that adds a label leaves out."""
    actions = payload.get("actions")
    if not isinstance(actions, list):
        return payload
    out = []
    for action in actions:
        cfg = action.get("actionConfiguration") if isinstance(action, dict) else None
        labels = cfg.get("labels") if isinstance(cfg, dict) else None
        if isinstance(labels, list):
            cfg = {**cfg, "labels": [
                {k: v for k, v in lab.items() if not (k == "labelType" and v == "User")}
                if isinstance(lab, dict) else lab
                for lab in labels
            ]}
            action = {**action, "actionConfiguration": cfg}
        out.append(action)
    return {**payload, "actions": out}


# ``envelope id -> workflow name`` of the local playbooks, set while drift
# or collect compares (see ``comparing_with_playbooks``).
_PLAYBOOK_WORKFLOWS: ContextVar[dict[str, str] | None] = ContextVar("_PLAYBOOK_WORKFLOWS", default=None)


def playbook_workflow_index(detections_root: Path) -> dict[str, str]:
    """``envelope id -> workflow name`` (``arm_name`` or id) of local playbooks."""
    out: dict[str, str] = {}
    for path in discover_assets(detections_root):
        try:
            loaded = load_asset(path)
        except Exception:  # noqa: BLE001 — reported by local_load_errors
            continue
        if loaded.envelope.asset is Asset.SENTINEL_PLAYBOOK:
            out[loaded.envelope.id] = loaded.envelope.arm_name or loaded.envelope.id
    return out


@contextmanager
def comparing_with_playbooks(detections_root: Path):
    """Make ``playbook: <id>`` and ``logicApp: <its workflow name>`` compare
    equal while the block runs (both deploy the same Logic App)."""
    token = _PLAYBOOK_WORKFLOWS.set(playbook_workflow_index(detections_root))
    try:
        yield
    finally:
        _PLAYBOOK_WORKFLOWS.reset(token)


def _automation_rule_canonical(payload: dict) -> dict:
    """Automation rules: the label default (see ``_without_default_label_type``)
    and one form for a RunPlaybook target. Collect writes ``playbook: <id>``
    only when that playbook's envelope exists, else ``logicApp: <name>``;
    both name the same Logic App, so both compare as its workflow name
    (case-insensitive, as ARM names are). Every caller compares inside
    ``comparing_with_playbooks``, so a ``playbook:`` id resolves to its
    workflow name; a Logic App name is never reduced to a slug (two names
    that differ only in punctuation are two Logic Apps)."""
    payload = _without_default_label_type(payload)
    actions = payload.get("actions")
    if not isinstance(actions, list):
        return payload
    index = _PLAYBOOK_WORKFLOWS.get() or {}
    out = []
    for action in actions:
        cfg = action.get("actionConfiguration") if isinstance(action, dict) else None
        if isinstance(cfg, dict) and action.get("actionType") == "RunPlaybook":
            target = cfg.get("playbook") or cfg.get("logicApp")
            if target:
                name = index.get(str(target), str(target)) if cfg.get("playbook") else str(target)
                cfg = {k: v for k, v in cfg.items() if k not in ("playbook", "logicApp")}
                cfg["logicApp"] = name.lower()
                action = {**action, "actionConfiguration": cfg}
        out.append(action)
    return {**payload, "actions": out}


#: Playbook connection fields only the file holds: the tenant's
#: ``$connections`` says nothing about them.
_CONNECTION_FILE_ONLY = ("authMode", "displayName", "auth")


def _playbook_canonical(payload: dict) -> dict:
    """Playbooks: compare connections without the fields only a file holds."""
    connections = payload.get("connections")
    if not isinstance(connections, list):
        return payload
    return {**payload, "connections": [
        {k: v for k, v in conn.items() if k not in _CONNECTION_FILE_ONLY}
        if isinstance(conn, dict) else conn
        for conn in connections
    ]}


def _defender_current_shape(payload: dict) -> dict:
    """Defender rules: Graph returns the deprecated keys filled in next to
    the current ones (``scopeNames`` next to ``deviceGroups``,
    ``responseActions`` next to ``automatedActions``, ...). Compared in
    the current shape (one key per old/new pair), a file that holds the
    current keys only is in sync with the tenant."""
    from contentops.defender.rule_shape import to_current_shape

    return to_current_shape(payload)


# Per-kind canonical form, applied to both sides before comparing.
_CANONICAL = {
    Asset.SENTINEL_AUTOMATION_RULE: _automation_rule_canonical,
    Asset.SENTINEL_PLAYBOOK: _playbook_canonical,
    Asset.DEFENDER_CUSTOM_DETECTION: _defender_current_shape,
}


def _comparable(local: dict, remote: dict, asset: Asset | None) -> tuple[dict, dict]:
    """The two payloads as drift compares them (see ``_SERVICE_FILLED``,
    ``_DEPLOY_ONLY``, ``_CANONICAL``)."""
    local = _drop_empty(local) if isinstance(local, dict) else local
    remote = _drop_empty(remote) if isinstance(remote, dict) else remote
    if asset is None or not isinstance(local, dict) or not isinstance(remote, dict):
        return local, remote
    canonical = _CANONICAL.get(asset)
    if canonical is not None:
        local, remote = canonical(local), canonical(remote)
    deploy_only = _DEPLOY_ONLY.get(asset, frozenset())
    service = _SERVICE_FILLED.get(asset, frozenset())
    local = {k: v for k, v in local.items() if not (k in deploy_only and k not in remote)}
    for path in service:
        if not _has_path(local, path):
            remote = _without_path(remote, path)
    return local, remote


def _has_path(payload: dict, dotted: str) -> bool:
    node: Any = payload
    for key in dotted.split("."):
        if not isinstance(node, dict) or key not in node:
            return False
        node = node[key]
    return True


def _without_path(payload: dict, dotted: str) -> dict:
    """A copy of ``payload`` without the field at ``dotted`` (if any)."""
    head, _, rest = dotted.partition(".")
    if head not in payload:
        return payload
    if not rest:
        return {k: v for k, v in payload.items() if k != head}
    child = payload[head]
    if not isinstance(child, dict):
        return payload
    return {**payload, head: _without_path(child, rest)}


def _remote_names(envelope: Any) -> list[str]:
    """Names the tenant may know a local envelope by, besides its id.

    ``metadata.arm_name`` when the file records one; otherwise the name a
    deploy gives an object it creates, where that is derived from the
    envelope id (automation rules: ``envelope_id_to_guid``)."""
    if envelope.arm_name:
        return [str(envelope.arm_name)]
    if envelope.asset is Asset.SENTINEL_AUTOMATION_RULE:
        from contentops.handlers.sentinel_automation_rule_models import envelope_id_to_guid
        return [envelope_id_to_guid(envelope.id)]
    return []


def _local_index(detections_root: Path, asset: Asset) -> dict[str, tuple[Path, dict]]:
    """Map ``key -> (path, payload)`` for every local YAML of ``asset``.

    The ``key`` is the unique remote identifier this envelope deploys
    against. We prefer ``metadata.arm_name`` (Sentinel) /
    ``metadata.graph_id`` (Defender) when set, because those are the
    authoritative remote names returned by ``list_remote()``. If
    neither is present, we fall back to ``envelope.id``.

    Why this matters: a remote slug like ``aad-failed-mfa`` lives at
    ARM resource name ``6babf568-...`` (the GUID). The local envelope
    on disk has ``id: aad-failed-mfa-6babf568`` (slug-disambiguated)
    and ``metadata.arm_name: 6babf568-...``. Without the arm_name
    lookup, drift and prune both compute the remote-side id as
    ``aad-failed-mfa`` (slug from displayName) and the local-side id
    as ``aad-failed-mfa-6babf568`` — they don't match, so the
    surviving rule gets flagged NEW (drift) / ORPHAN (prune).

    Each local envelope is registered under BOTH its arm_name (the
    primary remote-side key) AND its envelope id, so handlers that
    don't populate arm_name yet still find their local match.
    EnvelopeV2 stores arm_name as a top-level attribute (mirrored
    from ``metadata.arm_name``); Defender handlers reuse the same
    field for the Graph rule id.
    """
    out: dict[str, tuple[Path, dict]] = {}
    for path in discover_assets(detections_root):
        try:
            loaded = load_asset(path)
        except Exception as exc:  # noqa: BLE001 — bad YAML doesn't block drift run
            logger.warning("drift: skipping %s: %s", path, exc)
            continue
        if loaded.envelope.asset != asset:
            continue
        payload = loaded.payload
        if (
            asset is Asset.SENTINEL_ANALYTIC
            and loaded.envelope.status == "deprecated"
            and isinstance(payload, dict)
            and payload.get("enabled") is not False
        ):
            # Deploy switches a deprecated analytic off whatever the
            # payload says (emergency disable flips only the status), so
            # the tenant's ``enabled: false`` is what the repo asked for.
            payload = {**payload, "enabled": False}
        elif loaded.envelope.status == "deprecated" and isinstance(payload, dict):
            # Same for the support kinds: deploy sends a deprecated
            # automation rule with ``isEnabled: false`` and a deprecated
            # playbook with ``state: Disabled``.
            if asset is Asset.SENTINEL_AUTOMATION_RULE:
                from contentops.handlers.sentinel_automation_rule_models import is_expired
                logic = payload.get("triggeringLogic")
                # An expired rule is skipped by deploy (no disable is sent),
                # so it compares as the file has it.
                if (
                    isinstance(logic, dict) and logic.get("isEnabled") is not False
                    and not is_expired(logic.get("expirationTimeUtc"))
                ):
                    payload = {**payload, "triggeringLogic": {**logic, "isEnabled": False}}
            elif asset is Asset.SENTINEL_PLAYBOOK and payload.get("state") != "Disabled":
                payload = {**payload, "state": "Disabled"}
            elif asset is Asset.DEFENDER_CUSTOM_DETECTION:
                # Deploy sends a deprecated Defender rule as ``disabled``.
                payload = {k: v for k, v in payload.items() if k != "isEnabled"}
                payload["status"] = "disabled"
        entry = (path, payload)
        # Fallback key: envelope id (handlers w/o arm_name).
        out[loaded.envelope.id] = entry
        # Primary key: the authoritative remote name when known.
        for name in _remote_names(loaded.envelope):
            out[name] = entry
    return out


def _local_names(detections_root: Path, asset: Asset) -> dict[str, tuple[Path, dict, str]]:
    """Defender rules only: ``displayName -> (path, payload, arm_name)``.

    Graph keeps display names unique and deploy matches a file to a rule
    by its recorded id, then by its display name. A rule restored after a
    prune comes back under a new id while its file still records the
    deleted one; the name is then the only link left.
    """
    if asset is not Asset.DEFENDER_CUSTOM_DETECTION:
        return {}
    out: dict[str, tuple[Path, dict, str]] = {}
    for path in discover_assets(detections_root):
        try:
            loaded = load_asset(path)
        except Exception:  # noqa: BLE001 — reported by _local_index
            continue
        if loaded.envelope.asset != asset or not isinstance(loaded.payload, dict):
            continue
        name = loaded.payload.get("displayName")
        if name:
            out[str(name)] = (path, loaded.payload, str(loaded.envelope.arm_name or ""))
    return out


def _match_local(
    local: dict[str, tuple[Path, dict]],
    names: dict[str, tuple[Path, dict, str]],
    remote_ids: set[str],
    remote: dict,
    asset_id: str,
    envelope: dict,
) -> tuple[tuple[Path, dict] | None, bool]:
    """The local file for one remote object, and whether its recorded id
    is stale: by its remote name, then by the envelope id, then (Defender)
    by display name when the file's recorded id is no longer a live rule
    (so a name never takes a file another live rule owns)."""
    remote_key = remote.get("name") or remote.get("id") or ""
    match = local.get(str(remote_key)) if remote_key else None
    if match is None:
        match = local.get(asset_id)
    if match is None and names:
        name = (envelope.get("payload") or {}).get("displayName")
        candidate = names.get(str(name)) if name else None
        if candidate is not None and candidate[2] not in remote_ids:
            return (candidate[0], candidate[1]), True
    return match, False


def _payloads_match(local: dict, remote: dict, asset: Asset | None = None) -> bool:
    """Stable comparison of two payload dicts.

    Normalises strings the same way the YAML dumper does (strips
    per-line trailing whitespace, normalises CRLF). Without this,
    a remote string ending each line in two trailing spaces would
    diff against the on-disk version every time, because PyYAML's
    literal-block scalar style can't represent trailing whitespace
    so the dumper strips it before writing. With ``asset``, the
    per-kind rules of ``_comparable`` apply as well.
    """
    if asset is Asset.DEFENDER_CUSTOM_DETECTION and isinstance(local, dict) and isinstance(remote, dict):
        return _defender_in_sync(local, remote)
    local, remote = _comparable(local, remote, asset)
    return _normalize(local) == _normalize(remote)


def _defender_in_sync(local: dict, remote: dict) -> bool:
    """A Defender rule file and the tenant's rule, compared as deploy does.

    ``rule_compare.diff_rule`` is the comparison deploy makes before and
    after a write (OData annotations the tenant adds, ``PT60M`` for
    ``PT1H``, list order and service-filled fields are not differences), so
    a verified deploy always leaves drift in sync. A field the tenant
    filled that the file leaves empty (``not_cleared``) is drift: the
    portal added a value the repository does not hold. The enabled state
    is compared as deploy sends it.
    """
    from contentops.defender import rule_compare, rule_status

    body = rule_status.to_wire_body(local)
    diff = rule_compare.diff_rule(body, remote)
    if diff.changed or diff.not_cleared:
        return False
    # A value added in the portal to a field the file leaves out (deploy
    # does not touch such a field, so only drift can bring it into git).
    if rule_compare.added_in_tenant(body, remote):
        return False
    return "status" not in body or rule_status.rule_status(remote) == body["status"]


@dataclass(frozen=True)
class FieldDiff:
    """One field-level difference between two payloads.

    ``kind`` is one of ``added`` (key only in remote), ``removed``
    (key only in local), or ``modified`` (different value at the
    same key path). ``local_repr`` / ``remote_repr`` are short
    string renderings — empty for the side that doesn't have the
    key.
    """
    key: str
    kind: str
    local_repr: str
    remote_repr: str


def _short_repr(value: Any, *, max_len: int = 80) -> str:
    s = repr(value)
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def _diff_walk(local: Any, remote: Any, *, prefix: str) -> list[FieldDiff]:
    if local == remote:
        return []
    if isinstance(local, dict) and isinstance(remote, dict):
        out: list[FieldDiff] = []
        for k in sorted(set(local.keys()) | set(remote.keys())):
            sub = f"{prefix}.{k}" if prefix else k
            if k not in local:
                out.append(FieldDiff(sub, "added", "", _short_repr(remote[k])))
            elif k not in remote:
                out.append(FieldDiff(sub, "removed", _short_repr(local[k]), ""))
            else:
                out.extend(_diff_walk(local[k], remote[k], prefix=sub))
        return out
    # Lists / scalars / type mismatches — surface a single modification.
    return [FieldDiff(prefix or "(root)", "modified",
                      _short_repr(local), _short_repr(remote))]


def field_diff(local: Any, remote: Any, asset: Asset | None = None) -> list[FieldDiff]:
    """Return per-key differences between two payloads.

    Both sides are normalised (same rules as ``_payloads_match``)
    before walking, so trailing-whitespace and CRLF noise doesn't
    show up as a diff. Useful for diagnosing drift entries that
    report ``changed`` without it being obvious which field is
    triggering the comparison.
    """
    local, remote = _comparable(local, remote, asset)
    return _diff_walk(_normalize(local), _normalize(remote), prefix="")


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        if "\r" in value:
            value = value.replace("\r\n", "\n").replace("\r", "\n")
        # Match the dumper's per-line strip — trailing whitespace is
        # non-semantic and PyYAML's literal-block style can't represent
        # it anyway. Single-line strings get the same treatment so a
        # remote ``"text "`` (trailing space) compares equal to the
        # ``"text"`` we've written to disk.
        return "\n".join(
            line.rstrip() for line in value.split("\n")
        ).rstrip("\n")
    return value


def local_load_errors(detections_root: Path) -> list[tuple[Path, Exception]]:
    """Detection files under ``detections_root`` that fail to load.

    Such a file is left out of the local side, so its live rule would read
    as NEW (drift) or as an orphan (prune). Callers report or refuse
    instead of comparing without it.
    """
    out: list[tuple[Path, Exception]] = []
    for path in discover_assets(detections_root):
        try:
            load_asset(path)
        except Exception as exc:  # noqa: BLE001 — reported by the caller
            out.append((path, exc))
    return out


def _asset_of_path(path: Path) -> Asset | None:
    """The kind a file's folder names (``detections/<kind>/...``), if any."""
    values = {a.value: a for a in Asset}
    for part in path.parts:
        if part in values:
            return values[part]
    return None


def references_last(handlers: Iterable) -> list:
    """Handlers with the kinds that reference others (automation rules)
    after the kinds they reference, so the same run's new analytics and
    playbooks are known when the rules are mapped (stable otherwise)."""
    return sorted(handlers, key=lambda h: h.asset is Asset.SENTINEL_AUTOMATION_RULE)


def record_new_id(new_ids: dict[Asset, dict[str, str]], asset: Asset, asset_id: str, envelope: dict) -> None:
    """Note a new envelope's id against its remote name (see ``references_last``)."""
    md = envelope.get("metadata") or {}
    remote_name = md.get("arm_name") if isinstance(md, dict) else None
    new_ids.setdefault(asset, {})[asset_id] = str(remote_name or asset_id)


def seed_same_run_references(handler, new_ids: dict[Asset, dict[str, str]]) -> None:
    """Hand a referencing handler the new analytics and playbooks of this run."""
    seed = getattr(type(handler), "add_collected", None)
    if callable(seed):
        handler.add_collected(
            analytics=dict(new_ids.get(Asset.SENTINEL_ANALYTIC, {})),
            playbooks=dict(new_ids.get(Asset.SENTINEL_PLAYBOOK, {})),
        )


def detect_drift(
    handlers: Iterable[DriftCapable],
    detections_root: Path,
) -> DriftReport:
    with comparing_with_playbooks(detections_root):
        return _detect_drift(handlers, detections_root)


def _detect_drift(
    handlers: Iterable[DriftCapable],
    detections_root: Path,
) -> DriftReport:
    report = DriftReport()
    handlers = references_last(handlers)
    new_ids: dict[Asset, dict[str, str]] = {}
    checked = {h.asset for h in handlers}
    for path, exc in local_load_errors(detections_root):
        asset = _asset_of_path(path)
        if asset in checked:
            report.entries.append(DriftEntry(
                asset=asset, asset_id=path.name, kind="error",
                error=f"local file {path} failed to load ({exc}); its tenant item cannot be compared",
            ))
    for handler in handlers:
        asset = handler.asset
        local = _local_index(detections_root, asset)
        try:
            remote_items = handler.list_remote()
        except Exception as exc:  # noqa: BLE001
            # Don't silently swallow remote-list failures: a transient
            # ARM/Graph 401 / 500 used to log + continue, producing a
            # report that said "no drift" while the asset kind was never
            # actually checked. Surface the failure so the CLI summary
            # and any JSON report show it.
            logger.error("Failed to list remote %s: %s", asset.value, exc)
            report.entries.append(DriftEntry(
                asset=asset, asset_id="*", kind="error", error=str(exc),
            ))
            continue
        names = _local_names(detections_root, asset)
        remote_ids = {str(r.get("name") or r.get("id") or "") for r in remote_items}
        seed_same_run_references(handler, new_ids)

        # Pair each ``to_envelope`` result with its source remote so we
        # can look the match key up by the authoritative ARM/Graph name
        # rather than only by the slug-based envelope id (which collides
        # on tenants where two rules share a displayName).
        pairs: list[tuple[dict, dict]] = []
        for remote in remote_items:
            env = handler.to_envelope(remote)
            if env is None:
                continue
            pairs.append((env, remote))
        # C-5: ARM list responses are not order-stable. Without an
        # explicit sort the slug-disambiguation step (which runs in
        # input order) can produce different envelope ids for the same
        # tenant snapshot across drift runs. Sort by (envelope.id,
        # remote.name) so repeated runs are deterministic.
        pairs.sort(key=lambda p: (p[0].get("id") or "", p[1].get("name") or ""))
        # Slug-disambiguate the envelope ids so two un-paired colliding
        # remotes get distinct ids on the *output* side. The pre-disambig
        # envelopes preserve the original metadata.arm_name we use for
        # matching below.
        disambiguated = disambiguate_envelope_ids([e for e, _ in pairs])
        for (envelope, remote), env_id_disambig in zip(pairs, [d.get("id") for d in disambiguated]):
            asset_id = env_id_disambig or envelope.get("id")
            if not asset_id:
                continue
            envelope = dict(envelope)
            envelope["id"] = asset_id
            new_payload = envelope.get("payload", {})
            # Look up by the authoritative remote name first
            # (arm_name == remote.name for Sentinel; same field name
            # for Defender graph_id); fall back to the disambiguated
            # envelope id for envelopes that never carried a remote
            # name.
            match, stale_id = _match_local(local, names, remote_ids, remote, asset_id, envelope)
            if match is None:
                report.entries.append(DriftEntry(
                    asset=asset, asset_id=asset_id, kind="new", envelope=envelope,
                ))
                record_new_id(new_ids, asset, asset_id, envelope)
                continue
            local_path, local_payload = match
            # A stale recorded id is a change: the import records the
            # live rule's id in the file.
            if not stale_id and _payloads_match(local_payload, new_payload, asset):
                report.entries.append(DriftEntry(
                    asset=asset, asset_id=asset_id, kind="in-sync",
                    local_path=local_path,
                ))
            else:
                report.entries.append(DriftEntry(
                    asset=asset, asset_id=asset_id, kind="changed",
                    envelope=envelope, local_path=local_path,
                ))
    return report


def _preserve_local_id(envelope: dict, local_path: Path) -> dict:
    """Keep the on-disk ``id`` when re-importing an existing asset.

    Handlers derive ``id`` from the remote displayName. When a rule is
    renamed in the portal, the re-import matches the existing file (by
    ARM name / Graph id) but carries a new slug, so the file would keep
    its name while its ``id`` changed. That breaks every lookup keyed on
    ``path.stem == id`` and orphans references to the old id. The local
    file is the identity; the rename still lands via ``displayName``.
    """
    try:
        local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    except Exception:
        return envelope
    if isinstance(local, dict) and local.get("id"):
        envelope["id"] = local["id"]
    return envelope


def _preserve_local_version(envelope: dict, local_path: Path) -> dict:
    """Keep the on-disk ``version`` when re-importing an existing asset.

    ``version`` is a repo-side, operator-managed field: the remote tenant
    has no notion of it, so a collected envelope only ever carries the
    synthetic ``COLLECT_BASELINE_VERSION`` (see each handler's
    ``to_envelope``). A drift re-import therefore has nothing
    authoritative to say about version and must not touch it — letting
    the baseline win silently rolled back operator version bumps, which
    is how 7 production Defender detections got reset 0.1.1 -> 0.1.0 by
    the nightly drift PR.

    The baseline only applies to genuinely *new* assets (no local file);
    for those, ``write_drift`` never calls this function.

    When the re-import actually changes the envelope, the patch component
    is bumped (``1.0.6`` -> ``1.0.7``): a portal edit is a new revision,
    and ``scripts/check_version_bump.py`` refuses a content change under
    an unchanged version, so without the bump every drift PR carrying a
    portal edit failed validation. "Changed" uses the same comparison as
    that gate (parsed YAML, ``version`` set aside), so a cosmetic-only
    re-import never bumps.
    """
    try:
        local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    except Exception:
        return envelope
    if not isinstance(local, dict):
        return envelope
    local_version = local.get("version")
    if local_version:
        envelope["version"] = local_version
        if _body_without_version(envelope) != _body_without_version(local):
            envelope["version"] = _bump_patch(local_version)
    return envelope


def _body_without_version(envelope: dict) -> dict:
    """The envelope as it would read back from disk, minus ``version``."""
    try:
        parsed = yaml.safe_load(dump_envelope_yaml(envelope))
    except Exception:
        parsed = envelope
    if not isinstance(parsed, dict):
        return {}
    return {k: v for k, v in parsed.items() if k != "version"}


def _bump_patch(version: object) -> object:
    """``X.Y.Z`` -> ``X.Y.(Z+1)``; anything that isn't plain semver is kept."""
    parts = str(version).split(".")
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"
    return version


def _preserve_local_metadata(envelope: dict, local_path: Path) -> dict:
    """Merge the existing file's metadata block into the remote envelope.

    The remote API never returns operator-authored metadata fields
    (description, attackDescription, references, falsePositives, etc.).
    Without this merge, a drift-write would silently strip them.
    """
    try:
        local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    except Exception:
        return envelope
    if not isinstance(local, dict):
        return envelope
    local_meta = local.get("metadata")
    if not isinstance(local_meta, dict) or not local_meta:
        return envelope
    remote_meta = envelope.get("metadata")
    if isinstance(remote_meta, dict):
        merged = {**local_meta, **remote_meta}
    else:
        merged = local_meta
    envelope["metadata"] = merged
    return envelope


def _preserve_authored(envelope: dict, local_path: Path, asset: Asset) -> dict:
    """Keep what the tenant cannot say anything about when re-importing.

    * payload fields a deploy sends that the tenant never returns
      (``_DEPLOY_ONLY``: a watchlist's CSV, a playbook's declared roles);
    * top-level envelope keys the tenant has no notion of
      (``lifecycleStage``, ``legacy``, ``lifecycle``, ...);
    * the file's ``status`` when the rule is off on both sides: a rule
      authored as ``production`` with ``enabled: false`` is collected as
      ``deprecated``, and an unrelated import must not retire it.
    """
    try:
        local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    except Exception:
        return envelope
    if not isinstance(local, dict):
        return envelope
    local_payload = local.get("payload") if isinstance(local.get("payload"), dict) else {}
    payload = envelope.get("payload")
    if isinstance(payload, dict):
        for key in _DEPLOY_ONLY.get(asset, frozenset()):
            if key in local_payload and key not in payload:
                payload[key] = local_payload[key]
        if asset is Asset.SENTINEL_PLAYBOOK and isinstance(payload.get("connections"), list):
            # Fields only the file holds (``authMode`` is required for a
            # connector outside the known table): kept per connection name.
            local_conns = {
                c.get("name"): c for c in (local_payload.get("connections") or [])
                if isinstance(c, dict)
            }
            merged = []
            for conn in payload["connections"]:
                if isinstance(conn, dict) and conn.get("name") in local_conns:
                    extra = {
                        k: v for k, v in local_conns[conn["name"]].items()
                        if k in _CONNECTION_FILE_ONLY and k not in conn
                    }
                    conn = {**conn, **extra}
                merged.append(conn)
            payload["connections"] = merged
    for key, value in local.items():
        if key not in _ENVELOPE_KEYS_FROM_TENANT and key not in envelope:
            envelope[key] = value
    def _off(p: Any) -> bool:
        # Analytic: ``enabled: false``. Defender: ``status: disabled``.
        return isinstance(p, dict) and (p.get("enabled") is False or p.get("status") == "disabled")

    if (
        envelope.get("status") == "deprecated"
        and local.get("status") not in (None, "deprecated")
        and _off(local_payload) and _off(payload)
    ):
        envelope["status"] = local["status"]
    return envelope


def write_drift(report: DriftReport, out_dir: Path) -> list[Path]:
    """Write `new` and `changed` envelopes to `out_dir/<asset>/<id>.yml`.

    For `changed` entries, also overwrite the existing local file to
    keep the diff localized to one commit-ready place. Operator-authored
    metadata fields are preserved from the existing file.
    """
    written: list[Path] = []
    for entry in report.new + report.changed:
        if entry.envelope is None:
            continue
        # Convert to the on-disk form FIRST (playbooks move their
        # definition into a sidecar) so the preserve-* comparisons below
        # see the same shape the existing file has; otherwise every
        # re-import of an unchanged playbook would bump its version.
        entry.envelope, sidecars = split_sidecar_files(entry.envelope)
        if entry.local_path is not None:
            target = entry.local_path
            entry.envelope = _preserve_authored(entry.envelope, target, entry.asset)
            entry.envelope = _preserve_local_metadata(
                entry.envelope, target,
            )
            entry.envelope = _preserve_local_id(entry.envelope, target)
            entry.envelope = _preserve_local_version(
                entry.envelope, target,
            )
            entry.envelope = _bump_for_changed_sidecars(
                entry.envelope, target, sidecars,
            )
        else:
            target = out_dir / entry.asset.value / f"{entry.asset_id}.yml"
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            dump_envelope_yaml(entry.envelope),
            encoding="utf-8",
        )
        written.append(target)
        for name, text in sidecars.items():
            sidecar_path = target.parent / name
            if sidecar_path.exists() and sidecar_path.read_text(encoding="utf-8") == text:
                continue
            sidecar_path.write_text(text, encoding="utf-8")
            written.append(sidecar_path)
    return written


def _bump_for_changed_sidecars(
    envelope: dict, local_path: Path, sidecars: dict[str, str],
) -> dict:
    """A portal edit that only touched the playbook definition leaves the
    envelope body identical (the definition lives in the sidecar), so
    ``_preserve_local_version`` sees no change. Bump the patch version
    when a sidecar's new text differs from the file on disk — once, and
    only if the envelope body didn't already earn a bump."""
    if not sidecars:
        return envelope
    try:
        local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    except Exception:
        return envelope
    local_version = local.get("version") if isinstance(local, dict) else None
    if not local_version or envelope.get("version") != local_version:
        return envelope  # new asset, or body change already bumped it
    for name, text in sidecars.items():
        existing = local_path.parent / name
        if not existing.exists() or existing.read_text(encoding="utf-8") != text:
            envelope["version"] = _bump_patch(local_version)
            break
    return envelope


def split_sidecar_files(envelope: dict) -> tuple[dict, dict[str, str]]:
    """On-disk form of ``envelope`` plus any sidecar files to write
    alongside it (``{file name: text}``). Only playbooks have sidecars
    today; every other kind passes through unchanged."""
    if envelope.get("asset") == Asset.SENTINEL_PLAYBOOK.value:
        from contentops.handlers.sentinel_playbook_models import split_sidecars
        return split_sidecars(envelope)
    return envelope, {}


def disambiguate_envelope_ids(envelopes: list[dict]) -> list[dict]:
    """Resolve slug collisions within a single asset kind.

    If two envelopes from the same asset kind end up with the same
    base slug (e.g. two analytics named "Test"), both are rewritten
    to ``<slug>-<arm8>`` where ``arm8`` is the first 8 alphanumeric
    chars of the originating ARM resource name. When those 8 chars do
    not tell the colliding names apart (``Revoke-Session-Prod`` /
    ``Revoke-Session-Test``), the suffix is a hash of the full name
    instead, so no two envelopes leave with one id. The non-colliding
    envelopes pass through unchanged. Idempotent.
    """
    from contentops.utils.slug import arm_name_hash, arm_name_suffix, disambiguate

    def _arm_name(env: dict) -> str:
        md = env.get("metadata") or {}
        return str(md.get("arm_name") or "") if isinstance(md, dict) else ""

    counts: Counter[tuple[str, str]] = Counter(
        (e.get("asset", ""), e.get("id", "")) for e in envelopes if isinstance(e, dict)
    )
    # How many colliding envelopes share each short suffix, per slug.
    short: Counter[tuple[str, str, str]] = Counter(
        (e.get("asset", ""), e.get("id", ""), arm_name_suffix(_arm_name(e)))
        for e in envelopes
        if isinstance(e, dict) and counts[(e.get("asset", ""), e.get("id", ""))] > 1
    )
    out: list[dict] = []
    for env in envelopes:
        if not isinstance(env, dict):
            continue
        key = (env.get("asset", ""), env.get("id", ""))
        if counts[key] > 1:
            arm_name = _arm_name(env)
            suffix = arm_name_suffix(arm_name)
            if short[(*key, suffix)] > 1:
                suffix = arm_name_hash(arm_name)
            new_id = disambiguate(env.get("id", ""), arm_name, suffix=suffix)
            new_env = dict(env)
            new_env["id"] = new_id
            out.append(new_env)
        else:
            out.append(env)
    return out
