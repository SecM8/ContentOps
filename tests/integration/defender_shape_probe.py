# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live probe: how does Graph treat a custom detection rule sent with the
current property names only?

Microsoft deprecated ``schedule.period``, ``alertTemplate.category``,
``mitreTechniques``, ``impactedAssets``, ``responseActions`` and
``organizationalScope.scopeType`` / ``scopeNames`` in favour of
``frequency``, ``tactics``, ``entityMappings``, ``automatedActions`` and
``deviceGroups``. Several things the pipeline depends on are not
documented, so this probe asks the service directly and writes down the
answers.

Safety rules, each pinned by ``tests/v2/test_defender_shape_probe.py``:

* every rule it creates carries ``status: disabled`` and a query that
  cannot return a row; if a created rule does not come back disabled the
  probe deletes it and aborts;
* it writes only to rules it created itself;
* it deletes what it created, also when a step raises, and reports how
  many test rules are still listed afterwards;
* nothing read from the tenant is ever put in a finding, the report or
  an exception message. The scope step copies device-group names from an
  existing rule onto the disabled test rule and reports only booleans.

This module is not a test; ``test_defender_custom_detection_crud.py``
runs it against the live tenant.
"""

from __future__ import annotations

import copy
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

PREFIX = "zz_itest_"
NO_ROW_DEVICE = "zz-itest-no-such-device"

#: Defender is tenant-wide: every live Defender test writes to the real
#: tenant. The operator confirms that with ``i-know-this-hits-prod`` on the
#: workflow, which sets this variable to ``yes``.
CONFIRM_ENV = "I_UNDERSTAND_THIS_IS_PRODUCTION"

#: A device group the scope step may put on its disabled test rule. Without
#: it the step copies a group from an existing scoped rule, and skips when
#: the tenant has none. The name never appears in the report.
DEVICE_GROUP_ENV = "DEFENDER_PROBE_DEVICE_GROUP"


def require_confirmation() -> None:
    """Skip the test, before any call is made, unless the operator
    confirmed that this run may write to the production tenant.

    A skip, not a failure: the whole live suite also runs on paths that
    cannot confirm (a pull request label), and there no Defender test may
    write, while the Sentinel tests still run."""
    if os.environ.get(CONFIRM_ENV) != "yes":
        import pytest

        pytest.skip(
            "This test writes to the production Defender tenant. Start the workflow "
            f"with i-know-this-hits-prod set (it sets {CONFIRM_ENV}=yes)."
        )
QUERY = (
    "DeviceProcessEvents\n"
    "| where Timestamp > ago(1h)\n"
    f'| where DeviceName == "{NO_ROW_DEVICE}"\n'
    "| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, AccountSid"
)

_SERVER_KEYS = (
    "id", "createdDateTime", "lastModifiedDateTime", "createdBy",
    "lastModifiedBy", "lastExecutionDateTime", "detectorId", "lastRunDetails",
)
_OLD_DEVICE_ASSET = "#microsoft.graph.security.impactedDeviceAsset"
_OK = (200, 201, 204)


@dataclass
class Finding:
    key: str
    question: str
    answer: str
    stop: bool = False


@dataclass
class ProbeReport:
    findings: list[Finding] = field(default_factory=list)
    leftovers: int = 0
    aborted: str | None = None

    def stops(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.stop]


class ProbeAbort(RuntimeError):
    """A safety rule was violated; stop writing and clean up."""


class WriteNotVisible(RuntimeError):
    """An update was acknowledged but no read showed it within the long
    window. The step's question stays unanswered (a STOP), instead of
    being answered from the rule as it was before the write."""


def _ts(value: Any) -> datetime | None:
    """``lastModifiedDateTime`` as a datetime; Graph sends seven decimals."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        zone = tail[len(digits):]
        text = f"{head}.{digits[:6].ljust(6, '0')}{zone}"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _norm(value: Any) -> Any:
    """Drop empties, sort lists: the form two reads are compared in."""
    if isinstance(value, dict):
        out = {key: _norm(item) for key, item in value.items()}
        return {key: item for key, item in out.items() if not _empty(item)}
    if isinstance(value, list):
        items = [_norm(item) for item in value]
        items = [item for item in items if not _empty(item)]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def _diff_paths(left: Any, right: Any, prefix: str = "") -> list[str]:
    """Property paths where two normalised values differ. Paths only."""
    if isinstance(left, dict) and isinstance(right, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            paths.extend(_diff_paths(left.get(key), right.get(key), f"{prefix}.{key}" if prefix else key))
        return paths
    return [] if left == right else [prefix or "(root)"]


def _strip_server(rule: dict) -> dict:
    # ``@odata.*`` annotations (``@odata.context`` on a single read) are
    # not values, and are never sent back.
    out = {
        key: value for key, value in rule.items()
        if key not in _SERVER_KEYS and not str(key).startswith("@odata.")
    }
    for parent, nested in (("schedule", "nextRunDateTime"), ("queryCondition", "lastModifiedDateTime")):
        if isinstance(out.get(parent), dict):
            out[parent] = {key: value for key, value in out[parent].items() if key != nested}
    return out


def _rewritten_form(rule: dict) -> dict:
    """The rule as a file holds it once the old keys are gone."""
    body = copy.deepcopy(_strip_server(rule))
    body.pop("isEnabled", None)
    if isinstance(body.get("schedule"), dict):
        body["schedule"].pop("period", None)
    action = body.get("detectionAction")
    if isinstance(action, dict):
        action.pop("responseActions", None)
        template = action.get("alertTemplate")
        if isinstance(template, dict):
            for key in ("category", "mitreTechniques", "impactedAssets"):
                template.pop(key, None)
        scope = action.get("organizationalScope")
        if isinstance(scope, dict):
            scope.pop("scopeType", None)
            scope.pop("scopeNames", None)
    return body


def _template(rule: dict | None) -> dict:
    return ((rule or {}).get("detectionAction") or {}).get("alertTemplate") or {}


def _scope_groups(rule: dict | None) -> list[str]:
    scope = ((rule or {}).get("detectionAction") or {}).get("organizationalScope")
    return list((scope or {}).get("deviceGroups") or []) if isinstance(scope, dict) else []


def _filled_columns(rule: dict | None, collection: str) -> int:
    """Entries of ``collection`` that name at least one query column.
    An ``@odata.type`` annotation is not a column."""
    entries = (_template(rule).get("entityMappings") or {}).get(collection) or []
    return sum(
        1 for entry in entries
        if isinstance(entry, dict) and any(
            not _empty(value) for name, value in entry.items() if not str(name).startswith("@")
        )
    )


def _scan_actions(rule: dict | None) -> int:
    actions = ((rule or {}).get("detectionAction") or {}).get("automatedActions") or {}
    return len(actions.get("runAntivirusScans") or [])


def _technique_count(rule: dict | None) -> int:
    return sum(len(tactic.get("techniques") or []) for tactic in _template(rule).get("tactics") or [])


def _describe(response: Any, *, with_message: bool = True) -> str:
    """Status and Graph error code; the message only for synthetic bodies."""
    text = str(getattr(response, "status_code", "?"))
    try:
        error = (response.json() or {}).get("error") or {}
    except Exception:
        return text
    if error.get("code"):
        text += f" {error['code']}"
    if with_message and error.get("message"):
        text += f": {str(error['message'])[:200]}"
    return text


class _Probe:
    def __init__(
        self, client: Any, run_id: str, sleep: Callable[[float], None],
        converge_timeout_s: float, settle_timeout_s: float, poll_s: float,
        device_group: str | None = None,
    ) -> None:
        self.client = client
        self.run_id = run_id
        self.device_group = device_group
        self.sleep = sleep
        self.converge_attempts = max(1, int(converge_timeout_s / poll_s) + 1)
        self.settle_attempts = max(1, int(settle_timeout_s / poll_s) + 1)
        self.poll_s = poll_s
        self.report = ProbeReport()
        self.created: list[str] = []
        #: Per rule, the ``lastModifiedDateTime`` a read must show before
        #: it counts, and whether it must be strictly later (when the
        #: update response carried none, the last value seen before it).
        self.written: dict[str, tuple[datetime, bool]] = {}
        self.seen: dict[str, datetime] = {}

    # -- plumbing --------------------------------------------------------

    def note(self, key: str, question: str, answer: str, *, stop: bool = False) -> None:
        self.report.findings.append(Finding(key, question, answer, stop))

    def name(self, suffix: str) -> str:
        return f"{PREFIX}{self.run_id}_{suffix}"

    def create(self, body: dict, key: str, question: str, *, stop_on_reject: bool) -> str | None:
        if body.get("status") != "disabled":
            raise ProbeAbort("refused to send a create request without status: disabled")
        response = self.client.create_rule(body)
        if response.status_code not in _OK:
            self.note(key, question, f"rejected ({_describe(response)})", stop=stop_on_reject)
            return None
        created = response.json() or {}
        graph_id = str(created.get("id") or "")
        if not graph_id:
            self.note(key, question, "accepted, but the response carries no id", stop=True)
            return None
        self.created.append(graph_id)
        status = created.get("status")
        if status != "disabled":
            raise ProbeAbort("a test rule did not come back with status: disabled")
        self._remember_write(graph_id, created)
        return graph_id

    def patch(self, graph_id: str, body: dict) -> Any:
        if graph_id not in self.created:
            raise ProbeAbort("refused to update a rule the probe did not create")
        if body.get("status", "disabled") != "disabled":
            raise ProbeAbort("refused to send an update that changes status")
        response = self.client.update_rule(graph_id, body)
        if response.status_code in _OK:
            try:
                returned = response.json() or {}
            except Exception:
                returned = {}
            self._remember_write(graph_id, returned if isinstance(returned, dict) else {})
        return response

    def _remember_write(self, graph_id: str, returned: dict) -> None:
        stamp = _ts(returned.get("lastModifiedDateTime"))
        if stamp is not None:
            self.written[graph_id] = (stamp, False)
        elif graph_id in self.seen:
            self.written[graph_id] = (self.seen[graph_id], True)

    def _fresh(self, graph_id: str, rule: dict) -> bool:
        """Does ``rule`` show the last write to it? Without a timestamp on
        either side there is nothing to wait for."""
        want = self.written.get(graph_id)
        got = _ts(rule.get("lastModifiedDateTime"))
        if want is None or got is None:
            return True
        stamp, strictly_later = want
        return got > stamp if strictly_later else got >= stamp

    def _get(self, graph_id: str) -> dict | None:
        rule = self.client.get_rule(graph_id)
        if rule is not None and rule.get("status") not in (None, "disabled"):
            try:
                self.client.update_rule(graph_id, {"status": "disabled"})
            finally:
                raise ProbeAbort("a test rule was read back with a status other than disabled")
        return rule

    def read(self, graph_id: str, until: Callable[[dict], bool] | None = None, *, must: bool = True) -> dict | None:
        """GET the rule once it shows the last write to it (long window),
        then poll until ``until`` holds. ``must`` picks the long window
        (the change has to appear) or the short one (it may legitimately
        never appear) for that second part. A write that never shows
        raises ``WriteNotVisible``: no answer is read from a stale rule."""
        rule: dict | None = None
        for attempt in range(self.converge_attempts):
            rule = self._get(graph_id)
            if rule is not None and self._fresh(graph_id, rule):
                break
            if attempt < self.converge_attempts - 1:
                self.sleep(self.poll_s)
        else:
            if rule is not None:
                raise WriteNotVisible("an acknowledged update did not show within the long window")
            return None
        attempts = self.converge_attempts if must else self.settle_attempts
        for attempt in range(attempts):
            if rule is not None and self._fresh(graph_id, rule):
                stamp = _ts(rule.get("lastModifiedDateTime"))
                if stamp is not None:
                    self.seen[graph_id] = stamp
                if until is None or until(rule):
                    return rule
            if attempt < attempts - 1:
                self.sleep(self.poll_s)
                rule = self._get(graph_id)
        return rule

    def step(self, name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except ProbeAbort:
            raise
        except Exception as exc:  # the type only: a message could quote the tenant
            # A step that raised left its question unanswered, and a run
            # with an unanswered question is not a passed check.
            self.note(
                f"{name}_error", f"Step '{name}' completed?",
                f"error: {type(exc).__name__}", stop=True,
            )

    # -- bodies ----------------------------------------------------------

    def new_only_body(self, name: str) -> dict:
        return {
            "displayName": name,
            "status": "disabled",
            "description": "probe description 1",
            "queryCondition": {"queryText": QUERY},
            "schedule": {"frequency": "PT1H", "lookback": "PT4H"},
            "detectionAction": {
                "alertTemplate": {
                    "title": name,
                    "description": "probe alert description 1",
                    "severity": "informational",
                    "recommendedActions": "probe actions 1",
                    "tactics": [{"tactic": "Discovery", "techniques": [{"technique": "T1083", "subTechniques": []}]}],
                    "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]},
                    "customDetails": {"ProbeKey1": "DeviceName"},
                },
            },
        }

    def old_only_body(self, name: str) -> dict:
        return {
            "displayName": name,
            "status": "disabled",
            "queryCondition": {"queryText": QUERY},
            "schedule": {"period": "1H"},
            "detectionAction": {
                "alertTemplate": {
                    "title": name,
                    "description": "probe alert description (old keys)",
                    "severity": "informational",
                    "category": "Discovery",
                    "recommendedActions": "probe actions (old keys)",
                    "mitreTechniques": ["T1083"],
                    "impactedAssets": [{"@odata.type": _OLD_DEVICE_ASSET, "identifier": "deviceId"}],
                },
                "organizationalScope": None,
                "responseActions": [],
            },
        }

    # -- steps on the rule created with new keys only --------------------

    def old_keys_after_create(self, rule_id: str) -> None:
        rule = self.read(rule_id) or {}
        template = _template(rule)
        action = rule.get("detectionAction") or {}
        self.note(
            "old_keys_after_new_only_create",
            "Which old keys does Graph return for a rule created with new keys only?",
            f"period={(rule.get('schedule') or {}).get('period')!r}, category={template.get('category')!r}, "
            f"mitreTechniques={len(template.get('mitreTechniques') or [])}, "
            f"impactedAssets={len(template.get('impactedAssets') or [])}, "
            f"responseActions={len(action.get('responseActions') or [])}, "
            f"lookback={(rule.get('schedule') or {}).get('lookback')!r}",
        )

    def list_vs_get(self, rule_id: str) -> None:
        question = "Do the list call and the single-rule call return the same values?"
        paths: list[str] = ["(rule not listed)"]
        for attempt in range(self.settle_attempts):
            single = self.client.get_rule(rule_id)
            listed = next((r for r in self.client.list_rules() if str(r.get("id")) == rule_id), None)
            if single is not None and listed is not None:
                paths = _diff_paths(_norm(_strip_server(listed)), _norm(_strip_server(single)))
                if not paths:
                    break
            if attempt < self.settle_attempts - 1:
                self.sleep(self.poll_s)
        if paths:
            self.note("list_vs_get", question, "differ at: " + ", ".join(paths[:12]), stop=True)
        else:
            self.note("list_vs_get", question, "same")

    def patch_back_unchanged(self, rule_id: str) -> None:
        question = "Is a rule accepted unchanged when sent back in the rewritten form (expanded, no old keys)?"
        before = self.read(rule_id) or {}
        response = self.patch(rule_id, _rewritten_form(before))
        if response.status_code not in _OK:
            self.note("patch_back_unchanged", question, f"rejected ({_describe(response)})", stop=True)
            return
        after = self.read(rule_id, must=False) or {}
        paths = _diff_paths(_norm(_rewritten_form(before)), _norm(_rewritten_form(after)))
        if paths:
            self.note("patch_back_unchanged", question, "accepted, but changed: " + ", ".join(paths[:12]), stop=True)
        else:
            self.note("patch_back_unchanged", question, "accepted, unchanged")

    def edit_each_field(self, rule_id: str) -> None:
        response = self.patch(rule_id, {
            "description": "probe description 2",
            "schedule": {"frequency": "PT3H", "lookback": "PT12H"},
            "detectionAction": {
                "alertTemplate": {
                    "description": "probe alert description 2",
                    "severity": "low",
                    "recommendedActions": "probe actions 2",
                    "customDetails": {"ProbeKey2": "AccountName"},
                    "tactics": [{
                        "tactic": "Execution",
                        "techniques": [{"technique": "T1059", "subTechniques": ["T1059.001"]}],
                    }],
                    "entityMappings": {
                        "hosts": [{"deviceIdColumn": "DeviceId"}],
                        "accounts": [{"nameColumn": "AccountName", "sidColumn": "AccountSid"}],
                    },
                },
            },
        })
        question = "Is an update with new keys only applied to '{}'?"
        if response.status_code not in _OK:
            self.note("edit_request", "Is an update with new keys only accepted?",
                      f"rejected ({_describe(response)})", stop=True)
            return
        rule = self.read(rule_id, lambda r: r.get("description") == "probe description 2") or {}
        template = _template(rule)
        schedule = rule.get("schedule") or {}
        tactics = template.get("tactics") or []
        checks = {
            "description": (rule.get("description") == "probe description 2", False),
            "frequency": (schedule.get("frequency") == "PT3H", True),
            "lookback": (schedule.get("lookback") == "PT12H", False),
            "alert_description": (template.get("description") == "probe alert description 2", False),
            "severity": (template.get("severity") == "low", False),
            "recommendedActions": (template.get("recommendedActions") == "probe actions 2", False),
            "customDetails": (template.get("customDetails") == {"ProbeKey2": "AccountName"}, False),
            "tactics": (bool(tactics) and tactics[0].get("tactic") == "Execution" and _technique_count(rule) == 1, True),
            "entityMappings": (_filled_columns(rule, "accounts") == 1 and _filled_columns(rule, "hosts") == 1, True),
        }
        for name, (applied, is_pair) in checks.items():
            self.note(f"edit_{name}", question.format(name), "applied" if applied else "not applied",
                      stop=is_pair and not applied)
        self.note(
            "old_keys_after_new_only_update",
            "What do the old keys show after an update with new keys only?",
            f"period={schedule.get('period')!r}, category={template.get('category')!r}, "
            f"mitreTechniques={len(template.get('mitreTechniques') or [])}, "
            f"impactedAssets={len(template.get('impactedAssets') or [])}",
        )

    def replace_or_merge(self, rule_id: str) -> None:
        response = self.patch(rule_id, {"detectionAction": {"alertTemplate": {
            "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]},
        }}})
        question = "Does an update replace entity mappings, or merge them with the existing ones?"
        if response.status_code not in _OK:
            self.note("replace_or_merge", question, f"rejected ({_describe(response)})")
            return
        rule = self.read(rule_id, lambda r: _filled_columns(r, "accounts") == 0, must=False)
        self.note("replace_or_merge", question, "replace" if _filled_columns(rule, "accounts") == 0 else "merge")

    def clearing(self, rule_id: str) -> None:
        def values(rule: dict | None) -> dict[str, Any]:
            template = _template(rule)
            return {
                "description": (rule or {}).get("description"),
                "recommendedActions": template.get("recommendedActions"),
                "customDetails": template.get("customDetails"),
            }

        def body(forms: dict[str, Any]) -> dict:
            out: dict[str, Any] = {}
            if "description" in forms:
                out["description"] = forms["description"]
            template = {key: forms[key] for key in ("recommendedActions", "customDetails") if key in forms}
            if template:
                out["detectionAction"] = {"alertTemplate": template}
            return out

        answers: dict[str, str] = {}
        pending = ["description", "recommendedActions", "customDetails"]
        rounds = (
            ("null", {name: None for name in pending}),
            ("''", {"description": "", "recommendedActions": ""}),
            ("{}", {"customDetails": {}}),
        )
        for label, forms in rounds:
            forms = {name: form for name, form in forms.items() if name in pending}
            if not forms:
                continue
            response = self.patch(rule_id, body(forms))
            if response.status_code not in _OK:
                continue
            rule = self.read(rule_id, lambda r, f=forms: all(_empty(values(r)[n]) for n in f), must=False)
            for name in list(forms):
                if _empty(values(rule)[name]):
                    answers[name] = label
                    pending.remove(name)
        for name in ("description", "recommendedActions", "customDetails"):
            self.note(f"clear_{name}", f"Which empty form clears '{name}'?", answers.get(name, "none"))

    def tactics_shape(self, rule_id: str) -> None:
        sent = [
            {"tactic": "Persistence", "techniques": [{"technique": "T1136", "subTechniques": ["T1136.001"]}]},
            {"tactic": "Discovery", "techniques": [{"technique": "T1083", "subTechniques": []}]},
        ]
        response = self.patch(rule_id, {"detectionAction": {"alertTemplate": {"tactics": sent}}})
        if response.status_code not in _OK:
            self.note("two_tactics", "Are two tactics on one rule accepted?", f"rejected ({_describe(response)})")
            return
        rule = self.read(rule_id, lambda r: len(_template(r).get("tactics") or []) == 2, must=False)
        got = _template(rule).get("tactics") or []
        self.note("two_tactics", "Are two tactics on one rule accepted?", f"accepted; {len(got)} returned")
        order = [tactic.get("tactic") for tactic in got]
        self.note("tactics_order", "Is the order of tactics kept?",
                  "kept" if order == ["Persistence", "Discovery"] else f"returned as {order}")
        same = _norm(got) == _norm(sent)
        self.note("subtechnique_roundtrip", "Do techniques and sub-techniques come back as sent?",
                  "as sent" if same else "changed by the service")

    def schedule_forms(self, rule_id: str) -> None:
        response = self.patch(rule_id, {"schedule": {"frequency": "PT1H"}})
        if response.status_code in _OK:
            rule = self.read(rule_id, lambda r: (r.get("schedule") or {}).get("frequency") == "PT1H", must=False)
            self.note("lookback_when_omitted", "What lookback does the service set when none is sent?",
                      repr(((rule or {}).get("schedule") or {}).get("lookback")))
        else:
            self.note("lookback_when_omitted", "What lookback does the service set when none is sent?",
                      f"rejected ({_describe(response)})")

        response = self.patch(rule_id, {"schedule": {"frequency": "PT60M", "lookback": "PT240M"}})
        if response.status_code in _OK:
            rule = self.read(rule_id, must=False)
            schedule = (rule or {}).get("schedule") or {}
            self.note("duration_form_returned", "How does PT60M / PT240M come back?",
                      f"frequency={schedule.get('frequency')!r}, lookback={schedule.get('lookback')!r}")
        else:
            self.note("duration_form_returned", "How does PT60M / PT240M come back?",
                      f"rejected ({_describe(response)})")

        response = self.patch(rule_id, {"schedule": {"frequency": "PT0S"}})
        question = "Is a continuous rule (PT0S, no lookback, no period) accepted?"
        if response.status_code in _OK:
            rule = self.read(rule_id, lambda r: (r.get("schedule") or {}).get("frequency") == "PT0S", must=False)
            schedule = (rule or {}).get("schedule") or {}
            self.note("continuous_rule", question,
                      f"accepted; frequency={schedule.get('frequency')!r}, period={schedule.get('period')!r}, "
                      f"lookback={schedule.get('lookback')!r}")
        else:
            self.note("continuous_rule", question, f"rejected ({_describe(response)})")

        for key, schedule, question in (
            ("frequency_p1w", {"frequency": "P1W"}, "Is a one-week frequency (P1W) accepted?"),
            ("lookback_p1w", {"frequency": "P1D", "lookback": "P1W"}, "Is a one-week lookback (P1W) accepted?"),
        ):
            response = self.patch(rule_id, {"schedule": schedule})
            if response.status_code in _OK:
                field_name = "lookback" if "lookback" in schedule else "frequency"
                rule = self.read(
                    rule_id, lambda r, f=field_name: (r.get("schedule") or {}).get(f) == "P1W", must=False,
                )
                got = (rule or {}).get("schedule") or {}
                self.note(key, question, f"accepted; frequency={got.get('frequency')!r}, "
                          f"lookback={got.get('lookback')!r}, period={got.get('period')!r}")
            else:
                self.note(key, question, f"rejected ({_describe(response)})")
        self.patch(rule_id, {"schedule": {"frequency": "PT1H", "lookback": "PT4H"}})
        self.read(rule_id, lambda r: (r.get("schedule") or {}).get("frequency") == "PT1H", must=False)

    def automated_action(self, rule_id: str) -> None:
        question = "Is an automated action kept when sent without the old responseActions key?"
        response = self.patch(rule_id, {"detectionAction": {"automatedActions": {
            "runAntivirusScans": [{"deviceIdColumn": "DeviceId"}],
        }}})
        if response.status_code not in _OK:
            self.note("action_new_key_only", question, f"rejected ({_describe(response)})", stop=True)
            return
        rule = self.read(rule_id, lambda r: _scan_actions(r) == 1)
        if _scan_actions(rule) != 1:
            self.note("action_new_key_only", question, "not applied", stop=True)
            return
        old = len(((rule or {}).get("detectionAction") or {}).get("responseActions") or [])
        self.note("action_new_key_only", question, f"kept; the old key shows {old} action(s)")

        self.patch(rule_id, {"description": "probe description 3"})
        rule = self.read(rule_id, lambda r: r.get("description") == "probe description 3")
        kept = _scan_actions(rule) == 1
        self.note("action_survives_update", "Does the action survive an update that does not mention it?",
                  "kept" if kept else "lost", stop=not kept)

        response = self.patch(rule_id, {"detectionAction": {"automatedActions": {"runAntivirusScans": []}}})
        if response.status_code in _OK:
            rule = self.read(rule_id, lambda r: _scan_actions(r) == 0, must=False)
            self.note("action_removed_by_empty_list", "Does an empty list remove the action?",
                      "removed" if _scan_actions(rule) == 0 else "kept")
        else:
            self.note("action_removed_by_empty_list", "Does an empty list remove the action?",
                      f"rejected ({_describe(response)})")

    def scope_group(self) -> list[str]:
        """One device group for the disabled test rule: the operator's
        (``DEFENDER_PROBE_DEVICE_GROUP``), else one copied from an existing
        scoped rule, else none. Never reported."""
        if self.device_group:
            return [self.device_group]
        for rule in self.client.list_rules():
            if str(rule.get("id")) in self.created:
                continue
            groups = _scope_groups(rule)
            if groups:
                return [groups[0]]
        return []

    def scope(self, rule_id: str) -> None:
        question = "Does a rule keep its device-group scope when only deviceGroups is sent?"
        wanted = self.scope_group()
        if not wanted:
            self.note("scope_new_key_only", question,
                      "skipped: no device group named and no scoped rule in the tenant to copy a group from")
            self.note("scope_survives_update", "Does the scope survive an update that does not mention it?", "skipped")
            return
        response = self.patch(rule_id, {"detectionAction": {"organizationalScope": {"deviceGroups": wanted}}})
        if response.status_code not in _OK:
            self.note("scope_new_key_only", question,
                      f"rejected ({_describe(response, with_message=False)})", stop=True)
            return
        rule = self.read(rule_id, lambda r: _scope_groups(r) == wanted)
        if _scope_groups(rule) != wanted:
            self.note("scope_new_key_only", question, "not applied", stop=True)
            return
        old_scope = ((rule or {}).get("detectionAction") or {}).get("organizationalScope") or {}
        old_names_match = list(old_scope.get("scopeNames") or []) == wanted
        self.note("scope_new_key_only", question,
                  f"kept; old scopeType set: {bool(old_scope.get('scopeType'))}, old scopeNames match: {old_names_match}")

        self.patch(rule_id, {"description": "probe description 4"})
        rule = self.read(rule_id, lambda r: r.get("description") == "probe description 4")
        kept = _scope_groups(rule) == wanted
        self.note("scope_survives_update", "Does the scope survive an update that does not mention it?",
                  "kept" if kept else "lost", stop=not kept)

        response = self.patch(rule_id, {"detectionAction": {"organizationalScope": None}})
        if response.status_code in _OK:
            rule = self.read(rule_id, lambda r: not _scope_groups(r), must=False)
            self.note("scope_cleared_by_null", "Does organizationalScope: null remove the scope?",
                      "removed" if not _scope_groups(rule) else "kept")
        else:
            self.note("scope_cleared_by_null", "Does organizationalScope: null remove the scope?",
                      f"rejected ({_describe(response, with_message=False)})")

    def detection_action_parts(self, rule_id: str) -> None:
        """An update that changes the alert sends ``detectionAction`` with
        its ``alertTemplate`` only. Does the service keep the scope and the
        automated actions that request does not mention, or clear them?"""
        key = "detection_action_keeps_scope_and_actions"
        question = ("Does an update that carries detectionAction without organizationalScope "
                    "or automatedActions keep the rule's scope and actions?")
        groups = self.scope_group()
        setup: dict[str, Any] = {"automatedActions": {"runAntivirusScans": [{"deviceIdColumn": "DeviceId"}]}}
        if groups:
            setup["organizationalScope"] = {"deviceGroups": groups}

        def has_both(rule: dict | None) -> bool:
            return _scan_actions(rule) == 1 and (not groups or _scope_groups(rule) == groups)

        response = self.patch(rule_id, {"detectionAction": setup})
        if response.status_code not in _OK:
            self.note(key, question, f"not asked: setting scope and actions was rejected "
                      f"({_describe(response, with_message=False)})", stop=True)
            return
        if not has_both(self.read(rule_id, has_both)):
            self.note(key, question, "not asked: scope and actions did not apply", stop=True)
            return
        try:
            response = self.patch(rule_id, {"detectionAction": {"alertTemplate": {"severity": "medium"}}})
            if response.status_code not in _OK:
                self.note(key, question, f"rejected ({_describe(response)})", stop=True)
                return
            rule = self.read(rule_id, lambda r: _template(r).get("severity") == "medium")
            scope_kept = _scope_groups(rule) == groups if groups else None
            actions_kept = _scan_actions(rule) == 1
            scope_part = "scope not asked (no device group)" if scope_kept is None else (
                "scope kept" if scope_kept else "scope lost")
            actions_part = "actions kept" if actions_kept else "actions lost"
            self.note(key, question, f"{scope_part}, {actions_part}",
                      stop=scope_kept is False or not actions_kept)
        finally:
            self.patch(rule_id, {"detectionAction": {
                "organizationalScope": None, "automatedActions": {"runAntivirusScans": []},
            }})
            self.read(rule_id, lambda r: not _scope_groups(r) and _scan_actions(r) == 0, must=False)

    # -- steps on the rule created with old keys only --------------------

    def old_only_rule(self) -> None:
        question = "Is a rule with old keys only still accepted on create?"
        rule_id = self.create(self.old_only_body(self.name("old")), "create_old_only", question, stop_on_reject=False)
        if rule_id is None:
            return
        rule = self.read(rule_id) or {}
        self.note(
            "create_old_only", question,
            f"accepted; frequency={(rule.get('schedule') or {}).get('frequency')!r}, "
            f"tactics={len(_template(rule).get('tactics') or [])}, "
            f"techniques under tactics={_technique_count(rule)}, host columns={_filled_columns(rule, 'hosts')}",
        )
        question = "Old key filled and new key empty in one request (techniques): which one does Graph keep?"
        response = self.patch(rule_id, {"detectionAction": {"alertTemplate": {
            "category": "Discovery",
            "mitreTechniques": ["T1083", "T1082"],
            "tactics": [{"tactic": "Discovery", "techniques": []}],
        }}})
        if response.status_code not in _OK:
            self.note("old_filled_new_empty", question, f"rejected ({_describe(response)})")
            return
        rule = self.read(rule_id, lambda r: _technique_count(r) != 1, must=False)
        count = _technique_count(rule)
        if count == 2:
            answer = "the old key: both techniques are under tactics"
        elif count == 0:
            answer = "the new key: no techniques"
        else:
            answer = f"unclear: {count} technique(s) under tactics"
        self.note("old_filled_new_empty", question, answer)

    # -- cleanup ---------------------------------------------------------

    def cleanup(self) -> int:
        """Delete what was created, then every rule still carrying the
        test prefix; return how many such rules are still listed."""
        for graph_id in list(self.created):
            try:
                self.client.delete_rule(graph_id)
            except Exception:
                pass
        remaining = -1  # unknown until one list call succeeds
        for attempt in range(self.converge_attempts):
            try:
                leftovers = [
                    rule for rule in self.client.list_rules()
                    if str(rule.get("displayName", "")).startswith(PREFIX)
                ]
            except Exception:
                # Throttled past the client's retries, for example: wait
                # and list again rather than give up on the cleanup.
                if attempt < self.converge_attempts - 1:
                    self.sleep(self.poll_s)
                continue
            remaining = len(leftovers)
            if not remaining:
                return 0
            for rule in leftovers:
                try:
                    self.client.delete_rule(str(rule.get("id")))
                except Exception:
                    pass
            if attempt < self.converge_attempts - 1:
                self.sleep(self.poll_s)
        return remaining


def run_probe(
    client: Any,
    run_id: str,
    *,
    sleep: Callable[[float], None] = time.sleep,
    # Seen against a tenant: an acknowledged update took more than two
    # minutes to show in a read.
    converge_timeout_s: float = 300.0,
    settle_timeout_s: float = 30.0,
    poll_s: float = 5.0,
    device_group: str | None = None,
) -> ProbeReport:
    """Run every step against ``client`` and return the findings.

    Never raises for a service answer; a violated safety rule ends the
    run early (``report.aborted``). Created rules are deleted either way.
    ``device_group`` is the group the scope steps put on the disabled test
    rule (see ``DEVICE_GROUP_ENV``).
    """
    probe = _Probe(
        client, run_id, sleep, converge_timeout_s, settle_timeout_s, poll_s,
        device_group=device_group,
    )
    try:
        rule_id = probe.create(
            probe.new_only_body(probe.name("new")), "create_new_only",
            "Is a rule with new keys only, and no client id, accepted on create?", stop_on_reject=True,
        )
        if rule_id is not None:
            probe.note("create_new_only", "Is a rule with new keys only, and no client id, accepted on create?",
                       "accepted; status is disabled")
            for name, fn in (
                ("old_keys_after_create", probe.old_keys_after_create),
                ("list_vs_get", probe.list_vs_get),
                ("patch_back_unchanged", probe.patch_back_unchanged),
                ("edit_each_field", probe.edit_each_field),
                ("replace_or_merge", probe.replace_or_merge),
                ("clearing", probe.clearing),
                ("tactics_shape", probe.tactics_shape),
                ("schedule_forms", probe.schedule_forms),
                ("automated_action", probe.automated_action),
                ("scope", probe.scope),
                ("detection_action_parts", probe.detection_action_parts),
            ):
                probe.step(name, lambda fn=fn: fn(rule_id))
        probe.step("old_only_rule", probe.old_only_rule)
    except ProbeAbort as abort:
        probe.report.aborted = str(abort)
        probe.note("aborted", "Did the probe run to the end?", f"no: {abort}", stop=True)
    finally:
        probe.report.leftovers = probe.cleanup()
        if probe.report.leftovers:
            probe.note("cleanup", "Are all test rules gone?",
                       f"no: {probe.report.leftovers} still listed; run the sweep", stop=True)
        else:
            probe.note("cleanup", "Are all test rules gone?", "yes")
    return probe.report


def render_report(report: ProbeReport) -> str:
    """Markdown for the job summary. Synthetic values and booleans only."""
    lines = [
        "## Defender rule shape probe",
        "",
        f"- Aborted: {report.aborted or 'no'}",
        f"- Test rules still listed after cleanup: {report.leftovers}",
        f"- Answers that mean stop: {len(report.stops())}",
        "",
        "| Question | Answer | Stop |",
        "| --- | --- | --- |",
    ]
    for finding in report.findings:
        answer = finding.answer.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {finding.question} | {answer} | {'STOP' if finding.stop else ''} |")
    return "\n".join(lines) + "\n"
