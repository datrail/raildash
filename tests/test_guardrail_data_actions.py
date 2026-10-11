"""DR-205 M2: the `data_actions` rule (data-actions design §4.4)."""

from __future__ import annotations

import base64
import copy
import itertools
import json
from datetime import datetime, timezone

import pytest

from raildash import guardrail as g
from raildash.ingest import normalise
from raildash.store import Store
from test_guardrail_custody import _adopted, live, rows, send

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64).decode()
READ_SCHEMA = {"type": "object", "properties": {"doc_id": {"type": "string"}}}
UPLOAD_SCHEMA = {"type": "object", "properties": {"content": {"type": "string", "contentEncoding": "base64"}}}
LISTING = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
    {"name": "read_doc", "description": "Read one doc.", "inputSchema": READ_SCHEMA},
    {"name": "upload_file", "description": "Upload a file.", "inputSchema": UPLOAD_SCHEMA}]}}
ENDPOINT = "docs.example.com/mcp"
_IDS = itertools.count(1)


def rule(allowed=(), overrides=None, unclassified="flag"):
    return {"allowed": [dict(entry) for entry in allowed], "overrides": overrides or {},
            "unclassified": unclassified}


def mcp(body, reply=None):
    now = datetime.now(timezone.utc)
    return normalise({
        "interaction_id": f"da-{next(_IDS)}",
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "timestamp_ns": int(now.timestamp() * 1e9),
        "request": {"method": "POST", "path": "/mcp", "headers": {"host": "docs.example.com"}, "body": body},
        "response": {"status_code": 200, "headers": {"content-type": "application/json"}, "body": reply or {}},
    })


def call(name, arguments):
    return mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}})


def listed():
    return mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, LISTING)


# --------------------------------------------------------------- contract


def test_a_v2_version_validates_and_v1_still_does():
    base = {
        "guardrail_contract_version": 1, "guardrail_version_id": "grd-x", "version": "g1",
        "created_at": "2026-10-11T00:00:00Z",
        "agent_identity": {"kind": "local_agent_key", "value": "a"},
        "derived_from": {"alignment_version_id": "aspver-x"},
        "rules": {
            "uploads": {"allowed_hosts": [], "max_request_bytes": {}, "denied_tool_calls": []},
            "saved_files": {"allowed": []}, "service_ports": {"allowed": []},
            "out_of_spec_calls": {"allowed_hosts": [], "allowed_mcp_servers": [],
                                  "seeded_from_declared": {"hosts": [], "mcp_servers": []}},
        },
    }
    assert g.guardrail_problems(base) == []
    v2 = copy.deepcopy(base)
    v2["guardrail_contract_version"] = 2
    assert g.guardrail_problems(v2)  # v2 requires the rule
    v2["rules"]["data_actions"] = rule([{"tool": "mcp__docs__*", "actions": ["read"]}],
                                       overrides={"mcp__docs__sync": ["upload"]})
    assert g.guardrail_problems(v2) == []
    assert g.contract_rules(v2) == g.RULES_V2 and g.contract_rules(base) == g.RULES
    bad = copy.deepcopy(v2)
    bad["rules"]["data_actions"]["allowed"][0]["actions"] = ["exfiltrate"]
    assert g.guardrail_problems(bad)
    v1_with_rule = copy.deepcopy(v2)
    v1_with_rule["guardrail_contract_version"] = 1
    assert g.guardrail_problems(v1_with_rule)  # v1 is closed


def test_tool_globs_cross_slashes():
    assert g.tool_glob_matches("mcp@docs.example.com/*", "mcp@docs.example.com/mcp__read")
    assert g.tool_glob_matches("mcp__docs__*", "mcp__docs__read_doc")
    assert not g.tool_glob_matches("mcp__docs__read_doc", "mcp__docs__read_doc_x")
    assert not g.tool_glob_matches("mcp__docs__*", "mcp__other__read")


# -------------------------------------------------------------- evaluator


def calls(*items):
    return [{"tool": t, "class": "observed", "classified": a, "undeclared": u, "unreadable": False,
             "bytes": 10, "content_kinds": [], "endpoint": ENDPOINT, "not_offered": False}
            for t, a, u in items]


def evaluate(data_actions, found):
    contract = {"rules": {"data_actions": data_actions}}
    return {v["item"]: v for v in g.evaluate_data_actions(contract, found, {"id": 7})}


def test_an_action_no_entry_allows_is_a_violation():
    found = evaluate(rule([{"tool": "mcp__docs__read_doc", "actions": ["read"]}]), calls(
        ("mcp__docs__read_doc", ["read"], []),
        ("mcp__docs__upload_file", ["upload"], []),
        ("Bash", ["execute"], []),  # built-in: not judged
    ))
    assert set(found) == {"mcp__docs__upload_file · upload"}
    violation = found["mcp__docs__upload_file · upload"]
    assert violation["rule"] == "data_actions" and violation["detail"]["action"] == "upload"
    assert violation["source"] == {"kind": "interaction", "id": 7}


def test_overrides_replace_the_classification_but_not_an_undeclared_upload():
    data_actions = rule([{"tool": "mcp__docs__sync", "actions": ["read"]}], overrides={"mcp__docs__sync": ["read"]})
    assert evaluate(data_actions, calls(("mcp__docs__sync", ["upload"], []))) == {}
    found = evaluate(data_actions, calls(("mcp__docs__sync", ["upload"], ["secret"])))
    assert set(found) == {"mcp__docs__sync · upload"}
    assert found["mcp__docs__sync · upload"]["detail"]["from_undeclared"]


def test_unclassified_flags_unless_allowed_and_unreadable_calls_fail_closed():
    assert set(evaluate(rule(), calls(("mcp__docs__frob", [], [])))) == {"mcp__docs__frob · unclassified"}
    assert evaluate(rule(unclassified="allow"), calls(("mcp__docs__frob", [], []))) == {}
    unreadable = [{"tool": f"mcp@{ENDPOINT}", "class": "observed", "unreadable": True,
                   "classified": [], "undeclared": [], "bytes": 4_000_000, "endpoint": ENDPOINT}]
    found = evaluate(rule(), unreadable)
    assert set(found) == {f"mcp@{ENDPOINT} · unreadable"}
    assert evaluate(rule([{"tool": f"mcp@{ENDPOINT}", "actions": ["unreadable"]}]), unreadable) == {}


def test_a_v1_version_has_no_data_actions_rule():
    assert g.evaluate_data_actions({"rules": {"uploads": {}}}, calls(("mcp__docs__x", ["upload"], [])), {}) == []
    row = {"rule": "data_actions", "item": "x · upload", "detail": {"tool": "x", "action": "upload"}}
    assert g.item_allowed({"rules": {"uploads": {}}}, row)


def test_allow_this_adds_exactly_the_tool_and_action():
    rules = {"data_actions": rule([{"tool": "mcp__docs__read_doc", "actions": ["read"]}])}
    row = {"rule": "data_actions", "item": "mcp__docs__read_doc · upload",
           "detail": {"tool": "mcp__docs__read_doc", "action": "upload"}}
    updated = g.with_item_allowed(rules, row)
    assert updated["data_actions"]["allowed"] == [{"tool": "mcp__docs__read_doc", "actions": ["read", "upload"]}]
    new = {**row, "item": "mcp__docs__x · delete", "detail": {"tool": "mcp__docs__x", "action": "delete"}}
    assert g.with_item_allowed(rules, new)["data_actions"]["allowed"][-1] == {"tool": "mcp__docs__x", "actions": ["delete"]}
    assert g.item_allowed({"rules": updated}, row)
    with pytest.raises(ValueError):
        g.with_item_allowed({"uploads": {}}, row)


# ------------------------------------------------------------------ store


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "da.db")
    yield db
    db.close()


def with_data_actions(store, data_actions):
    return _adopted(store, data_actions=data_actions)


def test_the_kubecon_scenario_on_the_store(store):
    ref, adopted = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__read_doc", "actions": ["read"]}]))
    assert adopted["guardrail"]["guardrail_contract_version"] == 2
    live(store)
    send(store, listed(), call("read_doc", {"doc_id": "d1"}))
    detail = store.guardrail_detail(ref)
    assert not any(row["rule"] == "data_actions" for row in detail["rows"])
    assert detail["rules"]["data_actions"]["state"] == "held"
    send(store, call("upload_file", {"content": PNG}))
    found = rows(store, ref)
    upload = found[("data_actions", f"mcp@{ENDPOINT}__upload_file · upload")]
    assert upload["counts"] and upload["evidence_class"] == "observed"
    assert upload["detail"]["content_kinds"] == ["image"]
    detail = store.guardrail_detail(ref)
    assert detail["state"] == "violated"
    assert detail["rules"]["data_actions"]["state"] == "violated"
    # Allow this: a new version with that tool's upload allowed.
    store.allow_guardrail_row(upload["row_id"])
    active = store.guardrail_detail(ref)["active"]["guardrail"]["rules"]["data_actions"]
    assert {"tool": f"mcp@{ENDPOINT}__upload_file", "actions": ["upload"]} in active["allowed"]
    assert not rows(store, ref)[("data_actions", f"mcp@{ENDPOINT}__upload_file · upload")]["counts"]


def test_switching_back_to_a_v1_version_stops_the_rule(store):
    ref, adopted = _adopted(store)
    v1_id = adopted["guardrail"]["guardrail_version_id"]
    rules = copy.deepcopy(adopted["guardrail"]["rules"])
    rules["data_actions"] = rule()
    store.edit_guardrail(v1_id, rules)
    live(store)
    send(store, listed(), call("upload_file", {"content": PNG}))
    assert rows(store, ref)[("data_actions", f"mcp@{ENDPOINT}__upload_file · upload")]["counts"]
    store.switch_guardrail(v1_id)
    detail = store.guardrail_detail(ref)
    row = next(r for r in detail["rows"] if r["rule"] == "data_actions")
    assert not row["counts"]
    assert "data_actions" not in detail["rules"]
