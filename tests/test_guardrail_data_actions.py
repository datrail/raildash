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


def _adopted_v1(store):
    """An adopted guardrail made a v1 version (the proposal is v2 now)."""
    ref, adopted = _adopted(store)
    rules = {k: v for k, v in adopted["guardrail"]["rules"].items() if k != "data_actions"}
    return ref, store.edit_guardrail(adopted["guardrail"]["guardrail_version_id"], rules)


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
    assert set(found) == {f"{ENDPOINT} · unreadable call"}
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
    ref, adopted = _adopted_v1(store)
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


# ------------------------------------------------------- review round 1


def test_an_undeclared_upload_survives_a_later_override_and_rows_name_like_the_design():
    first = rule(overrides={"mcp__docs__sync": ["upload"]})
    [violation] = g.evaluate_data_actions({"rules": {"data_actions": first}},
                                          calls(("mcp__docs__sync", ["upload"], ["blob"])), {})
    assert violation["detail"]["from_undeclared"]
    later = rule(overrides={"mcp__docs__sync": ["read"]})
    assert not g.item_allowed({"rules": {"data_actions": later}}, violation)
    assert g.data_action_item("t", "not_offered", "e/mcp") == "t · not offered by e/mcp"


def test_allow_this_refuses_a_glob_like_name_and_calls_past_the_cap():
    rules = {"data_actions": rule()}
    star = {"rule": "data_actions", "item": "x", "detail": {"tool": "mcp@evil/mcp__*", "action": "upload"}}
    with pytest.raises(ValueError):
        g.with_item_allowed(rules, star)
    past = {"rule": "data_actions", "item": "x", "detail": {"tool": "mcp@(more calls)", "action": "unreadable",
                                                            "endpoint": None}}
    with pytest.raises(ValueError):
        g.with_item_allowed(rules, past)


def test_a_failure_to_classify_calls_makes_the_rule_unverified(store, monkeypatch):
    ref, _ = with_data_actions(store, rule())
    live(store)

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(type(store), "_calls_for_rule", broken)
    send(store, listed(), call("upload_file", {"content": PNG}))
    detail = store.guardrail_detail(ref)
    assert detail["rules"]["data_actions"]["state"] == "unverified"
    assert detail["state"] in ("unverified", "violated")


def test_calls_are_classified_for_judging_only_under_a_v2_version(store, monkeypatch):
    seen = []
    original = type(store)._calls_for_rule

    def spy(self, ref, calls):
        seen.append(ref)
        return original(self, ref, calls)

    monkeypatch.setattr(type(store), "_calls_for_rule", spy)
    _adopted_v1(store)  # v1 only
    live(store)
    send(store, listed(), call("read_doc", {"doc_id": "d"}))
    assert seen == []


def test_a_repeat_without_undeclared_arguments_keeps_the_upload_counting(store):
    ref, adopted = with_data_actions(store, rule(overrides={f"mcp@{ENDPOINT}__read_doc": ["read"]},
                                                 allowed=[{"tool": f"mcp@{ENDPOINT}__read_doc", "actions": ["read"]}]))
    live(store)
    send(store, listed(), call("read_doc", {"doc_id": "a", "blob": "x" * 40}))
    send(store, call("read_doc", {"doc_id": "b", "blob": "y"}))
    row = rows(store, ref)[("data_actions", f"mcp@{ENDPOINT}__read_doc · upload")]
    assert row["counts"] and row["detail"]["from_undeclared"] and row["detail"]["undeclared"] == ["blob"]


# ------------------------------------------------------------- M2b proposal


def test_the_proposal_allows_what_was_called_and_blocks_declared_upload_tools(store):
    from test_guardrail_custody import baseline

    live(store)
    # The learning window: the agent lists the server's tools and reads.
    send(store, listed(), call("read_doc", {"doc_id": "d"}))
    alignment, ref = baseline(store)
    proposal = store.propose_guardrail(alignment["alignment_version_id"])
    contract = proposal["guardrail"]
    assert contract["guardrail_contract_version"] == 2
    rule_ = contract["rules"]["data_actions"]
    assert {"tool": f"mcp@{ENDPOINT}__read_doc", "actions": ["read"]} in rule_["allowed"]
    assert rule_["unclassified"] == "flag" and rule_["overrides"] == {}
    blocked = {item["tool"]: item for item in proposal["data_actions_blocked"]}
    assert blocked[f"mcp@{ENDPOINT}__upload_file"]["actions"] == ["upload"]
    # Adopting it judges the upload the agent never made while learning.
    store.adopt_guardrail(alignment["alignment_version_id"])
    send(store, call("upload_file", {"content": PNG}))
    assert rows(store, ref)[("data_actions", f"mcp@{ENDPOINT}__upload_file · upload")]["counts"]


def test_a_hinted_read_is_blocked_not_allowed_by_the_proposal(store):
    from test_guardrail_custody import baseline

    hinted = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "sync_notes", "inputSchema": {"type": "object", "properties": {}},
         "annotations": {"readOnlyHint": True}}]}}
    send(store, mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, hinted))
    alignment, _ = baseline(store)
    proposal = store.propose_guardrail(alignment["alignment_version_id"])
    blocked = {item["tool"]: item for item in proposal["data_actions_blocked"]}
    assert blocked[f"mcp@{ENDPOINT}__sync_notes"]["weak_read"]
    assert not any(e["tool"].endswith("sync_notes") for e in proposal["guardrail"]["rules"]["data_actions"]["allowed"])


def test_a_v1_agent_is_offered_data_actions_until_it_accepts_or_dismisses(store):
    ref, adopted = _adopted_v1(store)
    rules = adopted["guardrail"]["rules"]
    send(store, listed(), call("read_doc", {"doc_id": "d"}))
    assert store.guardrail_detail(ref)["data_actions_offer_available"]
    offer = store.data_actions_offer(ref)
    assert {"tool": f"mcp@{ENDPOINT}__read_doc", "actions": ["read"]} in offer["rule"]["allowed"]
    made = store.add_data_actions(ref)
    assert made["guardrail"]["guardrail_contract_version"] == 2
    event = store.guardrail_detail(ref)["events"][0]
    assert event["action"] == "add_data_actions" and event["detail"]["edited"] is False
    assert not store.guardrail_detail(ref)["data_actions_offer_available"]
    with pytest.raises(ValueError):
        store.add_data_actions(ref)
    with pytest.raises(ValueError):
        store.dismiss_data_actions(ref)  # nothing to dismiss under a v2
    # Back to v1 and dismiss: not offered again, until a turn-off.
    store.edit_guardrail(made["guardrail"]["guardrail_version_id"], rules)
    assert store.guardrail_detail(ref)["data_actions_offer_available"]
    store.dismiss_data_actions(ref)
    assert not store.guardrail_detail(ref)["data_actions_offer_available"]
    store.turn_off_guardrail(ref)
    v1_id = store.guardrail_detail(ref)["versions"][0]["guardrail"]["guardrail_version_id"]
    store.switch_guardrail(v1_id)
    assert store.guardrail_detail(ref)["data_actions_offer_available"]


def test_the_proposal_counts_only_calls_in_the_learning_window(store):
    from test_guardrail_custody import baseline

    live(store)
    send(store, listed(), call("read_doc", {"doc_id": "d"}))
    alignment, _ = baseline(store)
    # After the lock: the same tool, now with an undeclared argument.
    send(store, call("read_doc", {"doc_id": "d", "blob": "x" * 50}))
    proposal = store.propose_guardrail(alignment["alignment_version_id"])
    allowed = {e["tool"]: e["actions"] for e in proposal["guardrail"]["rules"]["data_actions"]["allowed"]}
    assert allowed[f"mcp@{ENDPOINT}__read_doc"] == ["read"]


def test_the_routes_need_the_token_and_answer_as_the_store_does(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from raildash import app as app_module

    db = Store(tmp_path / "routes.db")
    monkeypatch.setattr(app_module, "store", db)
    client = TestClient(app_module.app)
    auth = {"X-RailDash-Token": app_module.LOCAL_TOKEN}
    ref, _ = _adopted_v1(db)
    path = f"/api/guardrails/{ref}"
    assert client.post(f"{path}/data-actions", json={}).status_code in (401, 403)
    assert client.get(f"{path}/data-actions-offer").status_code in (401, 403)
    assert client.get(f"{path}/data-actions-offer", headers=auth).json()["offer"]["rule"]["unclassified"] == "flag"
    assert client.post(f"{path}/data-actions", json={"rule": "x"}, headers=auth).status_code == 422
    assert client.post(f"{path}/data-actions", json={"rule": {"allowed": [{"tool": "x", "actions": ["steal"]}],
                                                              "overrides": {}, "unclassified": "flag"}},
                       headers=auth).status_code == 422
    assert client.post(f"{path}/data-actions", json={}, headers=auth).status_code == 201
    assert client.post(f"{path}/data-actions", json={}, headers=auth).status_code == 409
    assert client.post(f"{path}/data-actions/dismiss", json={}, headers=auth).status_code == 409
    assert client.post("/api/guardrails/nope/data-actions", json={}, headers=auth).status_code == 404
    db.close()


# ---------------------------------------------------------- M2c not offered


def _due_now(store):
    store._db.execute("UPDATE data_action_pending SET due_at = '2000-01-01T00:00:00.000000Z'")
    store._db.commit()


def test_a_tool_the_endpoint_never_listed_is_not_offered_after_the_delay(store):
    ref, _ = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions":
                                             ["read", "upload", "update", "delete", "execute", "unclassified"]}]))
    live(store)
    send(store, listed(), call("export_all", {}))
    # Queued, not judged yet: a listing may still arrive.
    assert not any(key[0] == "data_actions" for key in rows(store, ref))
    _due_now(store)
    live(store)  # a heartbeat runs the queue
    item = f"mcp@{ENDPOINT}__export_all · not offered by {ENDPOINT}"
    row = rows(store, ref)[("data_actions", item)]
    assert row["counts"] and row["evidence_class"] == "observed"
    store.allow_guardrail_row(row["row_id"])
    assert not rows(store, ref)[("data_actions", item)]["counts"]


def test_a_listing_that_arrives_within_the_delay_clears_the_call(store):
    ref, _ = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions": ["read", "unclassified"]}]))
    live(store)
    send(store, listed(), call("export_all", {}))
    later = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        *LISTING["result"]["tools"], {"name": "export_all", "inputSchema": READ_SCHEMA}]}}
    send(store, mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, later))
    _due_now(store)
    live(store)
    assert not any("not offered" in key[1] for key in rows(store, ref))


def test_an_endpoint_that_never_listed_its_tools_is_not_judged(store):
    ref, _ = with_data_actions(store, rule(unclassified="allow"))
    live(store)
    send(store, call("anything", {}))
    # Queued (its first listing may still come), then dropped unjudged.
    _due_now(store)
    live(store)
    assert store._db.execute("SELECT count(*) FROM data_action_pending").fetchone()[0] == 0
    assert not any("not offered" in key[1] for key in rows(store, ref))


def test_an_allowed_not_offered_tool_is_not_a_row(store):
    ref, _ = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions":
                                             ["read", "unclassified", "not_offered"]}]))
    live(store)
    send(store, listed(), call("export_all", {}))
    _due_now(store)
    live(store)
    assert not any("not offered" in key[1] for key in rows(store, ref))


def _age_listings(store, hours):
    from datetime import timedelta

    old = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    store._db.execute("UPDATE tool_schemas SET last_seen = ?, first_seen = ? WHERE source = 'mcp_tools_list'", (old, old))
    store._db.commit()


def test_every_page_of_the_newest_listing_counts_after_a_day(store):
    ref, _ = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions": ["read", "unclassified"]}]))
    live(store)
    pages = [{"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": n, "inputSchema": READ_SCHEMA} for n in names]}}
             for names in (("a_read", "b_read"), ("c_read", "d_read"))]
    send(store, *(mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, page) for page in pages))
    _age_listings(store, 25)
    send(store, call("a_read", {}))
    _due_now(store)
    live(store)
    assert not any("not offered" in key[1] for key in rows(store, ref))


def test_a_listing_in_the_batch_that_runs_the_queue_counts(store):
    ref, _ = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions": ["read", "unclassified"]}]))
    live(store)
    send(store, listed(), call("export_all", {}))
    _due_now(store)
    later = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "export_all", "inputSchema": READ_SCHEMA}]}}
    send(store, mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, later))
    assert not any("not offered" in key[1] for key in rows(store, ref))


def test_a_late_first_listing_is_still_compared(store):
    ref, _ = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions": ["read", "unclassified"]}]))
    live(store)
    send(store, call("export_all", {}))  # no listing yet
    send(store, listed())  # the first listing, without export_all
    _due_now(store)
    live(store)
    assert ("data_actions", f"mcp@{ENDPOINT}__export_all · not offered by {ENDPOINT}") in rows(store, ref)


def test_a_newer_version_judges_a_queued_call_and_a_turn_off_drops_it(store):
    ref, adopted = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions": ["read", "unclassified"]}]))
    live(store)
    send(store, listed(), call("export_all", {}))
    # An edit (as Allow this makes) in the delay doesn't lose the call.
    store.edit_guardrail(adopted["guardrail"]["guardrail_version_id"], adopted["guardrail"]["rules"])
    _due_now(store)
    live(store)
    assert any("not offered" in key[1] for key in rows(store, ref))
    send(store, call("another_tool", {}))
    store.turn_off_guardrail(ref)
    _due_now(store)
    live(store)
    assert not any("another_tool" in key[1] for key in rows(store, ref))


def test_a_failing_judgement_marks_the_check_and_does_not_block_the_queue(store, monkeypatch):
    ref, _ = with_data_actions(store, rule([{"tool": f"mcp@{ENDPOINT}__*", "actions": ["read", "unclassified"]}]))
    live(store)
    send(store, listed(), call("export_all", {}), call("other_tool", {}))
    _due_now(store)
    original = type(store)._judge_not_offered_locked
    calls_seen = []

    def flaky(self, *args):
        calls_seen.append(args[3])
        if len(calls_seen) == 1:
            raise RuntimeError("boom")
        return original(self, *args)

    monkeypatch.setattr(type(store), "_judge_not_offered_locked", flaky)
    live(store)
    assert len(calls_seen) == 2
    assert store._db.execute("SELECT count(*) FROM data_action_pending").fetchone()[0] == 0
    from raildash.guardrail_store import EVERY_AGENT, MARK_CHECK_FAILED

    assert store._mark_at(*EVERY_AGENT, MARK_CHECK_FAILED) is not None
    # The other call was still judged.
    assert any("not offered" in key[1] for key in rows(store, ref))


# ------------------------------------------------------------------ M3 panel


def test_a_tool_says_why_and_shows_its_schemas(store):
    send(store, listed(), call("upload_file", {"content": PNG}))
    found = store.data_action_tool(f"mcp@{ENDPOINT}__upload_file")
    assert found["classification"]["actions"] == ["upload"]
    assert any("base64" in reason for reason in found["classification"]["reasons"])
    assert found["schemas"][0]["endpoint"] == ENDPOINT and found["calls"] == 1
    assert store.data_action_tool("nope") is None


def test_the_tool_route_is_token_gated(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from raildash import app as app_module

    db = Store(tmp_path / "routes.db")
    monkeypatch.setattr(app_module, "store", db)
    client = TestClient(app_module.app)
    auth = {"X-RailDash-Token": app_module.LOCAL_TOKEN}
    db.upsert_session("s1")
    db.add_interactions("s1", [listed(), call("read_doc", {"doc_id": "d"})], authenticated=True)
    name = f"mcp@{ENDPOINT}__read_doc"
    assert client.get("/api/data-actions/tool", params={"name": name}).status_code in (401, 403)
    assert client.get("/api/data-actions/tool", params={"name": name}, headers=auth).json()["classification"]["actions"] == ["read"]
    assert client.get("/api/data-actions/tool", params={"name": "x"}, headers=auth).status_code == 404
    db.close()
