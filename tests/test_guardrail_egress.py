"""DR-207 M2: the `egress_containment` rule, contract v3, and the Egress line.

The ASPs are RailMon's real v1 fixture (`test_guardrail`'s helpers) carrying
`egress_containment` and `egress_proxy_declared` the way RailMon's rule
pack 11 writes them (railmon `tools/scan/egress_containment.py`), stored
through `Store.load_asp`, which runs the ASP hook.
"""

from __future__ import annotations

import copy
import itertools
import json

import pytest
from jsonschema import Draft202012Validator

from raildash import guardrail as g
from raildash.store import Store
from test_guardrail import NOW, PREVIOUS, SCHEMAS, guardrail, stored, v1_bundle
from test_guardrail_custody import asp, baseline, live, load, rows

EGRESS_METHOD = ("docker inspect of the container, its network-namespace owner, "
                 "its networks and their other containers")


def egress(level: str = "allow_list_enforced", status: str = "ANSWERED", *, peers=()) -> dict:
    """`egress_containment` in each status, as RailMon's pack 11 writes it."""
    if status in ("BLIND", "FAILED"):
        return {"value": None, "status": status, "reason": "NO_SOURCE_ACCESS", "tier": "observed",
                "method": EGRESS_METHOD}
    networks = [{"name": "private", "internal": True, "gateway_peers": list(peers)}] if (
        level == "internal_network") else []
    value = {
        "level": level,
        "contained": level in g.CONTAINED_LEVELS,
        "enforcer": "openshell" if level == "allow_list_enforced" else None,
        "observations": {
            "network_mode": {"allow_list_enforced": "none", "no_network": "none", "internal_network": "private",
                             "host_network": "host", "host_process": None}.get(level, "bridge"),
            "networks": networks,
            "openshell_labels": level == "allow_list_enforced",
            "privileged": False,
            "runtime_socket_mounts": [],
        },
        "via": None,
        "allow_list": None,
        "reasons": [f"why {level}"],
    }
    field = {"value": value, "status": status, "tier": "observed", "authored_by": "none",
             "method": EGRESS_METHOD}
    if status == "PARTIAL":
        field.update(reason="NO_SOURCE_ACCESS", note="a network that could not be inspected decided it")
    return field


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "egress.db")
    yield db
    db.close()


PROXY = {"value": {"HTTPS_PROXY": "http://proxy.corp:3128"}, "status": "ANSWERED", "tier": "declared",
         "authored_by": "subject", "method": "container environment: *_PROXY and NO_PROXY, credentials removed"}


# ------------------------------------------------------------------ contract


def test_v3_is_the_version_with_egress_containment_and_only_that():
    four = guardrail()["rules"]
    assert g.contract_version(four) == 1
    assert g.contract_version({**four, "data_actions": {}}) == 2
    assert g.contract_version({**four, "egress_containment": {"require": "contained"}}) == 3
    assert g.contract_version({**four, "data_actions": {}, "egress_containment": {"require": "contained"}}) == 3
    assert g.contract_rules({"rules": four}) == g.RULES
    assert g.contract_rules({"rules": {**four, "egress_containment": {}}}) == (*g.RULES, g.EGRESS)


def test_the_v3_schema_requires_the_rule_and_closes_it():
    schema = json.loads((SCHEMAS / "guardrail-version-v3.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    value = guardrail(egress_containment={"require": "contained"})
    value["guardrail_contract_version"] = 3
    assert g.guardrail_problems(value) == []
    for require in ("allow_list_enforced",):
        assert g.guardrail_problems({**value, "rules": {**value["rules"], "egress_containment": {"require": require}}}) == []
    missing = copy.deepcopy(value)
    del missing["rules"]["egress_containment"]
    assert g.guardrail_problems(missing)
    for bad in ({"require": "mostly"}, {"require": "contained", "extra": 1}, {}):
        broken = copy.deepcopy(value)
        broken["rules"]["egress_containment"] = bad
        assert g.guardrail_problems(broken), bad
    # The rule isn't a v1 or v2 field: those stay closed as they were.
    v1 = guardrail(egress_containment={"require": "contained"})
    assert g.guardrail_problems(v1)


# ---------------------------------------------------------------- evaluator


def _judge(store, attribute, require="contained", *, now=NOW):
    _, bundle = stored(store, v1_bundle(egress_containment=attribute))
    version = guardrail(egress_containment={"require": require})
    version["guardrail_contract_version"] = 3
    return g.evaluate_asp(version, bundle, asp_id="asp-1", previous_collected_at=PREVIOUS, now=now)


@pytest.mark.parametrize(
    "level, status, require, state, reason, items",
    [
        ("allow_list_enforced", "ANSWERED", "contained", "held", None, []),
        ("no_network", "ANSWERED", "contained", "held", None, []),
        ("internal_network", "ANSWERED", "contained", "held", None, []),
        ("open", "ANSWERED", "contained", "violated", None, ["open"]),
        ("host_network", "ANSWERED", "contained", "violated", None, ["host_network"]),
        ("host_process", "ANSWERED", "contained", "violated", None, ["host_process"]),
        ("allow_list_enforced", "ANSWERED", "allow_list_enforced", "held", None, []),
        ("no_network", "ANSWERED", "allow_list_enforced", "violated", None, ["no_network"]),
        # A network RailMon couldn't inspect decided it: missing evidence, not a break.
        ("open", "PARTIAL", "contained", "unverified", g.PARTIAL_NO_VIOLATION, []),
        ("open", "BLIND", "contained", "unverified", "BLIND", []),
        ("open", "FAILED", "contained", "unverified", "FAILED", []),
    ],
)
def test_the_rule_against_each_level_and_status(store, level, status, require, state, reason, items):
    result = _judge(store, egress(level, status), require)["rules"][g.EGRESS]
    assert (result["state"], result["reason"]) == (state, reason)
    assert [v["item"] for v in result["violations"]] == items
    for violation in result["violations"]:
        assert violation["evidence_class"] == g.OBSERVED and violation["source"]["kind"] == "asp"
        assert violation["detail"]["require"] == require and violation["detail"]["reasons"]


def test_an_asp_from_before_pack_11_or_with_a_bad_value_is_unverified(store):
    _, bundle = stored(store, v1_bundle(egress_containment=None))
    version = guardrail(egress_containment={"require": "contained"})
    version["guardrail_contract_version"] = 3
    result = g.evaluate_asp(version, bundle, asp_id="a", previous_collected_at=PREVIOUS, now=NOW)
    assert result["rules"][g.EGRESS] == {"state": "unverified", "reason": g.NOT_COLLECTED, "violations": []}
    # RailDash's vendored bundle schema refuses an unknown level at ingest;
    # the evaluator still doesn't trust one handed to it.
    bad = egress("open")
    bad["value"]["level"] = "mostly_contained"
    with pytest.raises(ValueError, match="egress_containment"):
        stored(store, v1_bundle(egress_containment=bad))
    tampered = copy.deepcopy(bundle)
    tampered["attributes"]["egress_containment"] = bad
    result = g.evaluate_asp(version, tampered, asp_id="a", previous_collected_at=PREVIOUS, now=NOW)
    assert (result["rules"][g.EGRESS]["state"], result["rules"][g.EGRESS]["reason"]) == (
        "unverified", g.MALFORMED_EVIDENCE)


def test_a_stale_asp_leaves_held_unverified_and_a_violation_real(store):
    later = "2026-09-24T04:00:00Z"
    held = _judge(store, egress("no_network"), now=later)["rules"][g.EGRESS]
    assert (held["state"], held["reason"]) == ("unverified", g.STALE)
    broken = _judge(store, egress("open"), now=later)["rules"][g.EGRESS]
    assert (broken["state"], broken["reason"], len(broken["violations"])) == ("violated", g.STALE, 1)


def test_a_version_without_the_rule_judges_nothing_new(store):
    _, bundle = stored(store, v1_bundle(egress_containment=egress("open")))
    result = g.evaluate_asp(guardrail(), bundle, asp_id="a", previous_collected_at=PREVIOUS, now=NOW)
    assert g.EGRESS not in result["rules"]


def test_rows_recheck_against_the_version_in_force():
    row = {"rule": g.EGRESS, "item": "no_network", "detail": {"level": "no_network"}}
    assert g.item_allowed(guardrail(egress_containment={"require": "contained"}), row)
    assert not g.item_allowed(guardrail(egress_containment={"require": "allow_list_enforced"}), row)
    # Switching to a version that doesn't require it stops the row.
    assert g.item_allowed(guardrail(), {**row, "item": "open", "detail": {"level": "open"}})
    with pytest.raises(ValueError, match="edit the version"):
        g.with_item_allowed(guardrail(egress_containment={"require": "contained"})["rules"], row)


def test_the_reading_never_calls_partial_contained():
    assert g.egress_reading(None) is None
    reading = g.egress_reading(egress("internal_network", peers=["squid"]))
    assert (reading["level"], reading["contained"], reading["gateway_peers"]) == ("internal_network", True, ["squid"])
    partial = egress("open", "PARTIAL")
    partial["value"]["level"] = "internal_network"  # never written, but never trusted either
    assert g.egress_reading(partial)["contained"] is False
    assert g.egress_reading(egress(status="BLIND")) == {"status": "BLIND", "level": None, "contained": None}


# ----------------------------------------------------------------- proposal


def test_the_proposal_requires_containment_only_from_a_contained_baseline(store):
    cases = [(egress("allow_list_enforced"), True), (egress("internal_network"), True),
             (egress("open"), False), (egress("open", "PARTIAL"), False),
             (egress(status="BLIND"), False), (None, False)]
    for index, (attribute, seeded) in enumerate(cases):
        alignment, ref = baseline(store, asp(deployment=f"agent-{index}", egress_containment=attribute))
        proposal = store.guardrail_detail(ref)["proposal"]
        rules = proposal["guardrail"]["rules"]
        assert (g.EGRESS in rules) is seeded, attribute
        if seeded:
            assert rules[g.EGRESS] == {"require": "contained"}
            assert proposal["guardrail"]["guardrail_contract_version"] == 3
        else:
            assert proposal["guardrail"]["guardrail_contract_version"] == 2  # data_actions only
        assert g.guardrail_problems(proposal["guardrail"]) == []


# ----------------------------------------------------------------- custody


def test_a_contained_agent_adopts_holds_and_a_regression_is_one_row(store):
    alignment, ref = baseline(store, asp(egress_containment=egress("allow_list_enforced")))
    adopted = store.adopt_guardrail(alignment["alignment_version_id"])
    assert adopted["guardrail"]["guardrail_contract_version"] == 3
    live(store)
    detail = store.guardrail_detail(ref)
    assert detail["rules"][g.EGRESS] == {"state": "held", "reason": None}
    assert detail["egress"]["reading"]["level"] == "allow_list_enforced"
    load(store, asp(egress_containment=egress("open")))
    found = rows(store, ref)
    assert found[(g.EGRESS, "open")]["counts"]
    assert store.guardrail_detail(ref)["rules"][g.EGRESS]["state"] == "violated"
    assert store.guardrail_detail(ref)["rows"][0]["allowable"] is False


def test_require_containment_on_an_open_agent_says_it_starts_violated(store):
    alignment, ref = baseline(store, asp(egress_containment=egress("open"), egress_proxy_declared=PROXY))
    adopted = store.adopt_guardrail(alignment["alignment_version_id"])
    before = adopted["guardrail"]["rules"]
    assert g.EGRESS not in before and adopted["guardrail"]["guardrail_contract_version"] == 2
    detail = store.guardrail_detail(ref)
    assert g.EGRESS not in detail["rules"]
    assert detail["egress"] == {
        "reading": {"status": "ANSWERED", "level": "open", "contained": False, "enforcer": None, "via": None,
                    "gateway_peers": [], "reasons": ["why open"], "stale": False, "multi_agent": False},
        "proxy_declared": {"HTTPS_PROXY": "http://proxy.corp:3128"},
    }
    made = store.require_containment(ref)
    assert made["starts_violated"] is True
    version = made["guardrail"]
    assert version["guardrail_contract_version"] == 3 and version["version"] == "g2"
    # Every rule the version had is carried unchanged, data_actions included.
    assert {k: v for k, v in version["rules"].items() if k != g.EGRESS} == before
    assert version["rules"][g.EGRESS] == {"require": "contained"}
    assert rows(store, ref)[(g.EGRESS, "open")]["counts"]
    with pytest.raises(ValueError, match="already requires"):
        store.require_containment(ref)
    with pytest.raises(g.GuardrailValidationError, match="require must be"):
        store.require_containment(ref, "sort_of")
    # Switching back to the version without the rule stops the row.
    store.switch_guardrail(adopted["guardrail"]["guardrail_version_id"])
    assert not rows(store, ref)[(g.EGRESS, "open")]["counts"]


def test_require_containment_needs_a_guardrail(store):
    _, ref = baseline(store, asp(egress_containment=egress("open")))
    with pytest.raises(ValueError, match="no active guardrail"):
        store.require_containment(ref)


def test_the_route_is_token_gated_and_answers_201(store, monkeypatch):
    from fastapi.testclient import TestClient

    from raildash import app as app_module

    alignment, ref = baseline(store, asp(egress_containment=egress("no_network")))
    store.adopt_guardrail(alignment["alignment_version_id"])
    monkeypatch.setattr(app_module, "store", store)
    client = TestClient(app_module.app)
    path = f"/api/guardrails/{ref}/egress-containment"
    assert client.post(path, json={}).status_code == 403
    headers = {"X-RailDash-Token": app_module.LOCAL_TOKEN}
    answer = client.post(path, json={"require": "allow_list_enforced"}, headers=headers)
    assert answer.status_code == 201, answer.text
    assert answer.json()["starts_violated"] is True
    assert client.post(path, json={"require": 1}, headers=headers).status_code == 422
    assert client.post(path, json={"require": "sort_of"}, headers=headers).status_code == 422
    assert client.post(path, json={"require": "allow_list_enforced"}, headers=headers).status_code == 409


def test_a_v2_bundle_holds_its_egress_value_to_the_published_shape(store):
    """Rail-review (82): v2's attributes have no per-attribute shape, so a
    malformed egress value in either scope is refused at ingest, as v1's is."""
    from raildash.asp import BundleValidationError, parse_bundle
    from test_guardrail import _single_agent_v2

    value = _single_agent_v2([], [])
    good = egress("internal_network", peers=["squid"])
    value["sandbox"]["attributes"]["egress_containment"] = good
    assert parse_bundle(json.dumps(value).encode())
    for scope in ("sandbox", "agent"):
        for mutate in (lambda v: v.update(reasons=5),
                       lambda v: v["observations"]["networks"][0].update(gateway_peers=5),
                       lambda v: v.update(via={"x": 1})):
            broken = copy.deepcopy(value)
            bad = copy.deepcopy(good)
            mutate(bad["value"])
            target = broken["sandbox"]["attributes"] if scope == "sandbox" else broken["agents"][0]["attributes"]
            target["egress_containment"] = bad
            with pytest.raises(BundleValidationError, match="egress_containment"):
                parse_bundle(json.dumps(broken).encode())


def test_a_bad_value_handed_to_the_reading_is_never_a_crash():
    bad = egress("internal_network")
    bad["value"].update(reasons=5, via={"x": 1})
    bad["value"]["observations"]["networks"] = [{"gateway_peers": 5}, "x"]
    reading = g.egress_reading(bad)
    assert (reading["reasons"], reading["via"], reading["gateway_peers"]) == ([], None, [])


def test_starts_violated_follows_what_the_recheck_recorded(store):
    """A stale newest ASP fails the rule but isn't a counted violation, so
    the new version doesn't start Violated."""
    from datetime import datetime, timedelta, timezone

    value = asp(egress_containment=egress("open"))
    value["collected_at"] = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat().replace("+00:00", "Z")
    alignment, ref = baseline(store, value)
    store.adopt_guardrail(alignment["alignment_version_id"])
    made = store.require_containment(ref)
    rule = store.guardrail_detail(ref)["rules"][g.EGRESS]
    assert made["starts_violated"] is (rule["state"] == g.VIOLATED)


# ------------------------------------------------------------- multi-agent
# DR-240: containment is the sandbox's, and RailMon emits it in a v2
# bundle's sandbox scope (`SANDBOX_ATTRIBUTES`), so a multi-agent sandbox
# is judged on that value, while every other rule stays MULTI_AGENT.


_TWO_AGENT_IDS = itertools.count(1)


def _two_agents(sandbox_egress=None, *, agent_egress=None, collected_at=None) -> dict:
    """RailMon's real two-agent v2 fixture with `egress_containment` in its
    sandbox scope (None leaves it out) and, if given, in an agent's."""
    from test_guardrail import TWO_AGENTS_FIXTURE

    value = json.loads(TWO_AGENTS_FIXTURE.read_bytes())
    if sandbox_egress is not None:
        value["sandbox"]["attributes"]["egress_containment"] = sandbox_egress
    if agent_egress is not None:
        value["agents"][0]["attributes"]["egress_containment"] = agent_egress
    if collected_at is not None:
        value["collected_at"] = collected_at
    value["bundle_id"] = f"bnd-egress-two-agents-{next(_TWO_AGENT_IDS)}"
    return value


def _judge_two_agents(store, value, require="contained", *, now=None, previous=None):
    _, bundle = stored(store, value)
    assert g.is_multi_agent(bundle)
    version = guardrail(egress_containment={"require": require})
    version["guardrail_contract_version"] = 3
    collected = bundle["collected_at"]
    return g.evaluate_asp(version, bundle, asp_id="asp-2", previous_collected_at=previous,
                          now=now or collected)


@pytest.mark.parametrize(
    "attribute, require, state, reason, items",
    [
        (egress("allow_list_enforced"), "contained", "held", None, []),
        (egress("internal_network", peers=["squid"]), "contained", "held", None, []),
        (egress("allow_list_enforced"), "allow_list_enforced", "held", None, []),
        (egress("open"), "contained", "violated", None, ["open"]),
        (egress("no_network"), "allow_list_enforced", "violated", None, ["no_network"]),
        (egress("open", "PARTIAL"), "contained", "unverified", g.PARTIAL_NO_VIOLATION, []),
        (egress("open", "FAILED"), "contained", "unverified", "FAILED", []),
        (None, "contained", "unverified", g.NOT_COLLECTED, []),
    ],
)
def test_a_multi_agent_sandbox_is_judged_on_its_sandbox_scoped_level(
    store, attribute, require, state, reason, items
):
    result = _judge_two_agents(store, _two_agents(attribute), require)
    assert result["multi_agent"] is True
    egress_result = result["rules"][g.EGRESS]
    assert (egress_result["state"], egress_result["reason"]) == (state, reason)
    assert [v["item"] for v in egress_result["violations"]] == items
    for violation in egress_result["violations"]:
        assert violation["source"] == {"kind": "asp", "id": "asp-2"}
    # Every other rule keeps its multi-agent Unverified, in the evaluator
    # and in the roll-up, request rules included.
    for rule in g.RULES:
        assert result["rules"][rule] == {"state": "unverified", "reason": g.MULTI_AGENT, "violations": []}
    states = g.rule_states(result, g.request_rules_status(
        now=NOW, last_heartbeat_at=NOW, last_unattributed_at=None, last_tool_calls_unreadable_at=None),
        g.contract_rules({"rules": {g.EGRESS: {}}}))
    assert {rule: (s["state"], s["reason"]) for rule, s in states.items()} == {
        **{rule: ("unverified", g.MULTI_AGENT) for rule in g.RULES}, g.EGRESS: (state, reason),
    }


def test_a_stale_multi_agent_asp_leaves_held_unverified_and_a_violation_real(store):
    later = "2026-09-25T00:00:00Z"
    held = _judge_two_agents(store, _two_agents(egress("no_network")), now=later)
    assert held["stale"] is True
    assert (held["rules"][g.EGRESS]["state"], held["rules"][g.EGRESS]["reason"]) == ("unverified", g.STALE)
    broken = _judge_two_agents(store, _two_agents(egress("open")), now=later)["rules"][g.EGRESS]
    assert (broken["state"], broken["reason"], len(broken["violations"])) == ("violated", g.STALE, 1)


def test_a_multi_agent_sandbox_reads_only_the_sandbox_scope(store):
    """An agent-scoped value names one agent, not the sandbox: it isn't read."""
    result = _judge_two_agents(store, _two_agents(agent_egress=egress("allow_list_enforced")))
    assert (result["rules"][g.EGRESS]["state"], result["rules"][g.EGRESS]["reason"]) == (
        "unverified", g.NOT_COLLECTED)


def test_a_multi_agent_version_without_the_rule_stays_all_multi_agent(store):
    _, bundle = stored(store, _two_agents(egress("open")))
    result = g.evaluate_asp(guardrail(), bundle, asp_id="a", previous_collected_at=None, now=NOW)
    assert g.EGRESS not in result["rules"]
    assert {r["reason"] for r in result["rules"].values()} == {g.MULTI_AGENT}


def test_a_multi_agent_sandbox_records_and_shows_an_egress_violation(store):
    from test_guardrail_custody import _now

    alignment, ref = baseline(store, _two_agents(egress("allow_list_enforced"), collected_at=_now()))
    rules = {**guardrail()["rules"], g.EGRESS: {"require": "contained"}}
    store.adopt_guardrail(alignment["alignment_version_id"], rules)
    live(store)
    detail = store.guardrail_detail(ref)
    assert detail["rules"][g.EGRESS] == {"state": "held", "reason": None}
    for rule in g.RULES:
        assert detail["rules"][rule] == {"state": "unverified", "reason": g.MULTI_AGENT}
    assert detail["state"] == g.STATE_UNVERIFIED
    assert detail["egress"]["reading"]["multi_agent"] is True
    load(store, _two_agents(egress("open"), collected_at=_now()))
    assert rows(store, ref)[(g.EGRESS, "open")]["counts"]
    detail = store.guardrail_detail(ref)
    assert detail["rules"][g.EGRESS]["state"] == "violated"
    assert detail["state"] == g.STATE_VIOLATED
