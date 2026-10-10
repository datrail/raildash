"""DR-184 M2: guardrail custody, the two store hooks, and the rows' bounds.

The ASPs are RailMon's real v1 fixture with the attributes each case needs,
built by `test_guardrail`'s helpers and stored through `Store.load_asp`,
which runs the ASP hook. Captured requests are `fixtures/capture.jsonl`'s
first request with its host, body and time changed, stored through
`Store.add_interactions`, which runs the request hook. Times are real: each
ASP is collected now and each request is sent now, so a guardrail adopted a
moment earlier judges them.
"""

from __future__ import annotations

import copy
import itertools
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from raildash import guardrail as g
from raildash.guardrail_store import GUARDRAIL_SCHEMA, agent_ref
from raildash.ingest import normalise
from raildash.store import SCHEMA, Store
from test_guardrail import (
    DEMO_LISTENER,
    FILE_METHOD,
    PORT_9000,
    _file,
    _with_response_tools,
    capture,
    declared,
    observed,
    raw,
    v1_bundle,
)

_IDS = itertools.count(1)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def asp(listeners=(DEMO_LISTENER,), files=(), *, deployment="payments-agent", **attributes) -> dict:
    value = v1_bundle(
        observed_listeners=observed(list(listeners)),
        observed_file_access=observed(list(files), method=FILE_METHOD),
        **attributes,
    )
    value["attributes"]["deployment"]["value"]["RAIL_DEPLOYMENT"] = deployment
    value["bundle_id"] = f"bnd-custody-{next(_IDS)}"
    value["collected_at"] = _now()
    return value


def load(store: Store, value: dict) -> str:
    return store.load_asp(raw(value))["asp_id"]


def request(host: str | None, *, body=True, size: int | None = 512, when: str | None = None,
            tools=(), method="POST") -> dict:
    item = copy.deepcopy(capture()[0])
    if tools:
        item = _with_response_tools(item, *tools)
    item["timestamp"] = when or _now()
    item["timestamp_ns"] = int(datetime.now(timezone.utc).timestamp() * 1e9)
    item["interaction_id"] = f"req-{next(_IDS)}"
    item["request"]["method"] = method
    headers = {key: value for key, value in item["request"]["headers"].items() if key != "host"}
    if host is not None:
        headers["host"] = host
    item["request"]["headers"] = headers
    if not body:
        item["request"]["body"] = None
    item["request_size"] = size
    return normalise(item)


def send(store: Store, *rows: dict, authenticated: bool = True) -> None:
    store.upsert_session("s1")
    store.add_interactions("s1", list(rows), authenticated=authenticated)


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "custody.db")
    yield db
    db.close()


def baseline(store: Store, value: dict | None = None) -> tuple[dict, str]:
    """Lock an ASP as the agent's active baseline; returns it and the ref."""
    asp_id = load(store, value or asp())
    made = store.make_baseline(asp_id, "v1.0")
    alignment = made["alignment_version"]
    identity = alignment["agent_identity"]
    ref = agent_ref(identity["kind"], json.dumps(identity["value"], sort_keys=True, separators=(",", ":")))
    return alignment, ref


def rows(store: Store, ref: str) -> dict:
    return {(row["rule"], row["item"]): row for row in store.guardrail_detail(ref)["rows"]}


def live(store: Store) -> None:
    store.record_heartbeat("collector", taps_attached=1, sent_at=_now())


# ----------------------------------------------------------- no guardrail


def test_an_agent_with_a_baseline_and_no_guardrail_is_offered_the_proposal(store):
    alignment, ref = baseline(store)
    load(store, asp(listeners=[DEMO_LISTENER, PORT_9000]))
    [agent] = store.guardrail_agents()
    assert agent["agent_ref"] == ref
    assert agent["state"] == g.STATE_NO_GUARDRAIL and agent["active_version"] is None
    detail = store.guardrail_detail(ref)
    assert detail["proposal"]["alignment_version_id"] == alignment["alignment_version_id"]
    assert detail["proposal"]["guardrail"]["rules"]["service_ports"] == {"allowed": []}
    assert [v["item"] for v in detail["proposal"]["would_be_violations"]] == ["tcp/127.0.0.1/8443"]
    # Nothing is judged until the user adopts it.
    assert detail["rows"] == [] and store._db.execute("SELECT count(*) FROM guardrail_rows").fetchone()[0] == 0  # noqa: SLF001


def test_a_database_with_no_guardrail_judges_nothing_on_either_ingest_path(store):
    """Only the ASP receipts are kept (so a guardrail adopted later knows how
    fresh its evidence is); nothing is judged or recorded against anyone."""
    baseline(store)
    load(store, asp(listeners=[PORT_9000]))
    send(store, request("exfil.attacker.net"))
    for table in ("guardrail_versions", "guardrail_bindings", "guardrail_rows", "guardrail_events"):
        assert store._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0, table  # noqa: SLF001
    marks = {row[0] for row in store._db.execute("SELECT mark FROM guardrail_marks")}  # noqa: SLF001
    assert marks <= {"asp_received", "asp_received_before"}


# ---------------------------------------------------------- adopt and state


def test_adopting_the_unedited_proposal_flags_the_baselines_own_listener(store):
    alignment, ref = baseline(store)
    adopted = store.adopt_guardrail(alignment["alignment_version_id"])
    assert adopted["guardrail"]["version"] == "g1" and adopted["active"]
    assert adopted["guardrail"]["derived_from"] == {"alignment_version_id": alignment["alignment_version_id"]}
    found = rows(store, ref)
    assert list(found) == [("service_ports", "tcp/127.0.0.1/8443")]
    row = found[("service_ports", "tcp/127.0.0.1/8443")]
    assert row["counts"] and row["evidence_class"] == "observed" and row["flagged_by"] == adopted["guardrail"]["guardrail_version_id"]
    assert row["source"]["kind"] == "asp"
    detail = store.guardrail_detail(ref)
    assert detail["state"] == g.STATE_VIOLATED
    assert [(e["action"], e["detail"]["version"]) for e in detail["events"]] == [("adopt", "g1")]
    with pytest.raises(ValueError, match="already has an active guardrail"):
        store.adopt_guardrail(alignment["alignment_version_id"])


def test_allow_this_on_the_listener_holds_once_every_rule_is_verified(store):
    alignment, ref = baseline(store, asp(files=[_file("/app/agent.log")]))
    store.adopt_guardrail(alignment["alignment_version_id"])
    row = rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]
    allowed = store.allow_guardrail_row(row["row_id"])
    assert allowed["guardrail"]["version"] == "g2"
    assert allowed["guardrail"]["rules"]["service_ports"]["allowed"] == [
        {"protocol": "tcp", "addr": "127.0.0.1", "port": 8443}
    ]
    row = rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]
    assert not row["counts"] and row["allowed_by"] == "g2" and row["count"] == 1
    # No collector heartbeat yet: the request rules can't be verified.
    detail = store.guardrail_detail(ref)
    assert detail["state"] == g.STATE_UNVERIFIED
    assert detail["rules"]["uploads"] == {"state": "unverified", "reason": g.NO_HEARTBEAT}
    live(store)
    assert store.guardrail_detail(ref)["state"] == g.STATE_HELD
    # A stale newest ASP leaves the ASP rules unverified.
    later = datetime.now(timezone.utc) + timedelta(hours=3)
    stale = store.guardrail_detail(ref, now=later)
    assert stale["rules"]["service_ports"]["reason"] == g.STALE


def test_a_hit_after_acknowledge_reopens_the_row(store):
    alignment, ref = baseline(store)
    store.adopt_guardrail(alignment["alignment_version_id"])
    load(store, asp(listeners=[DEMO_LISTENER, PORT_9000]))
    port = rows(store, ref)[("service_ports", "tcp/0.0.0.0/9000")]
    acknowledged = store.acknowledge_guardrail_row(port["row_id"])
    assert acknowledged["acknowledged"]
    assert not rows(store, ref)[("service_ports", "tcp/0.0.0.0/9000")]["counts"]
    load(store, asp(listeners=[PORT_9000]))
    again = rows(store, ref)[("service_ports", "tcp/0.0.0.0/9000")]
    assert again["counts"] and not again["acknowledged"] and again["count"] == 2
    assert [e["action"] for e in store.guardrail_detail(ref)["events"]] == ["acknowledge", "adopt"]


def test_switching_back_to_a_version_that_disallows_an_item_makes_its_row_count_again(store):
    alignment, ref = baseline(store)
    g1 = store.adopt_guardrail(alignment["alignment_version_id"])
    row = rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]
    store.allow_guardrail_row(row["row_id"])
    assert not rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]["counts"]
    switched = store.switch_guardrail(g1["guardrail"]["guardrail_version_id"])
    assert switched["guardrail"]["version"] == "g1"
    again = rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]
    assert again["counts"] and again["allowed_by"] is None
    assert store.guardrail_detail(ref)["events"][0]["action"] == "switch"


def test_turn_off_returns_to_no_guardrail_and_keeps_the_history(store):
    alignment, ref = baseline(store)
    store.adopt_guardrail(alignment["alignment_version_id"])
    assert store.turn_off_guardrail(ref)["state"] == g.STATE_NO_GUARDRAIL
    detail = store.guardrail_detail(ref)
    assert detail["state"] == g.STATE_NO_GUARDRAIL and detail["active"] is None
    assert [row["counts"] for row in detail["rows"]] == [False]
    assert [v["guardrail"]["version"] for v in detail["versions"]] == ["g1"]
    assert detail["proposal"] is not None
    with pytest.raises(ValueError, match="no active guardrail"):
        store.turn_off_guardrail(ref)
    # Adopting again is a new version, not a reuse of g1.
    assert store.adopt_guardrail(alignment["alignment_version_id"])["guardrail"]["version"] == "g2"


def test_versions_are_immutable_and_only_the_active_one_is_edited(store):
    alignment, ref = baseline(store)
    g1 = store.adopt_guardrail(alignment["alignment_version_id"])
    g1_id = g1["guardrail"]["guardrail_version_id"]
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._db.execute("UPDATE guardrail_versions SET version = 'x'")  # noqa: SLF001
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._db.execute("DELETE FROM guardrail_versions")  # noqa: SLF001
    store._db.rollback()  # noqa: SLF001
    rules = copy.deepcopy(g1["guardrail"]["rules"])
    rules["service_ports"]["allowed"] = [{"protocol": "tcp", "port": 8443}]
    rules["out_of_spec_calls"]["seeded_from_declared"] = {"hosts": [], "mcp_servers": []}
    g2 = store.edit_guardrail(g1_id, rules)
    assert g2["guardrail"]["version"] == "g2"
    with pytest.raises(ValueError, match="only the active"):
        store.edit_guardrail(g1_id, rules)
    bad = copy.deepcopy(rules)
    bad["uploads"]["blocked"] = True
    with pytest.raises(g.GuardrailValidationError):
        store.edit_guardrail(g2["guardrail"]["guardrail_version_id"], bad)


# --------------------------------------------------------------- requests


def _adopted(store, value=None, **edit) -> tuple[str, dict]:
    alignment, ref = baseline(store, value)
    adopted = store.adopt_guardrail(alignment["alignment_version_id"])
    if edit:
        rules = copy.deepcopy(adopted["guardrail"]["rules"])
        for name, rule in edit.items():
            rules[name] = rule
        adopted = store.edit_guardrail(adopted["guardrail"]["guardrail_version_id"], rules)
    return ref, adopted


def test_an_authenticated_upload_to_an_unlisted_host_is_two_rows(store):
    ref, _ = _adopted(store)
    send(store, request("exfil.attacker.net"))
    found = rows(store, ref)
    assert found[("uploads", "exfil.attacker.net")]["counts"]
    assert found[("out_of_spec_calls", "exfil.attacker.net")]["counts"]
    assert found[("uploads", "exfil.attacker.net")]["source"]["kind"] == "interaction"
    # A GET without a body is out of spec only.
    send(store, request("second.example.net", body=False, size=None, method="GET"))
    found = rows(store, ref)
    assert ("out_of_spec_calls", "second.example.net") in found
    assert ("uploads", "second.example.net") not in found


def test_unauthenticated_and_old_captures_never_touch_a_guardrail(store):
    ref, adopted = _adopted(store)
    send(store, request("forged.example.net"), authenticated=False)
    old = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    send(store, request("old.example.net", when=old))
    items = {item for _, item in rows(store, ref)}
    assert "forged.example.net" not in items and "old.example.net" not in items


def test_a_request_to_an_allowed_host_with_an_unlisted_mcp_server_is_one_requested_row(store):
    ref, _ = _adopted(store, uploads={"allowed_hosts": ["api.anthropic.com"], "max_request_bytes": {},
                                      "denied_tool_calls": ["mcp__fs__upload_file"]},
                      out_of_spec_calls={"allowed_hosts": ["api.anthropic.com"],
                                         "allowed_mcp_servers": ["example"],
                                         "seeded_from_declared": {"hosts": [], "mcp_servers": []}})
    send(store, request("api.anthropic.com", tools=("mcp__example__search", "mcp__notion__search",
                                                   "mcp__fs__upload_file")))
    found = rows(store, ref)
    assert set(found) == {("out_of_spec_calls", "mcp__notion"), ("out_of_spec_calls", "mcp__fs"),
                          ("uploads", "mcp__fs__upload_file"), ("service_ports", "tcp/127.0.0.1/8443")}
    assert found[("out_of_spec_calls", "mcp__notion")]["evidence_class"] == "requested"
    store.allow_guardrail_row(found[("out_of_spec_calls", "mcp__notion")]["row_id"])
    store.allow_guardrail_row(found[("uploads", "mcp__fs__upload_file")]["row_id"])
    active = store.guardrail_detail(ref)["active"]["guardrail"]["rules"]
    assert active["out_of_spec_calls"]["allowed_mcp_servers"] == ["example", "notion"]
    assert active["uploads"]["denied_tool_calls"] == []


def test_unattributed_traffic_leaves_every_agents_request_rules_unverified(store):
    ref_a, _ = _adopted(store, asp(deployment="agent-a"))
    ref_b, _ = _adopted(store, asp(deployment="agent-b"))
    live(store)
    assert store.guardrail_detail(ref_a)["rules"]["uploads"]["state"] == "held"
    # No attribution and two active guardrails: whose it is can't be told.
    send(store, request("api.anthropic.com"))
    for ref in (ref_a, ref_b):
        detail = store.guardrail_detail(ref)
        assert detail["rules"]["uploads"] == {"state": "unverified", "reason": g.UNATTRIBUTED_TRAFFIC}
        assert all(row["rule"] == "service_ports" for row in detail["rows"])
    later = datetime.now(timezone.utc) + timedelta(minutes=11)
    store.record_heartbeat("collector", taps_attached=1, sent_at=_now(), received_at=later)
    assert store.guardrail_detail(ref_a, now=later)["rules"]["uploads"]["state"] == "held"


def test_an_upload_row_is_judged_on_the_worst_request_it_has_seen(store):
    ref, adopted = _adopted(store)
    send(store, request("big.example.net", size=50_000))
    send(store, request("big.example.net", size=10))
    row = rows(store, ref)[("uploads", "big.example.net")]
    assert row["count"] == 2 and row["detail"]["request_size"] == 50_000 and row["detail"]["carries_body"]
    rules = copy.deepcopy(store.guardrail_detail(ref)["active"]["guardrail"]["rules"])
    rules["uploads"]["allowed_hosts"].append("big.example.net")
    rules["uploads"]["max_request_bytes"] = {"big.example.net": 1_000}
    store.edit_guardrail(store.guardrail_detail(ref)["active"]["guardrail"]["guardrail_version_id"], rules)
    assert rows(store, ref)[("uploads", "big.example.net")]["counts"]
    with pytest.raises(ValueError, match="size cap"):
        store.allow_guardrail_row(row["row_id"])


def test_allow_this_refuses_what_one_click_cant_allow(store):
    ref, _ = _adopted(store)
    send(store, request(None))
    unknown = rows(store, ref)[("uploads", "(unknown host)")]
    with pytest.raises(ValueError, match="no host"):
        store.allow_guardrail_row(unknown["row_id"])
    with pytest.raises(KeyError):
        store.allow_guardrail_row(10_000)


# ------------------------------------------------------------------ offers


DECLARING = dict(
    declared_destinations=declared(["api.anthropic.com"]),
    mcp_servers_declared=declared([{"name": "example", "url": "https://api.anthropic.com/mcp"}]),
)


def test_a_newly_declared_host_is_offered_until_allowed_or_dismissed(store):
    ref, g1 = _adopted(store, asp(**DECLARING))
    assert store.guardrail_detail(ref)["offers"] == []
    widened = dict(DECLARING, declared_destinations=declared(["api.anthropic.com", "attacker.example",
                                                             "docs.example"]))
    load(store, asp(**widened))
    detail = store.guardrail_detail(ref)
    assert detail["offers"] == [{"kind": "host", "value": "attacker.example"},
                                {"kind": "host", "value": "docs.example"}]
    # An offer isn't a row and doesn't change the state.
    assert all(row["rule"] == "service_ports" for row in detail["rows"])
    send(store, request("attacker.example"))
    assert rows(store, ref)[("out_of_spec_calls", "attacker.example")]["counts"]

    dismissed = store.choose_declared(ref, "host", "attacker.example", allow=False)
    rules = dismissed["guardrail"]["rules"]["out_of_spec_calls"]
    assert "attacker.example" not in rules["allowed_hosts"]
    assert "attacker.example" in rules["seeded_from_declared"]["hosts"]
    allowed = store.choose_declared(ref, "host", "docs.example", allow=True)
    assert "docs.example" in allowed["guardrail"]["rules"]["out_of_spec_calls"]["allowed_hosts"]
    assert store.guardrail_detail(ref)["offers"] == []
    # Not offered again, even after a switch back to a version from before.
    store.switch_guardrail(g1["guardrail"]["guardrail_version_id"])
    assert store.guardrail_detail(ref)["offers"] == []
    assert rows(store, ref)[("out_of_spec_calls", "attacker.example")]["counts"]
    with pytest.raises(ValueError, match="not a current declared offer"):
        store.choose_declared(ref, "host", "attacker.example", allow=True)
    actions = [e["action"] for e in store.guardrail_detail(ref)["events"]]
    assert actions[:3] == ["switch", "declared_allow", "declared_dismiss"]


def test_an_edit_keeps_what_the_user_was_shown_as_declared(store):
    ref, g1 = _adopted(store, asp(**DECLARING))
    rules = copy.deepcopy(g1["guardrail"]["rules"])
    rules["out_of_spec_calls"]["allowed_hosts"] = []
    rules["out_of_spec_calls"]["seeded_from_declared"] = {"hosts": [], "mcp_servers": []}
    g2 = store.edit_guardrail(g1["guardrail"]["guardrail_version_id"], rules)
    seeded = g2["guardrail"]["rules"]["out_of_spec_calls"]["seeded_from_declared"]
    assert seeded == {"hosts": ["api.anthropic.com"], "mcp_servers": ["example"]}
    # The user removed it to keep it out, so it isn't offered back.
    assert store.guardrail_detail(ref)["offers"] == []


# ------------------------------------------------------------------ bounds


def test_past_the_open_row_cap_new_items_count_in_one_overflow_row(store, monkeypatch):
    monkeypatch.setenv("RAILDASH_GUARDRAIL_MAX_OPEN_ROWS", "2")
    ref, _ = _adopted(store)  # one row: the demo listener
    writes = [_file(f"/data/out-{n}.zip") for n in range(4)]
    load(store, asp(files=writes))
    detail = store.guardrail_detail(ref)
    listed = [(row["rule"], row["item"]) for row in detail["rows"] if not row["overflow"]]
    assert len(listed) == 2
    [overflow] = [row for row in detail["rows"] if row["overflow"]]
    assert overflow["count"] == 3 and overflow["counts"]
    assert detail["state"] == g.STATE_VIOLATED
    with pytest.raises(ValueError, match="overflow"):
        store.allow_guardrail_row(overflow["row_id"])
    acknowledged = store.acknowledge_guardrail_row(overflow["row_id"])
    assert acknowledged["count"] == 0 and acknowledged["acknowledged"]
    # A repeat of a listed item updates its row; it isn't a new item.
    load(store, asp(files=writes))
    [overflow] = [row for row in store.guardrail_detail(ref)["rows"] if row["overflow"]]
    assert overflow["count"] == 3 and not overflow["acknowledged"]
    # A policy change re-checks the same ASP; that is no new hit either.
    store.acknowledge_guardrail_row(overflow["row_id"])
    store.switch_guardrail(store.guardrail_detail(ref)["active"]["guardrail"]["guardrail_version_id"])
    [overflow] = [row for row in store.guardrail_detail(ref)["rows"] if row["overflow"]]
    assert overflow["acknowledged"] and overflow["count"] == 0
    # Nor once a request has overflowed after it.
    send(store, request("exfil.attacker.net"))
    [overflow] = [row for row in store.guardrail_detail(ref)["rows"] if row["overflow"]]
    assert overflow["count"] == 2  # an upload and an out-of-spec call
    store.acknowledge_guardrail_row(overflow["row_id"])
    store.switch_guardrail(store.guardrail_detail(ref)["active"]["guardrail"]["guardrail_version_id"])
    [overflow] = [row for row in store.guardrail_detail(ref)["rows"] if row["overflow"]]
    assert overflow["acknowledged"] and overflow["count"] == 0
    # Acknowledged rows make room: a re-check lists what had only overflowed.
    for row in store.guardrail_detail(ref)["rows"]:
        store.acknowledge_guardrail_row(row["row_id"])
    store.switch_guardrail(store.guardrail_detail(ref)["active"]["guardrail"]["guardrail_version_id"])
    listed = {row["item"] for row in store.guardrail_detail(ref)["rows"] if not row["acknowledged"]}
    assert listed and listed <= {f"/data/out-{n}.zip" for n in range(4)}


def test_acknowledged_rows_are_deleted_after_the_retention_and_open_ones_never(store):
    ref, _ = _adopted(store)
    load(store, asp(listeners=[DEMO_LISTENER, PORT_9000]))
    port = rows(store, ref)[("service_ports", "tcp/0.0.0.0/9000")]
    store.acknowledge_guardrail_row(port["row_id"])
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="microseconds")
    store._db.execute("UPDATE guardrail_rows SET last_seen = ?", (old.replace("+00:00", "Z"),))  # noqa: SLF001
    store._db.commit()  # noqa: SLF001
    load(store, asp(listeners=[]))
    found = rows(store, ref)
    assert ("service_ports", "tcp/0.0.0.0/9000") not in found
    assert found[("service_ports", "tcp/127.0.0.1/8443")]["counts"]


# ------------------------------------------------------------------ schema


OLD_SCHEMA = SCHEMA.replace(GUARDRAIL_SCHEMA, "")


def test_the_old_schema_really_predates_m2():
    assert GUARDRAIL_SCHEMA in SCHEMA
    assert not re.search(r"guardrail_", OLD_SCHEMA)


def test_an_older_raildash_opens_the_upgraded_database_and_ignores_the_new_tables(tmp_path):
    path = tmp_path / "upgraded.db"
    store = Store(path)
    ref, _ = _adopted(store)
    store.close()

    old = sqlite3.connect(path)
    old.executescript(OLD_SCHEMA)
    assert old.execute("SELECT count(*) FROM asps").fetchone()[0] == 1
    old.execute("INSERT INTO sessions (session_id) VALUES ('from-old')")
    old.commit()
    old.close()

    reopened = Store(path)
    assert reopened.guardrail_detail(ref)["state"] == g.STATE_VIOLATED
    assert not reopened._needs_upgrade()  # noqa: SLF001
    reopened.close()


def test_opening_a_pre_m2_database_adds_the_tables(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript(OLD_SCHEMA)
    db.execute("PRAGMA user_version = 1")
    db.commit()
    db.close()
    store = Store(path)
    assert store.guardrail_agents() == []
    alignment, ref = baseline(store)
    assert store.guardrail_detail(ref)["state"] == g.STATE_NO_GUARDRAIL
    store.close()


def test_a_failing_check_keeps_the_evidence_and_fails_closed(store, monkeypatch, capsys):
    ref, _ = _adopted(store)
    live(store)

    def broken(*args, **kwargs):
        raise RuntimeError("evaluator bug")

    monkeypatch.setattr(g, "evaluate_request", broken)
    send(store, request("exfil.attacker.net"))
    assert store._db.execute("SELECT count(*) FROM interactions").fetchone()[0] == 1  # noqa: SLF001
    assert ("uploads", "exfil.attacker.net") not in rows(store, ref)
    assert "guardrail request check failed" in capsys.readouterr().err
    # Every rule stays Unverified past every liveness window, until a
    # version is made active again.
    later = datetime.now(timezone.utc) + timedelta(minutes=30)
    store.record_heartbeat("collector", taps_attached=1, sent_at=_now(), received_at=later)
    detail = store.guardrail_detail(ref, now=later)
    assert {rule["reason"] for rule in detail["rules"].values()} == {g.CHECK_FAILED}
    assert detail["state"] == g.STATE_VIOLATED  # the baseline's listener still counts
    store.acknowledge_guardrail_row(rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]["row_id"])
    assert store.guardrail_detail(ref, now=later)["state"] == g.STATE_UNVERIFIED
    monkeypatch.undo()
    store.switch_guardrail(store.guardrail_detail(ref)["active"]["guardrail"]["guardrail_version_id"])
    live(store)
    assert store.guardrail_detail(ref)["rules"]["uploads"]["reason"] is None

    monkeypatch.setattr(g, "evaluate_request", broken)
    monkeypatch.setattr(g, "evaluate_asp", broken)
    asp_id = load(store, asp(listeners=[PORT_9000]))
    assert store.asp_state(asp_id) is not None
    with pytest.raises(RuntimeError):
        store.guardrail_detail(ref)


def test_a_bad_guardrail_setting_stops_the_store_from_opening(tmp_path, monkeypatch):
    monkeypatch.setenv("RAILDASH_GUARDRAIL_MAX_OPEN_ROWS", "0")
    with pytest.raises(RuntimeError, match="RAILDASH_GUARDRAIL_MAX_OPEN_ROWS"):
        Store(tmp_path / "bad.db")


def test_a_policy_change_does_not_reopen_what_was_acknowledged(store):
    """§4.5: only a hit *after* the acknowledgement re-opens a row. The
    re-check on adopt, edit, switch or Allow this judges the same ASP again,
    which is not a new hit."""
    ref, g1 = _adopted(store)
    load(store, asp(listeners=[DEMO_LISTENER, PORT_9000]))
    found = rows(store, ref)
    store.acknowledge_guardrail_row(found[("service_ports", "tcp/0.0.0.0/9000")]["row_id"])
    store.allow_guardrail_row(found[("service_ports", "tcp/127.0.0.1/8443")]["row_id"])
    store.switch_guardrail(g1["guardrail"]["guardrail_version_id"])
    port = rows(store, ref)[("service_ports", "tcp/0.0.0.0/9000")]
    assert port["acknowledged"] and port["count"] == 1
    listener = rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]
    assert listener["count"] == 2  # the baseline's ASP, then the newer one
    load(store, asp(listeners=[PORT_9000]))
    assert not rows(store, ref)[("service_ports", "tcp/0.0.0.0/9000")]["acknowledged"]


def test_allow_this_refuses_a_wildcard_host_the_agent_sent(store):
    ref, _ = _adopted(store)
    send(store, request("*.com"))
    for rule in ("uploads", "out_of_spec_calls"):
        row = rows(store, ref)[(rule, "*.com")]
        with pytest.raises(ValueError, match="wildcard"):
            store.allow_guardrail_row(row["row_id"])


def test_a_re_sent_unchanged_asp_keeps_the_evidence_fresh(store):
    """RailMon re-sends an unchanged agent's previous bundle, `collected_at`
    and all (DR-157). Each delivery is fresh evidence, so the ASP rules stay
    verified; without deliveries they go stale."""
    value = asp()
    alignment_asp = load(store, value)
    made = store.make_baseline(alignment_asp, "v1.0")["alignment_version"]
    identity = made["agent_identity"]
    ref = agent_ref(identity["kind"], json.dumps(identity["value"], sort_keys=True, separators=(",", ":")))
    store.adopt_guardrail(made["alignment_version_id"])
    store.allow_guardrail_row(rows(store, ref)[("service_ports", "tcp/127.0.0.1/8443")]["row_id"])
    old = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(timespec="microseconds")
    store._db.execute("UPDATE guardrail_marks SET at = ? WHERE mark LIKE 'asp_received%'",  # noqa: SLF001
                      (old.replace("+00:00", "Z"),))
    store._db.commit()  # noqa: SLF001
    # The bundle's own collected_at is now; the last delivery is 3 h ago.
    assert store.guardrail_detail(ref)["rules"]["service_ports"]["reason"] == g.STALE
    # The scanner's next tick re-sends the very same bytes.
    assert store.load_asp(raw(value))["replayed"]
    later = datetime.now(timezone.utc) + timedelta(minutes=4)
    assert store.guardrail_detail(ref, now=later)["rules"]["service_ports"] == {"state": "held", "reason": None}
    # An unchanged agent whose bundle is hours old by collected_at, re-sent
    # each minute, is still fresh.
    value_old = dict(value, collected_at="2026-01-01T00:00:00Z", bundle_id="bnd-custody-old")
    load(store, value_old)
    store.load_asp(raw(value_old))
    assert store.guardrail_detail(ref)["rules"]["service_ports"]["reason"] is None
    # A re-sent *older* ASP isn't a receipt for the newest.
    store._db.execute("UPDATE guardrail_marks SET at = ? WHERE mark LIKE 'asp_received%'",  # noqa: SLF001
                      (old.replace("+00:00", "Z"),))
    store._db.commit()  # noqa: SLF001
    store.load_asp(raw(value))
    assert store.guardrail_detail(ref)["rules"]["service_ports"]["reason"] == g.STALE
