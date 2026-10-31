"""REST uploads M2: the `uploads` rule, its re-check and the proposal read
body kinds (`raildash.body_kinds`), under contract v4.

Requests are the real capture fixture's first exchange (a model request to
`api.anthropic.com`) with its host, path and body replaced by REST bodies
shaped as public APIs document them, normalized as ingest stores them.
"""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft202012Validator

from raildash import body_kinds as bk
from raildash import guardrail as g
from raildash import openshell_policy as osp
from raildash.ingest import normalise
from test_guardrail import DECLARED, SCHEMAS, _lock, _propose, capture, guardrail, store  # noqa: F401
from test_guardrail_custody import _now, baseline, live, rows, send
from test_openshell_export import export, imported

SEARCH = "api.search.example"
FILES = "files.example"
QUERY = {"q": "invoices 2026", "limit": 20}


def rest(host: str | None, body, *, path: str = "/v1/query", method: str = "POST",
         content_type: str = "application/json", when: str | None = None) -> dict:
    """One captured REST request, as ingest stores it."""
    item = copy.deepcopy(capture()[0])
    # The capture's own headers (its credential marker attributes it), with
    # this request's host and body framing.
    headers = {key: value for key, value in item["request"]["headers"].items() if key != "host"}
    headers["content-type"] = content_type
    if host is not None:
        headers["host"] = host
    text = body if isinstance(body, str) else json.dumps(body)
    headers["content-length"] = str(len(text.encode()))
    item["request"] = {"method": method, "path": path, "headers": headers, "body": body}
    item["request_size"] = len(text.encode()) + 120
    item["timestamp"] = when or _now()
    return normalise(item)


def upload_body(size: int = 20 * 1024) -> dict:
    return {"name": "export.csv", "rows": ["x" * 100] * (size // 100)}


def with_uploads(**members) -> dict:
    """The design's example with `uploads` gaining v4 members."""
    value = guardrail()
    value["rules"]["uploads"].update(members)
    value["guardrail_contract_version"] = g.contract_version(value["rules"])
    return value


def hosts(found: dict) -> dict:
    return {rule: [v["item"] for v in found[rule]] for rule in g.REQUEST_RULES}


@pytest.fixture(autouse=True)
def body_kinds_on(monkeypatch):
    monkeypatch.setenv(g.BODY_KINDS_ENV, "on")


@pytest.mark.parametrize("value, on", [
    (None, True), ("", True), ("on", True), ("ON", True), ("1", True), ("true", True),
    ("off", False), ("0", False), ("false", False), ("no", False), ("maybe", True),
])
def test_body_kinds_are_on_unless_switched_off(monkeypatch, value, on):
    if value is None:
        monkeypatch.delenv(g.BODY_KINDS_ENV)
    else:
        monkeypatch.setenv(g.BODY_KINDS_ENV, value)
    assert g.body_kinds_on() is on
    assert bool(hosts(g.evaluate_request(guardrail(), rest(SEARCH, QUERY)))["uploads"]) is not on


# ------------------------------------------------------------------ contract


def test_v4_is_written_exactly_when_uploads_has_a_body_kind_member():
    plain = guardrail()
    assert g.contract_version(plain["rules"]) == 1
    for member, value in (
        ("parameters_only_hosts", [SEARCH]),
        ("body_kind_overrides", [{"host": SEARCH, "method": "POST", "path": "/v1/query", "kind": "parameters"}]),
        ("parameters_budget", {"agent": 2 * 1024 * 1024, "entries": {"*.search.example": 512 * 1024}}),
    ):
        version = with_uploads(**{member: value})
        assert version["guardrail_contract_version"] == 4
        assert g.guardrail_problems(version) == []
        Draft202012Validator(json.loads((SCHEMAS / "guardrail-version-v4.schema.json").read_text())).validate(version)
    # A v4 rule set with egress_containment stays v4 (one encoding), and v4
    # needs no egress rule, unlike v3.
    contained = with_uploads(parameters_only_hosts=[SEARCH])
    contained["rules"]["egress_containment"] = {"require": "contained"}
    assert g.contract_version(contained["rules"]) == 4 and g.guardrail_problems(contained) == []


@pytest.mark.parametrize("member, value, problem", [
    # Empty members aren't written, so a v4 version always has one.
    ("parameters_only_hosts", [], "should be non-empty"),
    ("body_kind_overrides", [], "should be non-empty"),
    ("parameters_budget", {}, "should be non-empty"),
    ("parameters_only_hosts", ["API.Search.example"], "not a normalized host"),
    ("body_kind_overrides", [{"host": "*.search.example", "method": "POST", "path": "/q", "kind": "parameters"}],
     "not a normalized exact host"),
    ("body_kind_overrides", [{"host": SEARCH, "method": "post", "path": "/q", "kind": "parameters"}],
     "does not match"),
    ("body_kind_overrides", [{"host": SEARCH, "method": "POST", "path": "q", "kind": "parameters"}],
     "does not match"),
    ("body_kind_overrides", [{"host": SEARCH, "method": "POST", "path": "/q", "kind": "read"}],
     "is not one of"),
    ("body_kind_overrides", [{"host": SEARCH, "method": "POST", "path": "/v1/items/123", "kind": "parameters"}],
     "did you mean '/v1/items/*'"),
    ("body_kind_overrides", [{"host": SEARCH, "method": "POST", "path": "/q", "kind": "parameters"},
                             {"host": SEARCH, "method": "POST", "path": "/q", "kind": "upload"}],
     "a second answer for"),
    ("parameters_budget", {"agent": 1.5}, "is not of type 'integer'"),
    ("parameters_budget", {"agent": 1024.0}, "must be an integer"),
    ("parameters_budget", {"entries": {SEARCH: -1}}, "less than the minimum"),
    ("parameters_budget", {"hosts": {}}, "Additional properties"),
])
def test_v4_members_are_closed(member, value, problem):
    version = with_uploads(**{member: value})
    version["guardrail_contract_version"] = 4
    problems = g.guardrail_problems(version)
    assert any(problem in text for text in problems), problems


def test_a_v4_member_in_a_v3_version_is_refused():
    version = with_uploads(parameters_only_hosts=[SEARCH])
    version["rules"]["egress_containment"] = {"require": "contained"}
    version["guardrail_contract_version"] = 3
    assert any("Additional properties" in text for text in g.guardrail_problems(version))


# --------------------------------------------------------------- the rule


def test_a_query_post_to_an_unlisted_host_is_a_call_not_an_upload():
    found = g.evaluate_request(guardrail(), rest(SEARCH, QUERY))
    assert hosts(found) == {"uploads": [], "out_of_spec_calls": [SEARCH]}


@pytest.mark.parametrize("body, content_type, step, reason", [
    (upload_body(), "application/json", bk.STEP_HARD, "body over 16 KiB"),
    ("--b\r\nContent-Disposition: form-data; name=f\r\n\r\nx\r\n--b--", "multipart/form-data; boundary=b",
     bk.STEP_HARD, "multipart/form-data body"),
    ({"filter": {"a": {"b": {"c": {"d": 1}}}}}, "application/json", bk.STEP_OTHER, None),
])
def test_an_upload_or_unknown_body_to_an_unlisted_host_is_flagged_with_its_kind(body, content_type, step, reason):
    [row] = g.evaluate_request(guardrail(), rest(FILES, body, content_type=content_type))["uploads"]
    assert row["item"] == FILES and row["detail"]["reasons"] == ["body_to_unlisted_host"]
    [kind] = row["detail"]["bodies"]
    assert kind["step"] == step and kind["kind"] in (bk.UPLOAD, bk.UNKNOWN)
    assert kind["method"] == "POST" and kind["path_template"] == "/v1/query"
    if reason:
        assert reason in kind["reasons"]


def test_model_traffic_to_an_unlisted_host_is_an_upload_as_before():
    model = normalise(dict(capture()[0], request=dict(capture()[0]["request"],
                                                       headers={"host": "llm.example", "content-type": "application/json"})))
    [row] = g.evaluate_request(guardrail(), model)["uploads"]
    assert row["detail"]["bodies"][0]["source"] == bk.SOURCE_TRAFFIC


def test_a_parameters_body_still_meets_the_size_cap_and_a_hostless_one_stays_an_upload():
    capped = with_uploads(parameters_only_hosts=[SEARCH])
    capped["rules"]["uploads"]["max_request_bytes"] = {SEARCH: 10}
    [row] = g.evaluate_request(capped, rest(SEARCH, QUERY))["uploads"]
    assert row["detail"]["reasons"] == ["request_size_over_cap"]
    assert row["detail"]["bodies"][0]["kind"] == bk.PARAMETERS
    assert hosts(g.evaluate_request(guardrail(), rest(None, QUERY)))["uploads"] == [g.UNKNOWN_HOST]


def test_parameters_only_hosts_never_widen_allowed_hosts():
    version = with_uploads(parameters_only_hosts=[SEARCH])
    assert hosts(g.evaluate_request(version, rest(SEARCH, QUERY)))["uploads"] == []
    assert hosts(g.evaluate_request(version, rest(SEARCH, upload_body())))["uploads"] == [SEARCH]


# ----------------------------------------------------- overrides, re-check


DEEP = {"filter": {"a": {"b": {"c": {"d": 1}}}}}  # past the 4-deep bound: unknown


def override(kind: str, path: str = "/v1/query", host: str = SEARCH) -> dict:
    return {"host": host, "method": "POST", "path": path, "kind": kind}


def test_this_is_parameters_clears_an_unknown_row_and_this_is_an_upload_flags_a_query():
    [row] = g.evaluate_request(guardrail(), rest(SEARCH, DEEP))["uploads"]
    assert not g.item_allowed(guardrail(), row)
    assert g.item_allowed(with_uploads(body_kind_overrides=[override("parameters")]), row)
    # Another path's answer doesn't.
    assert not g.item_allowed(with_uploads(body_kind_overrides=[override("parameters", "/v1/other")]), row)
    # Applied at ingest too.
    marked = with_uploads(body_kind_overrides=[override("parameters")])
    assert hosts(g.evaluate_request(marked, rest(SEARCH, DEEP)))["uploads"] == []
    flagged = with_uploads(body_kind_overrides=[override("upload")])
    [row] = g.evaluate_request(flagged, rest(SEARCH, QUERY))["uploads"]
    assert row["detail"]["bodies"][0]["step"] == bk.STEP_OVERRIDE
    # Dropping that override later reads the body as unknown, not parameters.
    assert not g.item_allowed(guardrail(), row)


def test_an_override_never_clears_a_hard_upload_or_model_traffic():
    [row] = g.evaluate_request(guardrail(), rest(SEARCH, upload_body()))["uploads"]
    assert not g.item_allowed(with_uploads(body_kind_overrides=[override("parameters")]), row)
    model = normalise(dict(capture()[0], request=dict(capture()[0]["request"],
                                                       headers={"host": SEARCH, "content-type": "application/json"})))
    [row] = g.evaluate_request(guardrail(), model)["uploads"]
    assert not g.item_allowed(with_uploads(body_kind_overrides=[override("parameters", "/v1/messages")]), row)


def test_a_capture_that_cant_be_read_is_never_cleared_by_an_override():
    """Its hard signals couldn't be checked, so it is decided at step 1."""
    unreadable = rest(SEARCH, upload_body(5 * 1024 * 1024))
    unreadable["raw"] = "{" * 300 + "}" * 300
    marked = with_uploads(body_kind_overrides=[override("parameters")])
    [row] = g.evaluate_request(marked, unreadable)["uploads"]
    assert row["detail"]["bodies"][0]["step"] == bk.STEP_HARD
    assert row["detail"]["bodies"][0]["reasons"] == ["capture not readable"]
    assert not g.item_allowed(marked, row)


def test_a_row_from_before_body_kinds_reads_as_an_upload():
    [row] = g.evaluate_request(guardrail(), rest(SEARCH, DEEP))["uploads"]
    row["detail"].pop("bodies")
    assert not g.item_allowed(with_uploads(body_kind_overrides=[override("parameters")]), row)


def test_a_merged_row_keeps_every_distinct_body_and_overflows_closed():
    one = {"carries_body": True, "bodies": [{"kind": "unknown", "step": 5, "method": "POST", "path_template": "/a"}]}
    two = {"carries_body": True, "bodies": [{"kind": "unknown", "step": 5, "method": "POST", "path_template": "/b"}]}
    merged = g.merge_row_bodies(one, two)
    assert [b["path_template"] for b in merged["bodies"]] == ["/a", "/b"]
    assert g.merge_row_bodies(one, one) == {"bodies": one["bodies"]}
    # Answering one path leaves the row counting for the other.
    detail = {**two, **merged}
    row = {"rule": "uploads", "item": SEARCH, "detail": detail}
    assert not g.item_allowed(with_uploads(body_kind_overrides=[override("parameters", "/a")]), row)
    assert g.item_allowed(with_uploads(body_kind_overrides=[override("parameters", "/a"),
                                                            override("parameters", "/b")]), row)
    # A hit with a body and no list (before body kinds) leaves none.
    assert g.merge_row_bodies({"carries_body": True}, two) == {}
    many = {"carries_body": True, "bodies": [
        {"kind": "unknown", "step": 5, "method": "POST", "path_template": f"/{n}"} for n in range(g.MAX_ROW_BODIES)
    ]}
    assert g.merge_row_bodies(many, two)["bodies_overflow"] is True
    assert not g.item_allowed(with_uploads(body_kind_overrides=[
        override("parameters", f"/{n}") for n in [*range(g.MAX_ROW_BODIES), "b"]
    ]), {"rule": "uploads", "item": SEARCH, "detail": {**two, **g.merge_row_bodies(many, two)}})


def test_the_back_out_switch_reads_every_body_as_an_upload(monkeypatch):
    monkeypatch.setenv(g.BODY_KINDS_ENV, "off")
    assert hosts(g.evaluate_request(guardrail(), rest(SEARCH, QUERY)))["uploads"] == [SEARCH]
    [row] = g.evaluate_request(guardrail(), rest(SEARCH, QUERY))["uploads"]
    assert "bodies" not in row["detail"]
    # A version proposed with the narrow seed doesn't turn Violated on its queries.
    version = with_uploads(parameters_only_hosts=[SEARCH])
    assert hosts(g.evaluate_request(version, rest(SEARCH, QUERY)))["uploads"] == []
    assert g.item_allowed(version, row)


# --------------------------------------------------------------- proposal


def _requests():
    return [rest(SEARCH, QUERY, when="2026-08-15T17:05:00Z"),
            rest(FILES, upload_body(), path="/v1/files", when="2026-08-15T17:06:00Z"),
            rest("other.example", QUERY, when="2026-08-15T17:07:00Z"),
            rest("other.example", DEEP, when="2026-08-15T17:08:00Z")]


def test_a_proposal_seeds_only_hosts_it_uploaded_to(store):  # noqa: F811
    alignment, bundle = _lock(store, __import__("test_guardrail").v1_bundle(**DECLARED))
    proposal = _propose(alignment, bundle, _requests())
    version = proposal["guardrail"]
    uploads = version["rules"]["uploads"]
    # The base URL's host, the real upload, and the host that also got an
    # unknown body; the host it only queried is recorded apart.
    assert uploads["allowed_hosts"] == ["api.openai.com", FILES, "other.example"]
    assert uploads["parameters_only_hosts"] == [SEARCH]
    assert version["guardrail_contract_version"] == 4 and g.guardrail_problems(version) == []
    # Still a call to surface.
    assert ("out_of_spec_calls", SEARCH) in {(v["rule"], v["item"]) for v in proposal["would_be_violations"]}
    assert ("uploads", SEARCH) not in {(v["rule"], v["item"]) for v in proposal["would_be_violations"]}

    # Allow this on a later upload there moves the host across, and the
    # empty list goes, so the rule set is v1 again.
    [row] = g.evaluate_request(version, rest(SEARCH, upload_body()))["uploads"]
    allowed = g.with_item_allowed(version["rules"], row)
    assert SEARCH in allowed["uploads"]["allowed_hosts"] and "parameters_only_hosts" not in allowed["uploads"]
    assert g.contract_version(allowed) == 1


def test_with_body_kinds_off_the_proposal_is_as_before(store, monkeypatch):  # noqa: F811
    monkeypatch.setenv(g.BODY_KINDS_ENV, "off")
    alignment, bundle = _lock(store, __import__("test_guardrail").v1_bundle(**DECLARED))
    version = _propose(alignment, bundle, _requests())["guardrail"]
    assert version["rules"]["uploads"]["allowed_hosts"] == ["api.openai.com", SEARCH, FILES, "other.example"]
    assert "parameters_only_hosts" not in version["rules"]["uploads"]
    assert version["guardrail_contract_version"] == 1


# ------------------------------------------------------------------ store


def test_adopted_v4_judges_queries_as_calls_and_an_edit_with_an_override_clears_a_row(store):  # noqa: F811
    alignment, ref = baseline(store)
    live(store)
    proposal = store.propose_guardrail(alignment["alignment_version_id"])
    rules = proposal["guardrail"]["rules"]
    rules["uploads"]["parameters_only_hosts"] = [SEARCH]
    active = store.adopt_guardrail(alignment["alignment_version_id"], rules)
    assert active["guardrail"]["guardrail_contract_version"] == 4
    send(store, rest(SEARCH, QUERY), rest(SEARCH, DEEP, path="/v1/deep"))
    found = rows(store, ref)
    assert ("out_of_spec_calls", SEARCH) in found
    upload = found[("uploads", SEARCH)]
    assert upload["counts"] and [b["path_template"] for b in upload["detail"]["bodies"]] == ["/v1/deep"]
    rules = json.loads(json.dumps(active["guardrail"]["rules"]))
    rules["uploads"]["body_kind_overrides"] = [override("parameters", "/v1/deep")]
    store.edit_guardrail(active["guardrail"]["guardrail_version_id"], rules)
    assert not rows(store, ref)[("uploads", SEARCH)]["counts"]


# ---------------------------------------------------------- OpenShell export


def test_a_queried_host_is_exported_read_write_with_a_gap_line():
    record = imported("base.policy-only.yaml")
    version = {
        "out_of_spec_calls": {"allowed_hosts": ["api.github.com", SEARCH], "allowed_mcp_servers": [],
                              "seeded_from_declared": {"hosts": [], "mcp_servers": []}},
        "uploads": {"allowed_hosts": [], "max_request_bytes": {}, "denied_tool_calls": [],
                    "parameters_only_hosts": [SEARCH]},
        "saved_files": {"allowed": []}, "service_ports": {"allowed": []},
    }
    out = export(version, record, record)
    access = {endpoint["host"]: endpoint["access"]
              for policy in out["policy"]["network_policies"].values() for endpoint in policy["endpoints"]}
    assert access == {"api.github.com": "read-only", SEARCH: "read-write"}
    assert any(SEARCH in gap and "only RailDash tells an upload" in gap for gap in out["gaps"])
    assert osp is not None


# -------------------------------------------------------------- drip check


def test_a_drip_row_clears_only_under_budgets_its_sums_fit():
    body = {"kind": bk.UPLOAD, "step": bk.STEP_DRIP, "method": "POST", "path_template": "/v1/query",
            "drip": {"entries": {SEARCH: 256 * 1024 - 10}, "agent": 300 * 1024, "bytes": 100}}
    row = {"rule": "uploads", "item": SEARCH,
           "detail": {"kind": "host", "carries_body": True, "reasons": ["body_to_unlisted_host"], "bodies": [body]}}
    assert not g.item_allowed(guardrail(), row)
    # An override never answers the drip check.
    assert not g.item_allowed(with_uploads(body_kind_overrides=[override("parameters")]), row)
    assert not g.item_allowed(with_uploads(parameters_budget={"entries": {SEARCH: 256 * 1024 + 50}}), row)
    assert g.item_allowed(with_uploads(parameters_budget={"entries": {SEARCH: 256 * 1024 + 90}}), row)
    # The agent's bound too.
    assert not g.item_allowed(with_uploads(parameters_budget={"entries": {SEARCH: 512 * 1024}, "agent": 300 * 1024}),
                              row)
    # Sums that can't be read never clear it.
    body["drip"] = {"entries": {SEARCH: "x"}, "agent": 0, "bytes": 1}
    assert not g.item_allowed(with_uploads(parameters_budget={"entries": {SEARCH: 10 ** 9}}), row)


def test_drip_keys_share_a_wildcard_entry_or_fall_back_to_the_host():
    assert g.drip_keys("a.workers.dev", ["*.workers.dev", "api.github.com"]) == ["*.workers.dev"]
    assert g.drip_keys("a.example", ["*.workers.dev"]) == ["a.example"]


def _queries(host: str, n: int, start: str = "2026-10-31T00:00:00Z", size: int = 3000) -> list[dict]:
    from datetime import datetime, timedelta
    base = datetime.fromisoformat(start.replace("Z", "+00:00"))
    body = {"q": "x" * 200, **{f"k{i}": "y" * 200 for i in range(size // 210)}}
    return [rest(host, body, when=(base + timedelta(minutes=i)).isoformat().replace("+00:00", "Z"))
            for i in range(n)]


def test_the_store_counts_parameters_bytes_and_makes_the_overflow_an_upload(store):  # noqa: F811
    alignment, ref = baseline(store)
    live(store)
    rules = store.propose_guardrail(alignment["alignment_version_id"])["guardrail"]["rules"]
    rules["uploads"]["parameters_only_hosts"] = [SEARCH]
    rules["out_of_spec_calls"]["allowed_hosts"] = [*rules["out_of_spec_calls"]["allowed_hosts"], SEARCH]
    active = store.adopt_guardrail(alignment["alignment_version_id"], rules)
    # About 3 KiB each: 256 KiB a day for the entry is 80-odd of them.
    requests = _queries(SEARCH, 100, start=_now())
    size = json.loads(requests[0]["raw"])["request"]["headers"]["content-length"]
    send(store, *requests)
    found = rows(store, ref)
    assert ("out_of_spec_calls", SEARCH) not in found
    row = found[("uploads", SEARCH)]
    assert row["counts"]
    [body] = row["detail"]["bodies"][:1]
    assert body["step"] == bk.STEP_DRIP and body["reasons"][0] == f"parameters volume over 256 KiB a day to {SEARCH}"
    counted = store._db.execute(  # noqa: SLF001
        "SELECT sum(bytes) FROM guardrail_parameters_bytes WHERE budget_key = ?", (SEARCH,)).fetchone()[0]
    assert counted <= 256 * 1024 and counted > 256 * 1024 - 2 * int(size)
    # Raising the entry's budget past every stored sum clears the row.
    rules = json.loads(json.dumps(active["guardrail"]["rules"]))
    rules["uploads"]["parameters_budget"] = {"entries": {SEARCH: 1024 * 1024}}
    store.edit_guardrail(active["guardrail"]["guardrail_version_id"], rules)
    assert not rows(store, ref)[("uploads", SEARCH)]["counts"]


def test_the_agents_budget_spans_hosts(store):  # noqa: F811
    alignment, ref = baseline(store)
    live(store)
    rules = store.propose_guardrail(alignment["alignment_version_id"])["guardrail"]["rules"]
    hosts_ = [f"h{i}.search.example" for i in range(6)]
    rules["out_of_spec_calls"]["allowed_hosts"] = [*rules["out_of_spec_calls"]["allowed_hosts"], *hosts_]
    rules["uploads"]["parameters_budget"] = {"agent": 200 * 1024}
    store.adopt_guardrail(alignment["alignment_version_id"], rules)
    send(store, *[request for host in hosts_ for request in _queries(host, 15, start=_now())])
    found = rows(store, ref)
    over = [key for key in found if key[0] == "uploads"]
    assert over, found
    reasons = {r for key in over for b in found[key]["detail"]["bodies"] for r in b["reasons"]}
    assert "parameters volume over 200 KiB a day for the agent" in reasons


def test_the_proposal_runs_the_drip_check_over_the_window(store):  # noqa: F811
    alignment, bundle = _lock(store, __import__("test_guardrail").v1_bundle(**DECLARED))
    proposal = _propose(alignment, bundle, _queries(SEARCH, 100, start="2026-08-15T00:00:00Z"))
    uploads = proposal["guardrail"]["rules"]["uploads"]
    # The queries that fit make it a queried-only host; the overflow seeds
    # no upload host and is listed for the user instead.
    assert SEARCH not in uploads["allowed_hosts"]
    assert uploads.get("parameters_only_hosts") == [SEARCH]
    [row] = [v for v in proposal["would_be_violations"] if v["rule"] == "uploads"]
    assert row["item"] == SEARCH and row["detail"]["bodies"][0]["step"] == bk.STEP_DRIP


def _drip_agent(store):  # noqa: F811
    alignment, ref = baseline(store)
    live(store)
    rules = store.propose_guardrail(alignment["alignment_version_id"])["guardrail"]["rules"]
    rules["out_of_spec_calls"]["allowed_hosts"] = [*rules["out_of_spec_calls"]["allowed_hosts"], SEARCH]
    active = store.adopt_guardrail(alignment["alignment_version_id"], rules)
    return ref, active


def _counted(store) -> int:  # noqa: F811
    return store._db.execute(  # noqa: SLF001
        "SELECT coalesce(sum(bytes), 0) FROM guardrail_parameters_bytes WHERE budget_key = ?", (SEARCH,)).fetchone()[0]


@pytest.mark.parametrize("arrange", ["reversed", "future", "no_time", "naive_time", "days_old"])
def test_no_capture_time_gets_parameters_past_the_budget(store, arrange):  # noqa: F811
    """Late, future-stamped and unstamped bodies are all still bounded."""
    from datetime import datetime, timedelta, timezone
    ref, _ = _drip_agent(store)
    if arrange == "days_old":
        # A guardrail active for ten days: older captures are judged.
        store._db.execute("UPDATE guardrail_bindings SET activated_at = ?",  # noqa: SLF001
                          (store._receive_time(datetime.now(timezone.utc) - timedelta(days=10)),))  # noqa: SLF001
    requests = _queries(SEARCH, 120, start=_now())
    if arrange == "reversed":
        requests.reverse()
    for i, request in enumerate(requests):
        if arrange == "future":
            request["timestamp"] = (datetime.now(timezone.utc) + timedelta(days=30 + i)).isoformat()
        elif arrange == "no_time":
            request["timestamp"] = None
        elif arrange == "naive_time":
            request["timestamp"] = datetime.now().isoformat()
        elif arrange == "days_old":
            request["timestamp"] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    send(store, *requests)
    assert _counted(store) <= 256 * 1024
    assert rows(store, ref)[("uploads", SEARCH)]["counts"]


def test_a_drip_row_needs_a_budget_that_fits_every_byte_it_made_an_upload(store):  # noqa: F811
    ref, active = _drip_agent(store)
    send(store, *_queries(SEARCH, 300, start=_now()))
    row = rows(store, ref)[("uploads", SEARCH)]
    [drip] = [b["drip"] for b in row["detail"]["bodies"] if b["step"] == bk.STEP_DRIP]
    assert drip["over"] > 400 * 1024  # some 200 bodies past the budget, all on one entry
    rules = json.loads(json.dumps(active["guardrail"]["rules"]))
    rules["uploads"]["parameters_budget"] = {"entries": {SEARCH: 262 * 1024}}
    store.edit_guardrail(active["guardrail"]["guardrail_version_id"], rules)
    assert rows(store, ref)[("uploads", SEARCH)]["counts"]


def test_merged_drip_keeps_the_largest_sums_and_adds_the_bytes():
    one = {"entries": {SEARCH: 100}, "agent": 200, "bytes": 10}
    two = {"entries": {SEARCH: 90, "x": 5}, "agent": 300, "bytes": 20, "over": 50}
    assert g._merged_drip(one, two) == {"entries": {SEARCH: 100, "x": 5}, "agent": 300, "bytes": 20, "over": 60}
    assert g._merged_drip(one, {"entries": {SEARCH: "1"}, "agent": 1, "bytes": 1}) is None


def test_the_proposal_counts_unstamped_bodies_too(store):  # noqa: F811
    alignment, bundle = _lock(store, __import__("test_guardrail").v1_bundle(**DECLARED))
    requests = _queries(SEARCH, 100, start="2026-08-15T00:00:00Z")
    for request in requests:
        request["timestamp"] = None
    proposal = _propose(alignment, bundle, requests)
    assert [v["item"] for v in proposal["would_be_violations"] if v["rule"] == "uploads"] == [SEARCH]
