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
    monkeypatch.delenv(g.BODY_KINDS_ENV, raising=False)


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
    assert any(SEARCH in gap and "judged by RailDash only" in gap for gap in out["gaps"])
    assert osp is not None
