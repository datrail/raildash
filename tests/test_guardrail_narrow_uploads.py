"""REST uploads M2c: the *narrow uploads* offer (design §4).

An upload host the agent's last 24 hours only sent `parameters` bodies to
is offered for moving to `parameters_only_hosts`, once RailDash has checked
that the move makes no request in the window and no stored row count.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash import guardrail as g
from raildash.store import Store
from test_guardrail import guardrail, store  # noqa: F401
from test_guardrail_body_kinds import DEEP, FILES, QUERY, SEARCH, _queries, override, rest, upload_body, with_uploads
from test_guardrail_custody import _now, baseline, live, rows, send


@pytest.fixture(autouse=True)
def body_kinds_on(monkeypatch):
    monkeypatch.setenv(g.BODY_KINDS_ENV, "on")


def _version(*allowed: str, **members) -> dict:
    version = with_uploads(**members)
    version["rules"]["uploads"]["allowed_hosts"] = list(allowed)
    version["rules"]["out_of_spec_calls"]["allowed_hosts"] = [
        *version["rules"]["out_of_spec_calls"]["allowed_hosts"], *allowed]
    version["guardrail_contract_version"] = g.contract_version(version["rules"])
    return version


def offered(version: dict, requests: list[dict], stored: list[dict] = ()) -> list[str]:
    return [entry["host"] for entry in g.narrow_uploads_hosts(version, requests, list(stored))]


# ------------------------------------------------------------------- pure


def test_a_host_only_sent_queries_is_offered_and_one_sent_a_file_is_not():
    version = _version(SEARCH, FILES)
    requests = [rest(SEARCH, QUERY), rest(SEARCH, {"id": 7}, path="/v1/get"),
                rest(FILES, upload_body(), path="/v1/files")]
    [entry] = g.narrow_uploads_hosts(version, requests, [])
    assert entry["host"] == SEARCH and entry["requests"] == 2 and entry["bytes"] > 0


@pytest.mark.parametrize("extra", [
    rest(SEARCH, DEEP, path="/v1/deep"),                       # unknown: still an upload
    rest(SEARCH, upload_body(), path="/v1/files"),             # a file
    rest(SEARCH, "a,b\n1,2\n", content_type="text/csv"),       # a hard upload
])
def test_one_body_that_counts_keeps_the_host_an_upload_host(extra):
    assert offered(_version(SEARCH), [rest(SEARCH, QUERY), extra]) == []


def test_a_host_with_no_parameters_body_in_the_window_is_not_offered():
    # Nothing in the window says what it is sent; a GET carries no body.
    assert offered(_version(SEARCH), []) == []
    assert offered(_version(SEARCH), [rest(SEARCH, "", method="GET")]) == []


def test_the_versions_own_override_answers_a_body():
    version = _version(SEARCH, body_kind_overrides=[override("parameters", "/v1/deep")])
    assert offered(version, [rest(SEARCH, DEEP, path="/v1/deep")]) == [SEARCH]


def test_bodies_past_the_drip_budget_keep_the_host_an_upload_host():
    # About 3 KiB each: 100 of them pass the entry's 256 KiB a day.
    assert offered(_version(SEARCH), _queries(SEARCH, 100)) == []
    assert offered(_version(SEARCH), _queries(SEARCH, 20)) == [SEARCH]
    raised = _version(SEARCH, parameters_budget={"entries": {SEARCH: 1024 * 1024}})
    assert offered(raised, _queries(SEARCH, 100)) == [SEARCH]


def test_a_stored_row_the_move_would_make_count_keeps_the_host():
    version = _version(SEARCH)
    # Flagged before the host was allowed: a file to it, now allowed.
    [row] = g.evaluate_request(_version(), rest(SEARCH, upload_body(), path="/v1/files"))["uploads"]
    row = {**row, "acknowledged": False, "overflow": False}
    assert not g.row_counts(version, row)
    assert offered(version, [rest(SEARCH, QUERY)], [row]) == []
    # Acknowledged, it never counts again, so it doesn't stand in the way.
    assert offered(version, [rest(SEARCH, QUERY)], [{**row, "acknowledged": True}]) == [SEARCH]


def test_a_wildcard_entry_moves_while_another_entry_still_allows_the_upload():
    version = _version("*.search.example", SEARCH)
    requests = [rest("x.search.example", QUERY), rest(SEARCH, upload_body(), path="/v1/files")]
    assert offered(version, requests) == ["*.search.example"]


def test_entries_are_checked_together_not_only_one_by_one():
    # Each could move alone (the other still allows the file), never both:
    # the first in `allowed_hosts` order is offered, the second isn't.
    requests = [rest(SEARCH, QUERY), rest("x.search.example", upload_body(), path="/v1/files")]
    assert offered(_version("*.search.example", "*.example"), requests) == ["*.search.example"]
    assert offered(_version("*.example", "*.search.example"), requests) == ["*.example"]


def test_with_body_kinds_off_nothing_is_offered(monkeypatch):
    monkeypatch.setenv(g.BODY_KINDS_ENV, "off")
    assert offered(_version(SEARCH), [rest(SEARCH, QUERY)]) == []


# ------------------------------------------------------------------ store


def now(host, body, **kwargs) -> dict:
    """A request captured now: RailMon's `timestamp_ns` is wall-clock
    (epoch ms x 1e6), which the offer's 24-hour window reads."""
    from datetime import datetime
    when = _now()
    row = rest(host, body, when=when, **kwargs)
    row["timestamp_ns"] = int(datetime.fromisoformat(when.replace("Z", "+00:00")).timestamp() * 1e9)
    return row


def _agent(store, *hosts_):  # noqa: F811
    alignment, ref = baseline(store)
    live(store)
    rules = store.propose_guardrail(alignment["alignment_version_id"])["guardrail"]["rules"]
    rules["uploads"]["allowed_hosts"] = sorted({*rules["uploads"]["allowed_hosts"], *hosts_})
    rules["out_of_spec_calls"]["allowed_hosts"] = sorted({*rules["out_of_spec_calls"]["allowed_hosts"], *hosts_})
    active = store.adopt_guardrail(alignment["alignment_version_id"], rules)
    return ref, active


def test_narrow_uploads_moves_the_host_and_a_file_to_it_then_counts(store):  # noqa: F811
    ref, active = _agent(store, SEARCH, FILES)
    send(store, now(SEARCH, QUERY), now(FILES, upload_body(), path="/v1/files"))
    counting = {key for key, row in rows(store, ref).items() if row["counts"]}
    offer = store.guardrail_detail(ref)["narrow_uploads_offer"]
    assert [h["host"] for h in offer["hosts"]] == [SEARCH] and offer["version"] == active["guardrail"]["version"]
    made = store.narrow_uploads(ref, [SEARCH])
    uploads = made["guardrail"]["rules"]["uploads"]
    assert SEARCH not in uploads["allowed_hosts"] and uploads["parameters_only_hosts"] == [SEARCH]
    assert made["guardrail"]["guardrail_contract_version"] == 4 and made["created_by"] == "narrow_uploads"
    assert store.guardrail_detail(ref)["narrow_uploads_offer"] is None
    # Nothing that didn't count before counts now.
    assert {key for key, row in rows(store, ref).items() if row["counts"]} == counting
    assert ("uploads", SEARCH) not in rows(store, ref)
    send(store, now(SEARCH, upload_body(), path="/v1/files"))
    assert rows(store, ref)[("uploads", SEARCH)]["counts"]


def test_the_offer_follows_new_requests_and_accepting_reads_them_at_once(store, monkeypatch):  # noqa: F811
    from raildash import guardrail_store
    ref, _ = _agent(store, SEARCH)
    send(store, now(SEARCH, QUERY))
    assert store.guardrail_detail(ref)["narrow_uploads_offer"] is not None
    send(store, now(SEARCH, upload_body(), path="/v1/files"))
    # Within the minute the kept offer is shown; accepting it reads the
    # file and refuses.
    assert store.guardrail_detail(ref)["narrow_uploads_offer"] is not None
    with pytest.raises(ValueError, match="not in the narrow uploads offer"):
        store.narrow_uploads(ref, [SEARCH])
    monkeypatch.setattr(guardrail_store, "NARROW_OFFER_MIN_AGE", 0)
    assert store.guardrail_detail(ref)["narrow_uploads_offer"] is None


def test_a_violated_agent_is_still_offered_what_moves_safely():
    # The file to an unlisted host and the hostless body already count;
    # neither says anything about the queried host.
    requests = [rest(SEARCH, QUERY), rest("evil.example", upload_body(), path="/v1/files"),
                rest(None, upload_body(), path="/v1/files")]
    assert offered(_version(SEARCH), requests) == [SEARCH]


def test_dismiss_stops_offering_those_hosts(store):  # noqa: F811
    ref, _ = _agent(store, SEARCH, "api.other.example")
    send(store, now(SEARCH, QUERY), now("api.other.example", QUERY))
    offer = store.guardrail_detail(ref)["narrow_uploads_offer"]
    assert sorted(h["host"] for h in offer["hosts"]) == ["api.other.example", SEARCH]
    store.dismiss_narrow_uploads(ref, [SEARCH])
    offer = store.guardrail_detail(ref)["narrow_uploads_offer"]
    assert [h["host"] for h in offer["hosts"]] == ["api.other.example"]
    with pytest.raises(ValueError):
        store.narrow_uploads(ref, [SEARCH])
    assert any(e["action"] == "dismiss_narrow_uploads" for e in store.guardrail_detail(ref)["events"])


def test_a_window_past_the_read_limit_is_not_offered(store, monkeypatch):  # noqa: F811
    import time
    from raildash import guardrail_store
    ref, _ = _agent(store, SEARCH)
    # A file to the host, a query, then three captures of another agent:
    # with the limit at 4 the file is never read, even though this agent
    # owns fewer than 4 of what was read, so nothing is offered.
    send(store, now(SEARCH, upload_body(), path="/v1/files"))
    time.sleep(0.01)
    send(store, now(SEARCH, QUERY))
    others = []
    for _ in range(3):
        time.sleep(0.01)
        other = now("other.example", QUERY)
        other.update(attribution_state="attributed", agent_key="someone-else")
        others.append(other)
    send(store, *others)
    monkeypatch.setattr(guardrail_store, "PROPOSAL_MAX_REQUESTS", 4)
    assert store.guardrail_detail(ref)["narrow_uploads_offer"] is None


def test_dismissing_a_host_that_isnt_an_upload_host_is_refused(store):  # noqa: F811
    ref, _ = _agent(store, SEARCH)
    with pytest.raises(ValueError, match="not an upload host"):
        store.dismiss_narrow_uploads(ref, ["nowhere.example"])


# ----------------------------------------------------------------- routes


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = Store(tmp_path / "routes.db")
    monkeypatch.setattr(app_module, "store", db)
    yield TestClient(app_module.app), db
    db.close()


@pytest.mark.parametrize("body", [{}, {"hosts": []}, {"hosts": "x"}, {"hosts": [1]}, {"hosts": ["a", "a"]}])
def test_routes_refuse_a_malformed_host_list(client, body):
    http, _ = client
    for path in ("narrow-uploads", "narrow-uploads/dismiss"):
        res = http.post(f"/api/guardrails/none/{path}", json=body,
                        headers={"X-RailDash-Token": app_module.LOCAL_TOKEN})
        assert res.status_code == 422, res.text


def test_routes_need_the_local_token_and_narrow_through_http(client):
    http, db = client
    ref, _ = _agent(db, SEARCH)
    send(db, now(SEARCH, QUERY))
    assert http.post(f"/api/guardrails/{ref}/narrow-uploads", json={"hosts": [SEARCH]}).status_code in (401, 403)
    res = http.post(f"/api/guardrails/{ref}/narrow-uploads", json={"hosts": [SEARCH]},
                    headers={"X-RailDash-Token": app_module.LOCAL_TOKEN})
    assert res.status_code == 201, res.text
    assert json.loads(res.text)["guardrail"]["rules"]["uploads"]["parameters_only_hosts"] == [SEARCH]


def test_repeats_of_a_stored_row_dont_recompute_the_offer_on_every_poll(store, monkeypatch):  # noqa: F811
    ref, _ = _agent(store, SEARCH)
    send(store, now(SEARCH, QUERY), now("evil.example", upload_body(), path="/v1/files"))
    assert store.guardrail_detail(ref)["narrow_uploads_offer"] is not None
    calls = []
    real = g.narrow_uploads_hosts
    monkeypatch.setattr(g, "narrow_uploads_hosts", lambda *a: calls.append(1) or real(*a))
    for _ in range(3):
        send(store, now("evil.example", upload_body(), path="/v1/files"))
        assert store.guardrail_detail(ref)["narrow_uploads_offer"] is not None
    assert calls == []
