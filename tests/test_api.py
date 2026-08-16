"""The HTTP surface, against a store loaded from the fixture."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.ingest import normalise, read_jsonl
from raildash.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "capture.jsonl"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = Store(tmp_path / "test.db")
    monkeypatch.setattr(app_module, "store", store)
    items, _ = read_jsonl(str(FIXTURE))
    store.upsert_session("file:capture.jsonl", agent="openclaw-1", source="fixture")
    store.add_interactions("file:capture.jsonl", [normalise(i) for i in items])
    yield TestClient(app_module.app)
    store.close()


def test_health(client):
    body = client.get("/webhook/health").json()
    assert body["status"] == "ok"
    assert body["sessions"] == 1


def test_sessions_carry_counts(client):
    sessions = client.get("/api/sessions").json()
    assert len(sessions) == 1
    assert sessions[0]["interaction_count"] == 8
    # 429, 500 and 403 in the fixture.
    assert sessions[0]["error_count"] == 3


def test_overview_totals(client):
    data = client.get("/api/overview").json()
    totals = data["totals"]
    assert totals["interactions"] == 8
    assert totals["errors"] == 3
    assert totals["tool_calls"] == 2
    hosts = {h["host"]: h for h in data["hosts"]}
    assert hosts["api.anthropic.com"]["count"] == 3
    assert hosts["api.anthropic.com"]["errors"] == 1


def test_interactions_are_newest_first(client):
    items = client.get("/api/interactions").json()["items"]
    stamps = [i["timestamp"] for i in items if i["timestamp"]]
    assert stamps == sorted(stamps, reverse=True)


def test_filter_by_host(client):
    data = client.get("/api/interactions", params={"host": "registry.npmjs.org"}).json()
    assert data["total"] == 1
    assert data["items"][0]["path"] == "/left-pad"


def test_filter_errors_only(client):
    data = client.get("/api/interactions", params={"errors_only": True}).json()
    assert data["total"] == 3
    assert all(i["status_code"] >= 400 for i in data["items"])


def test_filter_by_status_class(client):
    data = client.get("/api/interactions", params={"status_class": "5"}).json()
    assert data["total"] == 1
    assert data["items"][0]["status_code"] == 500


def test_search_matches_path_and_host(client):
    assert client.get("/api/interactions", params={"q": "left-pad"}).json()["total"] == 1
    assert client.get("/api/interactions", params={"q": "anthropic"}).json()["total"] == 3


def test_search_does_not_reach_into_bodies(client):
    """Searching `raw` would be a substring search over captured credentials
    and customer data. `771234567890` appears only in bodies."""
    assert client.get("/api/interactions", params={"q": "771234567890"}).json()["total"] == 0


def test_pagination(client):
    first = client.get("/api/interactions", params={"limit": 3, "offset": 0}).json()
    second = client.get("/api/interactions", params={"limit": 3, "offset": 3}).json()
    assert first["total"] == second["total"] == 8
    assert len(first["items"]) == len(second["items"]) == 3
    assert {i["id"] for i in first["items"]} & {i["id"] for i in second["items"]} == set()


def test_detail_returns_the_untouched_interaction(client):
    row_id = client.get("/api/interactions").json()["items"][-1]["id"]
    detail = client.get(f"/api/interactions/{row_id}").json()
    assert detail["raw"]["request"]["method"] == "POST"
    assert detail["raw"]["response"]["status_code"] == 200


def test_missing_interaction_is_404(client):
    assert client.get("/api/interactions/999999").status_code == 404


def test_webhook_accepts_railmons_envelope(client):
    payload = {
        "session_id": "live-1",
        "agent": "railmon",
        "capture_start": "2026-08-15T18:00:00Z",
        "interactions": [
            {
                "timestamp": "2026-08-15T18:00:01Z",
                "timestamp_ns": 1786852801000000000,
                "request": {"method": "GET", "path": "/v1/models",
                            "headers": {"host": "api.openai.com"}},
                "response": {"status_code": 200},
                "latency_ms": 42.0,
            }
        ],
    }
    body = client.post("/webhook/http-interactions", json=payload).json()
    assert body == {"received": 1, "stored": 1, "session_id": "live-1"}
    assert client.get("/api/interactions",
                      params={"session_id": "live-1"}).json()["total"] == 1


def test_redelivery_is_idempotent(client):
    """A retrying sender must not double the counts."""
    payload = {
        "session_id": "live-2",
        "interactions": [
            {"interaction_id": "fixed-1",
             "request": {"method": "GET", "path": "/x", "headers": {"host": "h"}},
             "response": {"status_code": 200}}
        ],
    }
    first = client.post("/webhook/http-interactions", json=payload).json()
    second = client.post("/webhook/http-interactions", json=payload).json()
    assert first["stored"] == 1
    assert second["received"] == 1 and second["stored"] == 0
    assert client.get("/api/interactions",
                      params={"session_id": "live-2"}).json()["total"] == 1


def test_webhook_accepts_a_bare_array(client):
    items = [{"request": {"method": "GET", "path": "/y", "headers": {"host": "h"}},
              "response": {"status_code": 204}}]
    assert client.post("/webhook/http-interactions", json=items).json()["stored"] == 1


def test_malformed_json_is_400(client):
    res = client.post("/webhook/http-interactions", content=b"{not json",
                      headers={"content-type": "application/json"})
    assert res.status_code == 400


def test_wrong_shape_is_422(client):
    res = client.post("/webhook/http-interactions", json={"interactions": "nope"})
    assert res.status_code == 422


def test_raw_events_endpoint(client):
    payload = {"session_id": "ev-1",
               "events": [{"function": "SSL_write", "pid": 1, "len": 10, "data": "x"}]}
    assert client.post("/webhook/events", json=payload).json()["stored"] == 1


def test_legacy_session_detail_404s_instead_of_200_with_an_error(client):
    assert client.get("/webhook/sessions/nope").status_code == 404


def test_legacy_sessions_list_keeps_its_shape(client):
    row = client.get("/webhook/sessions").json()[0]
    assert set(row) == {
        "session_id", "agent", "capture_start", "event_count", "interaction_count"
    }


def test_index_and_assets_are_served(client):
    assert client.get("/").status_code == 200
    assert "RailDash" in client.get("/").text
    assert client.get("/app.css").status_code == 200
    assert client.get("/app.js").status_code == 200


def test_no_captured_value_is_interpolated_into_the_page(client):
    """The shell is static; every captured value arrives as JSON and is set
    with textContent. If markup ever starts carrying data, this fails."""
    html = client.get("/").text
    assert "api.anthropic.com" not in html
    assert "771234567890" not in html


def test_the_front_end_never_assigns_markup(client):
    """Captured traffic is untrusted — an agent under prompt injection is the
    case this dashboard exists to inspect. Matching the bare word would also
    match the comment saying we avoid it, so this looks for the assignment."""
    js = client.get("/app.js").text
    for sink in ("innerHTML =", "outerHTML =", "insertAdjacentHTML", "document.write"):
        assert sink not in js, f"{sink} would render captured traffic as markup"
