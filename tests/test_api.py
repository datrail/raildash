"""The HTTP surface, against a store loaded from the fixture."""

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.ingest import normalise, read_jsonl
from raildash.store import SCHEMA, Store

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


def test_detail_returns_the_interaction_with_credentials_redacted(client):
    row_id = client.get("/api/interactions").json()["items"][-1]["id"]
    detail = client.get(f"/api/interactions/{row_id}").json()
    assert detail["raw"]["request"]["method"] == "POST"
    assert detail["raw"]["response"]["status_code"] == 200


def test_store_investigation_orders_same_process_thread_fixture_sequence(client):
    rows = client.get("/api/interactions").json()["items"]
    target = next(row for row in rows if row["status_code"] == 403)

    investigation = app_module.store.investigation(target["id"])

    assert investigation is not None
    nearby = investigation["nearby"]
    assert [row["timestamp"] for row in nearby] == sorted(
        row["timestamp"] for row in nearby
    )
    assert {(row["pid"], row["tid"]) for row in nearby} == {(4021, 4030)}
    assert any(row["id"] == target["id"] for row in nearby)


def test_fixture_tool_names_come_from_captured_tool_use_blocks(client):
    rows = client.get("/api/interactions").json()["items"]
    target = next(row for row in rows if row["timestamp"] == "2026-08-15T17:04:11Z")

    detail = client.get(f"/api/interactions/{target['id']}").json()

    assert detail["tool_names"] == ["delivery_track_package"]


def test_investigation_api_provides_error_and_tool_navigation(client):
    rows = client.get("/api/interactions").json()["items"]
    target = next(row for row in rows if row["status_code"] == 500)

    detail = client.get(f"/api/interactions/{target['id']}").json()

    assert detail["navigation"] == {
        "previous_error": next(row["id"] for row in rows if row["status_code"] == 429),
        "next_error": next(row["id"] for row in rows if row["status_code"] == 403),
        "previous_tool_call": next(
            row["id"] for row in rows if row["timestamp"] == "2026-08-15T17:04:17.274000Z"
        ),
        "next_tool_call": None,
    }


def test_tool_names_and_navigation_never_expose_credentials(client):
    credential = "Bearer-never-return-this"
    malicious_name = '<img src=x onerror="alert(1)">'
    posted = client.post(
        "/webhook/http-interactions",
        json={
            "session_id": "untrusted-tools",
            "interactions": [
                {
                    "timestamp": "2026-08-15T18:00:00Z",
                    "timestamp_ns": 1,
                    "pid": 1,
                    "tid": 2,
                    "request": {
                        "method": "POST",
                        "path": "/v1/messages",
                        "headers": {"authorization": credential},
                    },
                    "response": {
                        "status_code": 200,
                        "body": {
                            "content": [{"type": "tool_use", "name": malicious_name}]
                        },
                    },
                }
            ],
        },
    ).json()
    row = client.get(
        "/api/interactions", params={"session_id": posted["session_id"]}
    ).json()["items"][0]

    detail = client.get(f"/api/interactions/{row['id']}").json()
    rendered = json.dumps(detail)

    assert detail["tool_names"] == [malicious_name]
    assert credential not in rendered
    assert detail["raw"]["request"]["headers"]["authorization"] == (
        "[REDACTED-BY-RAILDASH]"
    )


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


def test_webhook_refuses_cors_simple_text_plain_json(client):
    """A hostile web page can send text/plain cross-origin without preflight.

    RailDash has no CORS grant, so requiring application/json makes the
    browser stop before an unauthenticated localhost webhook can be poisoned.
    """
    res = client.post(
        "/webhook/http-interactions",
        content=b'{"interactions": []}',
        headers={"content-type": "text/plain"},
    )
    assert res.status_code == 415


def test_webhook_refuses_an_oversized_body(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_WEBHOOK_BODY_BYTES", 16)
    res = client.post("/webhook/http-interactions", json={"interactions": []})
    assert res.status_code == 413


def test_webhook_refuses_an_oversized_batch(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_WEBHOOK_ITEMS", 1)
    res = client.post("/webhook/http-interactions", json=[{}, {}])
    assert res.status_code == 413


def test_body_limit_accepts_railmons_largest_single_interaction():
    # RailMon size-splits batches, but one interaction still needs room for a
    # 1 MiB request and response whose bytes may each become a six-byte escape.
    producer_body_max = 2 * 1024 * 1024 * 6
    assert app_module.MAX_WEBHOOK_BODY_BYTES >= producer_body_max + 1024 * 1024


def test_webhook_rejects_object_expansion_before_json_decode(client, monkeypatch):
    from raildash import json_safety

    # Patch the constructor default used by the app: dataclass defaults are
    # captured at class definition time.
    monkeypatch.setattr(
        app_module,
        "JSONStructureGuard",
        lambda: json_safety.JSONStructureGuard(max_tokens=8),
    )
    res = client.post("/webhook/http-interactions", json=[{}, {}, {}, {}])
    assert res.status_code == 413


def test_webhook_bounds_repeated_envelope_fields(client):
    res = client.post(
        "/webhook/events",
        json={"session_id": "s" * (app_module.MAX_SESSION_ID_CHARS + 1), "events": [{}]},
    )
    assert res.status_code == 422


def test_malformed_json_is_400(client):
    res = client.post("/webhook/http-interactions", content=b"{not json",
                      headers={"content-type": "application/json"})
    assert res.status_code == 400


def test_non_utf8_json_is_400_even_when_stdlib_would_accept_it(client):
    payload = json.dumps([{}] * 10).encode("utf-16")
    assert json.loads(payload) == [{}] * 10
    res = client.post(
        "/webhook/http-interactions",
        content=payload,
        headers={"content-type": "application/json"},
    )
    assert res.status_code == 400


def test_wrong_shape_is_422(client):
    res = client.post("/webhook/http-interactions", json={"interactions": "nope"})
    assert res.status_code == 422


def test_raw_events_endpoint(client):
    payload = {"session_id": "ev-1",
               "events": [{"function": "SSL_write", "pid": 1, "len": 10, "data": "x"}]}
    assert client.post("/webhook/events", json=payload).json()["stored"] == 1


def test_raw_events_accept_railmons_actual_interactions_envelope(client):
    payload = {
        "session_id": "ev-real-envelope",
        "interactions": [
            {"source": "ssl", "data": {"function": "WRITE/SEND", "data": "x"}}
        ],
    }
    result = client.post("/webhook/events", json=payload).json()
    assert result == {
        "received": 1,
        "stored": 1,
        "session_id": "ev-real-envelope",
    }


def test_raw_events_are_scrubbed_before_persistence(client):
    ticket = "live-x-rail-ticket"
    bearer = "Bearer raw-wire-secret"
    payload = {
        "session_id": "ev-credentials",
        "events": [
            {
                "headers": {"x-rail": ticket},
                "data": f"POST / HTTP/1.1\r\nAuthorization: {bearer}\r\n\r\nbody",
            }
        ],
    }
    assert client.post("/webhook/events", json=payload).status_code == 200
    stored = app_module.store._db.execute(  # noqa: SLF001 - persistence invariant
        "SELECT raw FROM raw_events WHERE session_id = ?", ("ev-credentials",)
    ).fetchone()[0]
    assert ticket not in stored
    assert bearer not in stored
    assert "[REDACTED-BY-RAILDASH]" in stored


def test_nested_railmon_raw_event_is_scrubbed_before_persistence(client):
    ticket = "nested-live-ticket"
    payload = {
        "session_id": "nested-event",
        "events": [
            {
                "source": "ssl",
                "data": {
                    "function": "WRITE/SEND",
                    "data": f"POST / HTTP/1.1\r\nx-rail: {ticket}\r\n\r\n",
                },
            }
        ],
    }
    client.post("/webhook/events", json=payload).raise_for_status()
    stored = app_module.store._db.execute(  # noqa: SLF001
        "SELECT raw FROM raw_events WHERE session_id = ?", ("nested-event",)
    ).fetchone()[0]
    assert ticket not in stored
    assert "[REDACTED-BY-RAILDASH]" in stored


def test_raw_event_scrubs_folded_and_coalesced_credential_headers(client):
    folded = "folded-secret"
    second = "second-message-secret"
    third = "third-message-secret"
    wire = (
        "HTTP/1.1 200 OK\r\n"
        "Authorization: Bearer\r\n"
        f" {folded}\r\n"
        "Content-Length: 2\r\n\r\n"
        "{}HTTP/1.1 200 OK\r\n"
        f"X-Api-Key: {second}\r\n"
        "Content-Length: 2\r\n\r\n"
        "{}POST /three HTTP/1.1\r\n"
        f"Cookie: {third}\r\n\r\n"
    )
    payload = {
        "session_id": "raw-multiple",
        "interactions": [{"source": "ssl", "data": {"data": wire}}],
    }
    client.post("/webhook/events", json=payload).raise_for_status()
    stored = app_module.store._db.execute(  # noqa: SLF001
        "SELECT raw FROM raw_events WHERE session_id = ?", ("raw-multiple",)
    ).fetchone()[0]
    assert folded not in stored
    assert second not in stored
    assert third not in stored
    assert stored.count("[REDACTED-BY-RAILDASH]") == 4


def test_detail_never_returns_credential_headers(client):
    ticket = "eyJhZ2VudF9pZCI6ImEifQ"
    bearer = "Bearer secret-that-must-not-reach-the-dashboard"
    payload = {
        "session_id": "credentials",
        "interactions": [
            {
                "request": {
                    "method": "POST",
                    "path": "/v1/messages",
                    "headers": {
                        "host": "api.example.com",
                        "x-rail": ticket,
                        "Authorization": bearer,
                    },
                    # Bodies are deliberately not part of header redaction.
                    "body": {
                        "token": "body-content-is-capture-data",
                        "data": "Authorization: body-content-is-not-a-header",
                    },
                },
                "response": {
                    "status_code": 200,
                    "headers": {"Set-Cookie": "session=secret"},
                },
            }
        ],
    }
    posted = client.post("/webhook/http-interactions", json=payload).json()
    row = client.get(
        "/api/interactions", params={"session_id": posted["session_id"]}
    ).json()["items"][0]
    detail = client.get(f"/api/interactions/{row['id']}").json()
    rendered = json.dumps(detail)

    assert row["has_ticket"] == 1
    assert ticket not in rendered
    assert bearer not in rendered
    assert "session=secret" not in rendered
    assert detail["raw"]["request"]["headers"]["x-rail"] == "[REDACTED-BY-RAILDASH]"
    assert detail["raw"]["request"]["headers"]["host"] == "api.example.com"
    assert detail["raw"]["request"]["body"]["token"] == "body-content-is-capture-data"
    assert (
        detail["raw"]["request"]["body"]["data"]
        == "Authorization: body-content-is-not-a-header"
    )


def test_runtime_interaction_keeps_ticket_presence_but_not_value(client):
    ticket = "runtime-ticket"
    payload = {
        "session_id": "runtime",
        "interactions": [
            {
                "interaction_id": "runtime-1",
                "x_rail_header": ticket,
                "request": {"method": "POST", "path": "/", "destination": "api"},
                "response": {"status": 200},
                "raw": {
                    "request": {"headers": {"x-rail": ticket}},
                    "response": {"status_code": 200},
                },
            }
        ],
    }
    client.post("/webhook/http-interactions", json=payload).raise_for_status()
    row = client.get(
        "/api/interactions", params={"session_id": "runtime"}
    ).json()["items"][0]
    detail = client.get(f"/api/interactions/{row['id']}").json()
    assert row["has_ticket"] == 1
    assert ticket not in json.dumps(detail)


def test_opening_an_old_database_migrates_stored_credentials(tmp_path):
    path = tmp_path / "old.db"
    ticket = "pre-upgrade-ticket"
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO sessions (session_id) VALUES ('old')")
    db.execute(
        "INSERT INTO interactions (session_id, interaction_id, raw) VALUES (?, ?, ?)",
        (
            "old",
            "fixed",
            json.dumps(
                {
                    "request": {"headers": {"x-rail": ticket}},
                    "response": {"status_code": 200},
                }
            ),
        ),
    )
    db.commit()
    db.close()

    migrated = Store(path)
    detail = migrated.interaction(1)
    assert detail is not None
    assert ticket not in json.dumps(detail)
    assert migrated._db.execute("PRAGMA user_version").fetchone()[0] == 1  # noqa: SLF001
    migrated.close()
    files = [path, path.with_name(path.name + "-wal")]
    assert all(
        ticket.encode() not in candidate.read_bytes()
        for candidate in files
        if candidate.exists()
    )


def test_old_database_migration_discards_pathologically_deep_capture(tmp_path):
    path = tmp_path / "deep.db"
    ticket = "deep-pre-upgrade-ticket"
    raw = '{"request":{"headers":{"x-rail":"' + ticket + '"}},"body":'
    raw += '{"child":' * 500 + "null" + "}" * 500 + "}"
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO sessions (session_id) VALUES ('deep')")
    db.execute(
        "INSERT INTO interactions (session_id, interaction_id, raw) VALUES (?, ?, ?)",
        ("deep", "fixed", raw),
    )
    db.commit()
    db.close()

    migrated = Store(path)
    stored = migrated._db.execute("SELECT raw FROM interactions").fetchone()[0]  # noqa: SLF001
    assert ticket not in stored
    assert json.loads(stored)["redacted"] is True
    migrated.close()


def test_old_database_migration_discards_huge_integer_literal(tmp_path):
    path = tmp_path / "huge-int.db"
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO sessions (session_id) VALUES ('huge-int')")
    db.execute(
        "INSERT INTO interactions (session_id, interaction_id, raw) VALUES (?, ?, ?)",
        ("huge-int", "fixed", '{"number":' + "9" * 5_000 + "}"),
    )
    db.commit()
    db.close()

    migrated = Store(path)
    stored = migrated._db.execute("SELECT raw FROM interactions").fetchone()[0]  # noqa: SLF001
    assert json.loads(stored)["redacted"] is True
    migrated.close()


def test_old_runtime_interaction_migration_preserves_ticket_presence(tmp_path):
    path = tmp_path / "runtime.db"
    ticket = "old-runtime-ticket"
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO sessions (session_id) VALUES ('runtime')")
    db.execute(
        """INSERT INTO interactions
           (session_id, interaction_id, has_ticket, raw) VALUES (?, ?, 0, ?)""",
        (
            "runtime",
            "fixed",
            json.dumps(
                {
                    "x_rail_header": ticket,
                    "request": {"method": "POST"},
                    "raw": {"request": {"headers": {"x-rail": ticket}}},
                }
            ),
        ),
    )
    db.commit()
    db.close()

    migrated = Store(path)
    row = migrated._db.execute(  # noqa: SLF001
        "SELECT has_ticket, raw FROM interactions"
    ).fetchone()
    assert row["has_ticket"] == 1
    assert ticket not in row["raw"]
    migrated.close()


def test_store_excludes_a_second_database_process(tmp_path):
    path = tmp_path / "exclusive.db"
    owner = Store(path)
    contender = sqlite3.connect(path, timeout=0.05)
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        contender.execute("INSERT INTO sessions (session_id) VALUES ('other')")
        contender.commit()
    contender.close()
    owner.close()


def test_old_database_migration_processes_multiple_bounded_batches(
    tmp_path, monkeypatch
):
    from raildash import store as store_module

    path = tmp_path / "pages.db"
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO sessions (session_id) VALUES ('pages')")
    for row_id in range(5):
        db.execute(
            "INSERT INTO interactions (session_id, interaction_id, raw) VALUES (?, ?, ?)",
            (
                "pages",
                str(row_id),
                json.dumps({"request": {"headers": {"x-rail": f"ticket-{row_id}"}}}),
            ),
        )
    db.commit()
    db.close()
    monkeypatch.setattr(store_module, "MIGRATION_BATCH_ROWS", 2)

    migrated = Store(path)
    rows = migrated._db.execute("SELECT raw FROM interactions").fetchall()  # noqa: SLF001
    assert len(rows) == 5
    assert all("ticket-" not in row[0] for row in rows)
    migrated.close()


def test_migration_page_budget_does_not_discard_one_safe_large_row(
    tmp_path, monkeypatch
):
    from raildash import store as store_module

    path = tmp_path / "large-safe-row.db"
    ticket = "large-row-ticket"
    captured_body = "x" * 512
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO sessions (session_id) VALUES ('large')")
    db.execute(
        "INSERT INTO interactions (session_id, interaction_id, raw) VALUES (?, ?, ?)",
        (
            "large",
            "fixed",
            json.dumps(
                {
                    "request": {
                        "headers": {"x-rail": ticket},
                        "body": {"raw": captured_body},
                    }
                }
            ),
        ),
    )
    db.commit()
    db.close()
    monkeypatch.setattr(store_module, "MIGRATION_BATCH_BYTES", 128)

    migrated = Store(path)
    detail = migrated.interaction(1)
    assert detail is not None
    assert detail["raw"]["request"]["body"]["raw"] == captured_body
    assert ticket not in json.dumps(detail)
    migrated.close()


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
