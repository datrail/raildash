"""Collector heartbeat and authenticated captures (DR-184 M0).

The Data Guardrail's request rules read Held only while an authenticated
collector heartbeat is recent, and judge only captures that came with the
local write token (design §4.1, §4.3, §5). These tests pin RailDash's half
of that wire contract: the token-gated `POST /webhook/heartbeat`, the
`authenticated` mark on captures, and a schema change an older RailDash can
still open.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.cli import main
from raildash.ingest import normalise, read_jsonl
from raildash.store import SCHEMA, Store

FIXTURE = Path(__file__).parent / "fixtures" / "capture.jsonl"
HEARTBEAT = {
    "collector_id": "railmon-collect-1",
    "taps_attached": 2,
    "sent_at": "2026-10-10T12:00:00Z",
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = Store(tmp_path / "test.db")
    monkeypatch.setattr(app_module, "store", store)
    yield TestClient(app_module.app)
    store.close()


def auth():
    return {"X-RailDash-Token": app_module.LOCAL_TOKEN}


def captures(count: int = 2) -> list[dict]:
    items, _ = read_jsonl(str(FIXTURE))
    return items[:count]


def authenticated_flags(table: str = "interactions") -> list[int]:
    return [
        row[0]
        for row in app_module.store._db.execute(  # noqa: SLF001
            f"SELECT authenticated FROM {table} ORDER BY id"
        )
    ]


# ---------------------------------------------------------------- heartbeat


def test_a_heartbeat_with_the_token_is_stored_and_upserted(client):
    first = client.post("/webhook/heartbeat", json=HEARTBEAT, headers=auth())
    assert first.status_code == 200
    assert first.json() == {"status": "ok"}
    stored = app_module.store.collector_heartbeat("railmon-collect-1")
    assert stored["taps_attached"] == 2
    assert stored["sent_at"] == "2026-10-10T12:00:00Z"

    again = dict(HEARTBEAT, taps_attached=1, sent_at="2026-10-10T12:01:00+00:00")
    assert client.post("/webhook/heartbeat", json=again, headers=auth()).status_code == 200
    rows = app_module.store.collector_heartbeats()
    assert len(rows) == 1
    assert rows[0]["taps_attached"] == 1
    assert rows[0]["sent_at"] == "2026-10-10T12:01:00+00:00"
    assert rows[0]["last_heartbeat_at"] >= stored["last_heartbeat_at"]


def test_heartbeats_are_kept_per_collector_and_the_latest_is_the_newest(tmp_path):
    store = Store(tmp_path / "beats.db")
    assert store.latest_heartbeat_at() is None
    assert store.collector_heartbeat("a") is None
    store.record_heartbeat(
        "a", taps_attached=1, sent_at="x",
        received_at=datetime(2026, 10, 10, 12, 0, 0, 500_000, tzinfo=timezone.utc),
    )
    store.record_heartbeat(
        "b", taps_attached=1, sent_at="x",
        received_at=datetime(2026, 10, 10, 12, 0, 1, tzinfo=timezone.utc),
    )
    # Whole seconds stay fixed-width, so MAX() over the text is MAX() in time.
    assert store.latest_heartbeat_at() == "2026-10-10T12:00:01.000000Z"
    assert [row["collector_id"] for row in store.collector_heartbeats()] == ["b", "a"]
    store.close()


# A non-ASCII header (sent as raw bytes) once made `compare_digest` raise; it
# is just another wrong token.
NON_ASCII_TOKEN = {"X-RailDash-Token": "\u00e9".encode("latin-1")}


@pytest.mark.parametrize(
    "headers", [{}, {"X-RailDash-Token": "wrong-token-wrong-token"}, NON_ASCII_TOKEN]
)
def test_a_heartbeat_without_the_token_gets_the_same_403_as_other_token_routes(client, headers):
    res = client.post("/webhook/heartbeat", json=HEARTBEAT, headers=headers)
    gated = client.post("/api/asps/prune", headers=headers)
    assert res.status_code == gated.status_code == 403
    assert res.json() == gated.json() == {"detail": "missing or invalid X-RailDash-Token"}
    assert app_module.store.collector_heartbeats() == []


@pytest.mark.parametrize(
    "change",
    [
        {"collector_id": ""},
        {"collector_id": "x" * 129},
        {"collector_id": "tab\there"},
        {"collector_id": "caf\u00e9"},
        {"collector_id": 7},
        {"taps_attached": 0},
        {"taps_attached": -1},
        {"taps_attached": True},
        {"taps_attached": 1.0},
        {"taps_attached": "1"},
        {"taps_attached": 2**63},
        {"sent_at": "2026-10-10T12:00:00"},
        {"sent_at": "2026-10-10"},
        {"sent_at": "20261010T120000Z"},
        {"sent_at": "2026-13-10T12:00:00Z"},
        {"sent_at": "2026-02-30T12:00:00Z"},
        {"sent_at": "2026-10-10T12:00:00+24:00"},
        {"sent_at": 1791547200},
        {"extra": "field"},
    ],
)
def test_each_heartbeat_validation_rule_answers_422(client, change):
    res = client.post("/webhook/heartbeat", json={**HEARTBEAT, **change}, headers=auth())
    assert res.status_code == 422, change
    assert app_module.store.collector_heartbeats() == []


@pytest.mark.parametrize("missing", sorted(HEARTBEAT))
def test_a_heartbeat_missing_a_field_answers_422(client, missing):
    body = {key: value for key, value in HEARTBEAT.items() if key != missing}
    assert client.post("/webhook/heartbeat", json=body, headers=auth()).status_code == 422


@pytest.mark.parametrize(
    "change",
    [
        {"collector_id": "x"},
        {"collector_id": "x" * 128},
        {"collector_id": "host a/collect #1 ~"},
        {"taps_attached": 1},
        {"sent_at": "2026-10-10t12:00:00.123456789z"},
        {"sent_at": "2026-10-10T12:00:00.5-07:00"},
        {"sent_at": "2016-12-31T23:59:60Z"},
    ],
)
def test_the_edges_of_each_rule_are_accepted(client, change):
    res = client.post("/webhook/heartbeat", json={**HEARTBEAT, **change}, headers=auth())
    assert res.status_code == 200, (change, res.text)


def test_a_heartbeat_body_is_bounded_and_must_be_a_json_object(client):
    big = dict(HEARTBEAT, sent_at="2026-10-10T12:00:00." + "1" * 5_000 + "Z")
    assert client.post("/webhook/heartbeat", json=big, headers=auth()).status_code == 413
    assert client.post("/webhook/heartbeat", json=[HEARTBEAT], headers=auth()).status_code == 422
    plain = client.post(
        "/webhook/heartbeat",
        content=json.dumps(HEARTBEAT),
        headers={**auth(), "Content-Type": "text/plain"},
    )
    assert plain.status_code == 415


def test_liveness_is_raildashs_receive_time_never_sent_at(client):
    before = datetime.now(timezone.utc)
    future = dict(HEARTBEAT, sent_at="2099-01-01T00:00:00Z")
    assert client.post("/webhook/heartbeat", json=future, headers=auth()).status_code == 200
    after = datetime.now(timezone.utc)

    latest = app_module.store.latest_heartbeat_at()
    received = datetime.fromisoformat(latest.replace("Z", "+00:00"))
    assert before <= received <= after
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", latest)
    assert app_module.store.collector_heartbeat("railmon-collect-1")["sent_at"] == (
        "2099-01-01T00:00:00Z"
    )


# ----------------------------------------------------------------- captures


@pytest.mark.parametrize(
    "headers, expected",
    [
        (auth, 1),
        (lambda: {}, 0),
        (lambda: {"X-RailDash-Token": "wrong-token-wrong-token"}, 0),
        (lambda: NON_ASCII_TOKEN, 0),
    ],
)
def test_http_interactions_are_marked_by_their_token_and_never_refused(client, headers, expected):
    payload = {"session_id": "s", "agent": "a", "interactions": captures()}
    res = client.post("/webhook/http-interactions", json=payload, headers=headers())
    assert res.status_code == 200
    assert res.json() == {"received": 2, "stored": 2, "session_id": "s"}
    assert authenticated_flags() == [expected, expected]
    row_id = client.get("/api/interactions").json()["items"][0]["id"]
    assert app_module.store.interaction(row_id)["authenticated"] is bool(expected)


@pytest.mark.parametrize("headers, expected", [(auth, 1), (lambda: {}, 0)])
def test_raw_events_are_marked_by_their_token_too(client, headers, expected):
    payload = {"session_id": "s", "events": [{"function": "WRITE", "pid": 1, "len": 2}]}
    res = client.post("/webhook/events", json=payload, headers=headers())
    assert res.status_code == 200
    assert authenticated_flags("raw_events") == [expected]


def test_an_authenticated_delivery_replaces_a_forged_unauthenticated_copy(client):
    """A forger who posts first under the collector's dedup key must not get
    the real request dropped as a duplicate; the reverse must never happen."""
    real = captures(1)[0]
    forged = json.loads(json.dumps(real))
    forged["interaction_id"] = real["interaction_id"] = "same-dedup-key"
    forged["request"]["headers"]["host"] = "harmless.example"
    batch = lambda item: {"session_id": "s", "interactions": [item]}  # noqa: E731

    assert client.post("/webhook/http-interactions", json=batch(forged)).json()["stored"] == 1
    upgraded = client.post("/webhook/http-interactions", json=batch(real), headers=auth())
    assert upgraded.json()["stored"] == 1
    replayed = client.post("/webhook/http-interactions", json=batch(real), headers=auth())
    assert replayed.json()["stored"] == 0
    assert client.post("/webhook/http-interactions", json=batch(forged)).json()["stored"] == 0

    rows = app_module.store._db.execute(  # noqa: SLF001
        "SELECT id, host, authenticated FROM interactions"
    ).fetchall()
    assert [tuple(row) for row in rows] == [(1, "api.anthropic.com", 1)]


def test_a_replaced_forged_row_does_not_keep_its_session_first_seen(client):
    real = captures(1)[0]
    real["interaction_id"] = "same-dedup-key"
    real["timestamp"] = "2026-10-10T12:00:00Z"
    forged = dict(real, timestamp="2000-01-01T00:00:00Z")
    batch = lambda item: {"session_id": "s", "interactions": [item]}  # noqa: E731

    client.post("/webhook/http-interactions", json=batch(forged))
    assert client.get("/api/sessions").json()[0]["first_seen"] == "2000-01-01T00:00:00Z"
    client.post("/webhook/http-interactions", json=batch(real), headers=auth())
    session = client.get("/api/sessions").json()[0]
    assert session["first_seen"] == session["last_seen"] == "2026-10-10T12:00:00Z"


def test_open_read_routes_do_not_reveal_the_authenticated_mark(client):
    payload = {"session_id": "s", "interactions": captures()}
    client.post("/webhook/http-interactions", json=payload, headers=auth())
    listing = client.get("/api/interactions").json()
    detail = client.get(f"/api/interactions/{listing['items'][0]['id']}").json()
    session = client.get("/webhook/sessions/s").json()
    assert "authenticated" not in json.dumps([listing, detail, session])


def test_cli_load_is_stored_unauthenticated(tmp_path, capsys):
    db = tmp_path / "raildash.db"
    assert main(["--db", str(db), "load", str(FIXTURE)]) == 0
    capsys.readouterr()
    store = Store(db)
    flags = {row[0] for row in store._db.execute("SELECT authenticated FROM interactions")}  # noqa: SLF001
    assert flags == {0}
    assert store.interaction(1)["authenticated"] is False
    store.close()


# ------------------------------------------------------------------- schema

# The schema before DR-184 M0: no `authenticated` columns and no heartbeat
# table, the way `test_opening_a_pre_dr132_database_fills_in_content_kinds`
# rebuilds a pre-DR-132 one.
OLD_SCHEMA = re.sub(
    r"-- DR-184 M0:.*?\);\n",
    "",
    SCHEMA.replace("    authenticated  INTEGER NOT NULL DEFAULT 0,\n", "").replace(
        "    raw        TEXT NOT NULL,\n    authenticated INTEGER NOT NULL DEFAULT 0\n",
        "    raw        TEXT NOT NULL\n",
    ),
    flags=re.S,
)
# What a pre-M0 RailDash's `add_interactions`/`add_raw_events` write.
OLD_INTERACTION_INSERT = (
    "INSERT OR IGNORE INTO interactions (session_id, interaction_id, raw, content_kinds) "
    "VALUES (?, ?, ?, '')"
)
OLD_RAW_EVENT_INSERT = (
    "INSERT INTO raw_events (session_id, function, pid, len, raw) VALUES (?, ?, ?, ?, ?)"
)


def test_the_old_schema_really_predates_m0():
    assert "authenticated" not in OLD_SCHEMA
    assert "collector_heartbeats" not in OLD_SCHEMA
    assert "CREATE TABLE IF NOT EXISTS raw_events" in OLD_SCHEMA


def test_opening_a_pre_m0_database_adds_the_columns_and_marks_old_rows_unauthenticated(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript(OLD_SCHEMA)
    db.execute("PRAGMA user_version = 1")
    db.execute("INSERT INTO sessions (session_id) VALUES ('old')")
    db.execute(OLD_INTERACTION_INSERT, ("old", "i1", json.dumps(captures(1)[0])))
    db.execute(OLD_RAW_EVENT_INSERT, ("old", "WRITE", 1, 2, "{}"))
    db.commit()
    db.close()

    store = Store(path)
    assert store.interaction(1)["authenticated"] is False
    assert [row[0] for row in store._db.execute("SELECT authenticated FROM raw_events")] == [0]  # noqa: SLF001
    assert store.latest_heartbeat_at() is None
    store.record_heartbeat("c", taps_attached=1, sent_at="2026-10-10T12:00:00Z")
    assert store.latest_heartbeat_at() is not None
    assert not store._needs_upgrade()  # noqa: SLF001 - a second open is a no-op
    store.close()


def test_an_older_raildash_still_opens_and_writes_an_upgraded_database(tmp_path):
    """Additive only: the old schema script is a no-op on the new database,
    and the old INSERTs, which do not name the new column, still work and
    land as unauthenticated -- correctly, since the old process took no
    token."""
    path = tmp_path / "upgraded.db"
    store = Store(path)
    store.upsert_session("new")
    store.add_interactions("new", [normalise(captures(1)[0])], authenticated=True)
    store.record_heartbeat("c", taps_attached=1, sent_at="2026-10-10T12:00:00Z")
    store.close()

    old = sqlite3.connect(path)
    old.executescript(OLD_SCHEMA)
    old.execute("INSERT INTO sessions (session_id) VALUES ('from-old')")
    old.execute(OLD_INTERACTION_INSERT, ("from-old", "i1", "{}"))
    old.execute(OLD_RAW_EVENT_INSERT, ("from-old", "WRITE", 1, 2, "{}"))
    old.commit()
    # An old RailDash reads with explicit columns or `SELECT *`; both work.
    assert old.execute("SELECT * FROM interactions").fetchall()
    old.close()

    reopened = Store(path)
    flags = dict(
        reopened._db.execute("SELECT session_id, authenticated FROM interactions")  # noqa: SLF001
    )
    assert flags == {"new": 1, "from-old": 0}
    assert reopened.collector_heartbeat("c")["taps_attached"] == 1
    reopened.close()
