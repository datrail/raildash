"""REST uploads M2c: each stored request's body kind (`body_kind`), the
design's one-time pass over rows stored before it, and *Bytes sent per
host* split by kind in the observed profile (design §4 "What's stored",
"Shown")."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from raildash.store import SCHEMA, Store


def _iso(when: datetime) -> str:
    return when.isoformat().replace("+00:00", "Z")


def _request(host: str, body, *, path: str = "/v1/query", method: str = "POST",
             content_type: str = "application/json", when: datetime | None = None) -> dict:
    text = body if isinstance(body, str) else json.dumps(body)
    headers = {"host": host}
    if body is not None:
        headers.update({"content-type": content_type, "content-length": str(len(text.encode()))})
    return {
        "timestamp": _iso(when or datetime.now(timezone.utc)),
        "request": {"method": method, "path": path, "headers": headers, "body": body},
        "response": {"status_code": 200},
        "request_size": (len(text.encode()) if body is not None else 0) + 100,
    }


QUERY = {"q": "invoices 2026", "limit": 20}
FILE = {"name": "export.csv", "rows": ["x" * 100] * 200}
MODEL = {"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]}
DEEP = {"filter": {"a": {"b": {"c": {"d": 1}}}}}


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "kinds.db")
    yield db
    db.close()


def _kinds(store: Store) -> dict[str, str]:
    return {row[0]: row[1] for row in store._db.execute(  # noqa: SLF001
        "SELECT path, body_kind FROM interactions")}


def test_each_request_is_stored_with_its_body_kind(store):
    from raildash.ingest import normalise
    store.upsert_session("s")
    store.add_interactions("s", [normalise(item) for item in (
        _request("api.search.example", QUERY, path="/q"),
        _request("files.example", FILE, path="/files"),
        _request("files.example", "PK\x03\x04", path="/zip", content_type="application/zip"),
        _request("api.anthropic.com", MODEL, path="/v1/messages"),
        _request("api.search.example", DEEP, path="/deep"),
        _request("api.search.example", None, path="/get", method="GET"),
    )])
    assert _kinds(store) == {
        "/q": "parameters", "/files": "upload", "/zip": "upload",
        "/v1/messages": "traffic", "/deep": "unknown", "/get": "",
    }


def test_bytes_sent_per_host_are_split_by_kind(store):
    from raildash.ingest import normalise
    store.upsert_session("s")
    rows = [normalise(item) for item in (
        _request("api.search.example", QUERY, path="/q"),
        _request("api.search.example", QUERY, path="/q2"),
        _request("api.search.example", FILE, path="/files"),
        _request("api.search.example", None, path="/get", method="GET"),
    )]
    store.add_interactions("s", rows)
    [host] = store.observed_profile("s")["observed"]["upload_bytes"]
    sizes = [row["request_size"] for row in rows]
    assert host["total_bytes"] == sum(sizes)
    assert host["by_kind"] == {"upload": sizes[2], "parameters": sizes[0] + sizes[1], "no_body": sizes[3]}
    assert list(host["by_kind"]) == ["upload", "parameters", "no_body"]  # the order shown


def test_the_one_time_pass_classifies_the_last_day_and_leaves_older_rows(tmp_path):
    path = tmp_path / "old.db"
    old_schema = SCHEMA.replace("    body_kind      TEXT,\n", "")
    db = sqlite3.connect(path)
    db.executescript(old_schema)
    assert "body_kind" not in {row[1] for row in db.execute("PRAGMA table_info(interactions)")}
    db.execute("INSERT INTO sessions (session_id) VALUES ('old')")
    now = datetime.now(timezone.utc)
    for interaction_id, item in (
        ("recent-query", _request("api.search.example", QUERY, path="/q", when=now - timedelta(hours=2))),
        ("recent-file", _request("files.example", FILE, path="/files", when=now - timedelta(hours=23))),
        ("old-query", _request("api.search.example", QUERY, path="/old", when=now - timedelta(days=3))),
        ("no-time", {**_request("api.search.example", QUERY, path="/none"), "timestamp": None}),
    ):
        db.execute(
            "INSERT INTO interactions (session_id, interaction_id, timestamp, host, path, request_size, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("old", interaction_id, item["timestamp"], item["request"]["headers"]["host"],
             item["request"]["path"], item["request_size"], json.dumps(item)),
        )
    db.commit()
    db.close()

    store = Store(path)
    try:
        # Older rows (and one with no readable time) aren't rewritten: NULL
        # is shown as not classified.
        assert _kinds(store) == {"/q": "parameters", "/files": "upload", "/old": None, "/none": None}
        by_host = {h["value"]: h["by_kind"] for h in store.observed_profile("old")["observed"]["upload_bytes"]}
        assert set(by_host["api.search.example"]) == {"parameters", "unclassified"}
        assert set(by_host["files.example"]) == {"upload"}
        assert not store._needs_upgrade()  # noqa: SLF001
    finally:
        store.close()
    # Done once: a later open doesn't take the upgrade path again, even with
    # NULL rows still stored, or rows an older RailDash wrote since.
    db = sqlite3.connect(path)
    db.execute("INSERT INTO interactions (session_id, interaction_id, timestamp, raw) VALUES "
               "('old', 'older-writer', ?, '{}')", (_iso(datetime.now(timezone.utc)),))
    db.commit()
    db.close()
    store = Store(path)
    try:
        assert not store._needs_upgrade()  # noqa: SLF001
        assert _kinds(store)["/old"] is None
    finally:
        store.close()


def test_normalise_classifies_so_ingest_doesnt_parse_the_capture_again(store, monkeypatch):
    from raildash import store as store_module
    from raildash.ingest import normalise
    row = normalise(_request("files.example", FILE, path="/files"))
    assert row["body_kind"] == "upload"
    monkeypatch.setattr(store_module, "body_kind_value", lambda row: pytest.fail("parsed again"))
    store.upsert_session("s")
    store.add_interactions("s", [row])
    assert _kinds(store) == {"/files": "upload"}


@pytest.mark.parametrize("length", [None, ["0"], "abc", "5"])
def test_carries_body_reads_content_length_as_the_guardrail_always_has(length):
    from raildash import body_kinds as bk
    from raildash import guardrail as g
    request = {"method": "POST", "headers": {"host": "h.example", "content-length": length}, "body": None}
    # Anything but a readable zero or no header says a body was framed.
    assert bk.request_carries_body(request) is True
    assert g.carries_body({"raw": json.dumps({"request": request, "response": {}})}) is True


def test_a_row_without_a_kind_is_classified_from_its_raw(store):
    from raildash.ingest import normalise
    row = normalise(_request("api.search.example", QUERY, path="/q"))
    del row["body_kind"]
    store.upsert_session("s")
    store.add_interactions("s", [row])
    assert _kinds(store) == {"/q": "parameters"}
