"""The compatibility surface of `webhook_server:app`.

This file used to test the demo server directly, including its module-level
`sessions` dict. That dict is gone — the dashboard persists to SQLite now — so
what is worth pinning is the contract an existing deployment actually depends
on: the entry point resolves, the routes keep their paths, and RailMon's
envelope is still accepted at the same URL.
"""

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.store import Store

import webhook_server


@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = Store(tmp_path / "compat.db")
    monkeypatch.setattr(app_module, "store", store)
    yield TestClient(webhook_server.app)
    store.close()


def test_the_documented_entry_point_still_resolves():
    """`uvicorn webhook_server:app` is in the old README, the old Dockerfile
    CMD and openapi.yaml. It has to keep working."""
    assert webhook_server.app is app_module.app


def test_health_starts_empty(client):
    response = client.get("/webhook/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "sessions": 0}


def test_interaction_batch_appears_in_session_list(client):
    payload = {
        "session_id": "session-1",
        "agent": "openclaw",
        "interactions": [
            {
                "request": {"method": "POST", "path": "/mcp", "body": {}},
                "response": {"status_code": 200},
                "latency_ms": 12.5,
            }
        ],
    }

    response = client.post("/webhook/http-interactions", json=payload)

    assert response.status_code == 200
    # `received` is unchanged; `stored` is additive and distinguishes a first
    # delivery from a retry.
    assert response.json() == {"received": 1, "stored": 1, "session_id": "session-1"}

    listed = client.get("/webhook/sessions").json()
    assert listed[0]["session_id"] == "session-1"
    assert listed[0]["interaction_count"] == 1
    assert listed[0]["agent"] == "openclaw"


def test_raw_event_batch_is_counted(client):
    response = client.post(
        "/webhook/events",
        json={"session_id": "session-2", "events": [{"function": "WRITE/SEND"}]},
    )
    assert response.status_code == 200
    assert client.get("/webhook/sessions/session-2").json()["event_count"] == 1
