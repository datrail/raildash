from fastapi.testclient import TestClient

from webhook_server import app, sessions


client = TestClient(app)


def setup_function() -> None:
    sessions.clear()


def test_health_starts_empty() -> None:
    response = client.get("/webhook/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "sessions": 0}


def test_interaction_batch_appears_in_session_list() -> None:
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
    assert response.json() == {"received": 1, "session_id": "session-1"}
    listed = client.get("/webhook/sessions").json()
    assert listed[0]["session_id"] == "session-1"
    assert listed[0]["interaction_count"] == 1


def test_raw_event_batch_is_counted() -> None:
    response = client.post(
        "/webhook/events",
        json={"session_id": "session-2", "events": [{"function": "WRITE/SEND"}]},
    )

    assert response.status_code == 200
    assert client.get("/webhook/sessions/session-2").json()["event_count"] == 1
