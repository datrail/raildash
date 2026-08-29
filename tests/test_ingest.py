"""Normalisation, against RailMon's real output shape.

The fixture is not invented: it carries the fields `src/pipeline.rs` emits,
including the two that are routinely null in a real capture — a `request` that
was never decoded, and a `latency_ms` with no paired request to measure from.
Those are the cases that broke earlier integrations, so they are the ones with
tests.
"""

from pathlib import Path

from raildash.ingest import normalise, read_jsonl

FIXTURE = Path(__file__).parent / "fixtures" / "capture.jsonl"


def load():
    items, skipped = read_jsonl(str(FIXTURE))
    assert skipped == 0
    return items


def test_fixture_parses():
    assert len(load()) == 8


def test_host_and_path_from_headers():
    row = normalise(load()[0])
    assert row["host"] == "api.anthropic.com"
    assert row["path"] == "/v1/messages"
    assert row["method"] == "POST"
    assert row["status_code"] == 200


def test_absolute_request_uri_is_split():
    """A proxied request line carries the host in the path."""
    row = normalise(
        {
            "request": {
                "method": "get",
                "path": "https://api.example.com/v1/models?limit=5",
                "headers": {},
            },
            "response": {"status_code": 200},
        }
    )
    assert row["host"] == "api.example.com"
    assert row["path"] == "/v1/models?limit=5"
    assert row["method"] == "GET"


def test_http2_authority_is_used_when_there_is_no_host_header():
    row = normalise(
        {
            "request": {"method": "POST", "path": "/v1/messages",
                        "headers": {":authority": "api.anthropic.com"}},
            "response": {"status_code": 200},
        }
    )
    assert row["host"] == "api.anthropic.com"


def test_a_missing_request_does_not_raise():
    """Normal for a connection already open when the probe attached."""
    row = normalise(load()[7])
    assert row["method"] is None
    assert row["host"] is None
    assert row["status_code"] == 200


def test_null_latency_survives():
    row = normalise(load()[7])
    assert row["latency_ms"] is None


def test_tool_calls_are_counted():
    rows = [normalise(i) for i in load()]
    # Interaction 0 has one tool_use in the response, 2 has one in the request.
    assert rows[0]["tool_calls"] == 1
    assert rows[2]["tool_calls"] == 1
    assert rows[3]["tool_calls"] == 0


def test_model_is_extracted():
    assert normalise(load()[0])["model"] == "claude-sonnet-5"
    assert normalise(load()[3])["model"] is None


def test_ticket_presence_is_recorded_but_never_the_value():
    row = normalise(load()[0])
    assert row["has_ticket"] == 1
    # The row carries no column for it, and the only copy is inside `raw`,
    # which is the interaction exactly as RailMon emitted it.
    assert "x-rail" not in {k for k in row if k != "raw"}
    assert normalise(load()[3])["has_ticket"] == 0


def test_tool_call_counting_never_raises_on_hostile_shapes():
    """Bodies are attacker-influenced; this must degrade, not throw."""
    for body in (
        {"messages": "not-a-list"},
        {"messages": [None, 3, "x"]},
        {"messages": [{"content": [None, {"type": "tool_use"}]}]},
        {"choices": [{"message": {"tool_calls": "nope"}}]},
        {"choices": "no"},
    ):
        row = normalise({"request": {"method": "POST", "path": "/", "body": body},
                         "response": {"status_code": 200}})
        assert isinstance(row["tool_calls"], int)


def test_synthetic_id_is_stable_and_content_addressed():
    a = normalise(load()[0])["interaction_id"]
    b = normalise(load()[0])["interaction_id"]
    c = normalise(load()[1])["interaction_id"]
    assert a == b
    assert a != c


def test_railmon_interaction_id_is_preferred_when_present():
    row = normalise(
        {"interaction_id": "abc123", "request": {"method": "GET", "path": "/"},
         "response": {"status_code": 200}}
    )
    assert row["interaction_id"] == "abc123"


def test_a_truncated_final_line_is_skipped_not_fatal(tmp_path):
    path = tmp_path / "partial.jsonl"
    path.write_text('{"request":{"method":"GET","path":"/a"},"response":{}}\n{"req')
    items, skipped = read_jsonl(str(path))
    assert len(items) == 1
    assert skipped == 1


def test_a_webhook_envelope_in_the_file_is_unwrapped(tmp_path):
    path = tmp_path / "env.jsonl"
    path.write_text(
        '{"session_id":"s","interactions":['
        '{"request":{"method":"GET","path":"/a"},"response":{"status_code":200}},'
        '{"request":{"method":"GET","path":"/b"},"response":{"status_code":200}}]}\n'
    )
    items, skipped = read_jsonl(str(path))
    assert len(items) == 2
    assert skipped == 0
