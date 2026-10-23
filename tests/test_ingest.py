"""Normalisation, against RailMon's real output shape.

The fixture is not invented: it carries the fields `src/pipeline.rs` emits,
including the two that are routinely null in a real capture — a `request` that
was never decoded, and a `latency_ms` with no paired request to measure from.
Those are the cases that broke earlier integrations, so they are the ones with
tests.
"""

import json
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


def streamed(chunks, *, path="/v1beta/openai/chat/completions"):
    """A reply RailMon kept as raw event-stream text, as it stores any body
    that isn't one JSON value."""
    text = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n"
    return {
        "request": {"method": "POST", "path": path, "headers": {"host": "api.example.com"},
                    "body": {"model": "m", "messages": [], "stream": True}},
        "response": {"status_code": 200, "headers": {"content-type": "text/event-stream"},
                     "body": {"raw": text}},
    }


def gemini_call(call_id, name):
    """One Gemini chunk: the whole call, with its id and no index."""
    return {"choices": [{"index": 0, "finish_reason": "stop", "delta": {"role": "assistant",
            "tool_calls": [{"id": call_id, "type": "function",
                            "function": {"name": name, "arguments": "{}"}}]}}]}


def test_a_streamed_replys_tool_calls_are_counted():
    """DR-231: Kyle's OpenClaw run on Gemini showed `tool_calls: 0` on every
    row, though each stored stream held `choices[].delta.tool_calls`."""
    # OpenAI: the name on the first chunk of each call, then argument fragments.
    openai = [
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "c1", "function": {"name": "exec", "arguments": ""}}]}}]},
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": '{"cmd": "ls"}'}}]}}]},
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 1, "id": "c2", "function": {"name": "memory_search", "arguments": "{}"}}]}}]},
    ]
    assert normalise(streamed(openai))["tool_calls"] == 2
    # Gemini: two calls with no index, in one chunk or in two, stay two.
    assert normalise(streamed([gemini_call("f1", "exec"),
                               gemini_call("f2", "memory_search")]))["tool_calls"] == 2
    together = gemini_call("f1", "exec")
    together["choices"][0]["delta"]["tool_calls"] += gemini_call(
        "f2", "memory_search")["choices"][0]["delta"]["tool_calls"]
    assert normalise(streamed([together]))["tool_calls"] == 2
    anthropic = [
        {"type": "content_block_start", "index": 1,
         "content_block": {"type": "tool_use", "id": "t1", "name": "read_file", "input": {}}},
        {"type": "content_block_delta", "index": 1,
         "delta": {"type": "input_json_delta", "partial_json": '{"path": "a"}'}},
    ]
    assert normalise(streamed(anthropic, path="/v1/messages"))["tool_calls"] == 1
    text_only = [{"choices": [{"index": 0, "delta": {"content": "hi"}}]}]
    assert normalise(streamed(text_only))["tool_calls"] == 0


def test_a_raw_reply_that_is_not_a_stream_counts_nothing_and_never_raises():
    for text in ("<html>502</html>", "data: {not json\n\n", "data: [1, 2]\n\n",
                 'data: {"choices": [{"delta": {"tool_calls": [{"function": 3}]}}]}\n\n'):
        row = normalise({"request": {"method": "POST", "path": "/", "body": {}},
                         "response": {"status_code": 200, "body": {"raw": text}}})
        assert row["tool_calls"] == 0


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


def test_multi_agent_attribution_is_normalised():
    row = normalise({
        "runtime_identity_version": 1,
        "agent_ref": {"host_id": "h", "sandbox_name": "s", "agent_key": "planner"},
        "attribution": {"state": "attributed", "method": "process_target"},
        "request": {"method": "GET", "path": "/"},
    })
    assert (row["agent_host_id"], row["sandbox_name"], row["agent_key"]) == ("h", "s", "planner")
    assert row["attribution_state"] == "attributed"


def test_invalid_attributed_reference_fails_closed():
    row = normalise({
        "runtime_identity_version": 1,
        "agent_ref": {"host_id": "h", "agent_key": "planner"},
        "attribution": {"state": "attributed", "method": "process_target"},
    })
    assert row["agent_key"] is None
    assert row["attribution_state"] == "unknown"


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


def test_an_unattributed_row_keeps_its_reason_and_capturing_target():
    # Shaped like RailMon's keyed `conflict` output (railmon#36): the ticket
    # named a sibling, so no agent_ref, and the capturing tap is only a lead.
    row = normalise({
        "runtime_identity_version": 1,
        "agent_ref": None,
        "attribution": {
            "state": "conflict",
            "method": None,
            "reason": "TICKET_CLAIM_CONFLICT",
            "target_id": "executor",
            "process": {"pid": 42, "start_time_ticks": 7},
        },
        "request": {"method": "POST", "path": "/"},
    })
    assert row["attribution_state"] == "conflict"
    assert row["attribution_reason"] == "TICKET_CLAIM_CONFLICT"
    assert row["attribution_target"] == "executor"
    assert row["agent_key"] is None
    assert row["attribution_method"] is None


def test_an_unattributed_row_never_claims_a_method_or_an_agent():
    row = normalise({
        "runtime_identity_version": 1,
        "agent_ref": {"host_id": "h", "sandbox_name": "s", "agent_key": "planner"},
        "attribution": {"state": "ambiguous", "method": "process_target", "reason": "x" * 500},
    })
    assert row["agent_key"] is None
    assert row["attribution_method"] is None
    assert row["attribution_reason"] == "x" * 128


def test_an_attributed_row_with_no_reference_is_unknown_not_attributed():
    row = normalise({
        "runtime_identity_version": 1,
        "attribution": {"state": "attributed", "method": "process_target"},
    })
    assert row["attribution_state"] == "unknown"
    assert row["attribution_reason"] == "INCOMPLETE_AGENT_REF"
    assert row["agent_key"] is None


def test_a_runtime_interaction_is_read_from_the_exchange_it_nests():
    # RailMon's RuntimeInteraction envelope for a response-only row (an
    # HTTP/2 stream already open at attach): request is null in `raw`, and
    # the envelope only summarises. Everything but identity comes from `raw`.
    row = normalise({
        "interaction_id": "rt-1",
        "capture_source": "railmon",
        "timestamp": "2026-09-28T00:00:00+00:00",
        "request": {"method": "UNKNOWN", "path": "", "destination": "unknown"},
        "response": {"status": 200},
        "raw": {
            "timestamp_ns": 5,
            "pid": 42,
            "tid": 43,
            "request": None,
            "response": {
                "status_code": 200,
                "body": {"model": "claude-x", "content": [{"type": "tool_use", "name": "Bash"}]},
            },
            "response_size": 99,
        },
    })
    assert row["interaction_id"] == "rt-1"
    assert (row["status_code"], row["pid"], row["tid"], row["timestamp_ns"]) == (200, 42, 43, 5)
    assert row["response_size"] == 99
    assert row["model"] == "claude-x"
    assert row["tool_calls"] == 1
