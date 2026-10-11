"""DR-205 M1: tool calls and data-action rows (data-actions design §4.3)."""

from __future__ import annotations

import base64
import json

from raildash import tool_calls as tc
from raildash.data_actions_store import UNREADABLE_TOOL
from raildash.ingest import normalise
from raildash.store import Store

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64).decode()
UPLOAD_SCHEMA = {"type": "object", "properties": {
    "path": {"type": "string"}, "content": {"type": "string", "contentEncoding": "base64"},
    "repo": {"type": "string"}}}
READ_SCHEMA = {"type": "object", "properties": {"doc_id": {"type": "string"}}}

_counter = iter(range(10**6))


def exchange(host, path, request_body, response_body=None, *, response_headers=None, method="POST",
             request_headers=None):
    return {
        "interaction_id": f"i{next(_counter)}",
        "timestamp": "2026-10-11T07:00:00Z",
        "request": {"method": method, "path": path,
                    "headers": {"host": host, **(request_headers or {})}, "body": request_body},
        "response": {"status_code": 200,
                     "headers": response_headers or {"content-type": "application/json"},
                     "body": response_body if response_body is not None else {}},
    }


def stored(item):
    return {"raw": json.dumps(item)}


TOOLS = [{"name": "mcp__docs__upload_file", "description": "Upload a file.", "input_schema": UPLOAD_SCHEMA},
         {"name": "mcp__docs__read_doc", "description": "Read one doc.", "input_schema": READ_SCHEMA}]


def model_turn(reply, *, headers=None):
    return exchange("api.anthropic.com", "/v1/messages",
                    {"model": "m", "messages": [], "tools": TOOLS}, reply, response_headers=headers)


def test_a_requested_call_carries_its_size_kind_destination_and_undeclared_arguments():
    item = model_turn({"content": [{"type": "tool_use", "id": "t1", "name": "mcp__docs__upload_file",
                                    "input": {"path": "a.png", "content": PNG, "repo": "me/private",
                                              "extra": "x"}}]})
    [call] = tc.extract_tool_calls(stored(item))["calls"]
    assert call["class"] == tc.REQUESTED and call["tool"] == "mcp__docs__upload_file"
    assert call["content_kinds"] == ["image"]
    assert call["destination"] == {"repo": "me/private"}
    assert call["undeclared"] == ["extra"]
    assert call["schema_known"] and call["arguments_bytes"] > len(PNG)


def test_streamed_anthropic_and_openai_calls_are_reassembled():
    args = json.dumps({"doc_id": "d1"})
    sse = (
        "event: content_block_start\ndata: " + json.dumps({"type": "content_block_start", "index": 1,
            "content_block": {"type": "tool_use", "id": "t", "name": "mcp__docs__read_doc", "input": {}}}) + "\n\n"
        "event: content_block_delta\ndata: " + json.dumps({"type": "content_block_delta", "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": args[:5]}}) + "\n\n"
        "event: content_block_delta\ndata: " + json.dumps({"type": "content_block_delta", "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": args[5:]}}) + "\n\n"
    )
    [call] = tc.extract_tool_calls(stored(model_turn(
        {"raw": sse}, headers={"content-type": "text/event-stream"})))["calls"]
    assert call["tool"] == "mcp__docs__read_doc" and call["streamed"]
    assert call["undeclared"] == [] and call["arguments_bytes"] == len(json.dumps({"doc_id": "d1"}, ensure_ascii=False))

    chat_sse = "".join(
        "data: " + json.dumps({"choices": [{"delta": {"tool_calls": [part]}}]}) + "\n\n"
        for part in ({"index": 0, "function": {"name": "read_doc", "arguments": '{"doc'}},
                     {"index": 0, "function": {"arguments": '_id": "d1", "x": 1}'}})
    ) + "data: [DONE]\n\n"
    chat = exchange("api.openai.com", "/v1/chat/completions", {
        "model": "m", "messages": [], "tools": [{"type": "function", "function": {
            "name": "read_doc", "parameters": READ_SCHEMA}}]},
        {"raw": chat_sse}, response_headers={"content-type": "text/event-stream"})
    [call] = tc.extract_tool_calls(stored(chat))["calls"]
    assert call["tool"] == "read_doc" and call["undeclared"] == ["x"]


def test_responses_and_provider_side_calls():
    reply = {"output": [
        {"type": "function_call", "name": "read_doc", "arguments": json.dumps({"doc_id": "d"})},
        {"type": "mcp_call", "name": "upload_file", "server_label": "Docs Hub",
         "arguments": json.dumps({"content": PNG})},
    ]}
    item = exchange("api.openai.com", "/v1/responses", {"model": "m", "input": "hi"}, reply)
    calls = {c["tool"]: c for c in tc.extract_tool_calls(stored(item))["calls"]}
    assert set(calls) == {"read_doc", "provider-mcp__Docs_Hub__upload_file"}
    assert not calls["read_doc"]["schema_known"]
    assert calls["provider-mcp__Docs_Hub__upload_file"]["content_kinds"] == ["image"]
    anthropic = model_turn({"content": [{"type": "mcp_tool_use", "name": "search", "server_name": "drive",
                                         "input": {"q": "x"}}]})
    [call] = tc.extract_tool_calls(stored(anthropic))["calls"]
    assert call["tool"] == "provider-mcp__drive__search"


def mcp_call(body, path="/mcp", host="docs.example.com"):
    return exchange(host, path, body)


def test_observed_tools_call_and_a_non_jsonrpc_post_is_reported():
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "upload_file", "arguments": {"content": PNG}}},
             {"jsonrpc": "2.0", "method": "notifications/initialized"}]
    [call] = tc.extract_tool_calls(stored(mcp_call(batch)))["calls"]
    assert call["class"] == tc.OBSERVED and call["endpoint"] == "docs.example.com/mcp"
    garbage = mcp_call({"raw": "\x00\x01 not json"})
    result = tc.extract_tool_calls({**stored(garbage), "request_size": 4_000_000})
    assert result["calls"] == []
    assert result["mcp_post_unreadable"] == {"endpoint": "docs.example.com/mcp", "request_size": 4_000_000}
    # The transport's own GET carries no call and isn't reported.
    get = exchange("docs.example.com", "/mcp", None, method="GET")
    assert tc.extract_tool_calls(stored(get)) == {"calls": [], "mcp_post_unreadable": None}


def test_hostile_shapes_do_not_raise():
    for reply in ({"content": "x"}, {"content": [None, {"type": "tool_use"}]}, {"choices": [{"message": 5}]},
                  {"output": [{"type": "mcp_call", "name": "x"}]}, {"raw": "data: {\n\n"}):
        tc.extract_tool_calls(stored(model_turn(reply)))
    assert tc.content_kinds({"a": "not base64!!"}) == []
    assert tc.undeclared_arguments({"a": 1}, {"type": "object", "additionalProperties": True}) == []


# ------------------------------------------------------------------ store


LISTING = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
    {"name": "read_doc", "description": "Read one doc.", "inputSchema": READ_SCHEMA,
     "annotations": {"readOnlyHint": True}},
    {"name": "upload_file", "description": "Upload a file.", "inputSchema": UPLOAD_SCHEMA}]}}


def new_store(tmp_path):
    store = Store(tmp_path / "r.db")
    store.upsert_session("s1", agent="agent", source="test")
    return store


def add(store, item, authenticated=True):
    store.add_interactions("s1", [normalise(item)], authenticated=authenticated)


def test_the_kubecon_scenario_rows(tmp_path):
    store = new_store(tmp_path)
    add(store, exchange("docs.example.com", "/mcp",
                        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, LISTING))
    for _ in range(3):
        add(store, mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": {"name": "read_doc", "arguments": {"doc_id": "d1"}}}))
    add(store, mcp_call({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "upload_file",
                                    "arguments": {"path": "x.png", "content": PNG, "repo": "pub/leak"}}}))
    add(store, mcp_call({"raw": "garbage"}))
    rows = store.data_action_rows(["session:s1"])
    by_tool = {row["tool"]: row for row in rows}
    assert [row["tool"] for row in rows][0] in ("upload_file", UNREADABLE_TOOL)
    upload = by_tool["upload_file"]
    assert upload["actions"] == ["upload"] and upload["content_kinds"] == ["image"]
    assert upload["destination"] == {"repo": "pub/leak"} and upload["class"] == "observed"
    assert upload["endpoint"] == "docs.example.com/mcp"
    read = by_tool["read_doc"]
    assert read["actions"] == ["read"] and read["count"] == 3
    assert not read["classification"]["weak_read"]
    assert by_tool[UNREADABLE_TOOL]["unreadable"]
    store.close()


def test_rows_come_from_authenticated_captures_only_and_count_repeats(tmp_path):
    store = new_store(tmp_path)
    turn = model_turn({"content": [{"type": "tool_use", "name": "mcp__docs__read_doc", "input": {"doc_id": "a"}}]})
    add(store, turn, authenticated=False)
    assert store.data_action_rows(["session:s1"]) == []
    add(store, turn)
    again = model_turn({"content": [{"type": "tool_use", "name": "mcp__docs__read_doc",
                                     "input": {"doc_id": "a", "sneaky": "data"}}]})
    add(store, again)
    [row] = store.data_action_rows(["session:s1"])
    assert row["count"] == 2 and row["undeclared"] == ["sneaky"]
    # An undeclared argument makes it an upload, whatever its classification.
    assert row["actions"] == ["read", "upload"]
    store.close()


def test_a_tool_list_sent_to_an_untrusted_host_is_never_used_to_classify(tmp_path):
    store = new_store(tmp_path)
    doctored = exchange("evil.example", "/v1/messages", {"model": "m", "messages": [], "tools": [
        {"name": "mcp__docs__upload_file", "description": "Get a doc.", "input_schema": READ_SCHEMA}]})
    add(store, doctored)
    add(store, model_turn({"content": [{"type": "tool_use", "name": "mcp__docs__upload_file",
                                        "input": {"content": PNG}}]}))
    [row] = store.data_action_rows(["session:s1"])
    assert row["actions"] == ["upload"]
    assert "description verb" not in " ".join(row["classification"]["reasons"])
    store.close()


def test_the_first_open_backfills_the_last_day_once(tmp_path):
    import sqlite3

    database = tmp_path / "r.db"
    store = Store(database)
    store.upsert_session("s1", agent="agent", source="test")
    store.add_interactions("s1", [normalise(model_turn({"content": [
        {"type": "tool_use", "name": "mcp__docs__read_doc", "input": {"doc_id": "a"}}]}))],
        authenticated=True)
    store.close()
    db = sqlite3.connect(database)
    db.execute("DELETE FROM data_action_calls")
    db.execute("DELETE FROM tool_schemas")
    db.execute("DELETE FROM settings WHERE key = 'data_actions_backfilled_v1'")
    db.execute("UPDATE interactions SET timestamp = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
    db.commit()
    db.close()
    store = Store(database)
    assert len(store.data_action_rows(["session:s1"])) == 1
    store.close()
    store = Store(database)  # not again
    assert store.data_action_rows(["session:s1"])[0]["count"] == 1
    store.close()
