"""DR-205 M0: tool schemas read from captured traffic (data-actions design §4.1)."""

from __future__ import annotations

import json

from raildash import tool_schemas as ts
from raildash.ingest import normalise
from raildash.store import Store

UPLOAD_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}, "content": {"type": "string", "contentEncoding": "base64"}},
    "required": ["path", "content"],
}
READ_SCHEMA = {"type": "object", "properties": {"doc_id": {"type": "string"}}, "required": ["doc_id"]}


def stored(interaction: dict) -> dict:
    """The shape a stored row has: its exchange as `raw` JSON."""
    return {"raw": json.dumps(interaction)}


def exchange(host, path, request_body, response_body=None, *, response_headers=None):
    return {
        "interaction_id": f"i-{abs(hash((host, path, json.dumps(request_body)))) % 10**8}",
        "timestamp": "2026-10-11T07:00:00Z",
        "request": {"method": "POST", "path": path, "headers": {"host": host}, "body": request_body},
        "response": {
            "status_code": 200,
            "headers": response_headers or {"content-type": "application/json"},
            "body": response_body if response_body is not None else {},
        },
    }


def anthropic_request():
    return exchange("api.anthropic.com", "/v1/messages", {
        "model": "claude-sonnet-5",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [
            {"name": "Bash", "description": "Run a shell command.",
             "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}}},
            {"name": "mcp__docs__upload_file", "description": "Upload a file.",
             "input_schema": UPLOAD_SCHEMA},
            # A server tool: Anthropic runs it, and it carries no schema.
            {"type": "web_search_20250305", "name": "web_search", "max_uses": 3},
        ],
    })


def by_tool(result):
    return {item["tool"]: item for item in result["schemas"]}


def test_an_anthropic_request_gives_its_client_tools_with_their_schemas():
    result = ts.extract_tool_schemas(stored(anthropic_request()))
    tools = by_tool(result)
    assert result["reason"] is None
    assert set(tools) == {"Bash", "mcp__docs__upload_file"}
    upload = tools["mcp__docs__upload_file"]
    assert upload["source"] == ts.SOURCE_MODEL_REQUEST
    assert upload["input_schema"] == UPLOAD_SCHEMA
    assert upload["host"] == "api.anthropic.com"
    assert upload["endpoint"] is None
    assert upload["schema_hash"] == ts.schema_hash("Upload a file.", UPLOAD_SCHEMA, None)


def test_openai_chat_and_responses_requests_give_their_function_tools():
    chat = exchange("api.openai.com", "/v1/chat/completions", {
        "model": "gpt-5", "messages": [],
        "tools": [{"type": "function", "function": {
            "name": "read_doc", "description": "Read one doc.", "parameters": READ_SCHEMA}}],
    })
    responses = exchange("api.openai.com", "/v1/responses", {
        "model": "gpt-5", "input": "hi",
        "tools": [{"type": "function", "name": "read_doc", "description": "Read one doc.",
                   "parameters": READ_SCHEMA}],
    })
    for item in (chat, responses):
        tools = by_tool(ts.extract_tool_schemas(stored(item)))
        assert list(tools) == ["read_doc"]
        assert tools["read_doc"]["input_schema"] == READ_SCHEMA
    # The same schema, so the same hash, whichever API carried it.
    assert (
        ts.extract_tool_schemas(stored(chat))["schemas"][0]["schema_hash"]
        == ts.extract_tool_schemas(stored(responses))["schemas"][0]["schema_hash"]
    )


def test_a_model_shaped_tool_list_to_any_host_is_kept_with_its_host():
    """The classifier drops it unless the host is the agent's inference
    endpoint or a known provider; ingest keeps it with its host."""
    item = anthropic_request()
    item["request"]["headers"]["host"] = "llm.internal.example:8443"
    tools = by_tool(ts.extract_tool_schemas(stored(item)))
    assert tools["Bash"]["host"] == "llm.internal.example"
    assert not ts.known_model_host("llm.internal.example")
    assert ts.known_model_host("api.anthropic.com")
    assert ts.known_model_host("myres.openai.azure.com")
    assert ts.known_model_host("llm.internal.example", ("llm.internal.example",))


def mcp_tools_list(response_body, *, request_id=1, headers=None, path="/mcp"):
    return exchange(
        "docs.example.com", path,
        {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}},
        response_body, response_headers=headers,
    )


LISTING = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
    {"name": "read_doc", "description": "Read one doc.", "inputSchema": READ_SCHEMA,
     "annotations": {"readOnlyHint": True}},
    {"name": "upload_file", "description": "Upload a file.", "inputSchema": UPLOAD_SCHEMA},
], "nextCursor": "page-2"}}


def test_an_mcp_tools_list_reply_gives_each_tool_with_its_endpoint_and_annotations():
    tools = by_tool(ts.extract_tool_schemas(stored(mcp_tools_list(LISTING))))
    assert set(tools) == {"read_doc", "upload_file"}
    assert tools["read_doc"]["source"] == ts.SOURCE_MCP_TOOLS_LIST
    assert tools["read_doc"]["endpoint"] == "docs.example.com/mcp"
    assert tools["read_doc"]["annotations"] == {"readOnlyHint": True}
    assert tools["upload_file"]["annotations"] is None


def test_an_mcp_reply_streamed_as_sse_is_read_event_by_event():
    text = (
        "event: message\r\n"
        "data: " + json.dumps({"jsonrpc": "2.0", "method": "notifications/progress"}) + "\r\n\r\n"
        "event: message\n"
        "data: " + json.dumps(LISTING) + "\n\n"
    )
    item = mcp_tools_list({"raw": text}, headers={"content-type": "text/event-stream"})
    assert set(by_tool(ts.extract_tool_schemas(stored(item)))) == {"read_doc", "upload_file"}


def test_only_the_reply_to_the_tools_list_id_counts_and_a_batch_is_read():
    other = {"jsonrpc": "2.0", "id": 7, "result": {"tools": [
        {"name": "planted", "inputSchema": READ_SCHEMA}]}}
    # The listing answers id 1; a message with another id is not its answer.
    item = mcp_tools_list([LISTING, other])
    assert set(by_tool(ts.extract_tool_schemas(stored(item)))) == {"read_doc", "upload_file"}
    batch = exchange("docs.example.com", "/mcp", [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "resources/list"},
    ], [LISTING])
    assert set(by_tool(ts.extract_tool_schemas(stored(batch)))) == {"read_doc", "upload_file"}


def test_a_hosted_mcp_listing_in_a_responses_reply_is_prefixed_as_provider_side():
    listing = {"type": "mcp_list_tools", "server_label": "Docs Hub", "tools": [
        {"name": "upload_file", "description": "Upload a file.", "input_schema": UPLOAD_SCHEMA,
         "annotations": None}]}
    request = {"model": "gpt-5", "input": "hi",
               "tools": [{"type": "mcp", "server_label": "Docs Hub",
                          "server_url": "https://docs.example.com/mcp"}]}
    whole = exchange("api.openai.com", "/v1/responses", request, {"output": [listing]})
    streamed = exchange(
        "api.openai.com", "/v1/responses", request,
        {"raw": "event: response.output_item.done\ndata: "
         + json.dumps({"type": "response.output_item.done", "item": listing}) + "\n\n"
         "data: [DONE]\n\n"},
        response_headers={"content-type": "text/event-stream"},
    )
    for item in (whole, streamed):
        tools = by_tool(ts.extract_tool_schemas(stored(item)))
        assert list(tools) == ["provider-mcp__Docs_Hub__upload_file"]
        assert tools["provider-mcp__Docs_Hub__upload_file"]["server"] == "Docs_Hub"
        assert tools["provider-mcp__Docs_Hub__upload_file"]["source"] == ts.SOURCE_PROVIDER_MCP_LIST


def test_traffic_that_lists_no_tools_says_so_and_unreadable_traffic_gives_nothing():
    plain = exchange("api.example.com", "/v1/files", {"name": "x"})
    assert ts.extract_tool_schemas(stored(plain)) == {"schemas": [], "reason": ts.NOT_A_TOOL_SOURCE}
    assert ts.extract_tool_schemas({"raw": "{not json"})["reason"] == ts.UNREADABLE
    encoded = mcp_tools_list(LISTING, headers={"content-encoding": "gzip"})
    assert ts.extract_tool_schemas(stored(encoded))["schemas"] == []
    # A malformed tool (no schema object) is skipped, not fatal.
    broken = mcp_tools_list({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "x", "inputSchema": "not an object"}, LISTING["result"]["tools"][0]]}})
    assert set(by_tool(ts.extract_tool_schemas(stored(broken)))) == {"read_doc"}


def test_tool_lists_are_bounded():
    many = exchange("api.anthropic.com", "/v1/messages", {
        "model": "m", "messages": [],
        "tools": [{"name": f"t{i}", "input_schema": READ_SCHEMA}
                  for i in range(ts.MAX_TOOLS_PER_SOURCE + 5)],
    })
    result = ts.extract_tool_schemas(stored(many))
    assert len(result["schemas"]) == ts.MAX_TOOLS_PER_SOURCE
    assert result["reason"] == ts.TOO_MANY_TOOLS
    huge = exchange("api.anthropic.com", "/v1/messages", {
        "model": "m", "messages": [],
        "tools": [{"name": "big", "description": "x" * (ts.MAX_SCHEMA_BYTES + 1),
                   "input_schema": READ_SCHEMA}],
    })
    assert ts.extract_tool_schemas(stored(huge)) == {"schemas": [], "reason": ts.TOO_MANY_TOOLS}


# ------------------------------------------------------------------ store


def test_only_authenticated_captures_store_schemas_and_a_repeat_only_refreshes(tmp_path):
    store = Store(tmp_path / "r.db")
    store.upsert_session("s1", agent="agent", source="test")
    store.add_interactions("s1", [normalise(mcp_tools_list(LISTING))])
    assert store.tool_schemas() == []

    store.add_interactions("s1", [normalise(anthropic_request())], authenticated=True)
    rows = store.tool_schemas("session:s1")
    assert {row["tool"] for row in rows} == {"Bash", "mcp__docs__upload_file"}
    first = {row["tool"]: row["last_seen"] for row in rows}

    # The next turn resends the same list: same rows, newer last_seen.
    again = anthropic_request()
    again["interaction_id"] = "turn-2"
    again["timestamp"] = "2026-10-11T07:01:00Z"
    store.add_interactions("s1", [normalise(again)], authenticated=True)
    rows = store.tool_schemas("session:s1")
    assert len(rows) == 2
    assert all(row["last_seen"] >= first[row["tool"]] for row in rows)
    assert all(row["interaction_id"] == "turn-2" for row in rows)

    # A changed schema for the same tool is a second row, not an overwrite.
    changed = anthropic_request()
    changed["interaction_id"] = "turn-3"
    changed["request"]["body"]["tools"][1]["input_schema"] = READ_SCHEMA
    store.add_interactions("s1", [normalise(changed)], authenticated=True)
    upload_rows = [r for r in store.tool_schemas("session:s1") if r["tool"] == "mcp__docs__upload_file"]
    assert {json.dumps(r["input_schema"], sort_keys=True) for r in upload_rows} == {
        json.dumps(UPLOAD_SCHEMA, sort_keys=True), json.dumps(READ_SCHEMA, sort_keys=True)}
    store.close()


def test_an_attributed_capture_is_keyed_by_its_agent_and_mcp_rows_by_endpoint(tmp_path):
    store = Store(tmp_path / "r.db")
    store.upsert_session("s1", agent="agent", source="test")
    item = mcp_tools_list(LISTING)
    item.update({
        "runtime_identity_version": 1,
        "attribution": {"state": "attributed", "method": "cgroup"},
        "agent_ref": {"host_id": "h1", "sandbox_name": "box", "agent_key": "writer"},
    })
    store.add_interactions("s1", [normalise(item)], authenticated=True)
    rows = store.tool_schemas("agent:h1/box/writer")
    assert {(row["tool"], row["endpoint"]) for row in rows} == {
        ("read_doc", "docs.example.com/mcp"), ("upload_file", "docs.example.com/mcp")}
    assert store.tool_schemas("session:s1") == []
    store.close()


def test_a_failed_extraction_still_stores_the_capture(tmp_path, monkeypatch):
    store = Store(tmp_path / "r.db")
    store.upsert_session("s1", agent="agent", source="test")

    def boom(_interaction):
        raise RuntimeError("boom")

    monkeypatch.setattr(ts, "extract_tool_schemas", boom)
    assert store.add_interactions("s1", [normalise(anthropic_request())], authenticated=True) == 1
    assert store.tool_schemas() == []
    store.close()


# ------------------------------------------------------- review round 1


def test_odd_jsonrpc_ids_match_nothing_and_never_cost_the_rest_of_the_reply():
    odd = [{"jsonrpc": "2.0", "id": [1], "result": {"tools": [{"name": "x", "inputSchema": READ_SCHEMA}]}},
           {"jsonrpc": "2.0", "id": True, "result": {"tools": [{"name": "y", "inputSchema": READ_SCHEMA}]}},
           {"jsonrpc": "2.0", "id": 1.0, "result": {"tools": [{"name": "z", "inputSchema": READ_SCHEMA}]}},
           {"jsonrpc": "2.0", "id": "1", "result": {"tools": [{"name": "w", "inputSchema": READ_SCHEMA}]}},
           LISTING]
    assert set(by_tool(ts.extract_tool_schemas(stored(mcp_tools_list(odd))))) == {"read_doc", "upload_file"}
    string_id = mcp_tools_list({**LISTING, "id": "a"}, request_id="a")
    assert set(by_tool(ts.extract_tool_schemas(stored(string_id)))) == {"read_doc", "upload_file"}


def test_the_legacy_functions_list_is_read():
    item = exchange("api.openai.com", "/v1/chat/completions", {
        "model": "gpt-4", "messages": [],
        "functions": [{"name": "read_doc", "description": "Read one doc.", "parameters": READ_SCHEMA}],
    })
    assert list(by_tool(ts.extract_tool_schemas(stored(item)))) == ["read_doc"]


def test_a_huge_tool_list_stops_at_the_cap_quickly():
    import time
    huge = exchange("api.anthropic.com", "/v1/messages", {
        "model": "m", "messages": [],
        "tools": [{"name": f"t{i}", "input_schema": {}} for i in range(200_000)],
    })
    started = time.monotonic()
    result = ts.extract_tool_schemas(stored(huge))
    assert result["reason"] == ts.TOO_MANY_TOOLS
    assert len(result["schemas"]) == ts.MAX_TOOLS_PER_SOURCE
    assert time.monotonic() - started < 3


def test_rows_that_cannot_carry_tools_are_not_parsed():
    assert not ts.may_carry_tools(json.dumps(exchange("api.example.com", "/x", {"a": 1})))
    assert ts.may_carry_tools(json.dumps(anthropic_request()))
    assert ts.may_carry_tools(json.dumps(mcp_tools_list(LISTING)))


def test_a_schema_sent_to_a_bogus_host_first_does_not_take_the_trusted_row(tmp_path):
    store = Store(tmp_path / "r.db")
    store.upsert_session("s1", agent="agent", source="test")
    bogus = anthropic_request()
    bogus["interaction_id"] = "bogus"
    bogus["request"]["headers"]["host"] = "evil.example"
    store.add_interactions("s1", [normalise(bogus)], authenticated=True)
    store.add_interactions("s1", [normalise(anthropic_request())], authenticated=True)
    hosts = {(row["tool"], row["host"]) for row in store.tool_schemas("session:s1")}
    assert ("mcp__docs__upload_file", "evil.example") in hosts
    assert ("mcp__docs__upload_file", "api.anthropic.com") in hosts
    store.close()


def test_an_authenticated_copy_of_an_unauthenticated_capture_records_its_schemas(tmp_path):
    store = Store(tmp_path / "r.db")
    store.upsert_session("s1", agent="agent", source="test")
    store.add_interactions("s1", [normalise(anthropic_request())])
    assert store.tool_schemas() == []
    store.add_interactions("s1", [normalise(anthropic_request())], authenticated=True)
    assert {row["tool"] for row in store.tool_schemas("session:s1")} == {"Bash", "mcp__docs__upload_file"}
    store.close()


def test_a_database_from_before_m0_gains_the_table(tmp_path):
    import sqlite3

    database = tmp_path / "r.db"
    store = Store(database)
    store.close()
    db = sqlite3.connect(database)
    db.execute("DROP TABLE tool_schemas")
    db.commit()
    db.close()
    store = Store(database)
    store.upsert_session("s1", agent="agent", source="test")
    store.add_interactions("s1", [normalise(anthropic_request())], authenticated=True)
    assert len(store.tool_schemas()) == 2
    store.close()
