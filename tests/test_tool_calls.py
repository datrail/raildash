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


def test_streamed_gemini_calls_with_no_index_stay_apart():
    """DR-231: Gemini's chunks send each call whole, with an id and no index;
    keyed by index alone, a second call's name and arguments overwrote the
    first's."""
    calls = [{"id": f"f{n}", "type": "function", "function": {"name": name, "arguments": arguments}}
             for n, (name, arguments) in enumerate(
                 (("read_doc", '{"doc_id": "d1"}'), ("upload_file", '{"path": "a"}')))]
    for chunks in ([calls], [[calls[0]], [calls[1]]]):
        text = "".join(
            "data: " + json.dumps({"choices": [{"index": 0, "finish_reason": "stop",
                                                "delta": {"tool_calls": part}}]}) + "\n\n"
            for part in chunks)
        item = exchange("generativelanguage.googleapis.com", "/v1beta/openai/chat/completions",
                        {"model": "m", "messages": []}, {"raw": text},
                        response_headers={"content-type": "text/event-stream"})
        found = tc.extract_tool_calls(stored(item))["calls"]
        assert [(c["tool"], c["arguments_bytes"]) for c in found] == [
            ("read_doc", len('{"doc_id": "d1"}')), ("upload_file", len('{"path": "a"}'))]
    # A first chunk with the id and name, then fragments with neither.
    parts = ({"id": "f0", "function": {"name": "read_doc", "arguments": '{"doc'}},
             {"function": {"arguments": '_id": "d1"}'}})
    text = "".join("data: " + json.dumps({"choices": [{"delta": {"tool_calls": [part]}}]}) + "\n\n"
                   for part in parts)
    item = exchange("api.example.com", "/v1/chat/completions", {"model": "m", "messages": []},
                    {"raw": text}, response_headers={"content-type": "text/event-stream"})
    [call] = tc.extract_tool_calls(stored(item))["calls"]
    assert call["tool"] == "read_doc" and call["arguments_bytes"] == len('{"doc_id": "d1"}')
    # A name starts a call rather than renaming one, and the nameless
    # fragment after it continues it.
    parts = ({"function": {"name": "read_doc", "arguments": "{}"}},
             {"id": "f0", "function": {"name": "read_doc", "arguments": "{}"}},
             {"function": {"name": "upload_file", "arguments": '{"pa'}},
             {"function": {"arguments": 'th": "a"}'}})
    text = "".join("data: " + json.dumps({"choices": [{"delta": {"tool_calls": [part]}}]}) + "\n\n"
                   for part in parts)
    item = exchange("api.example.com", "/v1/chat/completions", {"model": "m", "messages": []},
                    {"raw": text}, response_headers={"content-type": "text/event-stream"})
    assert [(c["tool"], c["arguments_bytes"]) for c in tc.extract_tool_calls(stored(item))["calls"]] == [
        ("read_doc", 2), ("read_doc", 2), ("upload_file", len('{"path": "a"}'))]
    # An empty name renames nothing, and a nameless fragment never joins a
    # call numbered 0.
    parts = ({"id": "f0", "function": {"name": "read_doc", "arguments": '{"doc'}},
             {"id": "f0", "function": {"name": "", "arguments": '_id": "d1"}'}},
             {"index": 0, "function": {"name": "upload_file", "arguments": "{}"}},
             {"function": {"arguments": "{}"}})
    text = "".join("data: " + json.dumps({"choices": [{"delta": {"tool_calls": [part]}}]}) + "\n\n"
                   for part in parts)
    item = exchange("api.example.com", "/v1/chat/completions", {"model": "m", "messages": []},
                    {"raw": text}, response_headers={"content-type": "text/event-stream"})
    assert [(c["tool"], c["arguments_bytes"]) for c in tc.extract_tool_calls(stored(item))["calls"]] == [
        ("read_doc", len('{"doc_id": "d1"}')), ("upload_file", 2)]


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
    assert tc.extract_tool_calls(stored(get)) == {"calls": [], "mcp_post_unreadable": None, "truncated": False}


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
    assert [row["tool"] for row in rows][0] in ("mcp@docs.example.com/mcp__upload_file", UNREADABLE_TOOL)
    upload = by_tool["mcp@docs.example.com/mcp__upload_file"]
    assert upload["actions"] == ["upload"] and upload["content_kinds"] == ["image"]
    assert upload["destination"] == {"repo": "pub/leak"} and upload["class"] == "observed"
    assert upload["endpoint"] == "docs.example.com/mcp"
    read = by_tool["mcp@docs.example.com/mcp__read_doc"]
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
    [row] = store.data_action_rows(["session:s1"])
    stamp = sqlite3.connect(database).execute("SELECT timestamp FROM interactions").fetchone()[0]
    # The capture's own time, not the open's, in the store's fixed-width form.
    assert row["first_seen"] == stamp.replace("Z", ".000000Z")
    store.close()
    store = Store(database)  # not again
    assert store.data_action_rows(["session:s1"])[0]["count"] == 1
    store.close()


# ------------------------------------------------------- review round 1


def listed(store):
    add(store, exchange("docs.example.com", "/mcp",
                        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, LISTING))


def test_each_call_in_a_batch_is_checked_with_its_own_arguments(tmp_path):
    store = new_store(tmp_path)
    listed(store)
    add(store, mcp_call([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_doc", "arguments": {"doc_id": "a"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "read_doc", "arguments": {"doc_id": "b", "secret": "x"}}},
    ]))
    [row] = [r for r in store.data_action_rows(["session:s1"]) if r["tool"] == "mcp@docs.example.com/mcp__read_doc"]
    assert row["undeclared"] == ["secret"] and "upload" in row["actions"]
    store.close()


def test_a_large_batch_is_read_once(tmp_path):
    import time

    store = new_store(tmp_path)
    listed(store)
    padding = "A" * 20_000
    batch = [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
              "params": {"name": "read_doc", "arguments": {"doc_id": padding}}} for i in range(300)]
    started = time.monotonic()
    add(store, mcp_call(batch))
    assert time.monotonic() - started < 20
    tools = {r["tool"]: r for r in store.data_action_rows(["session:s1"])}
    # Past MAX_CALLS the rest is marked, and that fails closed.
    assert tools["(more calls)"]["unreadable"]
    store.close()


def test_a_jsonrpc_call_dressed_as_a_model_request_is_still_a_call():
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "model": "m", "messages": [],
            "params": {"name": "upload_file", "arguments": {"content": PNG}}}
    [call] = tc.extract_tool_calls(stored(mcp_call(body)))["calls"]
    assert call["class"] == tc.OBSERVED and call["tool"] == "upload_file"


def test_a_lost_request_body_falls_back_to_the_newest_known_schema(tmp_path):
    store = new_store(tmp_path)
    add(store, model_turn({"content": []}))  # the tool list, once
    lost = model_turn({"content": [{"type": "tool_use", "name": "mcp__docs__read_doc",
                                    "input": {"doc_id": "a", "extra": 1}}]})
    lost["request"]["body"] = {"raw": '{"model": "m", "messages": [ ... cut'}
    add(store, lost)
    [row] = store.data_action_rows(["session:s1"])
    assert row["tool"] == "mcp__docs__read_doc" and row["undeclared"] == ["extra"]
    assert row["schema_known"]
    store.close()


def test_past_the_row_bound_a_tool_keeps_its_own_row(tmp_path, monkeypatch):
    from raildash import data_actions_store as das

    monkeypatch.setattr(das, "MAX_ROWS_PER_CAPTURE", 3)
    monkeypatch.setattr(das, "MAX_ROWS_SLACK", 1)
    store = new_store(tmp_path)
    listed(store)
    for repo in ("a", "b", "c", "d", "e"):
        add(store, mcp_call({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": "read_doc", "arguments": {"doc_id": "x", "repo": repo}}}))
    add(store, mcp_call({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "upload_file", "arguments": {"content": PNG}}}))
    add(store, mcp_call({"raw": "garbage"}))
    tools = [r["tool"] for r in store.data_action_rows(["session:s1"])]
    assert "(unreadable call)" in tools
    # The upload either keeps its row or lands in the overflow row, which
    # counts as unreadable; it never reads as nothing.
    rows = store.data_action_rows(["session:s1"])
    assert any(r["tool"] == "mcp@docs.example.com/mcp__upload_file" and r["actions"] == ["upload"] for r in rows) or any(
        r["tool"] == "(more calls)" and r["unreadable"] for r in rows)
    store.close()


def test_a_declared_server_url_is_a_known_endpoint_for_unreadable_calls(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    monkeypatch.setattr(type(store), "_asp_facts",
                        lambda self: {"inference_hosts": set(), "mcp_endpoints": {"tools.example.com/rpc"}, "servers": {}})
    add(store, mcp_call({"raw": "garbage"}, host="tools.example.com", path="/rpc"))
    [row] = store.data_action_rows(["session:s1"])
    assert row["unreadable"] and row["endpoint"] == "tools.example.com/rpc"
    store.close()


# ------------------------------------------------------- review round 2


def test_a_model_request_with_a_stray_jsonrpc_key_keeps_its_requested_calls():
    item = model_turn({"content": [{"type": "tool_use", "name": "mcp__docs__read_doc", "input": {"doc_id": "a"}}]})
    item["request"]["body"]["jsonrpc"] = "2.0"
    [call] = tc.extract_tool_calls(stored(item))["calls"]
    assert call["class"] == tc.REQUESTED


def test_a_lost_body_post_is_reported_even_if_its_reply_looks_like_a_model(tmp_path):
    store = new_store(tmp_path)
    listed(store)
    item = mcp_call({"raw": '{"jsonrpc": "2.0", "method": "tools/call", ... cut'})
    item["response"]["body"] = {"content": []}
    add(store, item)
    assert any(r["unreadable"] for r in store.data_action_rows(["session:s1"]))
    store.close()


def test_the_fallback_schema_never_comes_from_an_untrusted_host(tmp_path):
    store = new_store(tmp_path)
    add(store, exchange("evil.example", "/v1/messages", {"model": "m", "messages": [], "tools": [
        {"name": "get_status", "input_schema": {"type": "object", "properties": {"notes": {}}}}]}))
    add(store, exchange("api.anthropic.com", "/v1/messages", {"model": "m", "messages": [], "tools": [
        {"name": "get_status", "input_schema": {"type": "object", "properties": {}}}]}))
    lost = model_turn({"content": [{"type": "tool_use", "name": "get_status", "input": {"notes": "x" * 50}}]})
    lost["request"]["body"] = {"raw": "cut"}
    add(store, lost)
    [row] = [r for r in store.data_action_rows(["session:s1"]) if r["tool"] == "get_status"]
    assert row["undeclared"] == ["notes"] and "upload" in row["actions"]
    store.close()


# ------------------------------------------------------------ profile (M1c)


def test_the_observed_profile_lists_data_actions_without_destination_values(tmp_path):
    store = new_store(tmp_path)
    listed(store)
    add(store, mcp_call({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "read_doc", "arguments": {"doc_id": "a"}}}))
    add(store, mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "upload_file", "arguments": {"content": PNG, "repo": "pub/x"}}}))
    profile = store.observed_profile("s1")
    actions = profile["observed"]["data_actions"]
    assert [item["tool"] for item in actions] == ["mcp@docs.example.com/mcp__upload_file", "mcp@docs.example.com/mcp__read_doc"]
    upload = actions[0]
    assert upload["actions"] == ["upload"] and upload["content_kinds"] == ["image"]
    assert upload["reasons"] and "destination" not in upload
    assert "pub/x" not in json.dumps(profile)
    # Another agent's view of the session has none of the unattributed rows.
    assert store.observed_profile("s1", agent_key="other")["observed"]["data_actions"] == []
    store.close()


def test_an_attributed_agents_profile_shows_its_own_rows(tmp_path):
    store = new_store(tmp_path)
    item = mcp_call({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "read_doc", "arguments": {"doc_id": "a"}}})
    item.update({"runtime_identity_version": 1, "attribution": {"state": "attributed", "method": "cgroup"},
                 "agent_ref": {"host_id": "h", "sandbox_name": "b", "agent_key": "writer"}})
    add(store, item)
    assert [a["tool"] for a in store.observed_profile("s1", agent_key="writer")["observed"]["data_actions"]] == ["mcp@docs.example.com/mcp__read_doc"]
    assert [a["tool"] for a in store.observed_profile("s1")["observed"]["data_actions"]] == ["mcp@docs.example.com/mcp__read_doc"]
    store.close()


def test_profile_entries_merge_per_tool_and_say_their_scope(tmp_path):
    store = new_store(tmp_path)
    store.upsert_session("s2", agent="agent", source="test")
    listed(store)

    def attributed(session, key, repo):
        item = mcp_call({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "upload_file", "arguments": {"content": PNG, "repo": repo}}})
        item.update({"runtime_identity_version": 1, "attribution": {"state": "attributed", "method": "cgroup"},
                     "agent_ref": {"host_id": "h", "sandbox_name": "b", "agent_key": key}})
        store.add_interactions(session, [normalise(item)], authenticated=True)

    attributed("s1", "k1", "pub/a")
    attributed("s1", "k1", "pub/b")
    attributed("s1", "k2", "pub/a")
    attributed("s2", "k1", "pub/c")
    [entry] = store.observed_profile("s1")["observed"]["data_actions"]
    # One entry per tool, whatever the destination or agent behind it.
    assert entry["tool"] == "mcp@docs.example.com/mcp__upload_file" and entry["scope"] == "agent"
    # An identified agent's calls count across its captures (s2's too).
    assert entry["count"] == 4
    [k1] = store.observed_profile("s1", agent_key="k1")["observed"]["data_actions"]
    assert k1["count"] == 3
    store.close()


def test_the_profile_caps_data_actions_and_says_so(tmp_path, monkeypatch):
    from raildash import store as store_module

    monkeypatch.setattr(store_module, "MAX_PROFILE_DIMENSION_VALUES", 3)
    store = new_store(tmp_path)
    for index in range(5):
        add(store, model_turn({"content": [{"type": "tool_use", "name": f"tool_{index}", "input": {}}]}))
    observed = store.observed_profile("s1")["observed"]
    assert len(observed["data_actions"]) == 3
    assert "data_actions" in observed["truncated_dimensions"]
    store.close()


# ------------------------------------------------------------- M1 line-up


def test_a_declared_server_lines_up_its_endpoint_and_model_side_names(tmp_path, monkeypatch):
    store = new_store(tmp_path)
    monkeypatch.setattr(type(store), "_asp_facts", lambda self: {
        "inference_hosts": set(), "mcp_endpoints": {"docs.example.com/mcp"},
        "servers": {"docs.example.com/mcp": "docs"}})
    # The server's listing carries the annotation; the model side only names.
    listing = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "tidy", "inputSchema": READ_SCHEMA, "annotations": {"destructiveHint": True}}]}}
    add(store, exchange("docs.example.com", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, listing))
    add(store, mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "tidy", "arguments": {}}}))
    add(store, model_turn({"content": [{"type": "tool_use", "name": "mcp__docs__tidy", "input": {}}]}))
    rows = {(r["class"], r["tool"]): r for r in store.data_action_rows(["session:s1"])}
    observed = rows[("observed", "mcp__docs__tidy")]
    requested = rows[("requested", "mcp__docs__tidy")]
    # Both sides see the server's destructiveHint through the line-up: it
    # adds no action, and both say so.
    assert observed["actions"] == requested["actions"] == []
    assert observed["classification"]["notes"] == requested["classification"]["notes"]
    assert any("destructiveHint" in note for note in observed["classification"]["notes"])
    assert observed["wire_tool"] == "tidy"
    store.close()


def test_a_requested_call_through_an_untrusted_host_is_held_to_the_trusted_schema(tmp_path):
    store = new_store(tmp_path)
    add(store, model_turn({"content": []}))  # the trusted list: read_doc takes doc_id only
    doctored = exchange("evil.example", "/v1/messages", {"model": "m", "messages": [], "tools": [
        {"name": "mcp__docs__read_doc", "input_schema": {"type": "object", "properties": {
            "doc_id": {}, "notes": {}}}}]},
        {"content": [{"type": "tool_use", "name": "mcp__docs__read_doc",
                      "input": {"doc_id": "a", "notes": "x" * 40}}]})
    add(store, doctored)
    [row] = store.data_action_rows(["session:s1"])
    assert row["undeclared"] == ["notes"] and "upload" in row["actions"]
    store.close()


def _asp_with_servers(store, servers, bundle_id="bnd-da"):
    from test_guardrail import declared, v1_bundle

    status = "ANSWERED" if servers is not None else "ABSENT"
    bundle = v1_bundle(mcp_servers_declared=declared(servers, status))
    bundle["bundle_id"] = bundle_id
    store.load_asp(json.dumps(bundle, sort_keys=True).encode())


def test_a_real_asp_declaring_a_server_lines_it_up(tmp_path):
    store = new_store(tmp_path)
    _asp_with_servers(store, [{"name": "docs", "url": "https://docs.example.com/mcp", "transport": "http"},
                              {"name": "x__read", "url": "https://other.example.com/mcp", "transport": "http"}])
    listed(store)
    add(store, mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "read_doc", "arguments": {"doc_id": "a"}}}))
    add(store, mcp_call({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "upload_file", "arguments": {"content": PNG}}},
                        host="other.example.com"))
    add(store, model_turn({"content": [{"type": "tool_use", "name": "plain_tool", "input": {}}]}))
    tools = {r["tool"] for r in store.data_action_rows(["session:s1"])}
    assert "mcp__docs__read_doc" in tools
    # A declared name with `__` isn't lined up: its endpoint keeps mcp@.
    assert "mcp@other.example.com/mcp__upload_file" in tools
    assert "plain_tool" in tools
    assert store.observed_profile("s1")["observed"]["data_actions"]
    store.close()


def test_a_real_asp_with_no_declared_servers_changes_nothing(tmp_path):
    store = new_store(tmp_path)
    _asp_with_servers(store, None)
    listed(store)
    add(store, model_turn({"content": [{"type": "tool_use", "name": "read_doc", "input": {}}]}))
    add(store, mcp_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "read_doc", "arguments": {"doc_id": "a"}}}))
    tools = {r["tool"] for r in store.data_action_rows(["session:s1"])}
    assert tools == {"read_doc", "mcp@docs.example.com/mcp__read_doc"}
    store.close()
