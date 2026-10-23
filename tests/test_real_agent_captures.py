"""DR-239: golden tests on real model-API captures from two coding agents.

- `fixtures/codex-responses-captures.jsonl`: the three OpenAI Responses
  exchanges (`POST chatgpt.com/backend-api/codex/responses`, streamed) of one
  `codex exec` 0.163.0 run, 2026-10-23, told to read a document with the
  railmon demo's MCP server (`demo`, its `read_doc` tool) and say what it
  returned. Codex ran in code mode: its one tool is the `exec` custom tool,
  whose JavaScript calls every other tool as `tools.<name>(…)`. Its first
  script only looked the tool up in `ALL_TOOLS`; its second called
  `tools.mcp__demo__read_doc`; its third turn was the answer.
- `fixtures/claude-code-messages-request.json`: a Claude Code (July 2025)
  `POST api.anthropic.com/v1/messages` request with its 17 tools, two of
  them the `ide` MCP server's. It is from AgentSight's public capture
  (eunomia-bpf/agentsight, `script/results/ssl_only/claude_code/
  analysis_modify_code`), which kept no streamed reply, so it has none.

Both were reduced the same way: credentials and per-account identifiers
(auth, account, session, installation and cookie headers, cache keys,
safety ids, moderation metadata) are gone, and the agents' own long
instructions and the conversation's text are replaced by their length. The
tools, the user's prompt, every call and its input, and the stream's events
are as captured.
"""

from __future__ import annotations

import json
from pathlib import Path

from raildash import guardrail as g
from raildash import tool_calls as tc
from raildash import tool_schemas as ts
from raildash.ingest import normalise
from raildash.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
CODEX = [json.loads(line) for line in (FIXTURES / "codex-responses-captures.jsonl").read_text().splitlines()]
CLAUDE = json.loads((FIXTURES / "claude-code-messages-request.json").read_text())
CLAUDE_CODE_TOOLS = {
    "Task", "Bash", "Glob", "Grep", "LS", "exit_plan_mode", "Read", "Edit", "MultiEdit", "Write",
    "NotebookRead", "NotebookEdit", "WebFetch", "TodoWrite", "WebSearch",
    "mcp__ide__getDiagnostics", "mcp__ide__executeCode",
}


def stored(capture: dict) -> dict:
    """A capture as RailDash keeps it: `raw` is the interaction's JSON text."""
    return {"raw": json.dumps(capture)}


def test_claude_codes_request_gives_its_seventeen_tools_and_both_mcp_ones():
    found = ts.extract_tool_schemas(stored(CLAUDE))
    tools = {item["tool"]: item for item in found["schemas"]}
    assert set(tools) == CLAUDE_CODE_TOOLS
    assert {item["source"] for item in found["schemas"]} == {ts.SOURCE_MODEL_REQUEST}
    assert {item["host"] for item in found["schemas"]} == {"api.anthropic.com"}
    assert tools["mcp__ide__getDiagnostics"]["input_schema"]["properties"]["uri"]["type"] == "string"
    assert tools["Write"]["input_schema"]["required"] == ["file_path", "content"]


def test_claude_codes_request_without_its_reply_asks_for_nothing():
    """The reply wasn't captured: no call is invented from the request."""
    assert tc.extract_tool_calls(stored(CLAUDE))["calls"] == []
    assert tc.requested_call_count(CLAUDE) == 0


def test_codex_code_mode_asks_for_the_mcp_tool_its_script_calls():
    calls = [tc.extract_tool_calls(stored(capture))["calls"] for capture in CODEX]
    assert [[(c["class"], c["tool"], c["arguments_bytes"]) for c in turn] for turn in calls] == [
        [],  # `ALL_TOOLS.filter(…)`: a lookup, no call
        [(tc.REQUESTED, "mcp__demo__read_doc", 0)],  # its arguments are JavaScript
        [],  # the answer
    ]
    assert [tc.requested_call_count(capture) for capture in CODEX] == [0, 1, 0]


def test_codex_code_mode_is_judged_by_out_of_spec_calls():
    names = [g.requested_tool_calls(normalise(capture)) for capture in CODEX]
    assert names == [
        {"names": [], "readable": True, "reason": None},
        {"names": ["mcp__demo__read_doc"], "readable": True, "reason": None},
        {"names": [], "readable": True, "reason": None},
    ]
    policy = {
        "rules": {
            "uploads": {"allowed_hosts": ["chatgpt.com"], "max_request_bytes": {}, "denied_tool_calls": []},
            "out_of_spec_calls": {"allowed_hosts": ["chatgpt.com"], "allowed_mcp_servers": []},
        }
    }
    [violation] = g.evaluate_request(policy, normalise(CODEX[1]))["out_of_spec_calls"]
    assert (violation["item"], violation["evidence_class"]) == ("mcp__demo", g.REQUESTED)
    policy["rules"]["out_of_spec_calls"]["allowed_mcp_servers"] = ["demo"]
    assert g.evaluate_request(policy, normalise(CODEX[1]))["out_of_spec_calls"] == []


def test_codex_lines_up_with_the_declared_demo_server(tmp_path):
    """The requested call is classified with the declared server's listing
    (the demo's real `tools/list`, DR-205's capture of the same server)."""
    from test_guardrail import declared, v1_bundle

    store = Store(tmp_path / "codex.db")
    bundle = v1_bundle(mcp_servers_declared=declared(
        [{"name": "demo", "url": "https://127.0.0.1:8443/mcp", "transport": "http"}], "ANSWERED"))
    bundle["bundle_id"] = "bnd-codex"
    store.load_asp(json.dumps(bundle, sort_keys=True).encode())
    listing = next(
        json.loads(line) for line in (FIXTURES / "mcp-demo-captures.jsonl").read_text().splitlines()
        if json.loads(line)["request"]["body"].get("method") == "tools/list"
    )
    store.upsert_session("s1")
    rows = [listing, *CODEX]
    store.add_interactions(
        "s1", [normalise({**row, "interaction_id": f"real-{i}"}) for i, row in enumerate(rows)],
        authenticated=True,
    )
    actions = {row["tool"]: row for row in store.data_action_rows(["session:s1"])}
    assert set(actions) == {"mcp__demo__read_doc"}
    assert actions["mcp__demo__read_doc"]["actions"] == ["read"]
    store.close()


def _exec(code: str) -> dict:
    return {"type": "custom_tool_call", "name": "exec", "input": code}


def test_a_script_names_its_tools_however_it_spells_them():
    code = ('await tools.mcp__a__x({}); await tools["mcp__b-c__y"]({}); '
            "await tools?.exec_command('ls'); await tools[`mcp__d__z`](); tools . spaced()")
    assert g.custom_tool_call_names(_exec(code)) == (
        ["mcp__a__x", "mcp__b-c__y", "exec_command", "mcp__d__z", "spaced"], False)
    assert g.custom_tool_call_names(_exec("mytools.x(); tools2.y(); ALL_TOOLS.length")) == ([], False)


def test_a_script_that_builds_a_tool_name_is_unreadable():
    for code in (
        "for (const t of ALL_TOOLS) await tools[t.name]({})",
        "const {mcp__evil__send: send} = tools; await send({})",
        "const t = tools; await t.mcp__evil__send({})",
        "await run(...tools)",
        'await globalThis["to" + "ols"].mcp__evil__send({})',
        'eval("to" + "ols.mcp__evil__send({})")',
        'new Function("return to" + "ols")().mcp__evil__send({})',
    ):
        names, dynamic = g.custom_tool_call_names(_exec(code))
        assert dynamic, code
    reply = {"output": [_exec("await tools.mcp__ok__read({}); await tools[name]({})")]}
    row = normalise({"request": {"method": "POST", "headers": {"host": "chatgpt.com"},
                                 "body": {"model": "m", "input": []}},
                     "response": {"status_code": 200, "body": reply}})
    assert g.requested_tool_calls(row) == {
        "names": ["mcp__ok__read"], "readable": False, "reason": g.RESPONSE_CODE_MODE_DYNAMIC}


def test_another_custom_tool_asks_for_itself_with_its_input():
    reply = {"output": [{"type": "custom_tool_call", "name": "apply_patch", "input": "*** Begin Patch"}]}
    capture = {"request": {"method": "POST", "headers": {"host": "api.openai.com"},
                           "body": {"model": "m", "input": []}},
               "response": {"status_code": 200, "body": reply}}
    [call] = tc.extract_tool_calls(stored(capture))["calls"]
    assert (call["tool"], call["arguments_bytes"]) == ("apply_patch", len("*** Begin Patch"))
    assert g.requested_tool_calls(normalise(capture))["names"] == ["apply_patch"]
