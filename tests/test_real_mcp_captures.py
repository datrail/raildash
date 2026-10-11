"""DR-205 M4: golden tests on real captures.

`fixtures/mcp-demo-captures.jsonl` holds five exchanges exactly as RailDash
stored them in datrail-project's stack CI (run 38130045764, the demo agent's
MCP server from railmon#85 tapped through AgentSight): the demo client's
`tools/list` and `read_doc`, and the README's `upload_file` (a PNG),
`export_all` (a tool the server never listed) and a POST that isn't
JSON-RPC. Local, self-signed demo traffic; credential headers are redacted
at ingest. Each is fed back through ingest as RailMon would deliver it.
"""

from __future__ import annotations

import json
from pathlib import Path

from raildash import tool_calls as tc
from raildash import tool_schemas as ts
from raildash.ingest import normalise
from raildash.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "mcp-demo-captures.jsonl"
ENDPOINT = "127.0.0.1/mcp"


def captures() -> dict[str, dict]:
    out = {}
    for line in FIXTURE.read_text().splitlines():
        raw = json.loads(line)
        body = raw["request"]["body"]
        if isinstance(body, dict) and body.get("method") == "tools/call":
            out[body["params"]["name"]] = raw
        elif isinstance(body, dict) and body.get("method"):
            out[body["method"]] = raw
        else:
            out["nonjson"] = raw
    return out


def test_the_real_tools_list_gives_both_schemas():
    found = ts.extract_tool_schemas({"raw": json.dumps(captures()["tools/list"])})
    tools = {item["tool"]: item for item in found["schemas"]}
    assert set(tools) == {"read_doc", "upload_file"}
    assert tools["upload_file"]["endpoint"] == ENDPOINT
    assert tools["upload_file"]["input_schema"]["properties"]["content"]["contentEncoding"] == "base64"


def test_the_real_calls_read_as_observed_calls():
    real = captures()
    upload = tc.extract_tool_calls({"raw": json.dumps(real["upload_file"])})["calls"]
    assert [(c["class"], c["tool"], c["endpoint"], c["content_kinds"]) for c in upload] == [
        ("observed", "upload_file", ENDPOINT, ["image"])]
    garbage = tc.extract_tool_calls({"raw": json.dumps(real["nonjson"]), "request_size": 10})
    assert garbage["calls"] == [] and garbage["mcp_post_unreadable"]["endpoint"] == ENDPOINT


def test_the_real_sequence_on_the_store(tmp_path):
    real = captures()
    store = Store(tmp_path / "real.db")
    store.upsert_session("s1")
    for name in ("tools/list", "read_doc", "upload_file", "export_all", "nonjson"):
        store.add_interactions("s1", [normalise({**real[name], "interaction_id": f"real-{name}"})],
                               authenticated=True)
    rows = {row["tool"]: row for row in store.data_action_rows(["session:s1"])}
    assert rows[f"mcp@{ENDPOINT}__read_doc"]["actions"] == ["read"]
    assert rows[f"mcp@{ENDPOINT}__upload_file"]["actions"] == ["upload"]
    assert rows[f"mcp@{ENDPOINT}__upload_file"]["content_kinds"] == ["image"]
    assert rows[f"mcp@{ENDPOINT}__export_all"]["unclassified"]
    assert rows["(unreadable call)"]["unreadable"]
    store.close()
