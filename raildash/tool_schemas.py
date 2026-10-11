"""Tool schemas from captured traffic (DR-205 M0, data-actions design §4.1).

The schema of every tool an agent can call is already in what RailDash
captures, and nothing needs to be asked of anyone to get it:

- a **model request** lists every tool the model may choose from: an
  Anthropic Messages body's `tools[]` (`name`, `description`,
  `input_schema`), an OpenAI Chat Completions body's `tools[].function`
  (`name`, `description`, `parameters`), or an OpenAI Responses body's
  function `tools[]` (the same three at the top level);
- an MCP server reached over HTTPS answers a JSON-RPC `tools/list` with
  `result.tools[]` (`name`, `description`, `inputSchema`, `annotations`),
  as plain JSON or as an event inside an SSE stream (streamable HTTP);
- an OpenAI Responses reply that used a hosted `mcp` tool carries an
  `mcp_list_tools` output item (`server_label`, `tools[]`).

This module only reads. Which of these a rule may trust is decided where
they are used: a tool list POSTed to a host that is neither the agent's
inference endpoint nor a known provider is kept with its host, and the
classifier (M1) leaves it out. Keeping it costs a row; dropping it at ingest
would need the agent's newest ASP for every captured request.

Nothing here fails closed, unlike `guardrail.requested_tool_calls`: a schema
that can't be read is simply not added, and the schemas a tool already has
stay. Each extraction says why it read nothing (`reason`), for the tests and
for the panel to explain an empty list.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit

from . import guardrail as g
from .ingest import _header, _split_host_path, legacy_exchange
from .json_safety import JSONStructureTooComplex, check_json_structure

SOURCE_MODEL_REQUEST = "model_request"
SOURCE_MCP_TOOLS_LIST = "mcp_tools_list"
SOURCE_PROVIDER_MCP_LIST = "provider_mcp_list"

# Hosts whose model requests are trusted for tools without an ASP saying so
# (design §4.1). The agent's own `inference_endpoint` host is added by the
# classifier from its ASP.
KNOWN_MODEL_HOSTS = (
    "api.anthropic.com",
    "api.openai.com",
    "*.openai.azure.com",
    "openrouter.ai",
)
PROVIDER_MCP_PREFIX = "provider-mcp__"

# Bounds. A tool list is the agent's (or a server's) own writing, so it is
# capped like any other untrusted input: past these, further tools are not
# read, and `reason` says so.
MAX_TOOLS_PER_SOURCE = 512
MAX_SCHEMA_BYTES = 64 * 1024

UNREADABLE = "UNREADABLE_CAPTURE"
NOT_A_TOOL_SOURCE = "NOT_A_TOOL_SOURCE"
TOO_MANY_TOOLS = "TOO_MANY_TOOLS"


def schema_hash(description: Any, input_schema: Any, annotations: Any) -> str:
    """One tool schema's identity: what the model or client is shown."""
    canonical = json.dumps(
        {"description": description, "input_schema": input_schema, "annotations": annotations},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def known_model_host(host: str | None, extra: tuple[str, ...] = ()) -> bool:
    return g.host_allowed(host, (*KNOWN_MODEL_HOSTS, *extra))


def extract_tool_schemas(interaction: Mapping[str, Any]) -> dict[str, Any]:
    """Every tool schema one stored interaction carries.

    Returns `{"schemas": [...], "reason": str | None}`. Each schema is
    `{source, tool, host, endpoint, server, description, input_schema,
    annotations, schema_hash}`: `endpoint` (host and path) is set for an MCP
    `tools/list`, `server` for a provider-side MCP listing, whose `tool` is
    already `provider-mcp__<server>__<name>`.
    """
    raw = g._stored_raw(interaction)
    if raw is None:
        return {"schemas": [], "reason": UNREADABLE}
    exchange = legacy_exchange(raw)
    request = exchange.get("request") if isinstance(exchange, dict) else None
    if not isinstance(request, dict):
        return {"schemas": [], "reason": NOT_A_TOOL_SOURCE}
    raw_host, raw_path = _split_host_path(request)
    host = g.normalize_host(raw_host)
    path = urlsplit(raw_path).path if isinstance(raw_path, str) else ""
    request_body = _json_body(request.get("body"))

    out: list[dict[str, Any]] = []
    capped = False

    def add(source: str, tool: Any, description: Any, input_schema: Any,
            annotations: Any = None, *, endpoint: str | None = None,
            server: str | None = None) -> None:
        nonlocal capped
        if not isinstance(tool, str) or not tool or not isinstance(input_schema, dict):
            return
        if sum(1 for item in out if item["source"] == source) >= MAX_TOOLS_PER_SOURCE:
            capped = True
            return
        description = description if isinstance(description, str) else None
        annotations = annotations if isinstance(annotations, dict) else None
        size = len(json.dumps([description, input_schema, annotations], ensure_ascii=False))
        if size > MAX_SCHEMA_BYTES:
            capped = True
            return
        out.append({
            "source": source, "tool": tool, "host": host, "endpoint": endpoint,
            "server": server, "description": description, "input_schema": input_schema,
            "annotations": annotations,
            "schema_hash": schema_hash(description, input_schema, annotations),
        })

    # A model request's tool list.
    if _is_model_request(request_body):
        for item in _dicts(request_body.get("tools")):
            function = item.get("function")
            if item.get("type") == "function" and isinstance(function, dict):
                # OpenAI Chat Completions.
                add(SOURCE_MODEL_REQUEST, function.get("name"), function.get("description"),
                    function.get("parameters"))
            elif item.get("type") == "function":
                # OpenAI Responses.
                add(SOURCE_MODEL_REQUEST, item.get("name"), item.get("description"),
                    item.get("parameters"))
            elif "input_schema" in item:
                # Anthropic Messages (client tools; server tools carry none).
                add(SOURCE_MODEL_REQUEST, item.get("name"), item.get("description"),
                    item.get("input_schema"))
        # A hosted MCP tool's listing comes back in the reply.
        for item in _response_items(exchange):
            if item.get("type") == "mcp_list_tools":
                label = item.get("server_label")
                if not isinstance(label, str) or not label:
                    continue
                server = g.normalize_mcp_server(label)
                for tool in _dicts(item.get("tools")):
                    name = tool.get("name")
                    add(SOURCE_PROVIDER_MCP_LIST,
                        f"{PROVIDER_MCP_PREFIX}{server}__{name}" if isinstance(name, str) else None,
                        tool.get("description"), tool.get("input_schema"),
                        tool.get("annotations"), server=server)

    # An MCP server's answer to `tools/list`.
    ids = _tools_list_ids(request_body)
    if ids:
        endpoint = f"{host or g.UNKNOWN_HOST}{path or '/'}"
        for message in _jsonrpc_replies(exchange):
            if message.get("id") not in ids:
                continue
            result = message.get("result")
            for tool in _dicts(result.get("tools") if isinstance(result, dict) else None):
                add(SOURCE_MCP_TOOLS_LIST, tool.get("name"), tool.get("description"),
                    tool.get("inputSchema"), tool.get("annotations"), endpoint=endpoint)

    if capped:
        return {"schemas": out, "reason": TOO_MANY_TOOLS}
    if not out and not _is_model_request(request_body) and not ids:
        return {"schemas": out, "reason": NOT_A_TOOL_SOURCE}
    return {"schemas": out, "reason": None}


def _json_body(body: Any) -> Any:
    """A request or response body as JSON: RailMon stores JSON parsed, and
    anything else as `{"raw": text}`, which is tried once, within bounds."""
    if isinstance(body, dict) and set(body) == {"raw"} and isinstance(body["raw"], str):
        text = body["raw"]
        try:
            check_json_structure(text)
            return json.loads(text)
        except (JSONStructureTooComplex, ValueError, RecursionError):
            return body
    return body


def _is_model_request(body: Any) -> bool:
    return isinstance(body, dict) and "model" in body and ("messages" in body or "input" in body)


def _tools_list_ids(body: Any) -> set[Any]:
    """The JSON-RPC ids of `tools/list` requests in a body (a batch counts)."""
    messages = body if isinstance(body, list) else [body]
    return {
        message.get("id") for message in _dicts(messages)
        if message.get("method") == "tools/list" and "id" in message
        and isinstance(message.get("id"), (str, int))
    }


def _response(exchange: Mapping[str, Any]) -> dict[str, Any] | None:
    response = exchange.get("response")
    if not isinstance(response, dict):
        return None
    encoding = _header(response.get("headers"), "content-encoding")
    if encoding is not None and encoding.strip().lower() not in ("", "identity"):
        return None
    return response


def _response_messages(exchange: Mapping[str, Any]) -> Iterator[Any]:
    """The response body's JSON values: the body itself, or each SSE event's
    data. An event that isn't JSON is skipped (§ module docstring)."""
    response = _response(exchange)
    if response is None:
        return
    body = response.get("body")
    text = body.get("raw") if isinstance(body, dict) and set(body) == {"raw"} else None
    if not isinstance(text, str):
        yield body
        return
    if len(text.encode("utf-8", "surrogatepass")) > g.MAX_SCANNED_RESPONSE_BYTES:
        return
    parsed = _json_body(body)
    if parsed is not body:
        yield parsed
        return
    for data in _sse_data(text):
        if data.strip() == "[DONE]":
            continue
        try:
            check_json_structure(data)
            yield json.loads(data)
        except (JSONStructureTooComplex, ValueError, RecursionError):
            continue


def _sse_data(text: str) -> Iterator[str]:
    """Each event's joined `data:` lines, per the SSE line rules
    `guardrail.requested_tool_calls` documents."""
    data: list[str] | None = None
    lines = g._SSE_LINE_END.split(text)
    for line in [*lines, ""]:
        if line == "":
            if data is not None:
                yield "\n".join(data)
            data = None
            continue
        field, _, value = line.partition(":")
        if field == "data":
            data = data if data is not None else []
            data.append(value[1:] if value.startswith(" ") else value)


def _jsonrpc_replies(exchange: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    for value in _response_messages(exchange):
        yield from _dicts(value if isinstance(value, list) else [value])


def _response_items(exchange: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """OpenAI Responses output items, from a whole reply or its stream's
    `response.output_item.done` events."""
    for value in _response_messages(exchange):
        if not isinstance(value, dict):
            continue
        yield from _dicts(value.get("output"))
        if value.get("type") == "response.output_item.done" and isinstance(value.get("item"), dict):
            yield value["item"]


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
