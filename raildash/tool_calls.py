"""Tool calls in captured traffic, with their arguments (DR-205 M1, data-
actions design §4.3).

Two kinds, kept apart as the glossary's evidence classes require:

- **requested**: the model asked for the call in its reply. An Anthropic
  `tool_use` or provider-side `mcp_tool_use` block, an OpenAI Chat
  `tool_calls[]` entry, or an OpenAI Responses `function_call` or
  provider-side `mcp_call` item, whole or streamed. A streamed call's
  arguments are reassembled from their deltas (Anthropic `input_json_delta`,
  Chat `arguments` fragments).
- **observed**: the call went out on the wire: a JSON-RPC `tools/call` in a
  request body (a batch counts), to the request's endpoint (host and path).

Each call carries its arguments' size in bytes, the arguments a schema
doesn't declare, and the content kinds its base64 or media-typed arguments
hold. A requested call is checked against the tool list in the same
request, the schema the model was actually given (design §4.3); an observed
call is checked by the caller, which has the endpoint's listing.

Like `tool_schemas`, this only reads, and nothing here raises on a hostile
shape: what can't be read is left out. A POST whose body isn't JSON-RPC is
reported as `mcp_post_unreadable`, and the caller decides whether its
endpoint is a known MCP endpoint (§4.3, "unreadable calls").
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit

from . import guardrail as g
from . import tool_schemas as ts
from .ingest import MEDIA_TYPE_KINDS, _header, _split_host_path, legacy_exchange
from .json_safety import JSONStructureTooComplex, check_json_structure

REQUESTED = "requested"
OBSERVED = "observed"

MAX_CALLS = 256
# Only the start of a base64 value is decoded to tell its kind.
_MAGIC_PREFIX_CHARS = 64
_MAGIC = (
    (b"\x89PNG", "image"), (b"\xff\xd8\xff", "image"), (b"GIF8", "image"),
    (b"%PDF", "document"), (b"PK\x03\x04", "document"),
    (b"ID3", "audio"), (b"OggS", "audio"), (b"fLaC", "audio"),
)


def call_name(kind: str, name: Any, server: Any = None) -> str | None:
    """A call's tool name as `tool_schemas` names it: a provider-side MCP
    call is `provider-mcp__<server>__<name>`."""
    if not isinstance(name, str) or not name:
        return None
    if kind == "provider":
        if not isinstance(server, str) or not server:
            return None
        return f"{ts.PROVIDER_MCP_PREFIX}{g.normalize_mcp_server(server)}__{name}"
    return name


def _arguments(value: Any) -> Any:
    """Arguments as JSON: OpenAI sends them as a string."""
    if isinstance(value, str):
        try:
            check_json_structure(value)
            return json.loads(value)
        except (JSONStructureTooComplex, ValueError, RecursionError):
            return value
    return value


def argument_bytes(arguments: Any) -> int:
    if arguments is None:
        return 0
    if isinstance(arguments, str):
        return len(arguments.encode("utf-8", "surrogatepass"))
    return len(json.dumps(arguments, ensure_ascii=False, default=str).encode("utf-8", "surrogatepass"))


def undeclared_arguments(arguments: Any, input_schema: Any) -> list[str]:
    """Arguments the schema's top-level `properties` doesn't name (§4.3). An
    explicitly loose schema already makes its tool an upload, so its calls
    aren't flagged argument by argument; no schema, nothing to compare."""
    if not isinstance(arguments, dict) or not isinstance(input_schema, dict):
        return []
    from .data_actions import explicitly_loose

    if explicitly_loose(input_schema):
        return []
    properties = input_schema.get("properties")
    declared = set(properties) if isinstance(properties, dict) else set()
    return sorted(str(name) for name in arguments if name not in declared)


def content_kinds(arguments: Any, input_schema: Any = None) -> list[str]:
    """Kinds (`image`, `document`, `audio`, as RailDash's observed profile
    already names them) of the top-level argument values: a schema's
    `contentMediaType`, else the decoded start of a base64 string."""
    if not isinstance(arguments, dict):
        return []
    properties = input_schema.get("properties") if isinstance(input_schema, dict) else None
    properties = properties if isinstance(properties, dict) else {}
    kinds: set[str] = set()
    for name, value in arguments.items():
        spec = properties.get(name)
        media = spec.get("contentMediaType") if isinstance(spec, dict) else None
        if isinstance(media, str):
            for prefix, kind in MEDIA_TYPE_KINDS:
                if media.lower().startswith(prefix):
                    kinds.add(kind)
        if isinstance(value, str) and len(value) >= 8:
            kind = _magic_kind(value)
            if kind:
                kinds.add(kind)
    return sorted(kinds)


def destination(arguments: Any, input_schema: Any = None) -> dict[str, str]:
    """Destination-hint values (Terms): arguments named like a destination,
    or that the schema marks as a URL. Values are identifiers the user needs
    to see (a repository, a bucket), cut to 200 characters."""
    from .data_actions import DESTINATION_NAMES

    if not isinstance(arguments, dict):
        return {}
    properties = input_schema.get("properties") if isinstance(input_schema, dict) else None
    properties = properties if isinstance(properties, dict) else {}
    out: dict[str, str] = {}
    for name, value in arguments.items():
        if not isinstance(name, str) or isinstance(value, (dict, list)) or value is None:
            continue
        spec = properties.get(name)
        is_url = isinstance(spec, dict) and spec.get("format") in ("uri", "url", "uri-reference")
        if name.lower() in DESTINATION_NAMES or is_url:
            out[name] = str(value)[:200]
        if len(out) >= 8:
            break
    return out


def _magic_kind(value: str) -> str | None:
    text = value
    if text.startswith("data:") and "," in text[:200]:
        text = text.split(",", 1)[1]
    head = text[:_MAGIC_PREFIX_CHARS]
    head = head[: len(head) - len(head) % 4]
    try:
        raw = base64.b64decode(head, validate=True)
    except (binascii.Error, ValueError):
        return None
    for magic, kind in _MAGIC:
        if raw.startswith(magic):
            return kind
    if raw[:4] == b"RIFF" and raw[8:12] in (b"WEBP", b"WAVE"):
        return "image" if raw[8:12] == b"WEBP" else "audio"
    return None


def extract_tool_calls(interaction: Mapping[str, Any]) -> dict[str, Any]:
    """`{calls: [...], mcp_post_unreadable: {endpoint, request_size} | None}`.

    A call is `{class, tool, endpoint, arguments_bytes, undeclared,
    content_kinds, streamed, schema_known}`; `endpoint` is set for an
    observed call. `undeclared` is filled for requested calls only.
    """
    out: dict[str, Any] = {"calls": [], "mcp_post_unreadable": None}
    raw = g._stored_raw(interaction)
    if raw is None:
        return out
    exchange = legacy_exchange(raw)
    request = exchange.get("request") if isinstance(exchange, dict) else None
    if not isinstance(request, dict):
        return out
    raw_host, raw_path = _split_host_path(request)
    host = g.normalize_host(raw_host)
    path = urlsplit(raw_path).path if isinstance(raw_path, str) else ""
    endpoint = f"{host or g.UNKNOWN_HOST}{path or '/'}"
    body = ts._json_body(request.get("body"))
    chunked = (_header(request.get("headers"), "transfer-encoding") or "").lower() == "chunked"

    def add(cls: str, tool: str | None, arguments: Any, *, schema: Any = None,
            schema_known: bool = False, streamed: bool = False, at: str | None = None) -> None:
        if tool is None or len(out["calls"]) >= MAX_CALLS:
            return
        out["calls"].append({
            "class": cls, "tool": tool, "endpoint": at,
            "arguments_bytes": argument_bytes(arguments),
            "undeclared": undeclared_arguments(arguments, schema) if schema_known else [],
            "content_kinds": content_kinds(arguments, schema),
            "destination": destination(arguments, schema),
            "streamed": streamed,
            "schema_known": schema_known,
        })

    # Requested: the model's reply, checked against this request's tools.
    if ts._is_model_request(body):
        given = {
            item["tool"]: item["input_schema"]
            for item in ts.extract_tool_schemas(interaction)["schemas"]
            if item["source"] in (ts.SOURCE_MODEL_REQUEST, ts.SOURCE_PROVIDER_MCP_LIST)
        }
        streamed = _response_is_stream(exchange)
        for kind, name, server, arguments in _requested(exchange):
            tool = call_name(kind, name, server)
            add(REQUESTED, tool, _arguments(arguments), schema=given.get(tool or ""),
                schema_known=(tool in given), streamed=streamed)

    # Observed: JSON-RPC `tools/call` on the wire.
    if (request.get("method") or "").upper() == "POST" and not ts._is_model_request(body):
        messages = body if isinstance(body, list) else [body]
        jsonrpc = [m for m in messages if isinstance(m, dict) and m.get("jsonrpc") == "2.0"]
        for message in jsonrpc:
            if message.get("method") != "tools/call":
                continue
            params = message.get("params")
            params = params if isinstance(params, dict) else {}
            add(OBSERVED, call_name("mcp", params.get("name")), params.get("arguments"),
                streamed=chunked, at=endpoint)
        if not jsonrpc:
            size = interaction.get("request_size")
            out["mcp_post_unreadable"] = {
                "endpoint": endpoint, "request_size": size if isinstance(size, int) else None,
            }
    return out


def _response_is_stream(exchange: Mapping[str, Any]) -> bool:
    response = exchange.get("response")
    if not isinstance(response, dict):
        return False
    media = (_header(response.get("headers"), "content-type") or "").lower()
    return media.startswith("text/event-stream")


def _requested(exchange: Mapping[str, Any]) -> Iterator[tuple[str, Any, Any, Any]]:
    """`(kind, name, server, arguments)` for each call the reply asks for;
    kind is `tool` or `provider`."""
    anthropic: dict[int, dict[str, Any]] = {}
    chat: dict[tuple[int, int], dict[str, Any]] = {}
    for value in ts._response_messages(exchange):
        if not isinstance(value, dict):
            continue
        # Whole replies.
        for block in ts._dicts(value.get("content")):
            if block.get("type") in ("tool_use", "tool_call"):
                yield "tool", block.get("name"), None, block.get("input")
            elif block.get("type") == "mcp_tool_use":
                yield "provider", block.get("name"), block.get("server_name"), block.get("input")
        for choice in ts._dicts(value.get("choices")):
            message = choice.get("message")
            for call in ts._dicts(message.get("tool_calls") if isinstance(message, dict) else None):
                function = call.get("function")
                if isinstance(function, dict):
                    yield "tool", function.get("name"), None, function.get("arguments")
        for item in ts._dicts(value.get("output")):
            yield from _responses_item(item)
        # Streamed events.
        kind = value.get("type")
        index = value.get("index")
        if kind == "content_block_start" and isinstance(index, int):
            block = value.get("content_block")
            if isinstance(block, dict) and block.get("type") in ("tool_use", "mcp_tool_use"):
                anthropic[index] = {"block": block, "json": []}
        elif kind == "content_block_delta" and isinstance(index, int) and index in anthropic:
            delta = value.get("delta")
            if isinstance(delta, dict) and delta.get("type") == "input_json_delta":
                fragment = delta.get("partial_json")
                if isinstance(fragment, str):
                    anthropic[index]["json"].append(fragment)
        elif kind in ("response.output_item.done",):
            item = value.get("item")
            if isinstance(item, dict):
                yield from _responses_item(item)
        for position, choice in enumerate(ts._dicts(value.get("choices"))):
            delta = choice.get("delta")
            for call in ts._dicts(delta.get("tool_calls") if isinstance(delta, dict) else None):
                call_index = call.get("index") if isinstance(call.get("index"), int) else 0
                entry = chat.setdefault((position, call_index), {"name": None, "arguments": []})
                function = call.get("function")
                if isinstance(function, dict):
                    if isinstance(function.get("name"), str):
                        entry["name"] = function["name"]
                    if isinstance(function.get("arguments"), str):
                        entry["arguments"].append(function["arguments"])
    for entry in anthropic.values():
        block = entry["block"]
        arguments = "".join(entry["json"]) if entry["json"] else block.get("input")
        if block.get("type") == "mcp_tool_use":
            yield "provider", block.get("name"), block.get("server_name"), arguments
        else:
            yield "tool", block.get("name"), None, arguments
    for entry in chat.values():
        yield "tool", entry["name"], None, "".join(entry["arguments"])


def _responses_item(item: Mapping[str, Any]) -> Iterator[tuple[str, Any, Any, Any]]:
    if item.get("type") == "function_call":
        yield "tool", item.get("name"), None, item.get("arguments")
    elif item.get("type") == "mcp_call":
        yield "provider", item.get("name"), item.get("server_label"), item.get("arguments")
