"""Body kinds: whether a REST request's body is an upload or only passes
parameters (REST uploads design §3, M1).

Each captured REST request that carries a body gets one of three kinds,
with the step that decided it and its reasons. The first step that decides
wins:

1. hard upload signals, which nothing below can overrule: a file media type
   (multipart, `octet-stream`, `image/*`, `audio/*`, `video/*`, PDF, zip),
   a body over 16 KiB, or a string over 1 KiB anywhere in it (a GraphQL
   body's `query` text excepted: step 4 bounds it);
2. a user override, keyed by host, method and path template;
3. an imported spec, which can only tighten (M3; not read here yet);
4. the body's shape: a JSON object or urlencoded form of at most 4 KiB,
   whose keys and values are all short scalars (strings of at most 256
   characters), nested at most 4 deep, with at most 64 values, is
   `parameters`; so is a GraphQL body of query operations only, within
   the same bounds and 8 KiB overall;
5. anything else is `unknown`, which the `uploads` rule reads as an upload.

A model request (DR-205's shape) or an MCP JSON-RPC message is never
classified: it isn't a REST request, so its body stays an upload, exactly
as today (§4, "Model and MCP traffic").

The drip check needs history, so it is a separate counter
(`ParametersBudget`) that the store applies to this module's answers in
capture-time order: past 256 KiB of `parameters` bytes a day for one
`out_of_spec_calls` entry, or 1 MiB for the agent, further `parameters`
bodies count as `upload`.

This module is pure: no storage, no network.
"""

from __future__ import annotations

import json
import re
from collections import deque
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl

from .ingest import _split_host_path
from .json_safety import JSONStructureTooComplex, check_json_structure

UPLOAD = "upload"
PARAMETERS = "parameters"
UNKNOWN = "unknown"
KINDS = (UPLOAD, PARAMETERS, UNKNOWN)

SOURCE_TRAFFIC = "traffic"  # a model or MCP request: not classified (§4)
SOURCE_HARD = "hard"
SOURCE_USER = "user"
SOURCE_SHAPE = "shape"

# The step that decided a body (§4, "Re-checking stored rows"): an override
# clears only a row decided by steps 3-5, and none decided by step 1 or by
# the drip check.
STEP_NOT_REST = 0
STEP_HARD = 1
STEP_OVERRIDE = 2
STEP_SPEC = 3
STEP_SHAPE = 4
STEP_OTHER = 5
STEP_DRIP = 6

# Bumped when a bound or a step changes, so stored kinds are redone (§4,
# "Versioning").
BODY_KIND_VERSION = 1

MAX_BODY_BYTES = 16 * 1024
MAX_STRING_CHARS = 1024
MAX_PARAMETERS_BYTES = 4 * 1024
MAX_PARAMETER_CHARS = 256
MAX_PARAMETERS_DEPTH = 4
MAX_PARAMETERS_VALUES = 64
MAX_GRAPHQL_QUERY_BYTES = 4 * 1024
MAX_GRAPHQL_BYTES = 8 * 1024

DAY_SECONDS = 24 * 60 * 60
ENTRY_BUDGET_BYTES = 256 * 1024
AGENT_BUDGET_BYTES = 1024 * 1024

MAX_REASONS = 8

FILE_MEDIA_TYPES = frozenset(
    ("application/octet-stream", "application/pdf", "application/zip")
)
FILE_MEDIA_FAMILIES = ("multipart/", "image/", "audio/", "video/")
FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"
GRAPHQL_KEYS = frozenset(("query", "variables", "operationName"))

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_OPAQUE_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.~=%")
_EOL = re.compile(r"[\n\r]")


# ----------------------------------------------------------------- inputs


def _header(headers: Any, name: str) -> str | None:
    if not isinstance(headers, Mapping):
        return None
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name:
            if isinstance(value, (list, tuple)):
                return ", ".join(str(v) for v in value)
            return value if isinstance(value, str) else None if value is None else str(value)
    return None


def media_types(headers: Any) -> list[str]:
    """Every media type the request's `Content-Type` names, without
    parameters, lower-cased. RailMon joins a repeated header with `, `, so
    `application/json, multipart/form-data` names two."""
    value = _header(headers, "content-type")
    if value is None:
        return []
    found = []
    for part in value.split(","):
        mtype = part.split(";", 1)[0].strip().lower()
        if "/" in mtype:
            found.append(mtype)
    return found


def _raw_text(body: Any) -> str | None:
    """The text RailMon kept for a body that wasn't a JSON object."""
    if isinstance(body, dict) and set(body) == {"raw"} and isinstance(body["raw"], str):
        return body["raw"]
    if isinstance(body, str):
        return body
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value) if isinstance(value, (int, float)) else int(str(value).strip())
    except (ValueError, OverflowError):
        return None


def body_bytes(body: Any, headers: Any = None, framed: Any = None) -> int:
    """The body's size: the larger of what was kept and what was framed.

    RailMon keeps a JSON object parsed and anything else as `{"raw": text}`.
    The kept object can be smaller than what was sent (a body the capture
    cut, or a repeated JSON key of which the parser kept the last), so a
    larger `Content-Length` or `framed` (the exchange's own size, see
    `framed_bytes`) counts instead.
    """
    text = _raw_text(body)
    if text is not None:
        kept = len(text.encode("utf-8", "surrogatepass"))
    elif body is None:
        kept = 0
    else:
        kept = len(json.dumps(body, separators=(",", ":"), ensure_ascii=False)
                   .encode("utf-8", "surrogatepass"))
    sizes = [kept]
    for value in (_header(headers, "content-length"), framed):
        size = _as_int(value)
        if size is not None:
            sizes.append(size)
    return max(sizes)


def framed_bytes(exchange: Mapping[str, Any]) -> int | None:
    """What the capture says the request's body was, or `None` when it says
    nothing: the parser's own `content_length` when it kept one, else the
    exchange's `request_size` less its request line and the headers that
    were kept.

    Headers RailMon removed (credentials, cookies) are still in
    `request_size`, so for an HTTP/1 request that estimate overstates the
    body, which errs towards an upload; it is used only when no length was
    kept (a chunked request). An HTTP/2 head is compressed, so there it can
    understate, and the kept body's own size is the floor.
    """
    request = exchange.get("request")
    request = request if isinstance(request, dict) else {}
    exact = _as_int(request.get("content_length"))
    if exact is not None:
        return exact
    total = _as_int(exchange.get("request_size"))
    if total is None:
        return None
    head = len(str(request.get("first_line") or "")) + 4
    headers = request.get("headers")
    if isinstance(headers, Mapping):
        head += sum(len(str(k)) + len(str(v)) + 4 for k, v in headers.items())
    return max(total - head, 0)


class _RepeatedKey(ValueError):
    pass


def _no_repeated_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise _RepeatedKey
    return out


def _json_value(body: Any) -> tuple[Any, bool, str | None]:
    """The body as JSON, whether it parsed, and why not: a kept object as
    itself, a kept text tried once within RailDash's JSON bounds. A text
    that repeats a key doesn't parse: a decoder keeps one of the values, so
    what was read wouldn't be all that was sent."""
    text = _raw_text(body)
    if text is None:
        return body, isinstance(body, dict), None
    try:
        check_json_structure(text)
        return json.loads(text, object_pairs_hook=_no_repeated_keys), True, None
    except _RepeatedKey:
        return text, False, "a repeated JSON key"
    except (JSONStructureTooComplex, ValueError, RecursionError):
        return text, False, None


def _kept_bytes_upper(value: Any) -> int:
    """The most a request could have taken to send a kept JSON object: its
    compact text (escaped, the larger form) plus generous room for
    whitespace around every token. More framed than this means the parser
    kept less than was sent (a repeated key keeps only its last value)."""
    tokens = sum(1 for _ in _strings(value)) + _other_tokens(value)
    compact = len(json.dumps(value, separators=(",", ":"), ensure_ascii=True))
    return compact + 16 * tokens + 64


def _other_tokens(value: Any) -> int:
    """Containers and non-string scalars in a JSON value."""
    count, stack = 0, [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            count += 1 + sum(1 for v in item.values() if not isinstance(v, (dict, list, str)))
            stack.extend(item.values())
        elif isinstance(item, list):
            count += 1 + sum(1 for v in item if not isinstance(v, (dict, list, str)))
            stack.extend(item)
    return count


def is_model_request(body: Any) -> bool:
    """DR-205's model-request shape (`tool_schemas._is_model_request`)."""
    return isinstance(body, dict) and "model" in body and ("messages" in body or "input" in body)


def is_jsonrpc(body: Any) -> bool:
    """A JSON-RPC 2.0 message, or a batch with one in it (MCP's framing)."""
    messages = body if isinstance(body, list) else [body]
    return any(isinstance(m, dict) and m.get("jsonrpc") == "2.0" for m in messages)


def path_template(path: Any) -> str:
    """§3 step 2's key without a spec: the literal path, query string
    dropped, with each all-digit, UUID or opaque segment (20 or more
    characters, a digit among them) as `*`. A long name of letters only
    (`searchDocumentsQuickly`) is a name, not an id, so it stays."""
    if not isinstance(path, str) or not path:
        return "/"
    path = path.split("?", 1)[0].split("#", 1)[0] or "/"
    out = []
    for segment in path.split("/"):
        if segment and (
            segment.isdigit()
            or _UUID.fullmatch(segment)
            or (len(segment) >= 20 and set(segment) <= _OPAQUE_CHARS
                and any(c.isdigit() for c in segment))
        ):
            out.append("*")
        else:
            out.append(segment)
    return "/".join(out)


# ------------------------------------------------------------------ shape


def _strings(value: Any, skip: Any = None) -> Iterable[str]:
    """Every key and string value in a JSON value, `skip` (one object
    member, by identity of its parent and key) left out."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            for key, child in item.items():
                yield key
                if skip is not None and skip == (id(item), key):
                    continue
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)


def _bounded(value: Any, depth: int, count: list[int]) -> str | None:
    """Why a JSON value isn't parameters-shaped, or `None` when it is."""
    if isinstance(value, (dict, list)) and depth > MAX_PARAMETERS_DEPTH:
        return f"nested over {MAX_PARAMETERS_DEPTH} deep"
    if isinstance(value, dict):
        children = []
        for key, child in value.items():
            if len(key) > MAX_PARAMETER_CHARS:
                return f"a key over {MAX_PARAMETER_CHARS} characters"
            children.append(child)
    elif isinstance(value, list):
        children = value
    else:
        count[0] += 1
        if count[0] > MAX_PARAMETERS_VALUES:
            return f"over {MAX_PARAMETERS_VALUES} values"
        if isinstance(value, str) and len(value) > MAX_PARAMETER_CHARS:
            return f"a string over {MAX_PARAMETER_CHARS} characters"
        return None
    for child in children:
        reason = _bounded(child, depth + 1, count)
        if reason is not None:
            return reason
    return None


_GRAPHQL_TOKEN = re.compile(
    r'''
      (?P<skip>[\s,﻿]+|\#[^\n\r]*)
    | (?P<block>"""(?:\\"""|[^"]|"(?!""))*""")
    | (?P<string>"(?:\\.|[^"\\\n\r])*")
    | (?P<number>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)
    | (?P<name>[_A-Za-z][_0-9A-Za-z]*)
    | (?P<punct>\.\.\.|[!$&()\:=@\[\]{|}])
    ''',
    re.X,
)
_GRAPHQL_START = re.compile(r"\{|(?:query|mutation|subscription|fragment)\b")


def _graphql_start(text: str) -> bool:
    """Whether a document's first token, after whitespace and `#` comments,
    begins a definition. A loop, not one regex: two patterns that can match
    the same characters backtrack exponentially on a failed match, as
    DR-239 (#100) found in `guardrail.py`."""
    pos = 0
    while True:
        while pos < len(text) and text[pos] in " \t\n\r,\ufeff":
            pos += 1
        if pos < len(text) and text[pos] == "#":
            eol = _EOL.search(text, pos)
            pos = eol.start() if eol else len(text)
            continue
        return bool(_GRAPHQL_START.match(text, pos))


def looks_like_graphql(body: Any) -> bool:
    """A JSON object of GraphQL's request members whose `query` starts like
    a GraphQL document. A search API's `{"query": "invoices"}` doesn't."""
    return (
        isinstance(body, dict)
        and isinstance(body.get("query"), str)
        and set(body) <= GRAPHQL_KEYS
        and _graphql_start(body["query"])
    )


def graphql_queries_only(text: str) -> str | None:
    """Why a GraphQL document isn't only query operations and fragments, or
    `None` when it is. A lexer plus the top-level structure: each definition
    is an anonymous `{…}`, `query …{…}` or `fragment …{…}`, brackets balance,
    and no comment, string or run of space is over 1 KiB."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = _GRAPHQL_TOKEN.match(text, pos)
        if match is None:
            return "not a GraphQL document"
        pos = match.end()
        if len(match.group()) > MAX_STRING_CHARS:
            # A comment or string literal is room for data, not a query.
            return f"a GraphQL comment or string over {MAX_STRING_CHARS // 1024} KiB"
        if match.lastgroup != "skip":
            tokens.append((match.lastgroup or "", match.group()))
    if not tokens:
        return "an empty GraphQL document"
    closing = {"{": "}", "(": ")", "[": "]"}
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "name" and value in ("mutation", "subscription"):
            return f"a GraphQL {value}"
        if not (value == "{" or (kind == "name" and value in ("query", "fragment"))):
            return "not a GraphQL document"
        # Up to this definition's selection set, then through its close.
        while i < len(tokens) and tokens[i][1] != "{":
            if tokens[i][1] in ("}", ")", "]"):
                return "not a GraphQL document"
            if tokens[i][1] in ("(", "["):
                stack = [tokens[i][1]]
                i += 1
                while i < len(tokens) and stack:
                    v = tokens[i][1]
                    if v in closing:
                        stack.append(v)
                    elif v in ("}", ")", "]"):
                        if closing[stack.pop()] != v:
                            return "not a GraphQL document"
                    i += 1
                if stack:
                    return "not a GraphQL document"
                continue
            i += 1
        if i == len(tokens):
            return "not a GraphQL document"
        stack = []
        while i < len(tokens):
            v = tokens[i][1]
            if v in closing:
                stack.append(v)
            elif v in ("}", ")", "]"):
                if not stack or closing[stack.pop()] != v:
                    return "not a GraphQL document"
            i += 1
            if not stack:
                break
        if stack:
            return "not a GraphQL document"
    return None


def _shape(value: Any, parsed: bool, mtype: str | None, size: int) -> tuple[str, list[str]]:
    """Step 4, then 5: `parameters` with what it is, else `unknown` with why."""
    if mtype == FORM_MEDIA_TYPE and isinstance(value, str):
        if size > MAX_PARAMETERS_BYTES:
            return UNKNOWN, [f"form over {MAX_PARAMETERS_BYTES // 1024} KiB"]
        try:
            pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=True,
                              max_num_fields=MAX_PARAMETERS_VALUES)
        except ValueError:
            return UNKNOWN, ["not a urlencoded form"]
        if any(len(k) > MAX_PARAMETER_CHARS or len(v) > MAX_PARAMETER_CHARS for k, v in pairs):
            return UNKNOWN, [f"a form value over {MAX_PARAMETER_CHARS} characters"]
        return PARAMETERS, [f"form, {len(pairs)} short values"]
    if value is None:
        return UNKNOWN, ["body not kept by the capture"]
    if not parsed:
        return UNKNOWN, ["not JSON" if mtype is None or "json" in mtype else f"{mtype} body"]
    if not isinstance(value, dict):
        return UNKNOWN, ["JSON, not an object"]
    if looks_like_graphql(value):
        if size > MAX_GRAPHQL_BYTES:
            return UNKNOWN, [f"GraphQL body over {MAX_GRAPHQL_BYTES // 1024} KiB"]
        query = value["query"]
        if len(query.encode("utf-8", "surrogatepass")) > MAX_GRAPHQL_QUERY_BYTES:
            return UNKNOWN, [f"GraphQL query over {MAX_GRAPHQL_QUERY_BYTES // 1024} KiB"]
        reason = graphql_queries_only(query)
        if reason is not None:
            return UNKNOWN, [reason]
        variables = value.get("variables")
        if variables is not None:
            if not isinstance(variables, dict):
                return UNKNOWN, ["GraphQL variables, not an object"]
            if len(json.dumps(variables, separators=(",", ":"), ensure_ascii=False)
                   .encode("utf-8", "surrogatepass")) > MAX_PARAMETERS_BYTES:
                return UNKNOWN, [f"GraphQL variables over {MAX_PARAMETERS_BYTES // 1024} KiB"]
            reason = _bounded(variables, 1, [0])
            if reason is not None:
                return UNKNOWN, [f"GraphQL variables: {reason}"]
        if value.get("operationName") is not None and not (
            isinstance(value["operationName"], str) and len(value["operationName"]) <= MAX_PARAMETER_CHARS
        ):
            return UNKNOWN, ["GraphQL operationName, not a short string"]
        return PARAMETERS, ["GraphQL query"]
    if size > MAX_PARAMETERS_BYTES:
        return UNKNOWN, [f"JSON over {MAX_PARAMETERS_BYTES // 1024} KiB"]
    count = [0]
    reason = _bounded(value, 1, count)
    if reason is not None:
        return UNKNOWN, [f"JSON with {reason}"]
    return PARAMETERS, [f"JSON object, {count[0]} short values"]


# --------------------------------------------------------------- classify


def _result(kind: str, source: str, step: int, reasons: list[str], template: str,
            size: int) -> dict[str, Any]:
    return {
        "kind": kind, "source": source, "step": step, "reasons": reasons[:MAX_REASONS],
        "path_template": template, "bytes": size, "version": BODY_KIND_VERSION,
    }


def _override(overrides: Iterable[Mapping[str, Any]], host: str | None, method: str,
              template: str) -> str | None:
    """Step 2: the user's kind for this host, method and path template."""
    for item in overrides or ():
        if (
            host is not None
            and isinstance(item, Mapping)
            and item.get("kind") in (UPLOAD, PARAMETERS)
            and item.get("host") == host
            and str(item.get("method") or "").upper() == method
            and item.get("path") == template
        ):
            return item["kind"]
    return None


def classify(
    *,
    method: Any,
    host: str | None,
    path: Any,
    headers: Any,
    body: Any,
    framed: Any = None,
    exact: Any = None,
    size_known: bool = True,
    overrides: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """One request that carries a body: its kind, the source and step that
    decided it, reasons, path template and size (§3 steps 1-5).

    `host` is compared as the caller normalized it. `framed` is the size
    the capture recorded (`framed_bytes`), which can overstate the body;
    `exact` is the parser's own body length, if it kept one, and with
    `Content-Length` is what shows a kept object is less than was sent.
    `size_known=False` says it
    recorded none and no `Content-Length` was sent either, so the kept body
    alone can't show the request was small, and it isn't parameters.
    """
    method = str(method or "").upper()
    template = path_template(path)
    size = max(body_bytes(body, headers, framed), body_bytes(None, None, exact))
    mtypes = media_types(headers)
    text = _raw_text(body)
    if size > MAX_BODY_BYTES and text is not None and text.lstrip()[:1] not in ("[", "{"):
        # Not JSON, so not model or MCP traffic either: an upload, unparsed.
        hard = [f"{t} body" for t in mtypes
                if t in FILE_MEDIA_TYPES or t.startswith(FILE_MEDIA_FAMILIES)]
        return _result(UPLOAD, SOURCE_HARD, STEP_HARD,
                       hard + [f"body over {MAX_BODY_BYTES // 1024} KiB"], template, size)
    value, parsed, unparsed = _json_value(body)

    if is_model_request(value) or is_jsonrpc(value):
        return _result(UPLOAD, SOURCE_TRAFFIC, STEP_NOT_REST,
                       ["model request" if is_model_request(value) else "MCP message"],
                       template, size)

    # Step 1: hard upload signals.
    # A repeated Content-Type names two kinds: the body is neither for sure.
    mtype = mtypes[0] if len(mtypes) == 1 else None
    hard = [f"{t} body" for t in mtypes if t in FILE_MEDIA_TYPES or t.startswith(FILE_MEDIA_FAMILIES)]
    if size > MAX_BODY_BYTES:
        hard.append(f"body over {MAX_BODY_BYTES // 1024} KiB")
        return _result(UPLOAD, SOURCE_HARD, STEP_HARD, hard, template, size)
    if parsed:
        # A GraphQL query's text is bounded by step 4 instead, but only a
        # query-only document within that bound: anything else in `query`
        # is one more string here, so an override can't clear it.
        skip = None
        if looks_like_graphql(value):
            query = value["query"]
            if (len(query.encode("utf-8", "surrogatepass")) <= MAX_GRAPHQL_QUERY_BYTES
                    and graphql_queries_only(query) is None):
                skip = (id(value), "query")
        strings: Iterable[str] = _strings(value, skip)
    elif isinstance(value, str) and mtype == FORM_MEDIA_TYPE:
        strings = [s for pair in parse_qsl(value, keep_blank_values=True) for s in pair]
    else:
        # Text that is neither JSON nor a form is one string.
        strings = [value] if isinstance(value, str) else []
    if any(len(s) > MAX_STRING_CHARS for s in strings):
        hard.append(f"a string over {MAX_STRING_CHARS // 1024} KiB")
    if hard:
        return _result(UPLOAD, SOURCE_HARD, STEP_HARD, hard, template, size)

    # Step 2: the user's override.
    kind = _override(overrides, host, method, template)
    if kind is not None:
        return _result(kind, SOURCE_USER, STEP_OVERRIDE, [f"you marked this {kind}"], template, size)

    # Step 3 (an imported spec) is M3. Steps 4 and 5: the body's shape, read
    # only when the capture shows all of it, as sent.
    encoding = (_header(headers, "content-encoding") or "").strip().lower()
    if encoding not in ("", "identity"):
        return _result(UNKNOWN, SOURCE_SHAPE, STEP_OTHER, [f"{encoding}-encoded body"], template, size)
    if not size_known:
        return _result(UNKNOWN, SOURCE_SHAPE, STEP_OTHER, ["body size not recorded"], template, size)
    if len(mtypes) > 1:
        return _result(UNKNOWN, SOURCE_SHAPE, STEP_OTHER, ["two content types"], template, size)
    if unparsed is not None:
        return _result(UNKNOWN, SOURCE_SHAPE, STEP_OTHER, [unparsed], template, size)
    sent = [n for n in (_as_int(exact), _as_int(_header(headers, "content-length"))) if n is not None]
    if parsed and _raw_text(body) is None and sent and max(sent) > _kept_bytes_upper(value):
        return _result(UNKNOWN, SOURCE_SHAPE, STEP_OTHER, ["more sent than was kept"], template, size)
    kind, reasons = _shape(value, parsed, mtype, size)
    step = STEP_SHAPE if kind == PARAMETERS else STEP_OTHER
    return _result(kind, SOURCE_SHAPE, step, reasons, template, size)


def classify_exchange(
    exchange: Mapping[str, Any],
    *,
    host: str | None,
    overrides: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """`classify` over one captured legacy exchange's request, its path
    read as ingest reads it (`path`, `uri` or `:path`, origin-form)."""
    request = exchange.get("request")
    request = request if isinstance(request, dict) else {}
    framed = framed_bytes(exchange)
    return classify(
        method=request.get("method"), host=host, path=_split_host_path(request)[1],
        headers=request.get("headers"), body=request.get("body"), framed=framed,
        exact=request.get("content_length"),
        size_known=framed is not None or _header(request.get("headers"), "content-length") is not None,
        overrides=overrides,
    )


def request_carries_body(request: Mapping[str, Any]) -> bool:
    """DR-184 §4.3: a request's `body` is present and not empty, or it has a
    `Content-Length` above zero (one that isn't a number still says a body
    was framed)."""
    if request.get("body") not in (None, ""):
        return True
    length = _header(request.get("headers"), "content-length")
    try:
        return length is not None and int(length.strip()) > 0
    except ValueError:
        return True


# What `stored_kind` gives a model or MCP request, which is never classified.
STORED_TRAFFIC = "traffic"


def stored_kind(exchange: Any) -> str:
    """The body kind an interaction row keeps (REST uploads §4 "What's
    stored"): the classifier's kind with no user answer, `traffic` for a
    model or MCP request, `""` with no body. An exchange that can't be read
    (None), or that the classifier can't finish, is `unknown`."""
    if not isinstance(exchange, Mapping):
        return UNKNOWN
    request = exchange.get("request")
    if not isinstance(request, Mapping):
        return ""
    if not request_carries_body(request):
        return ""
    try:
        found = classify_exchange(exchange, host=None)
    except Exception:  # noqa: BLE001 - fail closed, never stop ingest
        return UNKNOWN
    return STORED_TRAFFIC if found["source"] == SOURCE_TRAFFIC else str(found["kind"])


# ------------------------------------------------------------- drip check


def _bytes_text(n: int) -> str:
    if n and n % (1024 * 1024) == 0:
        return f"{n // (1024 * 1024)} MiB"
    return f"{n // 1024} KiB" if n and n % 1024 == 0 else f"{n} bytes"


class ParametersBudget:
    """§3's drip check for one agent, fed in capture-time order.

    `observe` takes one classified body, the `out_of_spec_calls` entries its
    host matches (or the host itself when it matches none) and the capture
    time in seconds. A `parameters` body that would take any of those
    entries past its day's budget, or the agent past its own, counts as
    `upload` instead (reason `parameters volume over …`) and adds nothing
    to the sums, so they fall back below as the day moves on. Every other
    kind passes through unchanged and is not counted.
    """

    def __init__(self, *, entry_budgets: Mapping[str, int] | None = None,
                 entry_budget: int = ENTRY_BUDGET_BYTES, agent_budget: int = AGENT_BUDGET_BYTES,
                 window: int = DAY_SECONDS) -> None:
        self.entry_budgets = dict(entry_budgets or {})
        self.entry_budget = entry_budget
        self.agent_budget = agent_budget
        self.window = window
        self._seen: deque[tuple[float, tuple[str, ...], int]] = deque()
        self._sums: dict[str, int] = {}
        self._agent = 0
        self._now = float("-inf")

    def _expire(self, at: float) -> None:
        self._now = max(self._now, at)
        while self._seen and self._seen[0][0] <= self._now - self.window:
            _, keys, size = self._seen.popleft()
            self._agent -= size
            for key in keys:
                self._sums[key] -= size

    def observe(self, result: Mapping[str, Any], keys: Iterable[str], at: float) -> dict[str, Any]:
        self._expire(at)
        if result.get("kind") != PARAMETERS:
            return dict(result)
        keys = tuple(dict.fromkeys(keys))
        size = int(result.get("bytes") or 0)
        sums = {key: self._sums.get(key, 0) for key in keys}
        over = [
            f"parameters volume over {_bytes_text(self.entry_budgets.get(key, self.entry_budget))} "
            f"a day to {key}"
            for key in keys
            if sums[key] + size > self.entry_budgets.get(key, self.entry_budget)
        ]
        if self._agent + size > self.agent_budget:
            over.append(f"parameters volume over {_bytes_text(self.agent_budget)} a day for the agent")
        if over:
            return {
                **result, "kind": UPLOAD, "step": STEP_DRIP,
                "reasons": (over + list(result.get("reasons") or []))[:MAX_REASONS],
                "drip": {"entries": sums, "agent": self._agent, "bytes": size},
            }
        self._seen.append((self._now, keys, size))
        self._agent += size
        for key in keys:
            self._sums[key] = sums[key] + size
        return dict(result)
