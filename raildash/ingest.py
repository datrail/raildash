"""Turn a RailMon interaction into a row this dashboard can index.

The shape is not guessed. RailMon's collector emits, per interaction
(`src/pipeline.rs`):

    {
      "timestamp":     "2026-08-15T17:04:11.412Z",
      "timestamp_ns":  1786...,
      "pid": 4021, "tid": 4033,
      "request":       {...} | null,
      "response":      {...},
      "request_size":  1180,
      "response_size": 24010,
      "latency_ms":    503.0 | null
    }

and the webhook wraps batches of those in

    {"session_id": ..., "agent": ..., "capture_start": ..., "interactions": [...]}

`request` is null when the HEADERS frame of an HTTP/2 stream was never decoded
— normal for a connection already open when the probe attached — so nothing
here may assume it exists. `latency_ms` is null when the response arrived
without a matching request. Both are ordinary, not corruption.

Everything the row stores is derived; `raw` keeps the interaction for the
detail view, with credential-bearing headers replaced before persistence.
Bodies are otherwise unchanged and remain sensitive capture data.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

# Header names are matched case-insensitively throughout: AgentSight preserves
# whatever the wire carried, and HTTP/2 lowercases while HTTP/1.1 does not.

CREDENTIAL_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "x-goog-api-key",
        "x-auth-token",
        "x-access-token",
        "x-session-token",
        "cookie",
        "set-cookie",
        "token",
        "bearer",
        # DatRail's ticket is itself a bearer credential. RailMon needs it long
        # enough to attribute an interaction, but RailDash must never persist
        # or display its value.
        "x-rail",
    }
)
REDACTED = "[REDACTED-BY-RAILDASH]"


def _redact_header_lines(text: str) -> str:
    """Scrub credentials from the header block of raw HTTP wire text."""
    changed = False
    in_headers = True
    redacting_continuation = False
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        trimmed = line.rstrip("\r\n")
        ending = line[len(trimmed) :]
        if not in_headers and _is_http_start_line(trimmed):
            # One SSL read can contain more than one HTTP message.  A blank
            # line ends one header block, but a recognised request/status line
            # starts the next one.
            in_headers = True
        if in_headers and not trimmed:
            in_headers = False
            redacting_continuation = False
        if in_headers and trimmed.startswith((" ", "\t")):
            if redacting_continuation:
                indentation = trimmed[: len(trimmed) - len(trimmed.lstrip(" \t"))]
                out.append(f"{indentation}{REDACTED}{ending}")
                changed = True
                continue
            out.append(line)
            continue
        redacting_continuation = False
        if in_headers and ":" in trimmed:
            name, _value = trimmed.split(":", 1)
            if name.strip().casefold() in CREDENTIAL_HEADERS:
                out.append(f"{name}: {REDACTED}{ending}")
                changed = True
                redacting_continuation = True
                continue
        out.append(line)
    return "".join(out) if changed else text


def _is_http_start_line(line: str) -> bool:
    """Recognise a request/status line that opens a coalesced header block."""
    # A Content-Length body does not have to end in CR/LF, so a coalesced
    # response may look like ``{}HTTP/1.1 200 OK`` on this text line. Inspect
    # the HTTP-version suffix rather than requiring it to start at byte zero.
    status_at = line.rfind("HTTP/")
    if status_at >= 0:
        status_parts = line[status_at:].split()
        if (
            len(status_parts) >= 2
            and len(status_parts[1]) == 3
            and status_parts[1].isdigit()
        ):
            return True
    # The same mid-line case applies to a pipelined request.  We cannot know
    # where arbitrary body text ended, so conservatively recognise a trailing
    # HTTP version when at least a method/target separator precedes it.
    request_version_at = line.rfind(" HTTP/")
    if request_version_at < 0:
        return False
    before_version = line[:request_version_at].rstrip()
    return any(char.isspace() for char in before_version)


def _copy_json_tree(value: Any) -> Any:
    """Copy JSON-compatible containers without recursion.

    Captured request bodies are attacker-influenced.  ``copy.deepcopy`` and a
    recursive visitor both raise ``RecursionError`` on sufficiently nested
    values, which used to let one legacy row prevent RailDash from starting.
    """
    if isinstance(value, dict):
        root: dict[Any, Any] | list[Any] = {}
    elif isinstance(value, list):
        root = []
    else:
        return value

    stack: list[tuple[dict[Any, Any] | list[Any], dict[Any, Any] | list[Any]]] = [
        (value, root)
    ]
    while stack:
        source, target = stack.pop()
        children = source.items() if isinstance(source, dict) else enumerate(source)
        for key, child in children:
            if isinstance(child, dict):
                clone: dict[Any, Any] | list[Any] = {}
            elif isinstance(child, list):
                clone = []
            else:
                if isinstance(target, dict):
                    target[key] = child
                else:
                    target.append(child)
                continue

            if isinstance(target, dict):
                target[key] = clone
            else:
                target.append(clone)
            stack.append((child, clone))
    return root


def redact_credential_headers(interaction: dict[str, Any]) -> dict[str, Any]:
    """Copy an interaction and scrub credentials from every header map.

    RailMon already removes common auth headers, but `x-rail` is intentionally
    present in its legacy payload so Rail Center can attribute the request.
    RailDash only needs the boolean produced by `_has_ticket`; keeping the
    bearer value in SQLite and returning it from the detail API would turn a
    local traffic viewer into a credential store.

    Runtime-interaction envelopes can contain the legacy event under `raw`, so
    this walks nested objects rather than assuming headers occur only once.
    Bodies are otherwise left untouched: their sensitivity is a documented
    property of a traffic capture, not something this narrow scrub can solve.
    """
    scrubbed = _copy_json_tree(interaction)
    stack: list[Any] = [scrubbed]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                folded = key.casefold() if isinstance(key, str) else ""
                if folded == "headers" and isinstance(child, dict):
                    for header in list(child):
                        if isinstance(header, str) and header.casefold() in CREDENTIAL_HEADERS:
                            child[header] = REDACTED
                    stack.append(child)
                elif folded == "x_rail_header" and child is not None:
                    value[key] = REDACTED
                elif isinstance(child, (dict, list)):
                    stack.append(child)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, (dict, list)):
                    stack.append(child)
    return scrubbed


def redact_raw_event(event: dict[str, Any]) -> dict[str, Any]:
    """Scrub a raw SSL event, including nested AgentSight wire payloads."""
    scrubbed = redact_credential_headers(event)
    stack: list[Any] = [scrubbed]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "data" and isinstance(child, str):
                    value[key] = _redact_header_lines(child)
                elif isinstance(child, (dict, list)):
                    stack.append(child)
        elif isinstance(value, list):
            stack.extend(child for child in value if isinstance(child, (dict, list)))
    return scrubbed


def _header(headers: Any, name: str) -> str | None:
    if not isinstance(headers, dict):
        return None
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return value if isinstance(value, str) else str(value)
    return None


def _split_host_path(request: dict[str, Any]) -> tuple[str | None, str | None]:
    """Host and path, from whichever of the three places carried them.

    A proxied request line is absolute (`GET https://api.example.com/v1`), a
    normal HTTP/1.1 one is not and the host is in the header, and HTTP/2 uses
    `:authority`. Taking only the header would leave the absolute-form ones
    unattributed, which is exactly the traffic a proxy deployment produces.
    """
    path = request.get("path") or request.get("uri") or request.get(":path")
    host = (
        _header(request.get("headers"), "host")
        or _header(request.get("headers"), ":authority")
        or request.get("host")
    )

    if isinstance(path, str) and "://" in path:
        parts = urlsplit(path)
        host = host or parts.netloc
        path = parts.path + (f"?{parts.query}" if parts.query else "")

    if isinstance(host, str):
        host = host.strip() or None
    if isinstance(path, str):
        path = path.strip() or None
    return host, path


def _count_tool_calls(body: Any) -> int:
    """Tool-use blocks in an Anthropic/OpenAI-shaped message body.

    This is the one piece of content interpretation the dashboard does, and it
    earns its place: "what did the agent actually try to do" is the question
    the traffic view exists to answer, and a tool call is the closest thing in
    the payload to an action.

    Unrecognised shapes count zero rather than raising. Bodies are attacker-
    influenced — an agent's traffic is exactly what a prompt injection would
    steer — so this must never be able to throw.
    """
    if not isinstance(body, dict):
        return 0

    def blocks_in(content: Any) -> int:
        if not isinstance(content, list):
            return 0
        return sum(
            1
            for block in content
            if isinstance(block, dict)
            and block.get("type") in {"tool_use", "tool_call"}
        )

    count = 0

    # A response puts its blocks at the top level; only a request nests them
    # under messages. Counting just the latter missed every tool call the
    # model actually made — which is the half that matters, since a request
    # only ever echoes back a call from a previous turn.
    count += blocks_in(body.get("content"))

    for message in body.get("messages", []) or []:
        if isinstance(message, dict):
            count += blocks_in(message.get("content"))
    # OpenAI puts them beside the message rather than inside content.
    for choice in body.get("choices", []) or []:
        if isinstance(choice, dict):
            message = choice.get("message")
            if isinstance(message, dict):
                calls = message.get("tool_calls")
                if isinstance(calls, list):
                    count += len(calls)
    return count


def _model(body: Any) -> str | None:
    if isinstance(body, dict):
        model = body.get("model")
        if isinstance(model, str) and model:
            return model
    return None


def _has_ticket(request: dict[str, Any]) -> bool:
    """Whether the request carried an `x-rail` ticket.

    Only ever whether, never the value. The ticket is a credential; RailMon
    redacts `Authorization` before anything leaves its process, and a
    dashboard that helpfully displayed the one credential RailMon did not
    strip would undo that.
    """
    return _header(request.get("headers"), "x-rail") is not None


def interaction_has_ticket(interaction: dict[str, Any]) -> bool:
    """Ticket presence in either legacy-http or RuntimeInteraction shape."""
    request = interaction.get("request")
    request = request if isinstance(request, dict) else {}
    if _has_ticket(request):
        return True
    top_level = interaction.get("x_rail_header")
    if top_level is not None and str(top_level).strip():
        return True
    raw = interaction.get("raw")
    if isinstance(raw, dict):
        raw_request = raw.get("request")
        if isinstance(raw_request, dict):
            return _has_ticket(raw_request)
    return False


def _synthetic_id(interaction: dict[str, Any]) -> str:
    """A stable id for an interaction RailMon did not hash.

    Content-addressed like RailMon's own, so re-importing the same file is
    idempotent. Not the same algorithm and not claimed to be — it exists only
    to give the dedup index something to work with.
    """
    payload = json.dumps(interaction, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def normalise(interaction: dict[str, Any]) -> dict[str, Any]:
    """One RailMon interaction to one `interactions` row."""
    request = interaction.get("request")
    request = request if isinstance(request, dict) else {}
    response = interaction.get("response")
    response = response if isinstance(response, dict) else {}

    host, path = _split_host_path(request)

    status = response.get("status_code")
    if not isinstance(status, int):
        try:
            status = int(status)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            status = None

    latency = interaction.get("latency_ms")
    if not isinstance(latency, (int, float)):
        latency = None

    interaction_id = interaction.get("interaction_id")
    if not isinstance(interaction_id, str) or not interaction_id:
        interaction_id = _synthetic_id(interaction)

    request_body = request.get("body")
    response_body = response.get("body")

    return {
        "interaction_id": interaction_id,
        "timestamp": interaction.get("timestamp"),
        "timestamp_ns": interaction.get("timestamp_ns") or 0,
        "pid": interaction.get("pid"),
        "tid": interaction.get("tid"),
        "method": (request.get("method") or "").upper() or None,
        "host": host,
        "path": path,
        "status_code": status,
        "latency_ms": float(latency) if latency is not None else None,
        "request_size": interaction.get("request_size"),
        "response_size": interaction.get("response_size"),
        "model": _model(request_body) or _model(response_body),
        "tool_calls": _count_tool_calls(request_body) + _count_tool_calls(response_body),
        "has_ticket": int(interaction_has_ticket(interaction)),
        "raw": json.dumps(redact_credential_headers(interaction), default=str),
    }


def read_jsonl(path: str) -> tuple[list[dict[str, Any]], int]:
    """Read RailMon's `--output` file. Returns (interactions, lines skipped).

    A capture that was still being written when the process was killed ends in
    a half-line. Skipping it and saying how many were skipped beats refusing
    the whole file, which would make the common case — importing the capture
    from the run that just crashed — the one case that does not work.
    """
    items: list[dict[str, Any]] = []
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if isinstance(obj, dict) and isinstance(obj.get("interactions"), list):
                # A captured webhook envelope rather than a bare interaction.
                items.extend(i for i in obj["interactions"] if isinstance(i, dict))
            elif isinstance(obj, dict):
                items.append(obj)
            else:
                skipped += 1
    return items, skipped
