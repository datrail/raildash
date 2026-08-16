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

Everything the row stores is derived; the untouched interaction is kept in
`raw` so the detail view never shows a lossy reconstruction.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

# Header names are matched case-insensitively throughout: AgentSight preserves
# whatever the wire carried, and HTTP/2 lowercases while HTTP/1.1 does not.


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
        "has_ticket": int(_has_ticket(request)),
        "raw": json.dumps(interaction, default=str),
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
