"""RailDash — a local view of what an agent actually did.

The case this serves is the one Lebin asked for: somebody has installed only
the open-source components, has no Rail Center, and wants to see the RailMon
report. So everything here works against a capture file or a webhook, and
nothing here talks to a control plane.

Two ways in, because RailMon has two ways out:

    railmon collect --output capture.jsonl     ->  raildash load capture.jsonl
    railmon collect --webhook http://...:8000/webhook/http-interactions

The webhook routes keep the paths and the response bodies the previous demo
server used, so an existing RailMon deployment does not need reconfiguring.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse

from .ingest import normalise, redact_raw_event
from .json_safety import (
    MAX_SAFE_JSON_BYTES,
    JSONStructureGuard,
    JSONStructureTooComplex,
)
from .store import Store

STATIC = Path(__file__).parent / "static"
# A companion RailMon sender change splits batches by their serialized size,
# including JSON escaping, before they reach this bound.  One interaction can
# legitimately carry a 1 MiB request and response whose control bytes expand
# sixfold, so 16 MiB leaves room for that worst case and its envelope without
# making every local RailDash accept a 128 MiB unauthenticated request.
MAX_WEBHOOK_BODY_BYTES = MAX_SAFE_JSON_BYTES
MAX_WEBHOOK_ITEMS = 1_000
MAX_SESSION_ID_CHARS = 256
MAX_AGENT_CHARS = 256
MAX_CAPTURE_START_CHARS = 128

app = FastAPI(
    title="RailDash",
    version="0.2.0",
    description="Local dashboard for RailMon captures. No control plane required.",
)

# One store for the process. RAILDASH_DB lets the container mount a volume and
# lets the tests point at a tmpdir; the default sits in the working directory
# because the expected way to run this is `raildash serve` in a shell.
store = Store(os.environ.get("RAILDASH_DB", "raildash.db"))


def get_store() -> Store:
    return store


# --------------------------------------------------------------------- ingest


@app.post("/webhook/http-interactions")
async def receive_http_interactions(request: Request) -> dict[str, Any]:
    """Receive a batch of paired interactions from RailMon.

    RailMon sends the `InteractionBatchRequest` envelope — session_id, agent,
    capture_start, interactions — and that is what this reads. A bare array is
    also accepted, because a `curl` of a capture file is the obvious thing
    somebody will try first and failing it teaches nothing.
    """
    body = await _json_body(request)

    if isinstance(body, list):
        session_id, agent, capture_start, items = "adhoc", "", "", body
    elif isinstance(body, dict):
        session_id = _bounded_text(body, "session_id", "unknown", MAX_SESSION_ID_CHARS)
        agent = _bounded_text(body, "agent", "", MAX_AGENT_CHARS)
        capture_start = _bounded_text(
            body, "capture_start", "", MAX_CAPTURE_START_CHARS
        )
        items = body.get("interactions") or []
    else:
        raise HTTPException(422, "expected an object or an array")

    if not isinstance(items, list):
        raise HTTPException(422, "interactions must be a list")
    if len(items) > MAX_WEBHOOK_ITEMS:
        raise HTTPException(413, f"batch exceeds {MAX_WEBHOOK_ITEMS} interactions")

    db = get_store()
    db.upsert_session(session_id, agent, capture_start, source="webhook")
    rows = [normalise(i) for i in items if isinstance(i, dict)]
    inserted = db.add_interactions(session_id, rows)

    # `received` counts what arrived and `stored` what was new. They differ on
    # a redelivery, and silently reporting only one of them is how a retrying
    # sender looks like data loss.
    return {"received": len(items), "stored": inserted, "session_id": session_id}


@app.post("/webhook/events")
async def receive_events(request: Request) -> dict[str, Any]:
    """Receive raw SSL events — the unpaired, pre-HTTP view."""
    body = await _json_body(request)
    if not isinstance(body, dict):
        raise HTTPException(422, "expected an object")
    session_id = _bounded_text(body, "session_id", "unknown", MAX_SESSION_ID_CHARS)
    # RailMon uses one Sink for every mode and therefore keeps the envelope
    # key `interactions` even when the items are raw AgentSight events.  Keep
    # accepting `events` for compatibility with the original demo server.
    events = body.get("events")
    if events is None:
        events = body.get("interactions") or []
    if not isinstance(events, list):
        raise HTTPException(422, "events must be a list")
    if len(events) > MAX_WEBHOOK_ITEMS:
        raise HTTPException(413, f"batch exceeds {MAX_WEBHOOK_ITEMS} events")

    db = get_store()
    db.upsert_session(
        session_id,
        _bounded_text(body, "agent", "", MAX_AGENT_CHARS),
        _bounded_text(body, "capture_start", "", MAX_CAPTURE_START_CHARS),
        source="webhook",
    )
    stored = db.add_raw_events(
        session_id,
        [redact_raw_event(e) for e in events if isinstance(e, dict)],
    )
    return {"received": len(events), "stored": stored, "session_id": session_id}


def _bounded_text(
    body: dict[str, Any], key: str, default: str, max_chars: int
) -> str:
    value = body.get(key)
    if value is None or value == "":
        return default
    if not isinstance(value, str):
        raise HTTPException(422, f"{key} must be a string")
    if len(value) > max_chars:
        raise HTTPException(422, f"{key} exceeds {max_chars} characters")
    return value


async def _json_body(request: Request) -> Any:
    # Besides documenting the contract, requiring a JSON media type prevents a
    # hostile web page from using a CORS-simple text/plain POST to poison a
    # RailDash listening on localhost. application/json triggers a browser
    # preflight, and this app deliberately grants no cross-origin access.
    media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media_type != "application/json" and not media_type.endswith("+json"):
        raise HTTPException(415, "content-type must be application/json")

    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise HTTPException(400, "invalid content-length") from exc
        if declared_size < 0:
            raise HTTPException(400, "invalid content-length")
        if declared_size > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(413, f"body exceeds {MAX_WEBHOOK_BODY_BYTES} bytes")

    body = bytearray()
    try:
        # Count the actual stream as well as Content-Length: a chunked request,
        # or a client lying about its length, must not bypass the bound.
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_WEBHOOK_BODY_BYTES:
                raise HTTPException(413, f"body exceeds {MAX_WEBHOOK_BODY_BYTES} bytes")
        # UTF-8 is the interoperable JSON encoding for the webhook.  Requiring
        # it also keeps UTF-16/32 NUL bytes from confusing a byte-level quote
        # scanner.  The scan and decode are CPU work, so keep them off the
        # async event loop that serves dashboard reads and health checks.
        return await run_in_threadpool(_decode_json, body)
    except HTTPException:
        raise
    except JSONStructureTooComplex as exc:
        raise HTTPException(413, str(exc)) from exc
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise HTTPException(400, f"invalid JSON body: {exc}") from exc


def _decode_json(body: bytearray) -> Any:
    text = body.decode("utf-8", "strict")
    JSONStructureGuard().feed(text)
    return json.loads(text)


# ------------------------------------------------------------------ read API


@app.get("/webhook/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "sessions": len(get_store().sessions())}


@app.get("/api/sessions")
def api_sessions() -> list[dict[str, Any]]:
    return get_store().sessions()


@app.get("/api/overview")
def api_overview(session_id: str | None = None) -> dict[str, Any]:
    return get_store().overview(session_id)


@app.get("/api/filters")
def api_filters(session_id: str | None = None) -> dict[str, Any]:
    db = get_store()
    return {
        "hosts": db.distinct("host", session_id),
        "methods": db.distinct("method", session_id),
    }


@app.get("/api/interactions")
def api_interactions(
    session_id: str | None = None,
    host: str | None = None,
    method: str | None = None,
    status_class: str | None = Query(None, pattern=r"^[1-5]$"),
    q: str | None = None,
    errors_only: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    return get_store().interactions(
        session_id=session_id,
        host=host,
        method=method,
        status_class=status_class,
        q=q,
        errors_only=errors_only,
        limit=limit,
        offset=offset,
    )


@app.get("/api/interactions/{row_id}")
def api_interaction(row_id: int) -> dict[str, Any]:
    found = get_store().interaction(row_id)
    if found is None:
        raise HTTPException(404, "no such interaction")
    return found


# --------------------------------------------------------- legacy JSON routes
# Kept because the previous server documented them in its own index page and
# openapi.yaml. Same paths, same meaning.


@app.get("/webhook/sessions")
def legacy_sessions() -> list[dict[str, Any]]:
    return [
        {
            "session_id": s["session_id"],
            "agent": s["agent"],
            "capture_start": s["capture_start"],
            "event_count": s["event_count"],
            "interaction_count": s["interaction_count"],
        }
        for s in get_store().sessions()
    ]


@app.get("/webhook/sessions/{session_id}")
def legacy_session(session_id: str) -> JSONResponse:
    db = get_store()
    match = [s for s in db.sessions() if s["session_id"] == session_id]
    if not match:
        # The demo server returned 200 with {"error": ...}, which means a
        # client cannot tell a missing session from a working one without
        # parsing the body. 404 is what the openapi.yaml already promises.
        return JSONResponse({"error": "Session not found"}, status_code=404)
    session = dict(match[0])
    session["http_interactions"] = db.interactions(
        session_id=session_id, limit=500
    )["items"]
    return JSONResponse(session)


# ------------------------------------------------------------------------ UI


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/app.js")
def appjs() -> FileResponse:
    return FileResponse(STATIC / "app.js", media_type="application/javascript")


@app.get("/app.css")
def appcss() -> FileResponse:
    return FileResponse(STATIC / "app.css", media_type="text/css")
