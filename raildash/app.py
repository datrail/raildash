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
import secrets
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from .ingest import normalise, redact_raw_event
from .json_safety import (
    MAX_SAFE_JSON_BYTES,
    JSONStructureGuard,
    JSONStructureTooComplex,
)
from .store import Store
from .asp import (
    DEFAULT_DRIFT_PAGE_SIZE,
    MAX_ASP_BUNDLE_BYTES,
    MAX_DRIFT_PAGE_SIZE,
    BundleValidationError,
    IdentityRequiredError,
)

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
# Bounds a lock/switch/accept/retention control-message body -- a version
# string and a couple of integers, never evidence content. Kept far below the
# webhook bound so one of these routes cannot be used to smuggle a large body
# past a reviewer skimming "it's bounded like the others".
MAX_CONTROL_BODY_BYTES = 4_096
# DR-120: RailDash's own ingest bound for `POST /v1/evidence-bundles`, mirroring
# Rail Center's MAX_EVIDENCE_BUNDLE_BYTES default (config.py there). Separately
# configurable from the fixed MAX_ASP_BUNDLE_BYTES that `asp.parse_bundle`
# itself enforces -- this env var can only make the *route's* bound tighter or
# equal; parse_bundle's own limit is not raised by setting it higher.
MAX_EVIDENCE_BUNDLE_BYTES = int(
    os.environ.get("RAILDASH_MAX_EVIDENCE_BUNDLE_BYTES", str(MAX_ASP_BUNDLE_BYTES))
)

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


# ------------------------------------------------------------ local write safety
#
# DR-120: the ASP standing decision says every ASP workflow must work from the
# UI, not just the CLI -- which means this process now exposes write routes
# (evidence-bundle ingest, lock, switch, accept-drift, retention settings,
# prune) that a CLI operation previously reached only through the SQLite file
# itself. `serve` still binds 127.0.0.1 by default (unchanged), but loopback
# alone does not stop another local account, or a malicious page a browser on
# this machine has open, from hitting a write route -- and that CSRF case is
# exactly what a browser-based UI adds that the CLI never had to worry about.
#
# A per-start random token, generated in memory here and injected server-side
# into the page RailDash itself serves (see `index()` below), is the same
# pattern Jupyter's classic notebook server uses for the same reason: a
# cross-site page cannot read the token without already having same-origin
# access to this page, so it cannot forge a same-origin write even though the
# browser will happily attach cookies. It is not multi-user auth -- anyone who
# can read this process's memory, its stdout, or the token file next to the
# database already has it, which is the same trust boundary the SQLite file's
# 0600 permissions assume today.
LOCAL_TOKEN = secrets.token_urlsafe(32)


def _write_local_token_file(db_path: str, token: str) -> None:
    """Best-effort convenience copy of the token for a co-located CLI/script.

    Every write route below checks the in-memory `LOCAL_TOKEN` above, not this
    file -- so a failure here (read-only filesystem, in-memory database) is
    not fatal, just less convenient. Named `<db>.token`, 0600, and covered by
    the same `*.db*` gitignore pattern as the database itself.
    """
    if db_path == ":memory:":
        return
    token_path = Path(f"{db_path}.token")
    try:
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode("ascii"))
        finally:
            os.close(fd)
    except OSError:
        pass


_write_local_token_file(store.path, LOCAL_TOKEN)


def require_local_token(
    x_raildash_token: str | None = Header(default=None, alias="X-RailDash-Token")
) -> None:
    """Guard for every write route, plus any read that returns exact evidence.

    403, not 401: there is nothing to authenticate *as* here (no accounts),
    only a bearer capability a same-origin page already has by construction.
    """
    if not x_raildash_token or not secrets.compare_digest(x_raildash_token, LOCAL_TOKEN):
        raise HTTPException(403, "missing or invalid X-RailDash-Token")


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


async def _json_body(request: Request, *, max_bytes: int | None = None) -> Any:
    # `max_bytes` defaults through a lookup inside the body, not a bound
    # default parameter, so tests that monkeypatch the module-level
    # MAX_WEBHOOK_BODY_BYTES (evaluated once at import if it were a default
    # value) keep working unchanged.
    if max_bytes is None:
        max_bytes = MAX_WEBHOOK_BODY_BYTES
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
        if declared_size > max_bytes:
            raise HTTPException(413, f"body exceeds {max_bytes} bytes")

    body = bytearray()
    try:
        # Count the actual stream as well as Content-Length: a chunked request,
        # or a client lying about its length, must not bypass the bound.
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > max_bytes:
                raise HTTPException(413, f"body exceeds {max_bytes} bytes")
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


async def _bounded_raw_body(request: Request, max_bytes: int) -> bytes:
    """Read a request body as raw bytes, bounded, no JSON decoding.

    Used for `POST /v1/evidence-bundles`: the bytes received are exactly the
    bytes `asp.bundle_digest`/`parse_bundle` must see, so nothing here may
    reparse or reserialize them (see `asp.py`'s module docstring on exact
    bytes as the dedup key).
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise HTTPException(400, "invalid content-length") from exc
        if declared_size < 0:
            raise HTTPException(400, "invalid content-length")
        if declared_size > max_bytes:
            raise HTTPException(413, f"body exceeds {max_bytes} bytes")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise HTTPException(413, f"body exceeds {max_bytes} bytes")
    if not body:
        raise HTTPException(422, "empty body")
    return bytes(body)


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


@app.get("/api/profile")
def api_observed_profile(session_id: str) -> JSONResponse:
    profile = get_store().observed_profile(session_id)
    if profile is None:
        raise HTTPException(404, "no such session")
    return JSONResponse(
        profile,
        headers={
            "Content-Disposition": (
                'attachment; filename="raildash-observed-profile.json"'
            )
        },
    )


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
    agent_key: str | None = None,
    attribution_state: str | None = Query(
        None, pattern=r"^(attributed|ambiguous|unknown|conflict)$"
    ),
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
        agent_key=agent_key,
        attribution_state=attribution_state,
        limit=limit,
        offset=offset,
    )


@app.get("/api/interactions/{row_id}")
def api_interaction(row_id: int) -> dict[str, Any]:
    found = get_store().investigation(row_id)
    if found is None:
        raise HTTPException(404, "no such interaction")
    return found


@app.get("/api/asps")
def api_asps(
    limit: int = Query(DEFAULT_DRIFT_PAGE_SIZE, ge=1, le=MAX_DRIFT_PAGE_SIZE),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Return redacted ASP metadata.

    Exact evidence needs the local write token (`GET .../bundle`,
    `GET .../drift/explained` below) or direct CLI/file access -- never this
    unauthenticated summary route.
    """
    db = get_store()
    return {
        "total": db.asp_count(),
        "items": db.asp_summaries(
            include_digest=False, limit=limit, offset=offset
        ),
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/alignments")
def api_alignments(
    limit: int = Query(DEFAULT_DRIFT_PAGE_SIZE, ge=1, le=MAX_DRIFT_PAGE_SIZE),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Return immutable alignment metadata and active-binding state."""
    db = get_store()
    return {
        "total": db.alignment_count(),
        "items": db.alignment_summaries(
            include_digest=False, limit=limit, offset=offset
        ),
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/asps/{asp_id}/state")
def api_asp_state(asp_id: str) -> dict[str, Any]:
    state = get_store().asp_state(asp_id)
    if state is None:
        raise HTTPException(404, "no such ASP")
    return state


@app.get("/api/asps/{asp_id}/drift")
def api_asp_drift(
    asp_id: str,
    limit: int = Query(DEFAULT_DRIFT_PAGE_SIZE, ge=1, le=MAX_DRIFT_PAGE_SIZE),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    result = get_store().drift_page(asp_id, limit=limit, offset=offset)
    if result is None:
        raise HTTPException(404, "no drift result for ASP")
    return result


# ---------------------------------------------------------- ASP write routes
#
# DR-120: everything below wraps the same `Store`/`asp.py` functions the
# `raildash asp ...` CLI already calls -- the CLI stays a thin wrapper over
# these, not a separate implementation (standing decision: ASP must not
# depend on the CLI). Every route here is gated by `require_local_token`
# because each one either mutates immutable custody state or returns exact
# evidence values that the summary routes above deliberately redact.


@app.get("/api/asps/{asp_id}/bundle", dependencies=[Depends(require_local_token)])
def api_asp_bundle(asp_id: str) -> dict[str, Any]:
    """The full parsed evidence bundle for one ASP -- the UI's inspect view.

    Same exact evidence `raildash asp export` writes to a private file,
    returned inline instead. Token-gated for the reason `asp export` needs
    filesystem access: this can contain sensitive attribute values.
    """
    bundle = get_store().asp_bundle(asp_id)
    if bundle is None:
        raise HTTPException(404, "no such ASP")
    return bundle


@app.get(
    "/api/asps/{asp_id}/drift/explained", dependencies=[Depends(require_local_token)]
)
def api_asp_drift_explained(
    asp_id: str,
    limit: int = Query(DEFAULT_DRIFT_PAGE_SIZE, ge=1, le=MAX_DRIFT_PAGE_SIZE),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Per-attribute drift with old/new values and evidence tier, paginated.

    Same full evidence `raildash asp drift-export` writes to a private file.
    `/api/asps/{asp_id}/drift` above stays redacted-by-design (change names
    and field names only) for callers that do not hold the local token; this
    is the equivalent detail view for the UI's "drift explained" panel.
    """
    try:
        result = get_store().drift_explained(asp_id, limit=limit, offset=offset)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if result is None:
        raise HTTPException(404, "no drift result for ASP")
    return result


@app.post(
    "/api/asps/{asp_id}/lock",
    status_code=201,
    dependencies=[Depends(require_local_token)],
)
async def api_lock_asp(asp_id: str, request: Request) -> dict[str, Any]:
    """Lock one stored ASP as a new immutable alignment version.

    Body: `{"version": "v1.0"}`. Equivalent to
    `raildash asp lock <asp_id> --version <version>`.
    """
    body = await _json_body(request, max_bytes=MAX_CONTROL_BODY_BYTES)
    if not isinstance(body, dict):
        raise HTTPException(422, "expected an object")
    version = body.get("version")
    if not isinstance(version, str):
        raise HTTPException(422, "version must be a string")
    try:
        return get_store().lock_alignment(asp_id, version)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post(
    "/api/alignments/{alignment_version_id}/switch",
    dependencies=[Depends(require_local_token)],
)
def api_switch_alignment(alignment_version_id: str) -> dict[str, Any]:
    """Make one existing alignment version the active baseline for its agent.

    Equivalent to `raildash asp switch <alignment_version_id>`.
    """
    try:
        return get_store().switch_alignment(alignment_version_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post(
    "/api/asps/{asp_id}/accept-drift",
    status_code=201,
    dependencies=[Depends(require_local_token)],
)
async def api_accept_drift(asp_id: str, request: Request) -> dict[str, Any]:
    """Accept a drifted ASP's current state as the new baseline, in one call.

    Body: `{"version": "v2.0"}`. Equivalent to running
    `raildash asp lock <asp_id> --version <version>` followed immediately by
    `raildash asp switch <the returned alignment_version_id>` -- the "accept
    new state as new baseline" action next to a drift result.
    """
    body = await _json_body(request, max_bytes=MAX_CONTROL_BODY_BYTES)
    if not isinstance(body, dict):
        raise HTTPException(422, "expected an object")
    version = body.get("version")
    if not isinstance(version, str):
        raise HTTPException(422, "version must be a string")
    db = get_store()
    try:
        locked = db.lock_alignment(asp_id, version)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    binding = db.switch_alignment(locked["alignment_version_id"])
    return {"alignment_version": locked, "binding": binding}


@app.get("/api/settings/asp-retention")
def api_get_asp_retention() -> dict[str, int]:
    """Current ASP retention bounds. Read-only and unauthenticated like the
    other settings-adjacent metadata above -- it carries counts, not evidence."""
    return get_store().get_asp_retention()


@app.post(
    "/api/settings/asp-retention", dependencies=[Depends(require_local_token)]
)
async def api_set_asp_retention(request: Request) -> dict[str, int]:
    """Change and persist the ASP retention bounds.

    Body: `{"keep_count": 100, "max_age_days": 30}`. Unlike the env vars
    `RAILDASH_ASP_RETENTION_COUNT`/`_DAYS`, a change here is stored in the
    database (a `settings` row) so it survives a restart without re-exporting
    anything -- the CLI equivalent is `raildash asp retention-set`.
    """
    body = await _json_body(request, max_bytes=MAX_CONTROL_BODY_BYTES)
    if not isinstance(body, dict):
        raise HTTPException(422, "expected an object")
    keep_count = body.get("keep_count")
    max_age_days = body.get("max_age_days")
    if not isinstance(keep_count, int) or isinstance(keep_count, bool):
        raise HTTPException(422, "keep_count must be an integer")
    if not isinstance(max_age_days, int) or isinstance(max_age_days, bool):
        raise HTTPException(422, "max_age_days must be an integer")
    try:
        return get_store().set_asp_retention(
            keep_count=keep_count, max_age_days=max_age_days
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/asps/prune", dependencies=[Depends(require_local_token)])
def api_prune_asps(
    keep_count: int | None = Query(None, ge=1),
    max_age_days: int | None = Query(None, ge=1),
) -> dict[str, Any]:
    """Prune unlocked ASP history now, using the current (or given) bounds.

    Equivalent to `raildash asp prune [--keep-count N] [--max-age-days N]`;
    an omitted parameter uses the currently configured setting rather than a
    fresh hardcoded default, so a one-off tighter prune does not silently
    change the standing bound.
    """
    db = get_store()
    current = db.get_asp_retention()
    removed = db.prune_asp_history(
        keep_count=keep_count if keep_count is not None else current["keep_count"],
        max_age_days=(
            max_age_days if max_age_days is not None else current["max_age_days"]
        ),
    )
    return {"removed": removed}


@app.post(
    "/v1/evidence-bundles",
    status_code=202,
    dependencies=[Depends(require_local_token)],
)
async def ingest_evidence_bundle(
    request: Request, agent_key: str | None = Query(default=None)
) -> JSONResponse:
    """Ingest one Agent Security Profile evidence bundle over HTTP (DR-120/DR-121).

    This is RailDash's counterpart to Rail Center's `POST /v1/evidence-bundles`
    (`rail-center/api/src/profiling/bundles_router.py`) -- same path and
    general shape, RailDash's own dedup semantics (content digest, not a
    client-asserted id).

    Contract for a delivering client (e.g. RailMon's scanner):

        POST /v1/evidence-bundles?agent_key=<optional>
        Headers:
            X-RailDash-Token: <the token printed at `raildash serve` startup,
                also written 0600 to `<db-path>.token`>
            X-RailDash-Agent-Key: <optional alternative to the query param>
        Body: the exact evidence-bundle bytes, unmodified and not
            reserialized or multipart-wrapped -- up to
            RAILDASH_MAX_EVIDENCE_BUNDLE_BYTES bytes (default 1_048_576,
            mirrors Rail Center's MAX_EVIDENCE_BUNDLE_BYTES).

    A minimal client:

        import requests
        requests.post(
            "http://127.0.0.1:8000/v1/evidence-bundles",
            data=raw_bytes,
            headers={"X-RailDash-Token": token},
        )

    Responses:
        202 {"accepted": true, "asp_id": "asp-...", "duplicate": bool}
            -- accepted, whether this is the first time these exact bytes
            were seen (`duplicate: false`) or a resend of them
            (`duplicate: true`). `asp_id` is RailDash's own generated
            identifier, not the bundle's own `bundle_id`.
        409 -- `bundle_id` (or, for an unkeyed bundle, the identity) already
            names a *different* stored bundle; the body was well-formed.
        422 -- the body is not a valid evidence bundle, or an unkeyed bundle
            arrived with no resolvable `agent_key`.
    """
    header_agent_key = request.headers.get("x-raildash-agent-key")
    resolved_agent_key = agent_key or header_agent_key or None
    raw = await _bounded_raw_body(request, MAX_EVIDENCE_BUNDLE_BYTES)
    db = get_store()
    try:
        result = db.load_asp(raw, agent_key=resolved_agent_key)
    except BundleValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    except IdentityRequiredError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ValueError as exc:
        # bundle_id collision with different bytes, or an exact-digest replay
        # asserting a different agent identity than the first load -- both
        # are "this content is already stored under a different identity",
        # the well-formed-but-conflicting case Rail Center's own route
        # answers with 409.
        raise HTTPException(409, str(exc)) from exc
    return JSONResponse(
        {
            "accepted": True,
            "asp_id": result["asp_id"],
            "duplicate": result["replayed"],
        },
        status_code=202,
    )


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
def index() -> HTMLResponse:
    # The token is injected server-side into the page this process serves,
    # same-origin, so the UI's own fetch calls can read it and attach it to
    # every write request -- see the `require_local_token` docstring above.
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    injected = html.replace(
        "</head>",
        f'<meta name="raildash-token" content="{LOCAL_TOKEN}">\n</head>',
        1,
    )
    return HTMLResponse(injected)


@app.get("/app.js")
def appjs() -> FileResponse:
    return FileResponse(STATIC / "app.js", media_type="application/javascript")


@app.get("/app.css")
def appcss() -> FileResponse:
    return FileResponse(STATIC / "app.css", media_type="text/css")
