#!/usr/bin/env python3
"""
Demo Webhook Server — receives eBPF-captured events from collector.py.

Usage:
    pip install fastapi uvicorn
    python3 webhook_server.py

    # Or with uvicorn directly:
    uvicorn webhook_server:app --host 0.0.0.0 --port 8000 --reload

Endpoints:
    POST /webhook/events            — receive raw SSL events
    POST /webhook/http-interactions  — receive parsed HTTP interactions
    GET  /webhook/health             — health check
    GET  /webhook/sessions           — list capture sessions
    GET  /webhook/sessions/{id}      — get session details and events
"""

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI(
    title="DatRail eBPF Webhook Demo",
    version="0.1.0",
    description="Demo webhook server for receiving eBPF-captured SSL/HTTP events",
)

# In-memory storage
sessions: dict[str, dict] = {}


def _ensure_session(session_id: str, agent: str = "", capture_start: str = "") -> dict:
    if session_id not in sessions:
        sessions[session_id] = {
            "session_id": session_id,
            "agent": agent,
            "capture_start": capture_start,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "raw_events": [],
            "http_interactions": [],
            "event_count": 0,
            "interaction_count": 0,
        }
    return sessions[session_id]


@app.get("/webhook/health")
def health_check():
    return {"status": "ok", "sessions": len(sessions)}


@app.post("/webhook/events")
async def receive_events(request: Request):
    """Receive raw SSL events from collector."""
    body = await request.json()
    session_id = body.get("session_id", "unknown")
    events = body.get("events", [])

    session = _ensure_session(
        session_id, body.get("agent", ""), body.get("capture_start", "")
    )
    session["raw_events"].extend(events)
    session["event_count"] += len(events)

    print(f"[webhook] Session {session_id[:8]}: received {len(events)} raw events "
          f"(total: {session['event_count']})")

    for evt in events:
        func = evt.get("function", "?")
        data = evt.get("data", "")
        preview = (data[:80] + "...") if data and len(data) > 80 else (data or "(no data)")
        print(f"  [{func}] pid={evt.get('pid')} len={evt.get('len')} | {preview}")

    return {"received": len(events), "session_id": session_id}


@app.post("/webhook/http-interactions")
async def receive_http_interactions(request: Request):
    """Receive parsed HTTP interactions from collector."""
    body = await request.json()
    session_id = body.get("session_id", "unknown")
    interactions = body.get("interactions", [])

    session = _ensure_session(
        session_id, body.get("agent", ""), body.get("capture_start", "")
    )
    session["http_interactions"].extend(interactions)
    session["interaction_count"] += len(interactions)

    print(f"\n[webhook] Session {session_id[:8]}: received {len(interactions)} HTTP interactions "
          f"(total: {session['interaction_count']})")

    for ix in interactions:
        req = ix.get("request", {})
        resp = ix.get("response", {})
        method = req.get("method", "?")
        path = req.get("path", "?")
        status = resp.get("status_code", "?")
        latency = ix.get("latency_ms", 0)
        print(f"  {method} {path[:60]} → {status} ({latency:.0f}ms)")

        # Show tool calls if present in request body
        req_body = req.get("body", {})
        if isinstance(req_body, dict):
            messages = req_body.get("messages", [])
            for msg in messages[-3:]:  # last 3 messages
                role = msg.get("role", "?")
                content = msg.get("content", "")
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict):
                            btype = block.get("type", "")
                            if btype == "tool_use":
                                print(f"    → tool_use: {block.get('name')} "
                                      f"input={json.dumps(block.get('input', {}))[:80]}")
                            elif btype == "tool_result":
                                print(f"    ← tool_result: {str(block.get('content', ''))[:80]}")
                            elif btype == "text":
                                text = block.get("text", "")
                                print(f"    [{role}] {text[:80]}")
                elif isinstance(content, str) and content:
                    print(f"    [{role}] {content[:80]}")

    return {"received": len(interactions), "session_id": session_id}


@app.get("/webhook/sessions")
def list_sessions():
    """List all capture sessions."""
    return [
        {
            "session_id": s["session_id"],
            "agent": s["agent"],
            "capture_start": s["capture_start"],
            "event_count": s["event_count"],
            "interaction_count": s["interaction_count"],
        }
        for s in sessions.values()
    ]


@app.get("/webhook/sessions/{session_id}")
def get_session(session_id: str):
    """Get full session details including events."""
    if session_id not in sessions:
        return {"error": "Session not found"}
    return sessions[session_id]


@app.get("/", response_class=HTMLResponse)
def index():
    """Simple dashboard."""
    rows = ""
    for s in sessions.values():
        rows += f"""<tr>
            <td><a href="/webhook/sessions/{s['session_id']}">{s['session_id'][:8]}...</a></td>
            <td>{s['agent']}</td>
            <td>{s['event_count']}</td>
            <td>{s['interaction_count']}</td>
            <td>{s['capture_start']}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><title>DatRail Webhook Demo</title>
<style>
body {{ font-family: monospace; margin: 2em; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d4ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background: #16213e; }}
a {{ color: #00d4ff; }}
.status {{ color: #00ff88; }}
</style></head><body>
<h1>DatRail eBPF Webhook Demo</h1>
<p class="status">Status: running | Sessions: {len(sessions)}</p>
<h2>Capture Sessions</h2>
<table>
<tr><th>Session ID</th><th>Agent</th><th>Raw Events</th><th>HTTP Interactions</th><th>Started</th></tr>
{rows if rows else '<tr><td colspan="5">No sessions yet. Start the collector to begin capturing.</td></tr>'}
</table>
<h2>API Endpoints</h2>
<ul>
<li><code>POST /webhook/events</code> — Raw SSL events</li>
<li><code>POST /webhook/http-interactions</code> — Parsed HTTP interactions</li>
<li><code>GET /webhook/sessions</code> — List sessions (JSON)</li>
<li><code>GET /webhook/sessions/{{id}}</code> — Session details (JSON)</li>
<li><code>GET /webhook/health</code> — Health check</li>
</ul>
</body></html>"""


if __name__ == "__main__":
    import uvicorn
    print("[webhook] Starting demo server on http://0.0.0.0:8000")
    print("[webhook] Dashboard: http://localhost:8000/")
    print("[webhook] Health:    http://localhost:8000/webhook/health")
    uvicorn.run(app, host="0.0.0.0", port=8000)
