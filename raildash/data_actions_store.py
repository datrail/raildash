"""Data-action rows: each tool call seen, deduplicated, with what it carried
(DR-205 M1, data-actions design §4.3).

A row is an observation, not a judgement: (capture ref, class, tool,
endpoint, destination hints) with first and last seen, a count, the bytes
its arguments carried (last, max, total), their content kinds, the
arguments its schema didn't declare and whether it was streamed. The
actions are worked out when the rows are read, from the tool's current
classification (`data_actions.classify` over its trusted schemas), so a new
schema, an override or a classifier change never leaves a row stale.

Rows come from authenticated captures only, in the transaction that stores
them, inside a savepoint: a failure is reported and rolled back, and the
capture is still stored. The first open of a database from before this
classifies the last 24 hours of stored authenticated captures once.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from . import data_actions as da
from . import guardrail as g
from . import tool_calls as tc
from . import tool_schemas as ts
from .asp import parse_bundle

UNREADABLE_TOOL = "(unreadable call)"
OVERFLOW_TOOL = "(more calls)"
MAX_ROWS_PER_CAPTURE = 2000
# Rows past the bound, without destination values, before the overflow row.
MAX_ROWS_SLACK = 500
SCHEMA_WINDOW = timedelta(days=30)
BACKFILL_WINDOW = timedelta(hours=24)
BACKFILL_SETTING = "data_actions_backfilled_v1"
MAX_DESTINATION_VALUE_CHARS = 200
# Cheap substrings a stored row must hold to be worth parsing for calls; a
# POST to a known MCP endpoint is parsed whatever it holds (unreadable calls).
_CALL_MARKERS = ("tool_use", "tool_calls", "function_call", "mcp_call", "tools/call")

DATA_ACTIONS_SCHEMA = """
-- DR-205 M1: one row per (capture, class, tool, endpoint, destination
-- hints); see raildash/data_actions_store.py. Observations only: actions are
-- worked out on read from the tool's classification.
CREATE TABLE IF NOT EXISTS data_action_calls (
    capture_ref         TEXT NOT NULL,
    class               TEXT NOT NULL,
    tool                TEXT NOT NULL,
    endpoint            TEXT NOT NULL DEFAULT '',
    destination         TEXT NOT NULL DEFAULT '',
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    count               INTEGER NOT NULL,
    bytes_last          INTEGER NOT NULL,
    bytes_max           INTEGER NOT NULL,
    bytes_total         INTEGER NOT NULL,
    kinds               TEXT NOT NULL,
    undeclared          TEXT NOT NULL,
    streamed            INTEGER NOT NULL,
    schema_known        INTEGER NOT NULL,
    last_interaction_id TEXT,
    PRIMARY KEY (capture_ref, class, tool, endpoint, destination)
);
CREATE INDEX IF NOT EXISTS tool_schemas_endpoint ON tool_schemas(source, endpoint, tool);
"""


def destination_values(arguments_hints: Mapping[str, Any]) -> str:
    """The canonical key of a call's destination-hint values."""
    if not arguments_hints:
        return ""
    return json.dumps(arguments_hints, sort_keys=True, ensure_ascii=False)


def _union_json(old: str, new: Iterable[str]) -> str:
    merged = set(json.loads(old or "[]")) | set(new)
    return json.dumps(sorted(merged))


class DataActionsStore:
    """Mixed into `Store`; uses its `_db`, `_lock`, `_receive_time`."""

    # ------------------------------------------------------------- writing

    def _record_tool_calls(
        self, interaction: dict[str, Any], capture_ref: str, *, at: str | None = None
    ) -> None:
        """The calls one newly stored authenticated request carries. `at` is
        the time to record (the capture's own, when backfilling)."""
        raw = interaction.get("raw")
        known = self._known_mcp_endpoints()
        if isinstance(raw, str) and not any(m in raw for m in _CALL_MARKERS):
            request = {"headers": {"host": interaction.get("host")}, "path": interaction.get("path")}
            if (interaction.get("method") or "").upper() != "POST" or tc.endpoint_key(request) not in known:
                return
        self._db.execute("SAVEPOINT tool_calls_hook")
        try:
            found = tc.extract_tool_calls(
                interaction,
                endpoint_schema=self._endpoint_schema,
                fallback_schema=lambda tool: self._fallback_schema(capture_ref, tool),
            )
            now = at or self._receive_time()
            interaction_id = interaction.get("interaction_id")
            for call in found["calls"]:
                self._upsert_call(capture_ref, call, now, interaction_id)
            unreadable = found["mcp_post_unreadable"]
            if unreadable and unreadable["endpoint"] in known:
                self._upsert_call(capture_ref, {
                    "class": tc.OBSERVED, "tool": UNREADABLE_TOOL, "endpoint": unreadable["endpoint"],
                    "arguments_bytes": unreadable["request_size"] or 0, "content_kinds": [],
                    "undeclared": [], "streamed": False, "schema_known": False, "destination": {},
                }, now, interaction_id)
            if found["truncated"]:
                # Calls past the cap weren't read; that must not read as
                # nothing (fails closed, like an unreadable call).
                self._upsert_call(capture_ref, {
                    "class": tc.OBSERVED, "tool": OVERFLOW_TOOL, "endpoint": "",
                    "arguments_bytes": 0, "content_kinds": [], "undeclared": [],
                    "streamed": False, "schema_known": False, "destination": {},
                }, now, interaction_id)
        except Exception as exc:  # noqa: BLE001 - evidence must still be stored
            self._db.execute("ROLLBACK TO tool_calls_hook")
            self._db.execute("RELEASE tool_calls_hook")
            print(f"raildash: tool call extraction failed: {exc!r}", file=sys.stderr)
            return
        self._db.execute("RELEASE tool_calls_hook")

    def _upsert_call(
        self, capture_ref: str, call: Mapping[str, Any], now: str, interaction_id: Any,
    ) -> None:
        destination = destination_values(call.get("destination") or {})
        endpoint = call["endpoint"] or ""
        key = [capture_ref, call["class"], call["tool"], endpoint, destination]
        where = ("WHERE capture_ref = ? AND class = ? AND tool = ? AND endpoint = ? "
                 "AND destination = ?")
        existing = self._db.execute(f"SELECT * FROM data_action_calls {where}", key).fetchone()
        if existing is None:
            rows = self._db.execute(
                "SELECT count(*) FROM data_action_calls WHERE capture_ref = ?", (capture_ref,)
            ).fetchone()[0]
            if rows >= MAX_ROWS_PER_CAPTURE and destination:
                # Past the bound, a new destination value joins its tool's
                # row without one, so the tool and its actions stay visible.
                key[4] = ""
                existing = self._db.execute(f"SELECT * FROM data_action_calls {where}", key).fetchone()
            if existing is None and rows >= MAX_ROWS_PER_CAPTURE + MAX_ROWS_SLACK and call["tool"] not in (
                UNREADABLE_TOOL, OVERFLOW_TOOL
            ):
                self._upsert_call(capture_ref, {
                    **call, "tool": OVERFLOW_TOOL, "endpoint": "", "destination": {},
                }, now, interaction_id)
                return
        size = int(call["arguments_bytes"] or 0)
        undeclared = call.get("undeclared") or []
        if existing is None:
            self._db.execute(
                """INSERT INTO data_action_calls (
                       capture_ref, class, tool, endpoint, destination, first_seen, last_seen,
                       count, bytes_last, bytes_max, bytes_total, kinds, undeclared,
                       streamed, schema_known, last_interaction_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (*key, now, now, size, size, size, json.dumps(sorted(call["content_kinds"])),
                 json.dumps(sorted(undeclared)), int(bool(call["streamed"])),
                 int(bool(call["schema_known"])), interaction_id),
            )
            return
        self._db.execute(
            f"""UPDATE data_action_calls SET
                   last_seen = max(last_seen, ?), count = count + 1, bytes_last = ?,
                   bytes_max = max(bytes_max, ?), bytes_total = bytes_total + ?,
                   kinds = ?, undeclared = ?, streamed = max(streamed, ?),
                   schema_known = max(schema_known, ?), last_interaction_id = ?
               {where}""",
            (now, size, size, size, _union_json(existing["kinds"], call["content_kinds"]),
             _union_json(existing["undeclared"], undeclared), int(bool(call["streamed"])),
             int(bool(call["schema_known"])), interaction_id, *key),
        )

    def _known_mcp_endpoints(self) -> set[str]:
        """Endpoints that answered `tools/list`, plus every declared MCP
        server `url` in an agent's newest ASP (§4.3)."""
        listed = {
            row[0] for row in self._db.execute(
                "SELECT DISTINCT endpoint FROM tool_schemas WHERE source = ?",
                (ts.SOURCE_MCP_TOOLS_LIST,),
            )
        }
        return listed | self._asp_facts()["mcp_endpoints"]

    def _endpoint_schema(self, endpoint: str, tool: str) -> dict[str, Any] | None:
        """The endpoint's newest `tools/list` entry for a tool (§4.3)."""
        row = self._db.execute(
            "SELECT input_schema FROM tool_schemas WHERE source = ? AND endpoint = ? AND tool = ? "
            "ORDER BY last_seen DESC LIMIT 1",
            (ts.SOURCE_MCP_TOOLS_LIST, endpoint, tool),
        ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def _fallback_schema(self, capture_ref: str, tool: str) -> dict[str, Any] | None:
        """The newest model-side schema of a tool for this capture, when the
        request a call came from couldn't be read (§4.3)."""
        trusted = self._trusted_model_hosts()
        for row in self._db.execute(
            "SELECT input_schema, host FROM tool_schemas WHERE capture_ref = ? AND tool = ? "
            "AND source IN (?, ?) ORDER BY last_seen DESC",
            (capture_ref, tool, ts.SOURCE_MODEL_REQUEST, ts.SOURCE_PROVIDER_MCP_LIST),
        ):
            # Only a list the agent sent to a trusted host (§4.1): a doctored
            # one sent elsewhere must not become the schema a call is held to.
            if g.host_allowed(row[1] or None, trusted):
                return json.loads(row[0])
        return None

    def _backfill_data_actions(self) -> None:
        """Once per database: the last 24 hours of stored authenticated
        captures get their schemas and calls recorded, at their own capture
        times, so the Data actions group and the guardrail's first offer
        have data from the start."""
        if self._db.execute("SELECT 1 FROM settings WHERE key = ?", (BACKFILL_SETTING,)).fetchone():
            return
        cutoff = (datetime.now(timezone.utc) - BACKFILL_WINDOW).strftime("%Y-%m-%dT%H:%M:%S")
        last_id = 0
        while True:
            rows = self._db.execute(
                "SELECT * FROM interactions WHERE authenticated = 1 AND id > ? "
                "AND timestamp >= ? ORDER BY id LIMIT 200",
                (last_id, cutoff),
            ).fetchall()
            if not rows:
                break
            now = datetime.now(timezone.utc)
            for row in rows:
                stored = dict(row)
                last_id = stored["id"]
                self._record_capture_tools(stored, at=self._capture_time(stored["timestamp"], now))
        self._db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (BACKFILL_SETTING, self._receive_time()),
        )

    def _capture_time(self, value: Any, now: datetime) -> str:
        """A capture's own timestamp in `_receive_time`'s fixed-width form, so
        it sorts with the rest, and never later than now (a future or
        unparsable value would otherwise pin `last_seen` for good)."""
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            parsed = now
        return self._receive_time(min(parsed, now))

    # ------------------------------------------------------------- reading

    def _asp_facts(self) -> dict[str, Any]:
        """What the newest ASP of every agent says that data actions use:
        inference-endpoint hosts (trusted for tool lists, §4.1) and declared
        MCP server endpoints (known for unreadable calls, §4.3). Cached until
        the ASP table changes."""
        stamp = tuple(self._db.execute("SELECT max(rowid), count(*) FROM asps").fetchone())
        cached = getattr(self, "_asp_facts_cache", None)
        if cached is not None and cached[0] == stamp:
            return cached[1]
        hosts: set[str] = set()
        endpoints: set[str] = set()
        for row in self._db.execute(
            """SELECT exact_bundle FROM asps a WHERE stored_at = (
                   SELECT max(stored_at) FROM asps b
                   WHERE b.identity_kind = a.identity_kind AND b.identity_value = a.identity_value)"""
        ):
            try:
                bundle = parse_bundle(bytes(row[0]))
                if g.is_multi_agent(bundle):
                    continue
                attributes = g._attributes(bundle)
                endpoint = attributes.get("inference_endpoint") or {}
                if endpoint.get("status") == "ANSWERED":
                    host = g._url_host(endpoint.get("value"))
                    if host:
                        hosts.add(host)
                servers = attributes.get("mcp_servers_declared") or {}
                if servers.get("status") == "ANSWERED" and isinstance(servers.get("value"), list):
                    for server in servers["value"]:
                        url = server.get("url") if isinstance(server, dict) else None
                        if isinstance(url, str) and url:
                            parts = urlsplit(url)
                            endpoints.add(tc.endpoint_key(
                                {"headers": {"host": parts.netloc}, "path": parts.path or "/"}
                            ))
            except Exception:  # noqa: BLE001 - an unreadable ASP adds nothing
                continue
        facts = {"inference_hosts": hosts, "mcp_endpoints": endpoints}
        self._asp_facts_cache = (stamp, facts)
        return facts

    def _trusted_model_hosts(self) -> tuple[str, ...]:
        """Known providers plus every agent's `inference_endpoint` host
        (design §4.1): a tool list sent anywhere else is stored but never
        classified. Single-user: any agent's endpoint is trusted for all."""
        return tuple(sorted(set(ts.KNOWN_MODEL_HOSTS) | self._asp_facts()["inference_hosts"]))

    def _trusted_schemas(self, capture_refs: list[str], trusted: tuple[str, ...]) -> dict[str, list[dict[str, Any]]]:
        cutoff = (datetime.now(timezone.utc) - SCHEMA_WINDOW).strftime("%Y-%m-%dT%H:%M:%S")
        marks = ",".join("?" * len(capture_refs))
        out: dict[str, list[dict[str, Any]]] = {}
        for row in self._db.execute(
            f"SELECT * FROM tool_schemas WHERE capture_ref IN ({marks}) AND last_seen >= ?",
            (*capture_refs, cutoff),
        ):
            item = dict(row)
            if item["source"] != ts.SOURCE_MCP_TOOLS_LIST and not g.host_allowed(item["host"] or None, trusted):
                continue
            item["input_schema"] = json.loads(item["input_schema"])
            item["annotations"] = json.loads(item["annotations"]) if item["annotations"] else None
            out.setdefault(item["tool"], []).append(item)
        return out

    def data_action_rows(self, capture_refs: Iterable[str]) -> list[dict[str, Any]]:
        """The data-action rows of some captures, each with its actions as
        classified now (§4.3), upload rows first, then by last seen."""
        refs = sorted(set(capture_refs))
        if not refs:
            return []
        with self._lock:
            trusted = self._trusted_model_hosts()
            schemas = self._trusted_schemas(refs, trusted)
            marks = ",".join("?" * len(refs))
            rows = [dict(row) for row in self._db.execute(
                f"SELECT * FROM data_action_calls WHERE capture_ref IN ({marks})", refs
            )]
            for row in rows:
                if row["class"] == tc.OBSERVED and row["endpoint"]:
                    listed = self._db.execute(
                        "SELECT * FROM tool_schemas WHERE source = ? AND endpoint = ? AND tool = ?",
                        (ts.SOURCE_MCP_TOOLS_LIST, row["endpoint"], row["tool"]),
                    ).fetchall()
                    row["_schemas"] = [
                        {**dict(item), "input_schema": json.loads(item["input_schema"]),
                         "annotations": json.loads(item["annotations"]) if item["annotations"] else None}
                        for item in listed
                    ]
                else:
                    row["_schemas"] = schemas.get(row["tool"], [])
        out = []
        for row in rows:
            special = row["tool"] in (UNREADABLE_TOOL, OVERFLOW_TOOL)
            classification = (
                None if special else da.classify(row["tool"], row.pop("_schemas"))
            )
            row.pop("_schemas", None)
            undeclared = json.loads(row["undeclared"])
            actions = list(classification["actions"]) if classification else []
            if undeclared and da.UPLOAD not in actions:
                actions = [a for a in da.ACTIONS if a in {*actions, da.UPLOAD}]
            out.append({
                "capture_ref": row["capture_ref"],
                "class": row["class"],
                "tool": row["tool"],
                "endpoint": row["endpoint"] or None,
                "destination": json.loads(row["destination"]) if row["destination"] else {},
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "count": row["count"],
                "bytes": {"last": row["bytes_last"], "max": row["bytes_max"], "total": row["bytes_total"]},
                "content_kinds": json.loads(row["kinds"]),
                "undeclared": undeclared,
                "streamed": bool(row["streamed"]),
                "schema_known": bool(row["schema_known"]),
                "actions": actions,
                "unclassified": bool(classification and classification["unclassified"] and not undeclared),
                # Calls past a bound weren't read either: both fail closed.
                "unreadable": row["tool"] in (UNREADABLE_TOOL, OVERFLOW_TOOL),
                "classification": classification,
            })
        uploads = [item for item in out if da.UPLOAD in item["actions"] or item["unreadable"]]
        others = [item for item in out if not (da.UPLOAD in item["actions"] or item["unreadable"])]
        uploads.sort(key=lambda item: item["last_seen"], reverse=True)
        others.sort(key=lambda item: item["last_seen"], reverse=True)
        return uploads + others
