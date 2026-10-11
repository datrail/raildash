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

from . import data_actions as da
from . import guardrail as g
from . import tool_calls as tc
from . import tool_schemas as ts
from .asp import parse_bundle

UNREADABLE_TOOL = "(unreadable call)"
OVERFLOW_TOOL = "(more calls)"
MAX_ROWS_PER_CAPTURE = 2000
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

    def _record_tool_calls(self, interaction: dict[str, Any], capture_ref: str) -> None:
        """The calls one newly stored authenticated request carries."""
        raw = interaction.get("raw")
        known = self._known_mcp_endpoints()
        if isinstance(raw, str) and not any(m in raw for m in _CALL_MARKERS):
            host = g.normalize_host(interaction.get("host"))
            path = (interaction.get("path") or "/").split("?", 1)[0]
            if (interaction.get("method") or "").upper() != "POST" or f"{host}{path}" not in known:
                return
        self._db.execute("SAVEPOINT tool_calls_hook")
        try:
            found = tc.extract_tool_calls(interaction)
            now = self._receive_time()
            for call in found["calls"]:
                undeclared = call["undeclared"]
                if call["class"] == tc.OBSERVED:
                    listing = self._endpoint_schema(call["endpoint"], call["tool"])
                    if listing is not None:
                        call["schema_known"] = True
                        undeclared = tc.undeclared_arguments(
                            self._call_arguments(interaction, call), listing
                        )
                self._upsert_call(capture_ref, call, undeclared, now, interaction.get("interaction_id"))
            unreadable = found["mcp_post_unreadable"]
            if unreadable and unreadable["endpoint"] in known:
                self._upsert_call(capture_ref, {
                    "class": tc.OBSERVED, "tool": UNREADABLE_TOOL, "endpoint": unreadable["endpoint"],
                    "arguments_bytes": unreadable["request_size"] or 0, "content_kinds": [],
                    "streamed": False, "schema_known": False, "destination": {},
                }, [], now, interaction.get("interaction_id"))
        except Exception as exc:  # noqa: BLE001 - evidence must still be stored
            self._db.execute("ROLLBACK TO tool_calls_hook")
            self._db.execute("RELEASE tool_calls_hook")
            print(f"raildash: tool call extraction failed: {exc!r}", file=sys.stderr)
            return
        self._db.execute("RELEASE tool_calls_hook")

    @staticmethod
    def _call_arguments(interaction: Mapping[str, Any], call: Mapping[str, Any]) -> Any:
        """An observed call's arguments, read again for the endpoint's schema."""
        raw = g._stored_raw(interaction)
        if raw is None:
            return None
        request = (g.legacy_exchange(raw) or {}).get("request") or {}
        body = ts._json_body(request.get("body") if isinstance(request, dict) else None)
        for message in body if isinstance(body, list) else [body]:
            if isinstance(message, dict) and message.get("method") == "tools/call":
                params = message.get("params")
                if isinstance(params, dict) and params.get("name") == call["tool"]:
                    return params.get("arguments")
        return None

    def _upsert_call(
        self, capture_ref: str, call: Mapping[str, Any], undeclared: list[str], now: str,
        interaction_id: Any,
    ) -> None:
        destination = destination_values(call.get("destination") or {})
        key = (capture_ref, call["class"], call["tool"], call["endpoint"] or "", destination)
        existing = self._db.execute(
            "SELECT * FROM data_action_calls WHERE capture_ref = ? AND class = ? AND tool = ? "
            "AND endpoint = ? AND destination = ?", key,
        ).fetchone()
        size = int(call["arguments_bytes"] or 0)
        if existing is None:
            rows = self._db.execute(
                "SELECT count(*) FROM data_action_calls WHERE capture_ref = ?", (capture_ref,)
            ).fetchone()[0]
            if rows >= MAX_ROWS_PER_CAPTURE and call["tool"] != OVERFLOW_TOOL:
                # Past the bound, new distinct calls count in one row.
                self._upsert_call(capture_ref, {
                    **call, "tool": OVERFLOW_TOOL, "endpoint": "", "destination": {},
                }, undeclared, now, interaction_id)
                return
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
            """UPDATE data_action_calls SET
                   last_seen = ?, count = count + 1, bytes_last = ?,
                   bytes_max = max(bytes_max, ?), bytes_total = bytes_total + ?,
                   kinds = ?, undeclared = ?, streamed = max(streamed, ?),
                   schema_known = max(schema_known, ?), last_interaction_id = ?
               WHERE capture_ref = ? AND class = ? AND tool = ? AND endpoint = ?
                 AND destination = ?""",
            (now, size, size, size, _union_json(existing["kinds"], call["content_kinds"]),
             _union_json(existing["undeclared"], undeclared), int(bool(call["streamed"])),
             int(bool(call["schema_known"])), interaction_id, *key),
        )

    def _known_mcp_endpoints(self) -> set[str]:
        return {
            row[0] for row in self._db.execute(
                "SELECT DISTINCT endpoint FROM tool_schemas WHERE source = ?",
                (ts.SOURCE_MCP_TOOLS_LIST,),
            )
        }

    def _endpoint_schema(self, endpoint: str | None, tool: str) -> dict[str, Any] | None:
        """The endpoint's newest `tools/list` entry for a tool (§4.3)."""
        if not endpoint:
            return None
        row = self._db.execute(
            "SELECT input_schema FROM tool_schemas WHERE source = ? AND endpoint = ? AND tool = ? "
            "ORDER BY last_seen DESC LIMIT 1",
            (ts.SOURCE_MCP_TOOLS_LIST, endpoint, tool),
        ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def _backfill_data_actions(self) -> None:
        """Once per database: the last 24 hours of stored authenticated
        captures get their schemas and calls recorded, so the Data actions
        group and the guardrail's first offer have data from the start."""
        if self._db.execute("SELECT 1 FROM settings WHERE key = ?", (BACKFILL_SETTING,)).fetchone():
            return
        cutoff = (datetime.now(timezone.utc) - BACKFILL_WINDOW).strftime("%Y-%m-%dT%H:%M:%S")
        last_id = 0
        while True:
            rows = self._db.execute(
                "SELECT * FROM interactions WHERE authenticated = 1 AND id > ? "
                "AND (timestamp IS NULL OR timestamp >= ?) ORDER BY id LIMIT 200",
                (last_id, cutoff),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                stored = dict(row)
                last_id = stored["id"]
                self._record_capture_tools(stored)
        self._db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (BACKFILL_SETTING, self._receive_time()),
        )

    # ------------------------------------------------------------- reading

    def _trusted_model_hosts(self) -> tuple[str, ...]:
        """Known providers plus every agent's `inference_endpoint` host in its
        newest ASP (design §4.1): a tool list sent anywhere else is stored but
        never classified."""
        hosts = set(ts.KNOWN_MODEL_HOSTS)
        for row in self._db.execute(
            """SELECT exact_bundle FROM asps a WHERE stored_at = (
                   SELECT max(stored_at) FROM asps b
                   WHERE b.identity_kind = a.identity_kind AND b.identity_value = a.identity_value)"""
        ):
            try:
                attributes = g._attributes(parse_bundle(bytes(row[0])))
            except Exception:  # noqa: BLE001 - an unreadable ASP adds no host
                continue
            endpoint = attributes.get("inference_endpoint") or {}
            if endpoint.get("status") == "ANSWERED":
                host = g._url_host(endpoint.get("value"))
                if host:
                    hosts.add(host)
        return tuple(sorted(hosts))

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
                "unreadable": row["tool"] == UNREADABLE_TOOL,
                "classification": classification,
            })
        uploads = [item for item in out if da.UPLOAD in item["actions"] or item["unreadable"]]
        others = [item for item in out if item not in uploads]
        uploads.sort(key=lambda item: item["last_seen"], reverse=True)
        others.sort(key=lambda item: item["last_seen"], reverse=True)
        return uploads + others
