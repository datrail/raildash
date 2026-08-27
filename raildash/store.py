"""SQLite storage for captured interactions.

Why a database and not the dict the demo server used: the thing this dashboard
is for is looking at what an agent did, which is usually a question asked
*after* something went wrong. An in-memory store answers it only if you
happened to still have the process running, and RailMon's own output is a file
that outlives any process. So the dashboard persists, and `raildash load` can
replay a capture from last week.

Stdlib `sqlite3` only. RailDash's whole dependency list is FastAPI and uvicorn
and it is worth keeping it that way — this is the component an OSS user runs
locally with no control plane behind it.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .ingest import interaction_has_ticket, redact_credential_headers, redact_raw_event
from .json_safety import (
    MAX_SAFE_JSON_BYTES,
    JSONStructureTooComplex,
    check_json_structure,
)

CREDENTIAL_REDACTION_SCHEMA_VERSION = 1
MIGRATION_BATCH_ROWS = 16
MIGRATION_BATCH_BYTES = 8 * 1024 * 1024
UNSAFE_LEGACY_CAPTURE = {
    "redacted": True,
    "reason": "legacy capture exceeded safe migration limits",
}
MAX_PROFILE_TOOL_ROWS = 10_000
MAX_PROFILE_TOOL_NAMES = 1_000
MAX_PROFILE_DIMENSION_VALUES = 100
MAX_PROFILE_VALUE_CHARS = 256

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    agent         TEXT NOT NULL DEFAULT '',
    capture_start TEXT NOT NULL DEFAULT '',
    first_seen    TEXT NOT NULL DEFAULT '',
    last_seen     TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS interactions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT NOT NULL,
    interaction_id TEXT,
    timestamp      TEXT,
    timestamp_ns   INTEGER,
    pid            INTEGER,
    tid            INTEGER,
    method         TEXT,
    host           TEXT,
    path           TEXT,
    status_code    INTEGER,
    latency_ms     REAL,
    request_size   INTEGER,
    response_size  INTEGER,
    model          TEXT,
    tool_calls     INTEGER NOT NULL DEFAULT 0,
    has_ticket     INTEGER NOT NULL DEFAULT 0,
    raw            TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- Dedup key. RailMon's interaction_id is a content hash, so re-importing the
-- same JSONL — which happens every time someone re-runs `raildash load` — must
-- not double every count on the overview.
CREATE UNIQUE INDEX IF NOT EXISTS interactions_dedup
    ON interactions(session_id, interaction_id)
    WHERE interaction_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS interactions_session ON interactions(session_id);
CREATE INDEX IF NOT EXISTS interactions_time    ON interactions(timestamp_ns);
CREATE INDEX IF NOT EXISTS interactions_host    ON interactions(host);

CREATE TABLE IF NOT EXISTS raw_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    function   TEXT,
    pid        INTEGER,
    len        INTEGER,
    raw        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS raw_events_session ON raw_events(session_id);
"""


class Store:
    """A SQLite-backed store. Safe to share across FastAPI's threadpool.

    `check_same_thread=False` plus one lock rather than a connection pool:
    the write volume here is a webhook batch every few seconds, and the
    read volume is one person with a browser open. A pool would be
    complexity bought for load that does not exist.
    """

    def __init__(self, path: str | Path = "raildash.db") -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, timeout=1.0, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        # A RailDash database is single-process.  Keeping SQLite's exclusive
        # locking mode for this connection prevents an older process from
        # inserting an unredacted row between migration pages and after the
        # schema version has already advanced.
        locking_mode = self._db.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()[0]
        if locking_mode.casefold() != "exclusive":
            raise RuntimeError("RailDash requires exclusive SQLite locking")
        # WAL so a read while a webhook is writing does not block; the
        # dashboard polls, and a stalled poll looks like a hung page.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._migrate()
        self._db.commit()

    def _migrate(self) -> None:
        """Remove credentials written by versions predating DR-20.

        Re-import cannot repair an old row because the interaction dedup index
        correctly ignores it. A one-time SQLite user_version migration updates
        both interaction and raw-event tables in place before any API can read
        them; read-time scrubbing below remains a defense-in-depth backstop.
        """
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version >= CREDENTIAL_REDACTION_SCHEMA_VERSION:
            return

        # Overwrite freed cell/overflow bytes as rows shrink.  The final WAL
        # checkpoint below then removes copies of the old pages from the WAL.
        # Backups and filesystem snapshots remain outside SQLite's control and
        # require credential rotation/deletion by the operator.
        secure_delete = self._db.execute("PRAGMA secure_delete=ON").fetchone()[0]
        if secure_delete != 1:
            raise RuntimeError("SQLite secure_delete is required for credential migration")

        for table in ("interactions", "raw_events"):
            last_id = 0
            while True:
                candidates = self._db.execute(
                    f"SELECT id, length(CAST(raw AS BLOB)) AS size FROM {table} "
                    "WHERE id > ? ORDER BY id LIMIT ?",
                    (last_id, MIGRATION_BATCH_ROWS),
                ).fetchall()
                if not candidates:
                    break

                batch: list[tuple[int, int]] = []
                batch_bytes = 0
                for candidate in candidates:
                    size = int(candidate["size"] or 0)
                    if batch and batch_bytes + size > MIGRATION_BATCH_BYTES:
                        break
                    batch.append((candidate["id"], size))
                    batch_bytes += size

                for row_id, size in batch:
                    if size > MAX_SAFE_JSON_BYTES:
                        # Do not even materialise a legacy row larger than the
                        # current safe wire bound.  SQLite can replace it in
                        # place while secure_delete erases the old payload.
                        self._db.execute(
                            f"UPDATE {table} SET raw = ? WHERE id = ?",
                            (json.dumps(UNSAFE_LEGACY_CAPTURE), row_id),
                        )
                        continue
                    row = self._db.execute(
                        f"SELECT raw FROM {table} WHERE id = ?", (row_id,)
                    ).fetchone()
                    if row is None:
                        continue
                    raw = row["raw"]
                    try:
                        check_json_structure(raw)
                        parsed = json.loads(raw)
                        if not isinstance(parsed, dict):
                            scrubbed_value: Any = UNSAFE_LEGACY_CAPTURE
                        else:
                            scrubber = (
                                redact_raw_event
                                if table == "raw_events"
                                else redact_credential_headers
                            )
                            scrubbed_value = scrubber(parsed)
                            if table == "interactions" and interaction_has_ticket(parsed):
                                self._db.execute(
                                    "UPDATE interactions SET has_ticket = 1 WHERE id = ?",
                                    (row_id,),
                                )
                    except (
                        JSONStructureTooComplex,
                        ValueError,
                        RecursionError,
                    ):
                        # Keeping an unparseable record would keep any embedded
                        # credential too.  Prefer dropping this pathological
                        # legacy payload to exposing or crashing on it.
                        scrubbed_value = UNSAFE_LEGACY_CAPTURE

                    scrubbed = json.dumps(scrubbed_value)
                    if scrubbed != raw:
                        self._db.execute(
                            f"UPDATE {table} SET raw = ? WHERE id = ?",
                            (scrubbed, row_id),
                        )

                last_id = batch[-1][0]
                # Bound both Python retention and the WAL created while old
                # potentially multi-MiB rows are rewritten.
                self._db.commit()

        checkpoint = self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or checkpoint[0] != 0:
            raise RuntimeError(
                "could not purge migrated credentials from the SQLite WAL; "
                "stop other RailDash processes and retry"
            )

        self._db.execute(
            f"PRAGMA user_version = {CREDENTIAL_REDACTION_SCHEMA_VERSION}"
        )

    @staticmethod
    def _safe_raw(raw: str, *, raw_event: bool = False) -> Any:
        """Parse and redact one stored row without letting it break an API."""
        try:
            check_json_structure(raw)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                return UNSAFE_LEGACY_CAPTURE
            return (
                redact_raw_event(parsed)
                if raw_event
                else redact_credential_headers(parsed)
            )
        except (JSONStructureTooComplex, ValueError, RecursionError):
            return UNSAFE_LEGACY_CAPTURE

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---------------------------------------------------------------- write

    def upsert_session(
        self,
        session_id: str,
        agent: str = "",
        capture_start: str = "",
        source: str = "",
    ) -> None:
        with self._lock:
            self._db.execute(
                """
                INSERT INTO sessions (session_id, agent, capture_start, source)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    -- Never overwrite a known value with a blank one. A later
                    -- batch in the same session often omits the metadata that
                    -- only the first one carried.
                    agent         = CASE WHEN excluded.agent         != '' THEN excluded.agent         ELSE sessions.agent         END,
                    capture_start = CASE WHEN excluded.capture_start != '' THEN excluded.capture_start ELSE sessions.capture_start END,
                    source        = CASE WHEN excluded.source        != '' THEN excluded.source        ELSE sessions.source        END
                """,
                (session_id, agent, capture_start, source),
            )
            self._db.commit()

    def add_interactions(self, session_id: str, rows: Iterable[dict[str, Any]]) -> int:
        """Insert normalised rows. Returns how many were new.

        Duplicates are ignored rather than rejected: replaying a file is a
        normal thing to do and should be idempotent, not an error.
        """
        inserted = 0
        with self._lock:
            for row in rows:
                cur = self._db.execute(
                    """
                    INSERT OR IGNORE INTO interactions (
                        session_id, interaction_id, timestamp, timestamp_ns,
                        pid, tid, method, host, path, status_code, latency_ms,
                        request_size, response_size, model, tool_calls,
                        has_ticket, raw
                    ) VALUES (
                        :session_id, :interaction_id, :timestamp, :timestamp_ns,
                        :pid, :tid, :method, :host, :path, :status_code, :latency_ms,
                        :request_size, :response_size, :model, :tool_calls,
                        :has_ticket, :raw
                    )
                    """,
                    {**row, "session_id": session_id},
                )
                inserted += cur.rowcount
            if inserted:
                self._db.execute(
                    """
                    UPDATE sessions SET
                        -- The outer COALESCE to '' is load-bearing: both
                        -- columns are NOT NULL, and a batch whose interactions
                        -- all lack a timestamp makes the subquery NULL. That
                        -- is a normal batch, not a bad one.
                        first_seen = COALESCE(NULLIF(first_seen, ''), (
                            SELECT MIN(timestamp) FROM interactions
                            WHERE session_id = ? AND timestamp IS NOT NULL), ''),
                        last_seen = COALESCE((
                            SELECT MAX(timestamp) FROM interactions
                            WHERE session_id = ? AND timestamp IS NOT NULL), '')
                    WHERE session_id = ?
                    """,
                    (session_id, session_id, session_id),
                )
            self._db.commit()
        return inserted

    def add_raw_events(self, session_id: str, events: Iterable[dict[str, Any]]) -> int:
        count = 0
        with self._lock:
            for evt in events:
                self._db.execute(
                    "INSERT INTO raw_events (session_id, function, pid, len, raw)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        session_id,
                        evt.get("function"),
                        evt.get("pid"),
                        evt.get("len"),
                        json.dumps(evt),
                    ),
                )
                count += 1
            self._db.commit()
        return count

    # ----------------------------------------------------------------- read

    def sessions(self) -> list[dict[str, Any]]:
        rows = self._db.execute(
            """
            SELECT s.*,
                   COUNT(i.id)                                   AS interaction_count,
                   COALESCE(SUM(i.status_code >= 400), 0)        AS error_count,
                   (SELECT COUNT(*) FROM raw_events r
                     WHERE r.session_id = s.session_id)          AS event_count
            FROM sessions s
            LEFT JOIN interactions i ON i.session_id = s.session_id
            GROUP BY s.session_id
            ORDER BY COALESCE(NULLIF(s.last_seen, ''), s.capture_start) DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def overview(self, session_id: str | None = None) -> dict[str, Any]:
        where, params = ("WHERE session_id = ?", (session_id,)) if session_id else ("", ())

        totals = self._db.execute(
            f"""
            SELECT COUNT(*)                            AS interactions,
                   COUNT(DISTINCT host)                AS hosts,
                   COALESCE(SUM(status_code >= 400), 0) AS errors,
                   COALESCE(SUM(tool_calls), 0)        AS tool_calls,
                   AVG(latency_ms)                     AS avg_latency_ms,
                   MAX(latency_ms)                     AS max_latency_ms,
                   COALESCE(SUM(request_size), 0)      AS request_bytes,
                   COALESCE(SUM(response_size), 0)     AS response_bytes
            FROM interactions {where}
            """,
            params,
        ).fetchone()

        hosts = self._db.execute(
            f"""
            SELECT COALESCE(host, '(unknown)')          AS host,
                   COUNT(*)                             AS count,
                   COALESCE(SUM(status_code >= 400), 0) AS errors,
                   AVG(latency_ms)                      AS avg_latency_ms
            FROM interactions {where}
            GROUP BY host ORDER BY count DESC LIMIT 50
            """,
            params,
        ).fetchall()

        models = self._db.execute(
            f"""
            SELECT model, COUNT(*) AS count FROM interactions
            {where + ' AND' if where else 'WHERE'} model IS NOT NULL
            GROUP BY model ORDER BY count DESC LIMIT 20
            """,
            params,
        ).fetchall()

        statuses = self._db.execute(
            f"""
            SELECT status_code, COUNT(*) AS count FROM interactions
            {where + ' AND' if where else 'WHERE'} status_code IS NOT NULL
            GROUP BY status_code ORDER BY status_code
            """,
            params,
        ).fetchall()

        return {
            "totals": dict(totals) if totals else {},
            "hosts": [dict(r) for r in hosts],
            "models": [dict(r) for r in models],
            "statuses": [dict(r) for r in statuses],
        }

    def observed_profile(self, session_id: str) -> dict[str, Any] | None:
        """Build a portable summary of facts observed in one capture.

        This deliberately contains no score or inferred posture. Values come
        only from the already-redacted interaction columns and captured
        ``tool_use`` names.
        """
        session = self._db.execute(
            "SELECT session_id, agent, capture_start FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if session is None:
            return None

        totals = self._db.execute(
            """
            SELECT COUNT(*) AS interactions,
                   COALESCE(SUM(status_code >= 400), 0) AS errors,
                   COALESCE(SUM(has_ticket), 0) AS ticket_interactions
            FROM interactions WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()

        truncated_dimensions: list[str] = []

        def mark_truncated(label: str) -> None:
            if label not in truncated_dimensions:
                truncated_dimensions.append(label)

        def counted(column: str, label: str) -> list[dict[str, Any]]:
            rows = self._db.execute(
                f"""SELECT substr({column}, 1, ?) AS value,
                           COUNT(*) AS count,
                           MAX(length({column}) > ?) AS value_truncated
                    FROM interactions
                    WHERE session_id = ? AND {column} IS NOT NULL AND {column} != ''
                    GROUP BY substr({column}, 1, ?)
                    ORDER BY count DESC, value
                    LIMIT ?""",
                (
                    MAX_PROFILE_VALUE_CHARS,
                    MAX_PROFILE_VALUE_CHARS,
                    session_id,
                    MAX_PROFILE_VALUE_CHARS,
                    MAX_PROFILE_DIMENSION_VALUES + 1,
                ),
            ).fetchall()
            if len(rows) > MAX_PROFILE_DIMENSION_VALUES:
                mark_truncated(label)
                rows = rows[:MAX_PROFILE_DIMENSION_VALUES]
            if any(row["value_truncated"] for row in rows):
                mark_truncated(label)
            return [{"value": row["value"], "count": row["count"]} for row in rows]

        tool_counts: dict[str, int] = {}
        tool_names_truncated = False
        raw_rows = self._db.execute(
            """SELECT raw FROM interactions
               WHERE session_id = ? AND tool_calls > 0
               ORDER BY id LIMIT ?""",
            (session_id, MAX_PROFILE_TOOL_ROWS + 1),
        )
        for index, row in enumerate(raw_rows):
            if index == MAX_PROFILE_TOOL_ROWS:
                tool_names_truncated = True
                break
            names = self._tool_names(
                self._safe_raw(row["raw"]),
                deduplicate=False,
                limit=MAX_PROFILE_TOOL_NAMES + 1,
            )
            if len(names) > MAX_PROFILE_TOOL_NAMES:
                names = names[:MAX_PROFILE_TOOL_NAMES]
                tool_names_truncated = True
            for name in names:
                if len(name) > MAX_PROFILE_VALUE_CHARS:
                    name = name[:MAX_PROFILE_VALUE_CHARS]
                    tool_names_truncated = True
                    mark_truncated("tool_names")
                if name not in tool_counts and len(tool_counts) >= MAX_PROFILE_TOOL_NAMES:
                    tool_names_truncated = True
                    continue
                tool_counts[name] = tool_counts.get(name, 0) + 1

        interaction_count = int(totals["interactions"])
        error_count = int(totals["errors"])
        ticket_count = int(totals["ticket_interactions"])
        return {
            "schema_version": "1.0",
            "source": "raildash-observed",
            "authoritative": False,
            "disclaimer": "Observed capture summary; not an authoritative Rail Center score.",
            "session": {
                "id": session["session_id"],
                "agent": session["agent"],
                "capture_start": session["capture_start"],
            },
            "observed": {
                "interaction_count": interaction_count,
                "error_count": error_count,
                "error_rate": (
                    round(error_count / interaction_count, 6)
                    if interaction_count
                    else 0.0
                ),
                "x_rail": {
                    "present": ticket_count > 0,
                    "interaction_count": ticket_count,
                },
                "hosts": counted("host", "hosts"),
                "methods": counted("method", "methods"),
                "models": counted("model", "models"),
                "tool_names": [
                    {"value": name, "count": count}
                    for name, count in sorted(
                        tool_counts.items(), key=lambda item: (-item[1], item[0])
                    )
                ],
                "tool_names_truncated": tool_names_truncated,
                "truncated_dimensions": [
                    label
                    for label in ("hosts", "methods", "models", "tool_names")
                    if label in truncated_dimensions
                ],
            },
        }

    def interactions(
        self,
        session_id: str | None = None,
        host: str | None = None,
        method: str | None = None,
        status_class: str | None = None,
        q: str | None = None,
        errors_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if host:
            clauses.append("host = ?")
            params.append(host)
        if method:
            clauses.append("method = ?")
            params.append(method.upper())
        if errors_only:
            clauses.append("status_code >= 400")
        if status_class and status_class.isdigit():
            lo = int(status_class) * 100
            clauses.append("status_code >= ? AND status_code < ?")
            params += [lo, lo + 100]
        if q:
            # Path and host only. Searching `raw` would search request and
            # response bodies, which is where the credentials and the customer
            # data live — a substring search over that is a data-exposure
            # feature disguised as a convenience.
            clauses.append("(path LIKE ? OR host LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total = self._db.execute(
            f"SELECT COUNT(*) FROM interactions {where}", params
        ).fetchone()[0]

        rows = self._db.execute(
            f"""
            SELECT id, session_id, interaction_id, timestamp, pid, tid, method,
                   host, path, status_code, latency_ms, request_size,
                   response_size, model, tool_calls, has_ticket
            FROM interactions {where}
            ORDER BY timestamp_ns DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}

    def interaction(self, row_id: int) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT * FROM interactions WHERE id = ?", (row_id,)
        ).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["raw"] = self._safe_raw(out["raw"])
        return out

    @staticmethod
    def _tool_names(
        raw: Any, *, deduplicate: bool = True, limit: int | None = None
    ) -> list[str]:
        """Return ordered tool_use names from captured message blocks.

        Capture bodies are untrusted, so only the known Anthropic message
        locations are inspected and every unexpected shape is ignored.
        """
        if not isinstance(raw, dict):
            return []

        names: list[str] = []

        def add_blocks(content: Any) -> None:
            if not isinstance(content, list):
                return
            for block in content:
                if limit is not None and len(names) >= limit:
                    return
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                name = block.get("name")
                if (
                    isinstance(name, str)
                    and name
                    and (not deduplicate or name not in names)
                ):
                    names.append(name)

        for direction in ("request", "response"):
            message = raw.get(direction)
            if not isinstance(message, dict):
                continue
            body = message.get("body")
            if not isinstance(body, dict):
                continue
            add_blocks(body.get("content"))
            messages = body.get("messages")
            if isinstance(messages, list):
                for nested in messages:
                    if isinstance(nested, dict):
                        add_blocks(nested.get("content"))
        return names

    def _interaction_summary(self, row: sqlite3.Row) -> dict[str, Any]:
        summary = dict(row)
        raw = self._safe_raw(summary.pop("raw"))
        summary["tool_names"] = self._tool_names(raw)
        return summary

    def investigation(self, row_id: int, nearby_each_side: int = 3) -> dict[str, Any] | None:
        """Detail, same pid/tid context, and notable-event navigation."""
        current_row = self._db.execute(
            "SELECT * FROM interactions WHERE id = ?", (row_id,)
        ).fetchone()
        if current_row is None:
            return None

        current = dict(current_row)
        current_raw = self._safe_raw(current["raw"])
        current["raw"] = current_raw
        current["tool_names"] = self._tool_names(current_raw)

        # Wall-clock timestamps are the route contract; timestamp_ns is an
        # optional RailMon/eBPF aid. julianday also normalises RFC 3339 offsets,
        # unlike lexical timestamp ordering. Fall back only for legacy rows
        # that have no parseable wall clock.
        # Do not compare timestamp_ns directly with the wall clock: eBPF's
        # monotonic nanoseconds have no Unix/Julian epoch. Rows without a
        # parseable wall clock form a deterministic group of their own, where
        # the monotonic value remains useful for relative ordering.
        order_expr = (
            "CASE WHEN julianday(timestamp) IS NULL THEN 0 ELSE 1 END, "
            "COALESCE(julianday(timestamp), 0), COALESCE(timestamp_ns, 0)"
        )
        order_desc = (
            "CASE WHEN julianday(timestamp) IS NULL THEN 0 ELSE 1 END DESC, "
            "COALESCE(julianday(timestamp), 0) DESC, "
            "COALESCE(timestamp_ns, 0) DESC, id DESC"
        )
        order_asc = f"{order_expr}, id"
        current_order = self._db.execute(
            f"SELECT {order_expr} FROM interactions WHERE id = ?", (row_id,)
        ).fetchone()
        current_order = tuple(current_order)
        key = (*current_order, current["id"])
        key_sql = "?, ?, ?, ?"
        common = (current["session_id"], current["pid"], current["tid"])
        columns = (
            "id, session_id, interaction_id, timestamp, timestamp_ns, pid, tid, "
            "method, host, path, status_code, latency_ms, request_size, "
            "response_size, model, tool_calls, has_ticket, raw"
        )
        before = self._db.execute(
            f"""SELECT {columns} FROM interactions
                WHERE session_id = ? AND pid IS ? AND tid IS ?
                  AND ({order_expr}, id) < ({key_sql})
                ORDER BY {order_desc} LIMIT ?""",
            (*common, *key, nearby_each_side),
        ).fetchall()
        after = self._db.execute(
            f"""SELECT {columns} FROM interactions
                WHERE session_id = ? AND pid IS ? AND tid IS ?
                  AND ({order_expr}, id) > ({key_sql})
                ORDER BY {order_asc} LIMIT ?""",
            (*common, *key, nearby_each_side),
        ).fetchall()
        nearby_rows = [*reversed(before), current_row, *after]
        current["nearby"] = [self._interaction_summary(row) for row in nearby_rows]

        navigation: dict[str, int | None] = {}
        for label, predicate in (
            ("error", "status_code >= 400"),
            ("tool_call", "tool_calls > 0"),
        ):
            previous = self._db.execute(
                f"""SELECT id FROM interactions
                    WHERE session_id = ? AND {predicate}
                      AND ({order_expr}, id) < ({key_sql})
                    ORDER BY {order_desc} LIMIT 1""",
                (current["session_id"], *key),
            ).fetchone()
            following = self._db.execute(
                f"""SELECT id FROM interactions
                    WHERE session_id = ? AND {predicate}
                      AND ({order_expr}, id) > ({key_sql})
                    ORDER BY {order_asc} LIMIT 1""",
                (current["session_id"], *key),
            ).fetchone()
            navigation[f"previous_{label}"] = previous["id"] if previous else None
            navigation[f"next_{label}"] = following["id"] if following else None
        current["navigation"] = navigation
        return current

    def distinct(self, column: str, session_id: str | None = None) -> list[str]:
        if column not in {"host", "method"}:
            raise ValueError(f"not a filterable column: {column}")
        where, params = ("WHERE session_id = ?", (session_id,)) if session_id else ("", ())
        rows = self._db.execute(
            f"SELECT DISTINCT {column} FROM interactions {where}"
            f" {'AND' if where else 'WHERE'} {column} IS NOT NULL ORDER BY {column}",
            params,
        ).fetchall()
        return [r[0] for r in rows]
