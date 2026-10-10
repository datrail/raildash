"""SQLite storage for captured interactions.

Why a database and not the dict the demo server used: the thing this dashboard
is for is looking at what an agent did, which is usually a question asked
*after* something went wrong. An in-memory store answers it only if you
happened to still have the process running, and RailMon's own output is a file
that outlives any process. So the dashboard persists, and `raildash load` can
replay a capture from last week.

Stdlib `sqlite3` only. RailDash's whole dependency list is FastAPI, uvicorn
and jsonschema, and it is worth keeping it that way — this is the component an OSS user runs
locally with no control plane behind it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .ingest import (
    interaction_has_ticket,
    legacy_exchange,
    redact_credential_headers,
    redact_raw_event,
    request_content_kinds,
    request_media_type,
)
from .json_safety import (
    MAX_SAFE_JSON_BYTES,
    JSONStructureTooComplex,
    check_json_structure,
)
from .asp import (
    BUNDLE_VERSION_V2,
    DEFAULT_DRIFT_PAGE_SIZE,
    BundleValidationError,
    FILE_ACCESS_ATTRIBUTE,
    MAX_DRIFT_PAGE_SIZE,
    bundle_digest,
    compare_alignment,
    identity_problems,
    parse_bundle,
    resolve_identity,
)

CREDENTIAL_REDACTION_SCHEMA_VERSION = 1
MIGRATION_BATCH_ROWS = 16
MIGRATION_BATCH_BYTES = 8 * 1024 * 1024
UNSAFE_LEGACY_CAPTURE = {
    "redacted": True,
    "reason": "legacy capture exceeded safe migration limits",
}
# Attribution states that name no agent (design doc §4.6): they go to the
# unattributed queue and never count toward any one agent.
UNATTRIBUTED_SQL = "('ambiguous', 'unknown', 'conflict')"
MAX_PROFILE_TOOL_ROWS = 10_000
# How long a statement waits for another process's write to finish -- a
# `raildash asp ...` command run while `raildash serve` is up, or the reverse.
# Every write transaction here is a few milliseconds, so this is headroom.
BUSY_TIMEOUT_SECONDS = 10.0
MAX_PROFILE_TOOL_NAMES = 1_000
MAX_PROFILE_DIMENSION_VALUES = 100
MAX_PROFILE_VALUE_CHARS = 256
MAX_PROFILE_FILE_CALLS = 100_000
MAX_PROFILE_CALL_ID_CHARS = 64
MAX_FILE_TYPE_CHARS = 16
# Tools whose input names a file, what they do to it, and which input keys
# hold the path(s): Claude Code's built-ins and the MCP reference filesystem
# server, whose tool names are matched under any MCP server name. A tool not
# listed here contributes nothing to file access; guessing from an arbitrary
# `path` argument would turn URLs and keys into "files".
FILE_TOOLS: dict[str, tuple[str, tuple[str, ...]]] = {
    "Read": ("read", ("file_path",)),
    "NotebookRead": ("read", ("notebook_path",)),
    "Write": ("write", ("file_path",)),
    "Edit": ("write", ("file_path",)),
    "MultiEdit": ("write", ("file_path",)),
    "NotebookEdit": ("write", ("notebook_path",)),
    "read_file": ("read", ("path",)),
    "read_text_file": ("read", ("path",)),
    "read_media_file": ("read", ("path",)),
    "read_multiple_files": ("read", ("paths",)),
    "get_file_info": ("read", ("path",)),
    "write_file": ("write", ("path",)),
    "edit_file": ("write", ("path",)),
    "move_file": ("write", ("source", "destination")),
}
# Anthropic's text editor tool names one file and says what to do in
# `command`; only `view` leaves the file as it was.
TEXT_EDITOR_TOOLS = frozenset({"str_replace_based_edit_tool", "str_replace_editor"})
TEXT_EDITOR_WRITE_COMMANDS = frozenset({"create", "str_replace", "insert", "undo_edit"})
# DR-154: how many sandboxes' kernel-observed file lists one profile view
# shows. A capture normally names one sandbox; this bounds the response, not
# a use case.
MAX_KERNEL_FILE_SOURCES = 8
ASP_RETENTION_COUNT = 100
ASP_RETENTION_DAYS = 30

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
    request_media_type TEXT,
    content_kinds  TEXT,
    agent_host_id  TEXT,
    sandbox_name   TEXT,
    agent_key      TEXT,
    attribution_state TEXT,
    attribution_method TEXT,
    attribution_reason TEXT,
    attribution_target TEXT,
    raw            TEXT NOT NULL,
    authenticated  INTEGER NOT NULL DEFAULT 0,
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
    raw        TEXT NOT NULL,
    authenticated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS raw_events_session ON raw_events(session_id);

-- DR-184 M0: the last heartbeat each `railmon collect` sent with the local
-- write token, so the guardrail can tell an idle agent from a dead collector
-- (design §4.1). One row per collector, upserted. `last_heartbeat_at` is
-- RailDash's own receive time; `sent_at` is kept as received, for display
-- and debugging only, since a collector's clock is not ours to trust.
CREATE TABLE IF NOT EXISTS collector_heartbeats (
    collector_id      TEXT PRIMARY KEY,
    last_heartbeat_at TEXT NOT NULL,
    taps_attached     INTEGER NOT NULL,
    sent_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asps (
    asp_id            TEXT PRIMARY KEY,
    bundle_id         TEXT NOT NULL UNIQUE,
    digest            TEXT NOT NULL UNIQUE,
    exact_bundle      BLOB NOT NULL,
    collected_at      TEXT NOT NULL,
    stored_at         TEXT NOT NULL,
    host_id           TEXT NOT NULL,
    sandbox_name      TEXT NOT NULL,
    bundle_version    INTEGER NOT NULL,
    rule_pack_version INTEGER NOT NULL,
    identity_kind     TEXT NOT NULL,
    identity_value    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS asps_identity
    ON asps(identity_kind, identity_value, stored_at DESC);

CREATE TABLE IF NOT EXISTS alignment_versions (
    alignment_version_id TEXT PRIMARY KEY,
    version              TEXT NOT NULL,
    locked_at            TEXT NOT NULL,
    identity_kind        TEXT NOT NULL,
    identity_value       TEXT NOT NULL,
    bundle_version       INTEGER NOT NULL,
    rule_pack_version    INTEGER NOT NULL,
    asp_id               TEXT NOT NULL,
    digest               TEXT NOT NULL,
    FOREIGN KEY (asp_id) REFERENCES asps(asp_id),
    UNIQUE(identity_kind, identity_value, version)
);

CREATE TABLE IF NOT EXISTS active_bindings (
    identity_kind        TEXT NOT NULL,
    identity_value       TEXT NOT NULL,
    alignment_version_id TEXT NOT NULL,
    switched_at          TEXT NOT NULL,
    PRIMARY KEY(identity_kind, identity_value),
    FOREIGN KEY (alignment_version_id)
        REFERENCES alignment_versions(alignment_version_id)
);

CREATE TABLE IF NOT EXISTS drift_results (
    drift_result_id      TEXT PRIMARY KEY,
    current_asp_id       TEXT NOT NULL,
    alignment_version_id TEXT NOT NULL,
    compared_at          TEXT NOT NULL,
    comparable           INTEGER NOT NULL,
    has_drift            INTEGER,
    reason               TEXT,
    change_count         INTEGER NOT NULL,
    result_json          TEXT NOT NULL,
    FOREIGN KEY (current_asp_id) REFERENCES asps(asp_id),
    FOREIGN KEY (alignment_version_id)
        REFERENCES alignment_versions(alignment_version_id),
    UNIQUE(current_asp_id, alignment_version_id)
);
CREATE INDEX IF NOT EXISTS drift_results_current
    ON drift_results(current_asp_id, compared_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS asps_immutable_update
BEFORE UPDATE ON asps BEGIN SELECT RAISE(ABORT, 'ASPs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS asps_immutable_delete
BEFORE DELETE ON asps
WHEN EXISTS (SELECT 1 FROM alignment_versions WHERE asp_id = OLD.asp_id)
BEGIN SELECT RAISE(ABORT, 'locked ASPs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS alignment_versions_immutable_update
BEFORE UPDATE ON alignment_versions
BEGIN SELECT RAISE(ABORT, 'alignment versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS alignment_versions_immutable_delete
BEFORE DELETE ON alignment_versions
BEGIN SELECT RAISE(ABORT, 'alignment versions are immutable'); END;
"""

SCHEMA_TABLES = frozenset(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA))
# Columns `_ensure_multi_agent_columns`/`_ensure_content_columns` add to a
# database created before them.
MULTI_AGENT_COLUMNS = (
    "agent_host_id",
    "sandbox_name",
    "agent_key",
    "attribution_state",
    "attribution_method",
    "attribution_reason",
    "attribution_target",
)
CONTENT_COLUMNS = ("request_media_type", "content_kinds")
UPGRADE_INTERACTION_COLUMNS = frozenset((*MULTI_AGENT_COLUMNS, *CONTENT_COLUMNS))
# DR-184 M0: whether a capture arrived with the local write token. Added to
# both capture tables by `_ensure_authenticated_columns`; see there.
AUTHENTICATED_COLUMN = "authenticated"
CAPTURE_TABLES = ("interactions", "raw_events")
_INTERACTION_INSERT_COLUMNS = (
    "session_id", "interaction_id", "timestamp", "timestamp_ns",
    "pid", "tid", "method", "host", "path", "status_code", "latency_ms",
    "request_size", "response_size", "model", "tool_calls",
    "has_ticket", "request_media_type", "content_kinds",
    "agent_host_id", "sandbox_name", "agent_key",
    "attribution_state", "attribution_method",
    "attribution_reason", "attribution_target", "raw", AUTHENTICATED_COLUMN,
)
# A duplicate is a conflict on `interactions_dedup`: `DO NOTHING` for an
# unauthenticated batch, exactly as `INSERT OR IGNORE` alone behaved, and the
# in-place upgrade below for an authenticated one (see `add_interactions`).
# `OR IGNORE` stays for every other constraint, as before.
_INSERT_INTERACTION = (
    f"INSERT OR IGNORE INTO interactions ({', '.join(_INTERACTION_INSERT_COLUMNS)}) "
    f"VALUES ({', '.join(':' + name for name in _INTERACTION_INSERT_COLUMNS)}) "
    "ON CONFLICT(session_id, interaction_id) WHERE interaction_id IS NOT NULL "
)
_UPGRADE_UNAUTHENTICATED_INTERACTION = (
    "DO UPDATE SET "
    + ", ".join(
        f"{name} = excluded.{name}"
        for name in _INTERACTION_INSERT_COLUMNS
        if name not in ("session_id", "interaction_id")
    )
    # Only ever upgrades: an authenticated row is never overwritten, not even
    # by another authenticated copy, so a redelivery stays a no-op.
    + " WHERE interactions.authenticated = 0"
)


def _comparison_state(comparable: Any, has_drift: Any) -> str:
    """A stored drift result's outcome, as the API and the dashboard name it."""
    if not comparable:
        return "COMPARISON_UNAVAILABLE"
    return "DRIFT_DETECTED" if has_drift else "ALIGNED"


def _check_drift_page(limit: int, offset: int) -> None:
    if limit < 1 or limit > MAX_DRIFT_PAGE_SIZE or offset < 0:
        raise ValueError("invalid drift page")


def _session_scope(session_id: str, agent_key: str | None) -> tuple[str, list[str]]:
    """The `interactions` filter for one capture, optionally one agent in it."""
    scope, params = "session_id = ?", [session_id]
    if agent_key:
        scope += " AND agent_key = ?"
        params.append(agent_key)
    return scope, params


class Store:
    """A SQLite-backed store. Safe to share across FastAPI's threadpool.

    `check_same_thread=False` plus one lock rather than a connection pool:
    the write volume here is a webhook batch every few seconds, and the
    read volume is one person with a browser open. A pool would be
    complexity bought for load that does not exist.
    """

    def __init__(self, path: str | Path = "raildash.db") -> None:
        self.path = str(path)
        self._prepare_private_database_path(Path(path))
        # Env-var/default retention bounds; a value stored by
        # `set_asp_retention` overrides them (see `_retention_locked`).
        self._asp_retention_defaults = {
            "keep_count": self._retention_setting(
                "RAILDASH_ASP_RETENTION_COUNT", ASP_RETENTION_COUNT
            ),
            "max_age_days": self._retention_setting(
                "RAILDASH_ASP_RETENTION_DAYS", ASP_RETENTION_DAYS
            ),
        }
        self._lock = threading.Lock()
        self._db = sqlite3.connect(
            self.path, timeout=BUSY_TIMEOUT_SECONDS, check_same_thread=False
        )
        self._db.row_factory = sqlite3.Row
        # WAL so a read while a webhook is writing does not block; the
        # dashboard polls, and a stalled poll looks like a hung page. Entered
        # in NORMAL locking mode on purpose: SQLite only lets a WAL connection
        # drop an exclusive lock again if it did not first enter WAL while
        # exclusive, and the lock below has to be dropped once startup ends.
        self._db.execute("PRAGMA journal_mode=WAL")
        # On a brand-new file the switch to WAL only takes effect on first
        # access; make that access now, while still in NORMAL mode.
        self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()
        # Upgrading an older database -- the credential migration above all --
        # runs under an exclusive lock, so no other process inserts an
        # unredacted row between migration pages or before the upgraded schema
        # version is committed. Every other open stays in NORMAL locking mode,
        # so an old pre-redaction RailDash started later against an upgraded
        # database is no longer locked out; its rows are still scrubbed when
        # read back (`_safe_raw`). RailDash once held the exclusive lock for
        # the life of the process, which kept every `raildash asp ...` command
        # out of the database while `raildash serve` ran, even though the
        # dashboard suggests those commands; SQLite's WAL locking already
        # serializes writers across processes, and each write transaction here
        # is short.
        upgrading = self._needs_upgrade()
        if upgrading:
            locking_mode = self._db.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()[0]
            if locking_mode.casefold() != "exclusive":
                raise RuntimeError("RailDash requires exclusive SQLite locking to upgrade")
            try:
                self._db.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError as exc:
                self._db.close()
                raise RuntimeError(
                    "this database needs a one-time upgrade; stop other RailDash "
                    f"processes using it and retry ({exc})"
                ) from exc
            self._db.commit()
        self._db.executescript(SCHEMA)
        self._ensure_multi_agent_columns()
        self._ensure_content_columns()
        self._ensure_authenticated_columns()
        self._migrate()
        self._db.commit()
        if upgrading:
            # Back to NORMAL; SQLite releases the lock on the next access.
            self._db.execute("PRAGMA locking_mode=NORMAL")
            self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()
        self._secure_database_files()

    def _needs_upgrade(self) -> bool:
        """Whether opening this database will change its schema or rows."""
        if (
            self._db.execute("PRAGMA user_version").fetchone()[0]
            < CREDENTIAL_REDACTION_SCHEMA_VERSION
        ):
            return True
        tables = {
            row[0]
            for row in self._db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not SCHEMA_TABLES <= tables:
            return True
        if not UPGRADE_INTERACTION_COLUMNS <= self._interaction_columns():
            return True
        if any(
            AUTHENTICATED_COLUMN not in self._table_columns(table)
            for table in CAPTURE_TABLES
        ):
            return True
        return (
            self._db.execute(
                "SELECT 1 FROM interactions WHERE content_kinds IS NULL LIMIT 1"
            ).fetchone()
            is not None
        )

    def _interaction_columns(self) -> set[str]:
        return self._table_columns("interactions")

    def _table_columns(self, table: str) -> set[str]:
        return {row["name"] for row in self._db.execute(f"PRAGMA table_info({table})")}

    def _add_interaction_columns(self, names: tuple[str, ...]) -> None:
        """Add each missing TEXT column; existing rows keep NULL in it."""
        existing = self._interaction_columns()
        for name in names:
            if name not in existing:
                self._db.execute(f"ALTER TABLE interactions ADD COLUMN {name} TEXT")

    def _ensure_multi_agent_columns(self) -> None:
        """Add DR-109 read columns without rewriting existing capture rows."""
        self._add_interaction_columns(MULTI_AGENT_COLUMNS)
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS interactions_agent_ref "
            "ON interactions(agent_host_id, sandbox_name, agent_key)"
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS interactions_attribution "
            "ON interactions(attribution_state)"
        )

    def _ensure_authenticated_columns(self) -> None:
        """Add DR-184's `authenticated` flag to both capture tables.

        `NOT NULL DEFAULT 0`, so every row captured before this column existed
        reads as unauthenticated -- which is what it was: the webhook took no
        token then. The same default is why an older RailDash can keep writing
        to an upgraded database: its INSERTs do not name the column, and what
        they store is correctly marked unauthenticated. Nothing is rewritten,
        so this costs one ALTER per table and no backfill.
        """
        for table in CAPTURE_TABLES:
            if AUTHENTICATED_COLUMN not in self._table_columns(table):
                self._db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {AUTHENTICATED_COLUMN} "
                    "INTEGER NOT NULL DEFAULT 0"
                )

    def _ensure_content_columns(self) -> None:
        """Add DR-132's request media columns and fill them for older rows.

        The values are derived from `raw`, which every row already holds, so a
        database captured before DR-132 shows its uploads too. New rows are
        always written with a non-NULL `content_kinds`, so NULL means "not yet
        derived": an interrupted fill resumes on the next open. Rows go in
        bounded pages like `_migrate`; one too large or malformed to parse
        gets an empty value rather than a guess.
        """
        self._add_interaction_columns(CONTENT_COLUMNS)
        # Holds only rows still to derive, so once filled it is empty and the
        # check on every later open costs nothing.
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS interactions_content_pending "
            "ON interactions(id) WHERE content_kinds IS NULL"
        )
        last_id = 0
        while True:
            rows = self._db.execute(
                "SELECT id, length(CAST(raw AS BLOB)) AS size FROM interactions "
                "WHERE content_kinds IS NULL AND id > ? ORDER BY id LIMIT ?",
                (last_id, MIGRATION_BATCH_ROWS),
            ).fetchall()
            if not rows:
                break
            for candidate in rows:
                media_type, kinds = None, ""
                if int(candidate["size"] or 0) <= MAX_SAFE_JSON_BYTES:
                    raw = self._db.execute(
                        "SELECT raw FROM interactions WHERE id = ?", (candidate["id"],)
                    ).fetchone()["raw"]
                    try:
                        exchange = legacy_exchange(self._safe_raw(raw))
                        request = (
                            exchange.get("request") if isinstance(exchange, dict) else None
                        )
                        if isinstance(request, dict):
                            media_type = request_media_type(request)
                            kinds = ",".join(request_content_kinds(request))
                    except Exception:  # noqa: BLE001 - one row must not stop startup
                        media_type, kinds = None, ""
                self._db.execute(
                    "UPDATE interactions SET request_media_type = ?, content_kinds = ? "
                    "WHERE id = ?",
                    (media_type, kinds, candidate["id"]),
                )
            last_id = rows[-1]["id"]
            self._db.commit()

    @staticmethod
    def _prepare_private_database_path(path: Path) -> None:
        """Refuse a database directory another local account can modify."""
        parent = path.resolve().parent
        if not parent.is_dir():
            raise RuntimeError(f"database parent does not exist: {parent}")
        mode = parent.stat().st_mode
        if mode & 0o022:
            raise RuntimeError(
                f"database parent must not be group/other writable: {parent}"
            )
        if path.exists() and hasattr(os, "geteuid"):
            if path.stat().st_uid != os.geteuid():
                raise RuntimeError("RailDash database must be owned by the current user")
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(path) + suffix)
            if candidate.exists():
                if hasattr(os, "geteuid") and candidate.stat().st_uid != os.geteuid():
                    raise RuntimeError("RailDash database files must be owned by the current user")
                candidate.chmod(0o600)

    @staticmethod
    def _retention_setting(name: str, default: int) -> int:
        try:
            value = int(os.environ.get(name, str(default)))
        except ValueError as exc:
            raise RuntimeError(f"{name} must be a non-negative integer") from exc
        if value <= 0:
            raise RuntimeError(f"{name} must be a positive integer")
        return value

    _RETENTION_SETTINGS_KEYS = {
        "keep_count": "asp_retention_keep_count",
        "max_age_days": "asp_retention_max_age_days",
    }

    def _retention_locked(self) -> dict[str, int]:
        """The retention bounds in force right now, read from the database.

        A UI/CLI retention change (`set_asp_retention`) persists in the
        settings table so it survives a restart without re-exporting an env
        var, and overrides the env-var/default value only once the table holds
        one. It is read on every use rather than cached, because another
        process -- `raildash asp retention-set` beside a running server -- may
        have changed it; a stale copy would prune ASPs under the old bounds.
        """
        bounds = dict(self._asp_retention_defaults)
        for name, key in self._RETENTION_SETTINGS_KEYS.items():
            row = self._db.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                continue
            try:
                value = int(row["value"])
            except ValueError:
                continue
            if value > 0:
                bounds[name] = value
        return bounds

    def get_asp_retention(self) -> dict[str, int]:
        """Current retention bounds -- env-var/default unless a UI change overrode them."""
        with self._lock:
            return self._retention_locked()

    def set_asp_retention(self, *, keep_count: int, max_age_days: int) -> dict[str, int]:
        """Persist a UI/CLI-driven retention change so it survives a restart.

        This is the one ASP setting that used to be environment-variable-only
        (`RAILDASH_ASP_RETENTION_COUNT`/`_DAYS`); a value set here is stored
        alongside the ASPs it governs so the dashboard's settings panel does
        not depend on re-exporting an env var and restarting the process.
        """
        if keep_count <= 0 or max_age_days <= 0:
            raise ValueError("keep_count and max_age_days must be positive integers")
        with self._write_transaction():
            for name, value in (("keep_count", keep_count), ("max_age_days", max_age_days)):
                self._db.execute(
                    """INSERT INTO settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                    (self._RETENTION_SETTINGS_KEYS[name], str(value)),
                )
        return self.get_asp_retention()

    def _secure_database_files(self) -> None:
        """Keep the database and SQLite sidecars readable only by their owner."""
        if self.path == ":memory:":
            return
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(self.path + suffix)
            if candidate.exists():
                candidate.chmod(0o600)

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
            self._secure_database_files()
            self._db.close()

    # --------------------------------------------------------------- ASP v1

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _identity_columns(identity: dict[str, Any]) -> tuple[str, str]:
        return identity["kind"], json.dumps(
            identity["value"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )

    @staticmethod
    def _identity_object(kind: str, value: str) -> dict[str, Any]:
        return {"kind": kind, "value": json.loads(value)}

    def load_asp(self, raw: bytes, *, agent_key: str | None = None) -> dict[str, Any]:
        """Validate and atomically retain exact evidence bytes as an immutable ASP."""
        bundle = parse_bundle(raw)
        identity = resolve_identity(bundle, agent_key)
        identity_kind, identity_value = self._identity_columns(identity)
        digest = bundle_digest(raw)
        with self._write_transaction():
            existing = self._db.execute(
                "SELECT * FROM asps WHERE digest = ?", (digest,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["identity_kind"] != identity_kind
                    or existing["identity_value"] != identity_value
                ):
                    raise ValueError(
                        "exact bundle is already stored under a different agent identity"
                    )
                return self._asp_summary(existing, replayed=True)
            collision = self._db.execute(
                "SELECT digest FROM asps WHERE bundle_id = ?", (bundle["bundle_id"],)
            ).fetchone()
            if collision is not None:
                raise ValueError("bundle_id already exists with different exact bytes")

            asp_id = f"asp-{uuid.uuid4()}"
            stored_at = self._now()
            self._db.execute(
                """INSERT INTO asps (
                       asp_id, bundle_id, digest, exact_bundle, collected_at, stored_at,
                       host_id, sandbox_name, bundle_version, rule_pack_version,
                       identity_kind, identity_value
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asp_id,
                    bundle["bundle_id"],
                    digest,
                    raw,
                    bundle["collected_at"],
                    stored_at,
                    bundle["host_id"],
                    bundle["sandbox_name"],
                    bundle["bundle_version"],
                    bundle["rule_pack_version"],
                    identity_kind,
                    identity_value,
                ),
            )
            self._compare_active_locked(asp_id, raw, identity_kind, identity_value)
            self._prune_asp_history_locked(**self._retention_locked())
            row = self._db.execute("SELECT * FROM asps WHERE asp_id = ?", (asp_id,)).fetchone()
        self._secure_database_files()
        return self._asp_summary(row, replayed=False)

    def _compare_active_locked(
        self, asp_id: str, raw: bytes, identity_kind: str, identity_value: str
    ) -> None:
        active = self._db.execute(
            """SELECT v.*, a.exact_bundle AS baseline_bundle
               FROM active_bindings b
               JOIN alignment_versions v USING (alignment_version_id)
               JOIN asps a ON a.asp_id = v.asp_id
               WHERE b.identity_kind = ? AND b.identity_value = ?""",
            (identity_kind, identity_value),
        ).fetchone()
        if active is None:
            return
        alignment = self._alignment_contract(active)
        local_key = json.loads(identity_value) if identity_kind == "local_agent_key" else None
        result = compare_alignment(
            alignment, bytes(active["baseline_bundle"]), raw, current_agent_key=local_key
        )
        self._db.execute(
            """INSERT OR IGNORE INTO drift_results (
                   drift_result_id, current_asp_id, alignment_version_id, compared_at,
                   comparable, has_drift, reason, change_count, result_json
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"drift-{uuid.uuid4()}",
                asp_id,
                active["alignment_version_id"],
                self._now(),
                int(result["comparable"]),
                None if result["has_drift"] is None else int(result["has_drift"]),
                result["reason"],
                result["change_count"],
                json.dumps(result, ensure_ascii=False, separators=(",", ":")),
            ),
        )

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        """One atomic write: committed on success, rolled back on any error.

        `BEGIN IMMEDIATE` takes SQLite's write lock up front, so a check made
        inside the block (is this digest stored? is this ASP locked?) still
        holds when the write lands, even if another process -- a
        `raildash asp ...` command beside a running server -- writes too.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._db.rollback()
                raise
            self._db.commit()

    @staticmethod
    def _check_version_label(version: str) -> None:
        if (
            not isinstance(version, str)
            or not version
            or len(version) > 128
            or version.strip() != version
        ):
            raise ValueError("version must be a non-empty trimmed string of at most 128 characters")

    def _locked_version_of(self, asp_id: str) -> sqlite3.Row | None:
        # A database written before an ASP could be locked only once may hold
        # several versions for one ASP; prefer the active one, then the first.
        return self._db.execute(
            """SELECT v.* FROM alignment_versions v
               LEFT JOIN active_bindings b
                 ON b.alignment_version_id = v.alignment_version_id
               WHERE v.asp_id = ?
               ORDER BY b.alignment_version_id IS NULL, v.locked_at, v.rowid LIMIT 1""",
            (asp_id,),
        ).fetchone()

    def _lock_locked(self, asp: sqlite3.Row, version: str) -> sqlite3.Row:
        # Every later compare validates this identity; one stored that it
        # rejects would fail every ingest for that identity from then on.
        problems = identity_problems(
            self._identity_object(asp["identity_kind"], asp["identity_value"])
        )
        if problems:
            raise ValueError(
                "this ASP's identity cannot be locked as a baseline: " + "; ".join(problems)
            )
        alignment_id = f"aspver-{uuid.uuid4()}"
        try:
            self._db.execute(
                """INSERT INTO alignment_versions (
                   alignment_version_id, version, locked_at, identity_kind,
                   identity_value, bundle_version, rule_pack_version, asp_id, digest
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alignment_id,
                    version,
                    self._now(),
                    asp["identity_kind"],
                    asp["identity_value"],
                    asp["bundle_version"],
                    asp["rule_pack_version"],
                    asp["asp_id"],
                    asp["digest"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "that alignment version already exists for this agent identity"
            ) from exc
        return self._db.execute(
            "SELECT * FROM alignment_versions WHERE alignment_version_id = ?",
            (alignment_id,),
        ).fetchone()

    def lock_alignment(self, asp_id: str, version: str) -> dict[str, Any]:
        """Lock one stored ASP as a new, immutable alignment version.

        An ASP is locked at most once: locking it again under another label
        would only add a second history row for the same evidence. Use
        `make_baseline` to activate an ASP whether or not it is locked yet.
        """
        self._check_version_label(version)
        with self._write_transaction():
            asp = self._db.execute("SELECT * FROM asps WHERE asp_id = ?", (asp_id,)).fetchone()
            if asp is None:
                raise KeyError("no such ASP")
            existing = self._locked_version_of(asp_id)
            if existing is not None:
                raise ValueError(
                    f"this ASP is already locked as {existing['version']}"
                    f" ({existing['alignment_version_id']})"
                )
            row = self._lock_locked(asp, version)
        return self._alignment_contract(row)

    def _switch_locked(self, version: sqlite3.Row) -> dict[str, Any]:
        switched_at = self._now()
        self._db.execute(
            """INSERT INTO active_bindings (
                   identity_kind, identity_value, alignment_version_id, switched_at
               ) VALUES (?, ?, ?, ?)
               ON CONFLICT(identity_kind, identity_value) DO UPDATE SET
                   alignment_version_id = excluded.alignment_version_id,
                   switched_at = excluded.switched_at""",
            (
                version["identity_kind"],
                version["identity_value"],
                version["alignment_version_id"],
                switched_at,
            ),
        )
        latest = self._db.execute(
            """SELECT asp_id, exact_bundle FROM asps
               WHERE identity_kind = ? AND identity_value = ?
               ORDER BY stored_at DESC, rowid DESC LIMIT 1""",
            (version["identity_kind"], version["identity_value"]),
        ).fetchone()
        if latest is not None:
            self._compare_active_locked(
                latest["asp_id"],
                bytes(latest["exact_bundle"]),
                version["identity_kind"],
                version["identity_value"],
            )
        return self._binding_contract(version, switched_at)

    def _binding_contract(self, version: sqlite3.Row, switched_at: str) -> dict[str, Any]:
        return {
            "binding_contract_version": 1,
            "agent_identity": self._identity_object(
                version["identity_kind"], version["identity_value"]
            ),
            "alignment_version_id": version["alignment_version_id"],
            "switched_at": switched_at,
        }

    def switch_alignment(self, alignment_version_id: str) -> dict[str, Any]:
        with self._write_transaction():
            version = self._db.execute(
                "SELECT * FROM alignment_versions WHERE alignment_version_id = ?",
                (alignment_version_id,),
            ).fetchone()
            if version is None:
                raise KeyError("no such alignment version")
            return self._switch_locked(version)

    def make_baseline(self, asp_id: str, version: str | None) -> dict[str, Any]:
        """Make one stored ASP the active baseline for its agent, idempotently.

        Locks it under `version` only if it is not locked yet, then makes that
        alignment version active unless it already is. Accepting the same
        drifted ASP twice, or picking an older locked ASP from the history,
        therefore never adds a second alignment version for the same evidence.
        `version` is required only when the ASP still has to be locked.
        """
        if version is not None:
            self._check_version_label(version)
        with self._write_transaction():
            asp = self._db.execute("SELECT * FROM asps WHERE asp_id = ?", (asp_id,)).fetchone()
            if asp is None:
                raise KeyError("no such ASP")
            row = self._locked_version_of(asp_id)
            locked = row is None
            if locked:
                if version is None:
                    raise ValueError("a version label is required to lock this ASP")
                row = self._lock_locked(asp, version)
            active = self._db.execute(
                """SELECT * FROM active_bindings
                   WHERE identity_kind = ? AND identity_value = ?""",
                (row["identity_kind"], row["identity_value"]),
            ).fetchone()
            if active is not None and active["alignment_version_id"] == row["alignment_version_id"]:
                binding, switched = self._binding_contract(row, active["switched_at"]), False
            else:
                binding, switched = self._switch_locked(row), True
            return {
                "alignment_version": self._alignment_contract(row),
                "binding": binding,
                "locked": locked,
                "switched": switched,
            }

    def asp_history(self, *, limit: int, offset: int = 0) -> dict[str, Any]:
        """Received ASPs, newest first, each with where it stands now.

        `status` is `baseline` (locked and the active version for its agent),
        `locked` (an alignment version that is not active), or `candidate`
        (received, never locked). `comparison` is the stored result against
        the agent's active baseline, when this ASP was compared with it.
        Metadata only: no evidence values or digests.
        """
        rows = self._db.execute(
            "SELECT * FROM asps ORDER BY stored_at DESC, rowid DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        items = []
        for row in rows:
            versions = self._db.execute(
                """SELECT v.alignment_version_id, v.version, v.locked_at,
                          b.alignment_version_id IS NOT NULL AS active
                   FROM alignment_versions v
                   LEFT JOIN active_bindings b
                     ON b.alignment_version_id = v.alignment_version_id
                   WHERE v.asp_id = ? ORDER BY v.locked_at, v.rowid""",
                (row["asp_id"],),
            ).fetchall()
            newest = self._db.execute(
                """SELECT asp_id FROM asps
                   WHERE identity_kind = ? AND identity_value = ?
                   ORDER BY stored_at DESC, rowid DESC LIMIT 1""",
                (row["identity_kind"], row["identity_value"]),
            ).fetchone()
            compared = self._db.execute(
                """SELECT d.comparable, d.has_drift, d.change_count, v.version
                   FROM drift_results d
                   JOIN active_bindings b
                     ON b.alignment_version_id = d.alignment_version_id
                    AND b.identity_kind = ? AND b.identity_value = ?
                   JOIN alignment_versions v
                     ON v.alignment_version_id = d.alignment_version_id
                   WHERE d.current_asp_id = ?
                   ORDER BY d.compared_at DESC LIMIT 1""",
                (row["identity_kind"], row["identity_value"], row["asp_id"]),
            ).fetchone()
            locked_versions = [
                {
                    "alignment_version_id": v["alignment_version_id"],
                    "version": v["version"],
                    "locked_at": v["locked_at"],
                    "active": bool(v["active"]),
                }
                for v in versions
            ]
            comparison = None
            if compared is not None:
                comparison = {
                    "against_version": compared["version"],
                    "state": _comparison_state(compared["comparable"], compared["has_drift"]),
                    "change_count": compared["change_count"],
                }
            items.append(
                {
                    **self._asp_summary(row, replayed=False, include_digest=False),
                    "status": (
                        "baseline"
                        if any(v["active"] for v in locked_versions)
                        else "locked"
                        if locked_versions
                        else "candidate"
                    ),
                    "latest_for_agent": newest is not None
                    and newest["asp_id"] == row["asp_id"],
                    "locked_versions": locked_versions,
                    "comparison": comparison,
                }
            )
        return {"total": self.asp_count(), "items": items, "limit": limit, "offset": offset}

    def asp_summaries(
        self,
        *,
        include_digest: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM asps ORDER BY stored_at DESC, rowid DESC"
        params: tuple[int, ...] = ()
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params = (limit, offset)
        rows = self._db.execute(sql, params).fetchall()
        return [
            self._asp_summary(row, replayed=False, include_digest=include_digest)
            for row in rows
        ]

    def alignment_summaries(
        self,
        *,
        include_digest: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        sql = (
            """SELECT v.*, b.alignment_version_id IS NOT NULL AS active
               FROM alignment_versions v
               LEFT JOIN active_bindings b
                 ON b.alignment_version_id = v.alignment_version_id
               ORDER BY v.locked_at DESC, v.rowid DESC"""
        )
        params: tuple[int, ...] = ()
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params = (limit, offset)
        rows = self._db.execute(sql, params).fetchall()
        return [
            {
                **self._alignment_contract(row, include_digest=include_digest),
                "active": bool(row["active"]),
            }
            for row in rows
        ]

    def asp_state(self, asp_id: str) -> dict[str, Any] | None:
        asp = self._db.execute("SELECT * FROM asps WHERE asp_id = ?", (asp_id,)).fetchone()
        if asp is None:
            return None
        active = self._db.execute(
            """SELECT v.alignment_version_id, v.version
               FROM active_bindings b JOIN alignment_versions v USING (alignment_version_id)
               WHERE b.identity_kind = ? AND b.identity_value = ?""",
            (asp["identity_kind"], asp["identity_value"]),
        ).fetchone()
        latest = None
        if active is not None:
            latest = self._db.execute(
                """SELECT result_json FROM drift_results
                   WHERE current_asp_id = ? AND alignment_version_id = ?
                   ORDER BY compared_at DESC LIMIT 1""",
                (asp_id, active["alignment_version_id"]),
            ).fetchone()
        if active is None:
            state, result = "NO_ACTIVE_ALIGNMENT", None
        elif latest is None:
            state, result = "ALIGNMENT_ACTIVE", None
        else:
            result = json.loads(latest["result_json"])
            state = _comparison_state(result["comparable"], result["has_drift"])
        return {
            "asp": self._asp_summary(asp, replayed=False, include_digest=False),
            "state": state,
            "active_alignment": dict(active) if active is not None else None,
            "drift": result,
        }

    def asp_count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM asps").fetchone()[0])

    def alignment_count(self) -> int:
        return int(
            self._db.execute("SELECT COUNT(*) FROM alignment_versions").fetchone()[0]
        )

    def drift_page(self, asp_id: str, *, limit: int = DEFAULT_DRIFT_PAGE_SIZE, offset: int = 0) -> dict[str, Any] | None:
        _check_drift_page(limit, offset)
        row = self._db.execute(
            """SELECT d.result_json FROM drift_results d
               JOIN asps a ON a.asp_id = d.current_asp_id
               JOIN active_bindings b
                 ON b.identity_kind = a.identity_kind
                AND b.identity_value = a.identity_value
                AND b.alignment_version_id = d.alignment_version_id
               WHERE d.current_asp_id = ? ORDER BY d.compared_at DESC LIMIT 1""",
            (asp_id,),
        ).fetchone()
        if row is None:
            return None
        result = json.loads(row["result_json"])
        changes = result.pop("changes")
        result["available_change_count"] = len(changes)
        result["changes"] = changes[offset : offset + limit]
        result["offset"] = offset
        result["limit"] = limit
        return result

    def asp_exact_bytes(self, asp_id: str) -> bytes | None:
        row = self._db.execute("SELECT exact_bundle FROM asps WHERE asp_id = ?", (asp_id,)).fetchone()
        return None if row is None else bytes(row["exact_bundle"])

    def asp_bundle(self, asp_id: str) -> dict[str, Any] | None:
        """The full parsed evidence bundle for one ASP -- the UI's inspect view.

        Same exact bytes `asp export` writes to a private file, parsed instead
        of written, so the caller (an HTTP route gated by the local write
        token, same as export needs filesystem access) can render it inline.
        """
        raw = self.asp_exact_bytes(asp_id)
        return None if raw is None else parse_bundle(raw)

    def drift_detail(self, asp_id: str) -> dict[str, Any] | None:
        """Return full local evidence for an owner-only CLI export."""
        row = self._db.execute(
            """SELECT d.result_json, d.compared_at,
                      current.exact_bundle AS current_bundle,
                      baseline.exact_bundle AS baseline_bundle,
                      v.alignment_version_id
               FROM drift_results d
               JOIN asps current ON current.asp_id = d.current_asp_id
               JOIN alignment_versions v
                 ON v.alignment_version_id = d.alignment_version_id
               JOIN asps baseline ON baseline.asp_id = v.asp_id
               JOIN active_bindings active
                 ON active.identity_kind = current.identity_kind
                AND active.identity_value = current.identity_value
                AND active.alignment_version_id = d.alignment_version_id
               WHERE d.current_asp_id = ?
               ORDER BY d.compared_at DESC LIMIT 1""",
            (asp_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "alignment_version_id": row["alignment_version_id"],
            "current_asp_id": asp_id,
            "compared_at": row["compared_at"],
            "summary": json.loads(row["result_json"]),
            "baseline": parse_bundle(bytes(row["baseline_bundle"])),
            "current": parse_bundle(bytes(row["current_bundle"])),
        }

    def kernel_file_access(
        self, session_id: str, agent_key: str | None = None
    ) -> dict[str, Any] | None:
        """The files the kernel saw a capture's sandbox open, beside it (DR-154).

        A capture's tool calls say which files the model *asked* for
        (`observed_profile`'s `file_access`). RailMon's filesnoop says which
        files the sandbox actually opened, in the `observed_file_access`
        attribute of the ASPs it delivers. This returns that attribute,
        unchanged in kind and kept apart from the asked list, from the latest
        ASP received for each sandbox the capture's interactions name
        (`matched_by: "sandbox"`). A capture with no sandbox identity, which
        is a single-agent RailMon's, names none; then it is the latest ASP
        of every sandbox (`matched_by: "latest"`), and the caller must say
        so. An ASP whose rule pack predates the attribute has `evidence:
        null`; so does one whose stored bytes no longer validate, with
        `error` saying so.
        """
        if self._db.execute(
            "SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone() is None:
            return None
        scope, params = _session_scope(session_id, agent_key)
        subjects = self._db.execute(
            f"""SELECT DISTINCT agent_host_id, sandbox_name FROM interactions
                WHERE {scope} AND agent_host_id IS NOT NULL AND sandbox_name IS NOT NULL
                ORDER BY agent_host_id, sandbox_name LIMIT ?""",
            (*params, MAX_KERNEL_FILE_SOURCES + 1),
        ).fetchall()
        matched_by = "sandbox"
        if not subjects:
            matched_by = "latest"
            subjects = self._db.execute(
                """SELECT host_id AS agent_host_id, sandbox_name FROM asps
                   GROUP BY host_id, sandbox_name
                   ORDER BY MAX(stored_at) DESC, host_id, sandbox_name LIMIT ?""",
                (MAX_KERNEL_FILE_SOURCES + 1,),
            ).fetchall()
        truncated = len(subjects) > MAX_KERNEL_FILE_SOURCES
        sources = []
        for subject in subjects[:MAX_KERNEL_FILE_SOURCES]:
            row = self._db.execute(
                """SELECT * FROM asps WHERE host_id = ? AND sandbox_name = ?
                   ORDER BY stored_at DESC, rowid DESC LIMIT 1""",
                (subject["agent_host_id"], subject["sandbox_name"]),
            ).fetchone()
            if row is None:
                continue
            summary = self._asp_summary(row, replayed=False, include_digest=False)
            source = {
                "asp_id": summary["asp_id"],
                "collected_at": summary["collected_at"],
                "stored_at": summary["stored_at"],
                "subject": summary["subject"],
                "contract": summary["contract"],
                "evidence": None,
                "error": None,
            }
            sources.append(source)
            # Stored under an older vendored schema, a bundle can fail a
            # stricter one; that is this sandbox's problem, not the page's.
            try:
                bundle = parse_bundle(bytes(row["exact_bundle"]))
            except BundleValidationError:
                source["error"] = "the stored bundle does not pass this RailDash's validation"
                continue
            attributes = (
                bundle["sandbox"]["attributes"]
                if bundle["bundle_version"] == BUNDLE_VERSION_V2
                else bundle["attributes"]
            )
            attribute = attributes.get(FILE_ACCESS_ATTRIBUTE)
            evidence = None
            if isinstance(attribute, dict):
                evidence = {
                    key: attribute.get(key)
                    for key in ("status", "reason", "tier", "authored_by", "note")
                }
                value = attribute.get("value")
                evidence["files"] = value if isinstance(value, list) else []
            source["evidence"] = evidence
        return {
            "session_id": session_id,
            "agent_key": agent_key or None,
            "attribute": FILE_ACCESS_ATTRIBUTE,
            "matched_by": matched_by,
            "sources": sources,
            "sources_truncated": truncated,
        }

    def drift_explained(
        self, asp_id: str, *, limit: int = DEFAULT_DRIFT_PAGE_SIZE, offset: int = 0
    ) -> dict[str, Any] | None:
        """Per-attribute drift with old/new values and evidence tier, paginated.

        `drift_page`/`/api/asps/{id}/drift` stay redacted to field names only
        (an existing, intentional, unauthenticated-read property some tests
        pin) -- this builds the fuller explanation the UI's drift view needs
        on top of `drift_detail`'s full baseline/current evidence, which is
        already owner-only (CLI: `asp drift-export`; HTTP: token-gated).
        """
        _check_drift_page(limit, offset)
        detail = self.drift_detail(asp_id)
        if detail is None:
            return None
        summary = detail["summary"]
        baseline = detail["baseline"]
        current = detail["current"]

        def scope_of(bundle: dict[str, Any], change: dict[str, Any]) -> dict[str, Any] | None:
            # A v1 bundle is its own single scope. A v2 change names its
            # scope: null is the shared sandbox, otherwise one agent_key.
            if "agent_key" not in change:
                return bundle
            if change["agent_key"] is None:
                return bundle["sandbox"]
            for agent in bundle["agents"]:
                if agent["agent_key"] == change["agent_key"]:
                    return agent
            return None

        def lookup(kind: str, change: dict[str, Any]) -> tuple[Any, Any]:
            name = change["name"]
            if kind in ("ATTRIBUTE", "SOURCE", "AGENT"):
                before_scope = scope_of(baseline, change)
                after_scope = scope_of(current, change)
            if kind == "AGENT":
                # The agent's discovery outcome, not its whole scope: its
                # attribute and source changes are listed separately.
                return tuple(
                    None if scope is None
                    else {"discovery_status": scope["discovery_status"]}
                    for scope in (before_scope, after_scope)
                )
            if kind == "ATTRIBUTE":
                return tuple(
                    None if scope is None else scope["attributes"].get(name)
                    for scope in (before_scope, after_scope)
                )
            if kind == "SOURCE":
                return tuple(
                    None if scope is None else scope["inputs_attempted"].get(name)
                    for scope in (before_scope, after_scope)
                )
            baseline_by_id = {a["id"]: a for a in baseline.get("attestations", [])}
            current_by_id = {a["id"]: a for a in current.get("attestations", [])}
            return baseline_by_id.get(name), current_by_id.get(name)

        all_changes = summary["changes"]
        explained = []
        for change in all_changes[offset : offset + limit]:
            kind = change["type"].split("_")[0]
            before, after = lookup(kind, change)
            explained.append({**change, "baseline": before, "current": after})

        return {
            "alignment_version_id": detail["alignment_version_id"],
            "current_asp_id": asp_id,
            "compared_at": detail["compared_at"],
            "comparable": summary["comparable"],
            "has_drift": summary["has_drift"],
            "reason": summary["reason"],
            "change_count": summary["change_count"],
            "available_change_count": len(all_changes),
            "truncated": summary["truncated"],
            "changes": explained,
            "limit": limit,
            "offset": offset,
        }

    def prune_asp_history(self, *, keep_count: int = ASP_RETENTION_COUNT, max_age_days: int = ASP_RETENTION_DAYS) -> int:
        if keep_count < 0 or max_age_days < 0:
            raise ValueError("retention bounds must be non-negative")
        # One IMMEDIATE transaction: the candidates chosen here are still
        # unlocked when they are deleted, even if a `raildash asp ...` command
        # locks one at the same moment, and any error rolls the whole prune back.
        with self._write_transaction():
            return self._prune_asp_history_locked(
                keep_count=keep_count, max_age_days=max_age_days
            )

    def _prune_asp_history_locked(self, *, keep_count: int, max_age_days: int) -> int:
        rows = self._db.execute(
                """SELECT asp_id, stored_at FROM asps
                   WHERE asp_id NOT IN (SELECT asp_id FROM alignment_versions)
                   ORDER BY stored_at DESC"""
        ).fetchall()
        cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400
        remove = []
        for index, row in enumerate(rows):
            when = datetime.fromisoformat(row["stored_at"].replace("Z", "+00:00")).timestamp()
            if index >= keep_count or when < cutoff:
                remove.append((row["asp_id"],))
        self._db.executemany(
            "DELETE FROM drift_results WHERE current_asp_id = ?", remove
        )
        self._db.executemany("DELETE FROM asps WHERE asp_id = ?", remove)
        return len(remove)

    def _asp_summary(
        self, row: sqlite3.Row, *, replayed: bool, include_digest: bool = True
    ) -> dict[str, Any]:
        result = {
            "asp_id": row["asp_id"],
            "bundle_id": row["bundle_id"],
            "collected_at": row["collected_at"],
            "stored_at": row["stored_at"],
            "subject": {"host_id": row["host_id"], "sandbox_name": row["sandbox_name"]},
            "contract": {
                "bundle_version": row["bundle_version"],
                "rule_pack_version": row["rule_pack_version"],
            },
            "agent_identity": self._identity_object(row["identity_kind"], row["identity_value"]),
            "replayed": replayed,
        }
        if include_digest:
            result["digest"] = row["digest"]
        return result

    def _alignment_contract(
        self, row: sqlite3.Row, *, include_digest: bool = True
    ) -> dict[str, Any]:
        result = {
            "alignment_contract_version": 1,
            "alignment_version_id": row["alignment_version_id"],
            "version": row["version"],
            "locked_at": row["locked_at"],
            "agent_identity": self._identity_object(row["identity_kind"], row["identity_value"]),
            "contract": {
                "bundle_version": row["bundle_version"],
                "rule_pack_version": row["rule_pack_version"],
            },
            "asp": {"asp_id": row["asp_id"], "digest": row["digest"]},
        }
        if not include_digest:
            result["asp"] = {"asp_id": row["asp_id"]}
        return result

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

    def add_interactions(
        self,
        session_id: str,
        rows: Iterable[dict[str, Any]],
        *,
        authenticated: bool = False,
    ) -> int:
        """Insert normalised rows. Returns how many were new.

        Duplicates are ignored rather than rejected: replaying a file is a
        normal thing to do and should be idempotent, not an error.

        `authenticated` (DR-184 M0) records that the batch came with the local
        write token. It defaults to False, so every caller that does not
        positively know -- `raildash load`, a script, the demo builder -- stores
        a capture the guardrail will ignore (design §4.1/§5). One exception to
        "duplicates are ignored": an authenticated delivery of an interaction
        that is already stored *unauthenticated* replaces that row in place
        and marks it authenticated. Otherwise anyone who can reach the open
        webhook could pre-post a harmless body under the dedup key of a request
        the collector is about to deliver, and the real one -- the one a
        guardrail should judge -- would be dropped as a duplicate. The reverse
        never happens: an unauthenticated copy never touches an authenticated
        row. An upgrade counts in the returned number, since what is stored
        changed.
        """
        inserted = 0
        statement = _INSERT_INTERACTION + (
            _UPGRADE_UNAUTHENTICATED_INTERACTION if authenticated else "DO NOTHING"
        )
        with self._lock:
            for row in rows:
                cur = self._db.execute(
                    statement,
                    {
                        "attribution_reason": None,
                        "attribution_target": None,
                        "request_media_type": None,
                        "content_kinds": "",
                        **row,
                        "session_id": session_id,
                        "authenticated": 1 if authenticated else 0,
                    },
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

    def add_raw_events(
        self,
        session_id: str,
        events: Iterable[dict[str, Any]],
        *,
        authenticated: bool = False,
    ) -> int:
        """Insert raw SSL events; `authenticated` as for `add_interactions`.

        Raw events have no dedup key, so there is nothing to upgrade in place.
        """
        count = 0
        with self._lock:
            for evt in events:
                self._db.execute(
                    "INSERT INTO raw_events"
                    " (session_id, function, pid, len, raw, authenticated)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        session_id,
                        evt.get("function"),
                        evt.get("pid"),
                        evt.get("len"),
                        json.dumps(evt),
                        1 if authenticated else 0,
                    ),
                )
                count += 1
            self._db.commit()
        return count

    @staticmethod
    def _receive_time(at: datetime | None = None) -> str:
        """A UTC instant as fixed-width RFC 3339, so MAX() over the text is
        MAX() over time. (`_now`'s `isoformat()` drops the fraction when it
        is zero, and `...:00Z` sorts after `...:00.5Z`.)"""
        at = datetime.now(timezone.utc) if at is None else at.astimezone(timezone.utc)
        return at.isoformat(timespec="microseconds").replace("+00:00", "Z")

    def record_heartbeat(
        self,
        collector_id: str,
        *,
        taps_attached: int,
        sent_at: str,
        received_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Upsert one collector's heartbeat (DR-184 M0, design §4.1).

        The caller has already checked the local write token and the body;
        this only stores it. `last_heartbeat_at` is RailDash's receive time --
        `received_at` exists for tests -- never the collector's `sent_at`: a
        collector with a skewed or forward-set clock must not be able to keep
        the request rules looking live.
        """
        row = {
            "collector_id": collector_id,
            "last_heartbeat_at": self._receive_time(received_at),
            "taps_attached": taps_attached,
            "sent_at": sent_at,
        }
        with self._write_transaction():
            self._db.execute(
                """INSERT INTO collector_heartbeats
                       (collector_id, last_heartbeat_at, taps_attached, sent_at)
                   VALUES (:collector_id, :last_heartbeat_at, :taps_attached, :sent_at)
                   ON CONFLICT(collector_id) DO UPDATE SET
                       last_heartbeat_at = excluded.last_heartbeat_at,
                       taps_attached     = excluded.taps_attached,
                       sent_at           = excluded.sent_at""",
                row,
            )
        return row

    # ----------------------------------------------------------------- read

    def latest_heartbeat_at(self) -> str | None:
        """The newest authenticated heartbeat over every collector, or None.

        What `guardrail.request_rules_status(last_heartbeat_at=...)` takes:
        the request rules are verifiable while *some* collector is alive.
        Only the token-gated route writes this table, so every row counts.
        """
        row = self._db.execute(
            "SELECT MAX(last_heartbeat_at) FROM collector_heartbeats"
        ).fetchone()
        return row[0]

    def collector_heartbeat(self, collector_id: str) -> dict[str, Any] | None:
        """One collector's last heartbeat: `{collector_id, last_heartbeat_at,
        taps_attached, sent_at}`, or None if it never sent one."""
        row = self._db.execute(
            "SELECT * FROM collector_heartbeats WHERE collector_id = ?",
            (collector_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    def collector_heartbeats(self) -> list[dict[str, Any]]:
        """Every collector's last heartbeat, most recently heard first."""
        rows = self._db.execute(
            "SELECT * FROM collector_heartbeats "
            "ORDER BY last_heartbeat_at DESC, collector_id"
        ).fetchall()
        return [dict(row) for row in rows]

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
                   TOTAL(request_size)                 AS request_bytes,
                   TOTAL(response_size)                AS response_bytes,
                   COALESCE(SUM(attribution_state IN {UNATTRIBUTED_SQL}), 0)
                                                       AS unattributed
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

        # TOTAL, not SUM: two captured sizes near 2**63 overflow SUM and
        # would fail this view outright.
        totals_out = dict(totals) if totals else {}
        for key in ("request_bytes", "response_bytes"):
            if key in totals_out:
                totals_out[key] = int(totals_out[key])
        return {
            "totals": totals_out,
            "hosts": [dict(r) for r in hosts],
            "models": [dict(r) for r in models],
            "statuses": [dict(r) for r in statuses],
        }

    def observed_profile(
        self, session_id: str, agent_key: str | None = None
    ) -> dict[str, Any] | None:
        """Build a portable summary of facts observed in one capture.

        This deliberately contains no score or inferred posture. Values come
        only from the already-redacted interaction columns and captured
        ``tool_use`` blocks: their names, and the file paths known file
        tools were asked to read or write.

        With ``agent_key`` the summary covers only interactions attributed to
        that agent. Ambiguous, unknown and conflict rows never carry an
        ``agent_key`` (see ``ingest``), so they stay in the unattributed queue
        and cannot shape any one agent's observed profile (design doc §4.6).
        """
        scope, scope_params = _session_scope(session_id, agent_key)
        session = self._db.execute(
            "SELECT session_id, agent, capture_start FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if session is None:
            return None

        totals = self._db.execute(
            f"""
            SELECT COUNT(*) AS interactions,
                   COALESCE(SUM(status_code >= 400), 0) AS errors,
                   COALESCE(SUM(has_ticket), 0) AS ticket_interactions
            FROM interactions WHERE {scope}
            """,
            scope_params,
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
                    WHERE {scope} AND {column} IS NOT NULL AND {column} != ''
                    GROUP BY substr({column}, 1, ?)
                    ORDER BY count DESC, value
                    LIMIT ?""",
                (
                    MAX_PROFILE_VALUE_CHARS,
                    MAX_PROFILE_VALUE_CHARS,
                    *scope_params,
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
        # A request replays every earlier turn, so the same tool_use block
        # reappears in each later call; its id counts it once per capture.
        file_calls_seen: set[str] = set()
        file_counts: dict[str, dict[str, int]] = {}
        type_counts: dict[str, dict[str, int]] = {}
        file_calls_truncated = False
        raw_rows = self._db.execute(
            f"""SELECT raw FROM interactions
               WHERE {scope} AND tool_calls > 0
               ORDER BY id LIMIT ?""",
            (*scope_params, MAX_PROFILE_TOOL_ROWS + 1),
        )
        for index, row in enumerate(raw_rows):
            if index == MAX_PROFILE_TOOL_ROWS:
                tool_names_truncated = True
                file_calls_truncated = True
                break
            raw = self._safe_raw(row["raw"])
            for block in self._tool_use_blocks(raw):
                accesses = self._file_access(block)
                if not accesses:
                    continue
                call_id = block.get("id")
                if isinstance(call_id, str) and call_id:
                    # An id is attacker-sized; keep a digest of a long one
                    # so the seen set stays small.
                    if len(call_id) > MAX_PROFILE_CALL_ID_CHARS:
                        call_id = hashlib.sha256(
                            call_id.encode("utf-8", "surrogatepass")
                        ).hexdigest()
                    if call_id in file_calls_seen:
                        continue
                    if len(file_calls_seen) >= MAX_PROFILE_FILE_CALLS:
                        file_calls_truncated = True
                        continue
                    file_calls_seen.add(call_id)
                if len(accesses) > MAX_PROFILE_TOOL_NAMES:
                    accesses = accesses[:MAX_PROFILE_TOOL_NAMES]
                    # One call does one thing to every file it names.
                    mark_truncated("file_access")
                    mark_truncated("file_types")
                    if accesses[0][0] == "write":
                        mark_truncated("file_writes")
                for operation, path in accesses:
                    file_type = self._file_type(path)
                    if len(path) > MAX_PROFILE_VALUE_CHARS:
                        path = path[:MAX_PROFILE_VALUE_CHARS]
                        mark_truncated("file_access")
                        if operation == "write":
                            mark_truncated("file_writes")
                    for counts, key, label in (
                        (file_counts, path, "file_access"),
                        (type_counts, file_type, "file_types"),
                    ):
                        if key not in counts:
                            if len(counts) >= MAX_PROFILE_TOOL_NAMES:
                                mark_truncated(label)
                                # A new written path displaces one only read.
                                displaced = (
                                    next(
                                        (k for k, ops in counts.items() if not ops["write"]),
                                        None,
                                    )
                                    if label == "file_access" and operation == "write"
                                    else None
                                )
                                if displaced is None:
                                    if label == "file_access" and operation == "write":
                                        mark_truncated("file_writes")
                                    continue
                                del counts[displaced]
                            counts[key] = {"read": 0, "write": 0}
                        counts[key][operation] += 1
            names = self._tool_names(
                raw,
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

        # Only BLOCK_TYPE_KINDS/MEDIA_TYPE_KINDS values are ever stored, so
        # this dimension is a closed vocabulary and needs no truncation.
        content_kind_counts: dict[str, int] = {}
        for row in self._db.execute(
            f"""SELECT content_kinds, COUNT(*) AS count FROM interactions
               WHERE {scope} AND content_kinds IS NOT NULL AND content_kinds != ''
               GROUP BY content_kinds""",
            scope_params,
        ):
            for kind in row["content_kinds"].split(","):
                content_kind_counts[kind] = content_kind_counts.get(kind, 0) + row["count"]

        # How much each destination host is sent, from the request size the
        # capture records (the whole HTTP request, headers included). Without
        # it, a host the agent already uses could start receiving files many
        # times the usual size and change no host, method, model or tool.
        # The size is whatever the capture said, so only a positive integer
        # counts (SQLite orders text above every number), and TOTAL cannot
        # overflow the way SUM can.
        upload_rows = self._db.execute(
            f"""SELECT substr(host, 1, ?) AS value,
                       COUNT(*) AS count,
                       TOTAL(request_size) AS total_bytes,
                       MAX(request_size) AS max_bytes,
                       MAX(length(host) > ?) AS value_truncated
                FROM interactions
                WHERE {scope} AND host IS NOT NULL AND host != ''
                      AND typeof(request_size) = 'integer' AND request_size > 0
                GROUP BY substr(host, 1, ?)
                ORDER BY total_bytes DESC, value
                LIMIT ?""",
            (
                MAX_PROFILE_VALUE_CHARS,
                MAX_PROFILE_VALUE_CHARS,
                *scope_params,
                MAX_PROFILE_VALUE_CHARS,
                MAX_PROFILE_DIMENSION_VALUES + 1,
            ),
        ).fetchall()
        if len(upload_rows) > MAX_PROFILE_DIMENSION_VALUES:
            mark_truncated("upload_bytes")
            upload_rows = upload_rows[:MAX_PROFILE_DIMENSION_VALUES]
        if any(row["value_truncated"] for row in upload_rows):
            mark_truncated("upload_bytes")

        if file_calls_truncated:
            # The rows or calls not read could have named any file.
            mark_truncated("file_access")
            mark_truncated("file_writes")
            mark_truncated("file_types")

        # Anything written ranks ahead of anything only read, and displaces
        # a read-only path at the counting cap above, so reading many files
        # cannot push a write out; only more written values than either
        # limit makes writes incomplete.
        def by_calls(counts: dict[str, dict[str, int]], label: str) -> list[dict[str, Any]]:
            ranked = sorted(
                counts.items(),
                key=lambda item: (
                    item[1]["write"] == 0,
                    -(item[1]["read"] + item[1]["write"]),
                    item[0],
                ),
            )
            if len(ranked) > MAX_PROFILE_DIMENSION_VALUES:
                mark_truncated(label)
                if label == "file_access" and ranked[MAX_PROFILE_DIMENSION_VALUES][1]["write"]:
                    mark_truncated("file_writes")
                ranked = ranked[:MAX_PROFILE_DIMENSION_VALUES]
            return [
                {
                    "value": value,
                    "count": ops["read"] + ops["write"],
                    "read": ops["read"],
                    "write": ops["write"],
                }
                for value, ops in ranked
            ]

        file_access = by_calls(file_counts, "file_access")
        file_types = by_calls(type_counts, "file_types")

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
                **({"agent_key": agent_key} if agent_key else {}),
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
                "request_media_types": counted(
                    "request_media_type", "request_media_types"
                ),
                "content_kinds": [
                    {"value": kind, "count": count}
                    for kind, count in sorted(
                        content_kind_counts.items(), key=lambda item: (-item[1], item[0])
                    )
                ],
                "upload_bytes": [
                    {
                        "value": row["value"],
                        "count": row["count"],
                        "total_bytes": int(row["total_bytes"]),
                        "max_bytes": int(row["max_bytes"]),
                    }
                    for row in upload_rows
                ],
                "file_access": file_access,
                "file_types": file_types,
                "truncated_dimensions": [
                    label
                    for label in (
                        "hosts",
                        "methods",
                        "models",
                        "tool_names",
                        "request_media_types",
                        "upload_bytes",
                        "file_access",
                        "file_writes",
                        "file_types",
                    )
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
        agent_key: str | None = None,
        attribution_state: str | None = None,
        unattributed: bool = False,
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
        if agent_key:
            clauses.append("agent_key = ?")
            params.append(agent_key)
        if attribution_state:
            clauses.append("attribution_state = ?")
            params.append(attribution_state)
        if unattributed:
            clauses.append(f"attribution_state IN {UNATTRIBUTED_SQL}")
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
                   response_size, model, tool_calls, has_ticket,
                   agent_host_id, sandbox_name, agent_key,
                   attribution_state, attribution_method, attribution_reason,
                   attribution_target
            FROM interactions {where}
            ORDER BY timestamp_ns DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}

    def interaction(self, row_id: int) -> dict[str, Any] | None:
        """One stored row, for RailDash's own use (the guardrail, tests).

        Carries `authenticated` as a bool -- `guardrail.request_owner`'s
        input. No unauthenticated route returns this dict; the HTTP detail
        view is `investigation`, which leaves the flag out.
        """
        row = self._db.execute(
            "SELECT * FROM interactions WHERE id = ?", (row_id,)
        ).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["raw"] = self._safe_raw(out["raw"])
        out[AUTHENTICATED_COLUMN] = bool(out[AUTHENTICATED_COLUMN])
        return out

    @staticmethod
    def _tool_use_blocks(raw: Any) -> Iterator[dict[str, Any]]:
        """Yield tool_use blocks from captured Anthropic message locations.

        Capture bodies are untrusted, so only the known locations are
        inspected and every unexpected shape is ignored.
        """
        raw = legacy_exchange(raw)
        if not isinstance(raw, dict):
            return

        def blocks(content: Any) -> Iterator[dict[str, Any]]:
            if not isinstance(content, list):
                return
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    yield block

        for direction in ("request", "response"):
            message = raw.get(direction)
            if not isinstance(message, dict):
                continue
            body = message.get("body")
            if not isinstance(body, dict):
                continue
            yield from blocks(body.get("content"))
            messages = body.get("messages")
            if isinstance(messages, list):
                for nested in messages:
                    if isinstance(nested, dict):
                        yield from blocks(nested.get("content"))

    @classmethod
    def _tool_names(
        cls, raw: Any, *, deduplicate: bool = True, limit: int | None = None
    ) -> list[str]:
        """Return ordered tool_use names from captured message blocks."""
        names: list[str] = []
        for block in cls._tool_use_blocks(raw):
            if limit is not None and len(names) >= limit:
                break
            name = block.get("name")
            if (
                isinstance(name, str)
                and name
                and (not deduplicate or name not in names)
            ):
                names.append(name)
        return names

    @staticmethod
    def _file_access(block: dict[str, Any]) -> list[tuple[str, str]]:
        """The (operation, path) pairs one tool_use block asks for.

        This is what the model asked a tool to do, read from the captured
        conversation; it is not a filesystem trace and says nothing about
        whether the tool ran or succeeded.
        """
        name = block.get("name")
        arguments = block.get("input")
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return []
        # Claude Code names MCP tools mcp__<server>__<tool>.
        if name.startswith("mcp__"):
            name = name.rsplit("__", 1)[-1]
        if name in TEXT_EDITOR_TOOLS:
            command = arguments.get("command")
            if command == "view":
                operation = "read"
            elif command in TEXT_EDITOR_WRITE_COMMANDS:
                operation = "write"
            else:
                return []
            keys: tuple[str, ...] = ("path",)
        elif name in FILE_TOOLS:
            operation, keys = FILE_TOOLS[name]
        else:
            return []
        accesses: list[tuple[str, str]] = []
        for key in keys:
            value = arguments.get(key)
            # Only a `paths` argument is a list; anything else names one file.
            paths = value if key == "paths" and isinstance(value, list) else [value]
            for path in paths:
                if isinstance(path, str) and path.strip():
                    accesses.append((operation, path.strip()))
                    # One more than the caller keeps, so it can tell.
                    if len(accesses) > MAX_PROFILE_TOOL_NAMES:
                        return accesses
        return accesses

    @staticmethod
    def _file_type(path: str) -> str:
        """A path's lower-cased extension, `(none)` without one."""
        base = path.replace("\\", "/").rsplit("/", 1)[-1]
        stem, dot, extension = base.rpartition(".")
        if not dot or not stem or not extension:
            return "(none)"
        if len(extension) >= MAX_FILE_TYPE_CHARS:
            return "(other)"
        return "." + extension.lower()

    def _interaction_summary(self, row: sqlite3.Row) -> dict[str, Any]:
        summary = dict(row)
        # The current row arrives as `SELECT *`; whether a capture was
        # authenticated is guardrail input, not something the open detail
        # route reveals (design §5: no new unauthenticated surface).
        summary.pop(AUTHENTICATED_COLUMN, None)
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
        current.pop(AUTHENTICATED_COLUMN, None)  # see `_interaction_summary`
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
        if column not in {"host", "method", "agent_key"}:
            raise ValueError(f"not a filterable column: {column}")
        where, params = ("WHERE session_id = ?", (session_id,)) if session_id else ("", ())
        rows = self._db.execute(
            f"SELECT DISTINCT {column} FROM interactions {where}"
            f" {'AND' if where else 'WHERE'} {column} IS NOT NULL ORDER BY {column}",
            params,
        ).fetchall()
        return [r[0] for r in rows]
