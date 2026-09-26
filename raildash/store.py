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
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .ingest import interaction_has_ticket, redact_credential_headers, redact_raw_event
from .json_safety import (
    MAX_SAFE_JSON_BYTES,
    JSONStructureTooComplex,
    check_json_structure,
)
from .asp import (
    DEFAULT_DRIFT_PAGE_SIZE,
    MAX_DRIFT_PAGE_SIZE,
    bundle_digest,
    compare_alignment,
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
MAX_PROFILE_TOOL_ROWS = 10_000
MAX_PROFILE_TOOL_NAMES = 1_000
MAX_PROFILE_DIMENSION_VALUES = 100
MAX_PROFILE_VALUE_CHARS = 256
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
    agent_host_id  TEXT,
    sandbox_name   TEXT,
    agent_key      TEXT,
    attribution_state TEXT,
    attribution_method TEXT,
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
        self._asp_retention_count = self._retention_setting(
            "RAILDASH_ASP_RETENTION_COUNT", ASP_RETENTION_COUNT
        )
        self._asp_retention_days = self._retention_setting(
            "RAILDASH_ASP_RETENTION_DAYS", ASP_RETENTION_DAYS
        )
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
        self._ensure_multi_agent_columns()
        self._migrate()
        # A UI-driven retention change (`set_asp_retention`) persists here so it
        # survives a restart without re-exporting an env var. It only overrides
        # the env-var/default value computed above once the settings table
        # actually holds one -- an env var alone, with no prior UI change, still
        # behaves exactly as it always has.
        self._apply_stored_retention_overrides()
        self._db.commit()
        self._secure_database_files()

    def _ensure_multi_agent_columns(self) -> None:
        """Add DR-109 read columns without rewriting existing capture rows."""
        existing = {
            row["name"] for row in self._db.execute("PRAGMA table_info(interactions)")
        }
        for name in (
            "agent_host_id",
            "sandbox_name",
            "agent_key",
            "attribution_state",
            "attribution_method",
        ):
            if name not in existing:
                self._db.execute(f"ALTER TABLE interactions ADD COLUMN {name} TEXT")
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS interactions_agent_ref "
            "ON interactions(agent_host_id, sandbox_name, agent_key)"
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS interactions_attribution "
            "ON interactions(attribution_state)"
        )

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

    def _apply_stored_retention_overrides(self) -> None:
        attrs = {"keep_count": "_asp_retention_count", "max_age_days": "_asp_retention_days"}
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
                setattr(self, attrs[name], value)

    def get_asp_retention(self) -> dict[str, int]:
        """Current retention bounds -- env-var/default unless a UI change overrode them."""
        return {
            "keep_count": self._asp_retention_count,
            "max_age_days": self._asp_retention_days,
        }

    def set_asp_retention(self, *, keep_count: int, max_age_days: int) -> dict[str, int]:
        """Persist a UI/CLI-driven retention change so it survives a restart.

        This is the one ASP setting that used to be environment-variable-only
        (`RAILDASH_ASP_RETENTION_COUNT`/`_DAYS`); a value set here is stored
        alongside the ASPs it governs so the dashboard's settings panel does
        not depend on re-exporting an env var and restarting the process.
        """
        if keep_count <= 0 or max_age_days <= 0:
            raise ValueError("keep_count and max_age_days must be positive integers")
        with self._lock:
            for name, value in (("keep_count", keep_count), ("max_age_days", max_age_days)):
                self._db.execute(
                    """INSERT INTO settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                    (self._RETENTION_SETTINGS_KEYS[name], str(value)),
                )
            self._db.commit()
        self._asp_retention_count = keep_count
        self._asp_retention_days = max_age_days
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
        with self._lock:
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
            self._prune_asp_history_locked(
                keep_count=self._asp_retention_count,
                max_age_days=self._asp_retention_days,
            )
            self._db.commit()
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

    def lock_alignment(self, asp_id: str, version: str) -> dict[str, Any]:
        if not version or len(version) > 128 or version.strip() != version:
            raise ValueError("version must be a non-empty trimmed string of at most 128 characters")
        with self._lock:
            asp = self._db.execute("SELECT * FROM asps WHERE asp_id = ?", (asp_id,)).fetchone()
            if asp is None:
                raise KeyError("no such ASP")
            alignment_id = f"aspver-{uuid.uuid4()}"
            locked_at = self._now()
            try:
                self._db.execute(
                    """INSERT INTO alignment_versions (
                       alignment_version_id, version, locked_at, identity_kind,
                       identity_value, bundle_version, rule_pack_version, asp_id, digest
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alignment_id,
                        version,
                        locked_at,
                        asp["identity_kind"],
                        asp["identity_value"],
                        asp["bundle_version"],
                        asp["rule_pack_version"],
                        asp_id,
                        asp["digest"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                self._db.rollback()
                raise ValueError(
                    "that alignment version already exists for this agent identity"
                ) from exc
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM alignment_versions WHERE alignment_version_id = ?",
                (alignment_id,),
            ).fetchone()
            return self._alignment_contract(row)

    def switch_alignment(self, alignment_version_id: str) -> dict[str, Any]:
        with self._lock:
            version = self._db.execute(
                "SELECT * FROM alignment_versions WHERE alignment_version_id = ?",
                (alignment_version_id,),
            ).fetchone()
            if version is None:
                raise KeyError("no such alignment version")
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
                    alignment_version_id,
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
            self._db.commit()
            return {
                "binding_contract_version": 1,
                "agent_identity": self._identity_object(
                    version["identity_kind"], version["identity_value"]
                ),
                "alignment_version_id": alignment_version_id,
                "switched_at": switched_at,
            }

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
            state = (
                "COMPARISON_UNAVAILABLE"
                if not result["comparable"]
                else "DRIFT_DETECTED"
                if result["has_drift"]
                else "ALIGNED"
            )
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
        if limit < 1 or limit > MAX_DRIFT_PAGE_SIZE or offset < 0:
            raise ValueError("invalid drift page")
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
        if limit < 1 or limit > MAX_DRIFT_PAGE_SIZE or offset < 0:
            raise ValueError("invalid drift page")
        detail = self.drift_detail(asp_id)
        if detail is None:
            return None
        summary = detail["summary"]
        baseline = detail["baseline"]
        current = detail["current"]

        def lookup(kind: str, name: str) -> tuple[Any, Any]:
            if kind == "ATTRIBUTE":
                return baseline["attributes"].get(name), current["attributes"].get(name)
            if kind == "SOURCE":
                return (
                    baseline["inputs_attempted"].get(name),
                    current["inputs_attempted"].get(name),
                )
            baseline_by_id = {a["id"]: a for a in baseline.get("attestations", [])}
            current_by_id = {a["id"]: a for a in current.get("attestations", [])}
            return baseline_by_id.get(name), current_by_id.get(name)

        all_changes = summary["changes"]
        explained = []
        for change in all_changes[offset : offset + limit]:
            kind = change["type"].split("_")[0]
            before, after = lookup(kind, change["name"])
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
        with self._lock:
            removed = self._prune_asp_history_locked(
                keep_count=keep_count, max_age_days=max_age_days
            )
            self._db.commit()
            return removed

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
                        has_ticket, agent_host_id, sandbox_name, agent_key,
                        attribution_state, attribution_method, raw
                    ) VALUES (
                        :session_id, :interaction_id, :timestamp, :timestamp_ns,
                        :pid, :tid, :method, :host, :path, :status_code, :latency_ms,
                        :request_size, :response_size, :model, :tool_calls,
                        :has_ticket, :agent_host_id, :sandbox_name, :agent_key,
                        :attribution_state, :attribution_method, :raw
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
        agent_key: str | None = None,
        attribution_state: str | None = None,
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
                   attribution_state, attribution_method
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
