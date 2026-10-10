"""Guardrail custody and the two store hooks (DR-184, milestone M2).

The design is railxia/docs `design/2026-10-07-data-guardrail/
data-guardrail-design.md`; section numbers below are its. `raildash.guardrail`
is the pure contract and evaluator (M1); this is where its results are kept:

- **Versions** (`guardrail_versions`) are immutable, like alignment versions.
  Every change of policy -- adopt, edit, Allow this, a declared host allowed
  or dismissed -- creates one, labelled `g1`, `g2`, ... per agent.
- **The active pointer** (`guardrail_bindings`) names at most one version per
  agent identity, with the moment it was made active. Switch moves it, and
  Turn off deletes it, which is *No guardrail*.
- **Rows** (`guardrail_rows`) are the §4.5 violation rows, one per (agent
  identity, rule, item), updated on a repeat. Unacknowledged rows are never
  pruned; past the open-row cap a new item counts in one overflow row, and
  an acknowledged row is deleted once its last hit is older than the
  retention. Both numbers are settings (`RAILDASH_GUARDRAIL_MAX_OPEN_ROWS`,
  `RAILDASH_GUARDRAIL_ACK_RETENTION_DAYS`).
- **Marks** (`guardrail_marks`) are the receive times the request rules'
  liveness reads besides the heartbeat and refusal tables M0 added: the last
  authenticated request that couldn't be given to one agent (every agent's),
  and the last request of an agent whose response's tool calls couldn't be
  read (that agent's).
- **Events** (`guardrail_events`) are the visible history of every
  token-gated action, switches, turn-offs and acknowledgements included,
  which leave no version behind.

The hooks run inside the store's own ingest transactions (§4.5 "When it
runs"), so `raildash load`, `raildash asp load` and the webhooks run the same
code: `_guardrail_on_asp` from `Store.load_asp`, `_guardrail_on_request` from
`Store.add_interactions`. Neither takes the store's lock; their callers hold
it. The state (`guardrail_detail`) is computed when read, because the
staleness and liveness windows depend on the time of the read.

Where the design is silent this module chooses:

- An agent is addressed by an opaque `agent_ref`, a hash of its identity, so
  a route never carries an identity value in its path.
- Every ASP is checked when stored, including one older than the newest
  (a re-imported file): its violations are real observations, and a stale
  newest ASP keeps the ASP rules Unverified rather than hiding anything.
- `uploads` host rows keep the largest request size and whether any hit
  carried a body, so a later version is judged against the worst request
  seen, not the last one (M1 review, score 50).
- **Allow this** refuses the overflow row, `(unknown host)`, a server-less
  MCP name and an upload over a size cap; the cap is changed by an edit.
- **Allow this** and **Dismiss** on a declared offer need the offer to be
  current, so a stale page can't record a choice nobody was shown.
- A hook that fails is rolled back to a savepoint, so the evidence it was
  judging is still stored and drift still runs. It fails closed: which agent
  the evidence belonged to may be what failed, so every rule of every agent
  whose version was made active before the failure reads Unverified
  (`CHECK_FAILED`) until a version is made active again, which re-checks the
  newest ASP. The error goes to stderr. The settings are checked when the
  store opens, so a bad one stops startup rather than every hook.
- A hit from the source a row already holds (the same ASP re-checked on
  adopt, edit, switch or Allow this) is not a new hit: it neither counts
  again nor re-opens an acknowledged row (§4.5: only a hit *after* the
  acknowledgement does). Nor does a re-check count in the overflow row.
  But once acknowledgements bring the open rows under the cap, a re-check
  lists items of that ASP that had only overflowed: they are real
  violations that were never shown one by one.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Mapping

from .asp import parse_bundle

GUARDRAIL_MAX_OPEN_ROWS = 1_000
GUARDRAIL_ACK_RETENTION_DAYS = 30
# The proposal reads at most this many of the agent's requests from the
# 24 h before the lock, newest first.
PROPOSAL_MAX_REQUESTS = 5_000
MAX_GUARDRAIL_EVENTS_SHOWN = 100
OVERFLOW_RULE = "(overflow)"
OVERFLOW_ITEM = "(overflow)"
# Identity columns of a mark that applies to every agent.
EVERY_AGENT = ("", "")
MARK_UNATTRIBUTED = "unattributed"
MARK_TOOL_CALLS_UNREADABLE = "tool_calls_unreadable"
MARK_CHECK_FAILED = "check_failed"

GUARDRAIL_SCHEMA = """
-- DR-184 M2: guardrail custody (design §4.2/§4.5). Additive: a database
-- with no rows here behaves exactly as before, and an older RailDash opens
-- it and ignores these tables.
CREATE TABLE IF NOT EXISTS guardrail_versions (
    guardrail_version_id TEXT PRIMARY KEY,
    version              TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    identity_kind        TEXT NOT NULL,
    identity_value       TEXT NOT NULL,
    created_by           TEXT NOT NULL,
    contract_json        TEXT NOT NULL,
    UNIQUE(identity_kind, identity_value, version)
);

CREATE TABLE IF NOT EXISTS guardrail_bindings (
    identity_kind        TEXT NOT NULL,
    identity_value       TEXT NOT NULL,
    guardrail_version_id TEXT NOT NULL,
    activated_at         TEXT NOT NULL,
    PRIMARY KEY(identity_kind, identity_value),
    FOREIGN KEY (guardrail_version_id)
        REFERENCES guardrail_versions(guardrail_version_id)
);

CREATE TABLE IF NOT EXISTS guardrail_rows (
    row_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_kind   TEXT NOT NULL,
    identity_value  TEXT NOT NULL,
    rule            TEXT NOT NULL,
    item            TEXT NOT NULL,
    overflow        INTEGER NOT NULL DEFAULT 0,
    evidence_class  TEXT NOT NULL,
    detail_json     TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    hits            INTEGER NOT NULL,
    flagged_by      TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    acknowledged_at TEXT,
    UNIQUE(identity_kind, identity_value, rule, item)
);
CREATE INDEX IF NOT EXISTS guardrail_rows_open
    ON guardrail_rows(identity_kind, identity_value, acknowledged_at);

CREATE TABLE IF NOT EXISTS guardrail_marks (
    identity_kind  TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    mark           TEXT NOT NULL,
    at             TEXT NOT NULL,
    PRIMARY KEY(identity_kind, identity_value, mark)
);

CREATE TABLE IF NOT EXISTS guardrail_events (
    event_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at                   TEXT NOT NULL,
    identity_kind        TEXT NOT NULL,
    identity_value       TEXT NOT NULL,
    action               TEXT NOT NULL,
    guardrail_version_id TEXT,
    detail_json          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS guardrail_events_identity
    ON guardrail_events(identity_kind, identity_value, event_id);

CREATE TRIGGER IF NOT EXISTS guardrail_versions_immutable_update
BEFORE UPDATE ON guardrail_versions
BEGIN SELECT RAISE(ABORT, 'guardrail versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS guardrail_versions_immutable_delete
BEFORE DELETE ON guardrail_versions
BEGIN SELECT RAISE(ABORT, 'guardrail versions are immutable'); END;
"""


def agent_ref(identity_kind: str, identity_value: str) -> str:
    """The opaque, stable name routes use for one agent identity."""
    digest = hashlib.sha256(f"{identity_kind}\0{identity_value}".encode()).hexdigest()
    return f"agt-{digest[:24]}"


def _setting(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _merged_detail(rule: str, old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """The detail a repeat leaves on a row: the new hit's, except that an
    `uploads` host row keeps the worst request seen, so that a later
    version re-checking it (`guardrail.item_allowed`) can't be passed by a
    small last request after a large one."""
    if rule != "uploads" or new.get("kind") != "host" or old.get("kind") != "host":
        return dict(new)
    merged = dict(new)
    hits = (old, new)
    body = any(g._row_carries_body(detail) for detail in hits)
    unknown = any(
        type(detail.get("request_size")) is not int and g._row_carries_body(detail)
        for detail in hits
    )
    sizes = [d["request_size"] for d in hits if type(d.get("request_size")) is int]
    merged["carries_body"] = body
    merged["request_size"] = None if unknown or not sizes else max(sizes)
    merged["reasons"] = sorted({*(old.get("reasons") or ()), *(new.get("reasons") or ())})
    return merged


class GuardrailCustody:
    """Store methods for guardrail custody; mixed into `raildash.store.Store`,
    whose `_db`, `_lock`, `_write_transaction`, `_receive_time` and identity
    helpers it uses."""

    _db: sqlite3.Connection

    def _guardrail_settings(self) -> dict[str, int]:
        return {
            "max_open_rows": _setting("RAILDASH_GUARDRAIL_MAX_OPEN_ROWS", GUARDRAIL_MAX_OPEN_ROWS),
            "ack_retention_days": _setting(
                "RAILDASH_GUARDRAIL_ACK_RETENTION_DAYS", GUARDRAIL_ACK_RETENTION_DAYS
            ),
        }

    # ------------------------------------------------------------ lookups

    def _guardrail_version_row(self, guardrail_version_id: str) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM guardrail_versions WHERE guardrail_version_id = ?",
            (guardrail_version_id,),
        ).fetchone()
        if row is None:
            raise KeyError("no such guardrail version")
        return row

    def _active_guardrail_row(self, kind: str, value: str) -> sqlite3.Row | None:
        return self._db.execute(
            """SELECT v.*, b.activated_at FROM guardrail_bindings b
               JOIN guardrail_versions v USING (guardrail_version_id)
               WHERE b.identity_kind = ? AND b.identity_value = ?""",
            (kind, value),
        ).fetchone()

    def _known_identities(self) -> list[tuple[str, str]]:
        rows = self._db.execute(
            """SELECT identity_kind, identity_value FROM active_bindings
               UNION SELECT identity_kind, identity_value FROM guardrail_versions
               ORDER BY 1, 2"""
        ).fetchall()
        return [(row[0], row[1]) for row in rows]

    def _resolve_agent_ref(self, ref: str) -> tuple[str, str]:
        for kind, value in self._known_identities():
            if agent_ref(kind, value) == ref:
                return kind, value
        raise KeyError("no such agent")

    def _newest_asps(self, kind: str, value: str) -> list[sqlite3.Row]:
        return self._db.execute(
            """SELECT asp_id, exact_bundle, collected_at FROM asps
               WHERE identity_kind = ? AND identity_value = ?
               ORDER BY stored_at DESC, rowid DESC LIMIT 2""",
            (kind, value),
        ).fetchall()

    def _sandboxes(self, kind: str, value: str) -> list[tuple[str, str]]:
        rows = self._db.execute(
            "SELECT DISTINCT host_id, sandbox_name FROM asps "
            "WHERE identity_kind = ? AND identity_value = ?",
            (kind, value),
        ).fetchall()
        return [(row[0], row[1]) for row in rows]

    def _active_guardrails(self) -> list[dict[str, Any]]:
        """Every active guardrail, as `guardrail.request_owner` takes them."""
        rows = self._db.execute(
            """SELECT v.*, b.activated_at FROM guardrail_bindings b
               JOIN guardrail_versions v USING (guardrail_version_id)"""
        ).fetchall()
        return [
            {
                "identity": self._identity_object(row["identity_kind"], row["identity_value"]),
                "sandboxes": self._sandboxes(row["identity_kind"], row["identity_value"]),
                "row": row,
            }
            for row in rows
        ]

    def _mark(self, kind: str, value: str, mark: str, at: str) -> None:
        self._db.execute(
            """INSERT INTO guardrail_marks (identity_kind, identity_value, mark, at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(identity_kind, identity_value, mark)
               DO UPDATE SET at = MAX(at, excluded.at)""",
            (kind, value, mark, at),
        )

    def _mark_at(self, kind: str, value: str, mark: str) -> str | None:
        row = self._db.execute(
            "SELECT at FROM guardrail_marks "
            "WHERE identity_kind = ? AND identity_value = ? AND mark = ?",
            (kind, value, mark),
        ).fetchone()
        return row[0] if row is not None else None

    def _event(
        self, kind: str, value: str, action: str, version_id: str | None,
        detail: Mapping[str, Any],
    ) -> None:
        self._db.execute(
            """INSERT INTO guardrail_events
                   (at, identity_kind, identity_value, action, guardrail_version_id, detail_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (self._receive_time(), kind, value, action, version_id,
             json.dumps(detail, ensure_ascii=False, sort_keys=True)),
        )

    # --------------------------------------------------------------- rows

    def _record_violations(
        self, kind: str, value: str, version_id: str, violations: Iterable[Mapping[str, Any]],
        at: str, *, recheck: bool = False,
    ) -> None:
        settings = self._guardrail_settings()
        for violation in violations:
            self._record_violation(
                kind, value, version_id, violation, at, settings["max_open_rows"], recheck
            )
        cutoff = (
            _instant(at) - timedelta(days=settings["ack_retention_days"])
        ).astimezone(timezone.utc)
        self._db.execute(
            "DELETE FROM guardrail_rows WHERE identity_kind = ? AND identity_value = ? "
            "AND acknowledged_at IS NOT NULL AND last_seen < ?",
            (kind, value, self._receive_time(cutoff)),
        )

    def _record_violation(
        self, kind: str, value: str, version_id: str, violation: Mapping[str, Any], at: str,
        max_open_rows: int, recheck: bool,
    ) -> None:
        source = violation["source"]
        existing = self._db.execute(
            "SELECT * FROM guardrail_rows WHERE identity_kind = ? AND identity_value = ? "
            "AND rule = ? AND item = ?",
            (kind, value, violation["rule"], violation["item"]),
        ).fetchone()
        if (
            existing is not None
            and existing["source_kind"] == source["kind"]
            and existing["source_id"] == str(source["id"])
        ):
            return  # The same evidence judged again is not a new hit.
        if existing is None:
            open_rows = self._db.execute(
                "SELECT count(*) FROM guardrail_rows WHERE identity_kind = ? "
                "AND identity_value = ? AND acknowledged_at IS NULL AND overflow = 0",
                (kind, value),
            ).fetchone()[0]
            if open_rows >= max_open_rows:
                self._record_overflow(kind, value, version_id, violation, at, recheck)
                return
            self._db.execute(
                """INSERT INTO guardrail_rows (
                       identity_kind, identity_value, rule, item, overflow, evidence_class,
                       detail_json, first_seen, last_seen, hits, flagged_by,
                       source_kind, source_id, acknowledged_at
                   ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, 1, ?, ?, ?, NULL)""",
                (kind, value, violation["rule"], violation["item"],
                 violation["evidence_class"], json.dumps(violation["detail"], sort_keys=True),
                 at, at, version_id, source["kind"], str(source["id"])),
            )
            return
        detail = _merged_detail(
            violation["rule"], json.loads(existing["detail_json"]), violation["detail"]
        )
        # A hit after an acknowledgement re-opens the row (§4.5).
        self._db.execute(
            """UPDATE guardrail_rows SET
                   evidence_class = ?, detail_json = ?, last_seen = MAX(last_seen, ?),
                   hits = hits + 1, flagged_by = ?, source_kind = ?, source_id = ?,
                   acknowledged_at = NULL
               WHERE row_id = ?""",
            (violation["evidence_class"], json.dumps(detail, sort_keys=True), at, version_id,
             source["kind"], str(source["id"]), existing["row_id"]),
        )

    def _record_overflow(
        self, kind: str, value: str, version_id: str, violation: Mapping[str, Any], at: str,
        recheck: bool,
    ) -> None:
        """One more distinct item past the open-row cap: counted in the
        agent's one overflow row, which keeps the state Violated until it
        is acknowledged (§4.5 "Bounds").

        A re-check (adopt, edit, switch, Allow this) judges evidence already
        judged, and the overflow row mixes every source, so it can't tell
        which items it counted before: a re-check creates the row if there
        is none but never counts or re-opens an existing one."""
        source = violation["source"]
        if recheck and self._db.execute(
            "SELECT 1 FROM guardrail_rows WHERE identity_kind = ? AND identity_value = ? "
            "AND rule = ? AND item = ?",
            (kind, value, OVERFLOW_RULE, OVERFLOW_ITEM),
        ).fetchone() is not None:
            return
        self._db.execute(
            """INSERT INTO guardrail_rows (
                   identity_kind, identity_value, rule, item, overflow, evidence_class,
                   detail_json, first_seen, last_seen, hits, flagged_by,
                   source_kind, source_id, acknowledged_at
               ) VALUES (?, ?, ?, ?, 1, ?, '{}', ?, ?, 1, ?, ?, ?, NULL)
               ON CONFLICT(identity_kind, identity_value, rule, item) DO UPDATE SET
                   evidence_class = excluded.evidence_class,
                   last_seen = MAX(last_seen, excluded.last_seen),
                   hits = hits + 1, flagged_by = excluded.flagged_by,
                   source_kind = excluded.source_kind, source_id = excluded.source_id,
                   acknowledged_at = NULL""",
            (kind, value, OVERFLOW_RULE, OVERFLOW_ITEM, violation["evidence_class"], at, at,
             version_id, source["kind"], str(source["id"])),
        )

    @staticmethod
    def _row_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "row_id": row["row_id"],
            "rule": row["rule"],
            "item": row["item"],
            "overflow": bool(row["overflow"]),
            "evidence_class": row["evidence_class"],
            "detail": json.loads(row["detail_json"]),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "count": row["hits"],
            "flagged_by": row["flagged_by"],
            "source": {"kind": row["source_kind"], "id": row["source_id"]},
            "acknowledged": row["acknowledged_at"] is not None,
            "acknowledged_at": row["acknowledged_at"],
        }

    # -------------------------------------------------------------- hooks

    @contextmanager
    def _hook_guard(self, where: str) -> Iterator[None]:
        """Run one hook in a savepoint of the caller's transaction; see
        the module docstring for what a failure does."""
        self._db.execute("SAVEPOINT guardrail_hook")
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - evidence must still be stored
            self._db.execute("ROLLBACK TO guardrail_hook")
            self._db.execute("RELEASE guardrail_hook")
            print(f"raildash: guardrail {where} check failed: {exc!r}", file=sys.stderr)
            self._mark(*EVERY_AGENT, MARK_CHECK_FAILED, self._receive_time())
            return
        self._db.execute("RELEASE guardrail_hook")

    def _guardrail_on_asp(self, asp_id: str, bundle: Mapping[str, Any], kind: str, value: str) -> None:
        """§4.5 "On ASP ingest": `service_ports` and `saved_files` against
        one newly stored ASP, under the version in force. Called by
        `Store.load_asp` inside its write transaction, after the drift
        comparison."""
        active = self._active_guardrail_row(kind, value)
        if active is None:
            return
        with self._hook_guard("ASP"):
            self._check_asp_locked(active, asp_id, bundle, kind, value)

    def _check_asp_locked(
        self, active: sqlite3.Row, asp_id: str, bundle: Mapping[str, Any], kind: str, value: str,
        *, recheck: bool = False,
    ) -> None:
        previous = self._db.execute(
            """SELECT collected_at FROM asps
               WHERE identity_kind = ? AND identity_value = ? AND asp_id != ?
               ORDER BY stored_at DESC, rowid DESC LIMIT 1""",
            (kind, value, asp_id),
        ).fetchone()
        now = self._receive_time()
        result = g.evaluate_asp(
            json.loads(active["contract_json"]), bundle, asp_id=asp_id,
            previous_collected_at=previous[0] if previous else None, now=now,
        )
        violations = [v for rule in g.ASP_RULES for v in result["rules"][rule]["violations"]]
        self._record_violations(
            kind, value, active["guardrail_version_id"], violations, now, recheck=recheck
        )

    def _recheck_newest_asp(self, active: sqlite3.Row, kind: str, value: str) -> None:
        """§4.5 "On adopt, switch or edit": the newest ASP is re-checked.
        Requests are not back-filled."""
        newest = self._newest_asps(kind, value)
        if newest:
            bundle = parse_bundle(bytes(newest[0]["exact_bundle"]))
            self._check_asp_locked(active, newest[0]["asp_id"], bundle, kind, value, recheck=True)

    def _guardrail_on_request(
        self, interaction: Mapping[str, Any], active: list[dict[str, Any]]
    ) -> None:
        """§4.5 "On request ingest": `uploads` and `out_of_spec_calls`
        against one newly stored authenticated request, in the transaction
        that stores it. `active` is `_active_guardrails()`, read once per
        batch. An unauthenticated request never reaches here (§4.1)."""
        with self._hook_guard("request"):
            self._check_request_locked(interaction, active)

    def _check_request_locked(
        self, interaction: Mapping[str, Any], active: list[dict[str, Any]]
    ) -> None:
        now = self._receive_time()
        owner = g.request_owner(interaction, active, authenticated=True)
        if owner["decision"] == "unattributed":
            self._mark(*EVERY_AGENT, MARK_UNATTRIBUTED, now)
            return
        if owner["decision"] != "guardrail":
            return
        kind, value = self._identity_columns(owner["identity"])
        entry = next(
            item for item in active
            if (item["row"]["identity_kind"], item["row"]["identity_value"]) == (kind, value)
        )
        version = entry["row"]
        # An old capture loaded now isn't new traffic (§4.5).
        when = g._instant(interaction.get("timestamp")) or _instant(now)
        if when < _instant(version["activated_at"]):
            return
        result = g.evaluate_request(json.loads(version["contract_json"]), interaction)
        if not result["tool_calls"]["readable"]:
            self._mark(kind, value, MARK_TOOL_CALLS_UNREADABLE, now)
        self._record_violations(
            kind, value, version["guardrail_version_id"],
            [*result["uploads"], *result["out_of_spec_calls"]], now,
        )

    # ------------------------------------------------------------- custody

    def _next_version_label(self, kind: str, value: str) -> str:
        count = self._db.execute(
            "SELECT count(*) FROM guardrail_versions WHERE identity_kind = ? AND identity_value = ?",
            (kind, value),
        ).fetchone()[0]
        return f"g{count + 1}"

    def _seeded_over_all_versions(self, kind: str, value: str) -> dict[str, list[str]]:
        hosts: set[str] = set()
        servers: set[str] = set()
        for row in self._db.execute(
            "SELECT contract_json FROM guardrail_versions "
            "WHERE identity_kind = ? AND identity_value = ?",
            (kind, value),
        ):
            seeded = json.loads(row[0])["rules"]["out_of_spec_calls"]["seeded_from_declared"]
            hosts.update(seeded["hosts"])
            servers.update(seeded["mcp_servers"])
        return {"hosts": sorted(hosts), "mcp_servers": sorted(servers)}

    def _create_version_locked(
        self, kind: str, value: str, rules: Mapping[str, Any], *, derived_from: str,
        created_by: str, detail: Mapping[str, Any],
    ) -> sqlite3.Row:
        """Validate, store and activate one new version, re-check the newest
        ASP against it, and record the action. The caller holds the write
        transaction."""
        version_id = f"grd-{uuid.uuid4()}"
        contract = {
            "guardrail_contract_version": g.GUARDRAIL_CONTRACT_VERSION,
            "guardrail_version_id": version_id,
            "version": self._next_version_label(kind, value),
            "created_at": self._receive_time(),
            "agent_identity": self._identity_object(kind, value),
            "derived_from": {"alignment_version_id": derived_from},
            "rules": rules,
        }
        g.validate_guardrail(contract)
        self._db.execute(
            """INSERT INTO guardrail_versions (
                   guardrail_version_id, version, created_at, identity_kind, identity_value,
                   created_by, contract_json
               ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (version_id, contract["version"], contract["created_at"], kind, value, created_by,
             json.dumps(contract, ensure_ascii=False, sort_keys=True)),
        )
        active = self._activate_locked(kind, value, version_id)
        self._event(kind, value, created_by, version_id, {"version": contract["version"], **detail})
        return active

    def _activate_locked(self, kind: str, value: str, version_id: str) -> sqlite3.Row:
        self._db.execute(
            """INSERT INTO guardrail_bindings
                   (identity_kind, identity_value, guardrail_version_id, activated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(identity_kind, identity_value) DO UPDATE SET
                   guardrail_version_id = excluded.guardrail_version_id,
                   activated_at = excluded.activated_at""",
            (kind, value, version_id, self._receive_time()),
        )
        active = self._active_guardrail_row(kind, value)
        assert active is not None
        self._recheck_newest_asp(active, kind, value)
        return active

    def _alignment_row(self, alignment_version_id: str) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM alignment_versions WHERE alignment_version_id = ?",
            (alignment_version_id,),
        ).fetchone()
        if row is None:
            raise KeyError("no such alignment version")
        return row

    def _proposal_locked(self, alignment: sqlite3.Row) -> dict[str, Any]:
        kind, value = alignment["identity_kind"], alignment["identity_value"]
        asp = self._db.execute(
            "SELECT exact_bundle FROM asps WHERE asp_id = ?", (alignment["asp_id"],)
        ).fetchone()
        bundle = parse_bundle(bytes(asp["exact_bundle"]))
        locked_at = _instant(alignment["locked_at"])
        start = locked_at - g.PROPOSAL_LOOKBACK
        candidates = [
            {
                "identity": self._identity_object(row[0], row[1]),
                "sandboxes": self._sandboxes(row[0], row[1]),
            }
            for row in self._db.execute("SELECT identity_kind, identity_value FROM active_bindings")
        ]
        if not any(self._identity_columns(c["identity"]) == (kind, value) for c in candidates):
            candidates.append(
                {"identity": self._identity_object(kind, value), "sandboxes": self._sandboxes(kind, value)}
            )
        rows = self._db.execute(
            """SELECT * FROM interactions
               WHERE authenticated = 1 AND timestamp_ns BETWEEN ? AND ?
               ORDER BY timestamp_ns DESC, id DESC LIMIT ?""",
            (int(start.timestamp() * 1e9), int(locked_at.timestamp() * 1e9), PROPOSAL_MAX_REQUESTS),
        ).fetchall()
        mine = []
        for row in rows:
            request = dict(row)
            owner = g.request_owner(request, candidates, authenticated=True)
            if owner["decision"] == "guardrail" and self._identity_columns(owner["identity"]) == (kind, value):
                mine.append(request)
        return g.propose_guardrail(
            self._alignment_contract(alignment), bundle, mine,
            guardrail_version_id="grd-proposed",
            version=self._next_version_label(kind, value),
            created_at=self._receive_time(),
        )

    def propose_guardrail(self, alignment_version_id: str) -> dict[str, Any]:
        """§4.4's proposal from one locked baseline. Nothing is stored."""
        with self._lock:
            alignment = self._alignment_row(alignment_version_id)
            result = self._proposal_locked(alignment)
            result["agent_ref"] = agent_ref(alignment["identity_kind"], alignment["identity_value"])
            return result

    def adopt_guardrail(
        self, alignment_version_id: str, rules: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """**Adopt**: store the proposal from this baseline -- or `rules`, the
        proposal as the user edited it -- as a new version and make it
        active. An agent with an active guardrail edits it instead."""
        with self._write_transaction():
            alignment = self._alignment_row(alignment_version_id)
            kind, value = alignment["identity_kind"], alignment["identity_value"]
            if self._active_guardrail_row(kind, value) is not None:
                raise ValueError("this agent already has an active guardrail; edit it instead")
            edited = rules is not None
            if rules is None:
                proposal = self._proposal_locked(alignment)
                if proposal["guardrail"] is None:
                    raise ValueError(f"no guardrail can be proposed: {proposal['reason']}")
                rules = proposal["guardrail"]["rules"]
            active = self._create_version_locked(
                kind, value, rules, derived_from=alignment_version_id, created_by="adopt",
                detail={"edited": edited},
            )
            return self._version_view(active, active=True)

    def edit_guardrail(self, guardrail_version_id: str, rules: Mapping[str, Any]) -> dict[str, Any]:
        """**Edit**: a new version from the active one, with `rules`. What
        the user was shown as declared stays recorded (§4.2)."""
        with self._write_transaction():
            base = self._require_active(guardrail_version_id)
            kind, value = base["identity_kind"], base["identity_value"]
            if not isinstance(rules, dict):
                raise ValueError("rules must be an object")
            rules = json.loads(json.dumps(rules))
            base_contract = json.loads(base["contract_json"])
            seeded = (rules.get("out_of_spec_calls") or {}).get("seeded_from_declared")
            base_seeded = base_contract["rules"]["out_of_spec_calls"]["seeded_from_declared"]
            if isinstance(seeded, dict):
                for key in ("hosts", "mcp_servers"):
                    if isinstance(seeded.get(key), list):
                        seeded[key] = sorted({*seeded[key], *base_seeded[key]})
            active = self._create_version_locked(
                kind, value, rules, derived_from=base_contract["derived_from"]["alignment_version_id"],
                created_by="edit", detail={"from": base["version"]},
            )
            return self._version_view(active, active=True)

    def _require_active(self, guardrail_version_id: str) -> sqlite3.Row:
        version = self._guardrail_version_row(guardrail_version_id)
        active = self._active_guardrail_row(version["identity_kind"], version["identity_value"])
        if active is None or active["guardrail_version_id"] != guardrail_version_id:
            raise ValueError("only the active guardrail version can be changed")
        return active

    def switch_guardrail(self, guardrail_version_id: str) -> dict[str, Any]:
        """**Switch**: make an existing version the active one (a pointer move)."""
        with self._write_transaction():
            version = self._guardrail_version_row(guardrail_version_id)
            kind, value = version["identity_kind"], version["identity_value"]
            active = self._activate_locked(kind, value, guardrail_version_id)
            self._event(kind, value, "switch", guardrail_version_id, {"version": version["version"]})
            return self._version_view(active, active=True)

    def turn_off_guardrail(self, ref: str) -> dict[str, Any]:
        """**Turn off**: clear the agent's active pointer, so it has *No
        guardrail*. Its versions and rows stay."""
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            self._db.execute(
                "DELETE FROM guardrail_bindings WHERE identity_kind = ? AND identity_value = ?",
                (kind, value),
            )
            self._event(kind, value, "turn_off", active["guardrail_version_id"],
                        {"version": active["version"]})
            return {"agent_ref": ref, "state": g.STATE_NO_GUARDRAIL}

    def _guardrail_row(self, row_id: int) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM guardrail_rows WHERE row_id = ?", (row_id,)).fetchone()
        if row is None:
            raise KeyError("no such guardrail row")
        return row

    def acknowledge_guardrail_row(self, row_id: int) -> dict[str, Any]:
        """**Acknowledge**: the row is seen up to now. A later hit re-opens
        it; the overflow row's count starts again from zero."""
        with self._write_transaction():
            row = self._guardrail_row(row_id)
            self._db.execute(
                "UPDATE guardrail_rows SET acknowledged_at = ?, "
                "hits = CASE WHEN overflow = 1 THEN 0 ELSE hits END WHERE row_id = ?",
                (self._receive_time(), row_id),
            )
            self._event(row["identity_kind"], row["identity_value"], "acknowledge", None,
                        {"row_id": row_id, "rule": row["rule"], "item": row["item"]})
            return self._row_view(self._guardrail_row(row_id))

    def allow_guardrail_row(self, row_id: int) -> dict[str, Any]:
        """**Allow this** on a row: a new version with its item added."""
        with self._write_transaction():
            row = self._guardrail_row(row_id)
            kind, value = row["identity_kind"], row["identity_value"]
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            contract = json.loads(active["contract_json"])
            rules = g.with_item_allowed(contract["rules"], self._row_view(row))
            created = self._create_version_locked(
                kind, value, rules,
                derived_from=contract["derived_from"]["alignment_version_id"],
                created_by="allow", detail={"row_id": row_id, "rule": row["rule"], "item": row["item"]},
            )
            return self._version_view(created, active=True)

    def choose_declared(self, ref: str, kind_of_item: str, item: str, *, allow: bool) -> dict[str, Any]:
        """**Allow this** (`allow=True`) or **Dismiss** on a *declared since
        gN* offer: a new version that records it as shown, and allows it
        only on Allow."""
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            offers = self._offers_locked(active, kind, value)
            if {"kind": kind_of_item, "value": item} not in offers:
                raise ValueError("that is not a current declared offer")
            contract = json.loads(active["contract_json"])
            rules = g.with_declared_choice(contract["rules"], kind_of_item, item, allow=allow)
            created = self._create_version_locked(
                kind, value, rules,
                derived_from=contract["derived_from"]["alignment_version_id"],
                created_by="declared_allow" if allow else "declared_dismiss",
                detail={"kind": kind_of_item, "item": item},
            )
            return self._version_view(created, active=True)

    def _offers_locked(self, active: sqlite3.Row, kind: str, value: str) -> list[dict[str, str]]:
        newest = self._newest_asps(kind, value)
        if not newest:
            return []
        bundle = parse_bundle(bytes(newest[0]["exact_bundle"]))
        return g.declared_offers(
            json.loads(active["contract_json"]), bundle, self._seeded_over_all_versions(kind, value)
        )

    # --------------------------------------------------------------- read

    def _version_view(self, row: sqlite3.Row, *, active: bool) -> dict[str, Any]:
        view = {
            "guardrail": json.loads(row["contract_json"]),
            "created_by": row["created_by"],
            "active": active,
            "agent_ref": agent_ref(row["identity_kind"], row["identity_value"]),
        }
        if active and "activated_at" in row.keys():
            view["activated_at"] = row["activated_at"]
        return view

    def _state_locked(
        self, kind: str, value: str, now: datetime | None
    ) -> tuple[dict[str, Any], sqlite3.Row | None, list[dict[str, Any]]]:
        current = self._receive_time(now)
        active = self._active_guardrail_row(kind, value)
        contract = json.loads(active["contract_json"]) if active is not None else None
        rows = [
            self._row_view(row)
            for row in self._db.execute(
                "SELECT * FROM guardrail_rows WHERE identity_kind = ? AND identity_value = ? "
                "ORDER BY acknowledged_at IS NOT NULL, last_seen DESC, row_id DESC",
                (kind, value),
            )
        ]
        for row in rows:
            row["counts"] = g.row_counts(contract, row)
            row["allowed_by"] = (
                contract["version"]
                if contract is not None and not row["overflow"] and g.item_allowed(contract, row)
                else None
            )
        if contract is None:
            return {"state": g.STATE_NO_GUARDRAIL, "rules": None}, None, rows
        newest = self._newest_asps(kind, value)
        asp_result = None
        if newest:
            asp_result = g.evaluate_asp(
                contract, parse_bundle(bytes(newest[0]["exact_bundle"])),
                asp_id=newest[0]["asp_id"],
                previous_collected_at=newest[1]["collected_at"] if len(newest) > 1 else None,
                now=current,
            )
        request_status = g.request_rules_status(
            now=current,
            last_heartbeat_at=self.latest_heartbeat_at(),
            last_unattributed_at=self._mark_at(*EVERY_AGENT, MARK_UNATTRIBUTED),
            last_tool_calls_unreadable_at=self._mark_at(kind, value, MARK_TOOL_CALLS_UNREADABLE),
            last_capture_refused_at=self.latest_capture_refusal_at(),
        )
        rules = g.rule_states(asp_result, request_status)
        failed = self._mark_at(*EVERY_AGENT, MARK_CHECK_FAILED)
        if failed is not None and _instant(failed) >= _instant(active["activated_at"]):
            rules = {
                rule: {"state": g.UNVERIFIED, "reason": g.CHECK_FAILED, "violations": []}
                for rule in g.RULES
            }
        state = g.agent_state(
            has_active_guardrail=True, rule_results=rules,
            counting_rows=sum(1 for row in rows if row["counts"]),
        )
        summary = {
            "state": state,
            "rules": {
                rule: {"state": result["state"], "reason": result.get("reason")}
                for rule, result in rules.items()
            },
        }
        return summary, active, rows

    def guardrail_agents(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        """Every agent with a baseline or a guardrail, and its state. No item
        values: hosts, paths and ports are in the token-gated detail."""
        agents = []
        with self._lock:
            for kind, value in self._known_identities():
                summary, active, rows = self._state_locked(kind, value, now)
                agents.append({
                    "agent_ref": agent_ref(kind, value),
                    "agent_identity": self._identity_object(kind, value),
                    **summary,
                    "active_version": (
                        {"guardrail_version_id": active["guardrail_version_id"],
                         "version": active["version"]}
                        if active is not None else None
                    ),
                    "counting_rows": sum(1 for row in rows if row["counts"]),
                })
        return agents

    def guardrail_detail(self, ref: str, *, now: datetime | None = None) -> dict[str, Any]:
        """One agent's guardrail: state, rows, offers, versions and history,
        and the proposal when it has a baseline and no guardrail."""
        with self._lock:
            kind, value = self._resolve_agent_ref(ref)
            summary, active, rows = self._state_locked(kind, value, now)
            versions = [
                self._version_view(row, active=active is not None
                                   and row["guardrail_version_id"] == active["guardrail_version_id"])
                for row in self._db.execute(
                    "SELECT * FROM guardrail_versions WHERE identity_kind = ? "
                    "AND identity_value = ? ORDER BY created_at DESC, rowid DESC",
                    (kind, value),
                )
            ]
            events = [
                {"at": row["at"], "action": row["action"],
                 "guardrail_version_id": row["guardrail_version_id"],
                 "detail": json.loads(row["detail_json"])}
                for row in self._db.execute(
                    "SELECT * FROM guardrail_events WHERE identity_kind = ? AND identity_value = ? "
                    "ORDER BY event_id DESC LIMIT ?",
                    (kind, value, MAX_GUARDRAIL_EVENTS_SHOWN),
                )
            ]
            proposal = None
            if active is None:
                baseline = self._db.execute(
                    "SELECT alignment_version_id FROM active_bindings "
                    "WHERE identity_kind = ? AND identity_value = ?",
                    (kind, value),
                ).fetchone()
                if baseline is not None:
                    proposal = self._proposal_locked(self._alignment_row(baseline[0]))
                    proposal["alignment_version_id"] = baseline[0]
            return {
                "agent_ref": ref,
                "agent_identity": self._identity_object(kind, value),
                **summary,
                "active": self._version_view(active, active=True) if active is not None else None,
                "rows": rows,
                "offers": self._offers_locked(active, kind, value) if active is not None else [],
                "versions": versions,
                "events": events,
                "proposal": proposal,
            }


# Last, and only as a module reference: `raildash.guardrail` reads the store
# module, and the store imports this one while it loads. By the time any
# method above runs, all three modules are complete, whichever was imported
# first.
from . import guardrail as g  # noqa: E402
