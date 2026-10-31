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
- **Marks** (`guardrail_marks`) are receive times. The request rules'
  liveness reads two besides the heartbeat and refusal tables M0 added: the
  last authenticated request that couldn't be given to one agent (every
  agent's), and the last request of an agent whose response's tool calls
  couldn't be read (that agent's). The ASP rules' staleness reads the last
  two deliveries of each agent's newest ASP, which are kept for every agent
  with or without a guardrail, so one adopted later is fresh at once.
- **Events** (`guardrail_events`) are the visible history of every
  token-gated action, switches, turn-offs and acknowledgements included,
  which leave no version behind.

The hooks run inside the store's own ingest transactions (§4.5 "When it
runs"), so `raildash load`, `raildash asp load` and the webhooks run the same
code: `_guardrail_on_asp` from `Store.load_asp`, `_guardrail_on_request` from
`Store.add_interactions`. Neither takes the store's lock; their callers hold
it. The state (`guardrail_detail`) is computed when read, because the
staleness and liveness windows depend on the time of the read.

**One deviation from the design.** §4.3 judges staleness on the newest
ASP's `collected_at`. RailMon re-sends an unchanged agent's previous bundle
with the time its content was first collected (DR-157), which RailDash
stores once, so that rule made every unchanged agent's ASP rules Unverified
within minutes. Here every delivery of the agent's newest ASP, a re-send
included, is a receipt keyed by that ASP, and the bound is three times the
gap between its last two receipts: §4.3's rule, on deliveries. A re-send is
fresh evidence because RailMon reuses a bundle only when a fresh scan found
the same content; a dead probe turns its attribute `PARTIAL`, which is new
content. The cost: a token holder re-loading an old bundle by hand keeps it
fresh. Without a receipt for the newest ASP (a database from before them),
`collected_at` is used, as in the design.

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
- **Allow all** (DR-202) allows several of one rule's counting rows in one
  version, so allowing nine rows is one version, not g2...g10. It takes the
  row ids the page showed, not "every row of the rule", so it allows exactly
  what the user saw: a row that arrived since isn't allowed unseen. It is
  all or nothing: if any id isn't a counting row of this agent's rule that
  Allow this could allow, nothing is created. Each counting row reports
  whether Allow this alone would succeed on it (`allowable`, the version it
  would make checked against the contract too), so the page offers only
  those.
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
import ipaddress
import json
import os
import re
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .asp import parse_bundle

GUARDRAIL_MAX_OPEN_ROWS = 1_000
GUARDRAIL_ACK_RETENTION_DAYS = 30
# The proposal reads at most this many of the agent's requests from the
# 24 h before the lock, newest first.
PROPOSAL_MAX_REQUESTS = 5_000
# REST uploads M3: what an imported spec's host may be, besides an IP
# literal: DNS labels of letters, digits, `-` and `_`.
_HOST_NAME = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*")


def _ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


# REST uploads §4: how long a computed *narrow uploads* offer is kept
# before new captures are read again, and before the window is moved.
NARROW_OFFER_MIN_AGE = 60
NARROW_OFFER_MAX_AGE = 600
MAX_GUARDRAIL_EVENTS_SHOWN = 100
# DR-249: Blocked by OpenShell shows a day of denials (design §4.3), and
# keeps a week, for an agent whose page isn't open every day.
OPENSHELL_DENIALS_SHOWN = timedelta(hours=24)
OPENSHELL_DENIAL_RETENTION = timedelta(days=7)
OPENSHELL_DENIAL_GROUPS_SHOWN = 50
# The newest this many denials make the groups, so an agent retrying a
# blocked call all day can't slow the panel; counts then are lower bounds.
OPENSHELL_DENIALS_READ = 20_000
# How many of an agent's newest imports an export looks through for one
# that carries a base policy.
OPENSHELL_BASE_SCAN = 50
OPENSHELL_POLICIES_KEPT = 20
# DR-261 (Lebin's DR-194 Q1, an attempt OpenShell blocked doesn't count): a
# request answered 403, from an agent whose sandbox the collector reports
# on, waits this long for OpenShell's own denial of it before it is judged,
# and a denial logged this close to the capture is that request's.
OPENSHELL_HOLD = timedelta(minutes=5)
OPENSHELL_DENIAL_MATCH = timedelta(seconds=10)
# Past this many held requests of one agent, the next 403 is judged at once,
# as `data_actions_store.MAX_PENDING` bounds the not-offered queue; and one
# release judges at most this many.
OPENSHELL_HELD_MAX = 1000
OPENSHELL_RELEASE_BATCH = 500
OVERFLOW_RULE = "(overflow)"
OVERFLOW_ITEM = "(overflow)"
# Identity columns of a mark that applies to every agent.
EVERY_AGENT = ("", "")
MARK_UNATTRIBUTED = "unattributed"
MARK_TOOL_CALLS_UNREADABLE = "tool_calls_unreadable"
MARK_CHECK_FAILED = "check_failed"
# Each keyed by the ASP it is a delivery of (`asp_received@<asp_id>`), so a
# receipt never vouches for another ASP, say once the one it was for is
# pruned.
MARK_ASP_RECEIVED = "asp_received@{}"
MARK_ASP_RECEIVED_BEFORE = "asp_received_before@{}"

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

-- REST uploads M2b: the drip check's history (design §3). One row per
-- budget a counted `parameters` body went against: each out_of_spec_calls
-- entry its host matched (or the host), and '' for the agent. `at` is the
-- capture time, as `_receive_time` writes it, so a text range is a window.
CREATE TABLE IF NOT EXISTS guardrail_parameters_bytes (
    identity_kind  TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    budget_key     TEXT NOT NULL,
    at             TEXT NOT NULL,
    bytes          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guardrail_parameters_bytes_window
    ON guardrail_parameters_bytes(identity_kind, identity_value, budget_key, at);
CREATE INDEX IF NOT EXISTS guardrail_parameters_bytes_age
    ON guardrail_parameters_bytes(identity_kind, identity_value, at);

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

-- DR-248 (DR-194 M2): each OpenShell policy imported for an agent, as
-- `raildash.openshell_policy.parse_policy` reads it: its network endpoints,
-- revision and (DR-258) the static sections an export starts from, field by
-- field, so no credential field. Beside the ASP, never in it: no ASP, baseline or
-- guardrail version refers to a row here. The newest row is the policy.
CREATE TABLE IF NOT EXISTS openshell_policies (
    policy_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_kind  TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    imported_at    TEXT NOT NULL,
    source         TEXT NOT NULL,
    record_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS openshell_policies_identity
    ON openshell_policies(identity_kind, identity_value, policy_id);

-- REST uploads M3: an OpenAPI spec the user imported for one host, as
-- `raildash.api_specs.parse_spec` indexes it (operations and their upload
-- marks; the file itself isn't kept). Requests to the host are classified
-- with it from then on (step 3), for every agent.
CREATE TABLE IF NOT EXISTS api_specs (
    host        TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    index_json  TEXT NOT NULL
);

-- DR-249 (DR-194 M3): what `railmon openshell` posts, keyed by the sandbox's
-- name, which an ASP of an agent in it carries as `sandbox_name` (DR-247).
-- Policy revisions as parse_policy reads them; the denials OpenShell's
-- supervisor logged, one row per log line; and the spans a batch couldn't
-- show it held every denial for (PARTIAL).
CREATE TABLE IF NOT EXISTS openshell_sandbox_policies (
    policy_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox     TEXT NOT NULL,
    received_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS openshell_sandbox_policies_sandbox
    ON openshell_sandbox_policies(sandbox, policy_id);
CREATE TABLE IF NOT EXISTS openshell_denials (
    denial_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox   TEXT NOT NULL,
    at        TEXT NOT NULL,
    line_hash TEXT NOT NULL,
    kind      TEXT NOT NULL,
    host      TEXT,
    port      INTEGER,
    method    TEXT,
    path      TEXT,
    binary    TEXT,
    policy    TEXT,
    reason    TEXT,
    UNIQUE(sandbox, line_hash)
);
CREATE INDEX IF NOT EXISTS openshell_denials_sandbox_at ON openshell_denials(sandbox, at);
CREATE INDEX IF NOT EXISTS openshell_denials_at ON openshell_denials(at);
CREATE TABLE IF NOT EXISTS openshell_denial_gaps (
    gap_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox      TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    gap_from     TEXT,
    gap_to       TEXT NOT NULL,
    reasons_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS openshell_denial_gaps_sandbox ON openshell_denial_gaps(sandbox, gap_to);

-- DR-261: requests held instead of judged on ingest (OPENSHELL_HOLD), with
-- the version in force and the data-action calls they were stored under.
-- OpenShell's denial of one drops it; one with none in time is judged then.
CREATE TABLE IF NOT EXISTS openshell_held_requests (
    interaction_row      INTEGER PRIMARY KEY,
    identity_kind        TEXT NOT NULL,
    identity_value       TEXT NOT NULL,
    guardrail_version_id TEXT NOT NULL,
    held_at              TEXT NOT NULL,
    calls_json           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS openshell_held_requests_identity
    ON openshell_held_requests(identity_kind, identity_value);
-- Each denial excuses one request only: the denials a held or incoming
-- request was dropped for.
CREATE TABLE IF NOT EXISTS openshell_denials_used (
    denial_id INTEGER PRIMARY KEY
);
"""


# `egress_containment.require`'s values (guardrail-version-v3's enum).
EGRESS_REQUIRES = ("contained", "allow_list_enforced")


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


def _allowed_by_one_click(contract: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
    """The rules **Allow this** on `row` would store in a version made from
    `contract`, checked as that version would be. Raises `ValueError` where
    Allow this refuses the row, and `GuardrailValidationError` (a
    `ValueError` too) where the version it made would break the contract:
    a captured Host header is the agent's own text, and one too long or
    with a `/` or a space in it can't be listed."""
    rules = g.with_item_allowed(contract["rules"], row)
    g.validate_guardrail({**contract, "rules": rules})
    return rules


def _one_click_allowable(contract: Mapping[str, Any] | None, row: Mapping[str, Any]) -> bool:
    """Whether a counting row is one **Allow all** can take (DR-202): Allow
    this on it alone would succeed against the version in force (`contract`;
    None with no guardrail). The server's own answer, so the page needn't
    mirror every refusal, an upload over a size cap or an unlistable host
    included. False for a row that doesn't count (acknowledged, already
    allowed, no guardrail), which Allow all never takes, so a poll checks
    only the rows it could offer."""
    if contract is None or not row["counts"] or row["overflow"]:
        return False
    try:
        _allowed_by_one_click(contract, row)
    except ValueError:
        return False
    return True


def _merged_detail(rule: str, old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """The detail a repeat leaves on a row: the new hit's, except that an
    `uploads` host row keeps the worst request seen, so that a later
    version re-checking it (`guardrail.item_allowed`) can't be passed by a
    small last request after a large one, and every body kind it was
    hit by. A `data_actions` row keeps every
    undeclared argument it has seen, and that its upload came from one, so
    a later version's override can't clear it (DR-205)."""
    if rule == g.DATA_ACTIONS:
        merged = dict(new)
        merged["undeclared"] = sorted({*(old.get("undeclared") or ()), *(new.get("undeclared") or ())})
        merged["from_undeclared"] = bool(old.get("from_undeclared") or new.get("from_undeclared"))
        return merged
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
    # REST uploads: every body kind the row was hit by, so a later version's
    # override clears it only if it answers each (`guardrail.item_allowed`).
    merged.pop("bodies", None)
    merged.pop("bodies_overflow", None)
    merged.update(g.merge_row_bodies(old, new))
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

    def _guardrail_asp_received(self, asp_id: str, kind: str, value: str) -> None:
        """Record one delivery of an ASP, new or re-sent, if it is the
        agent's newest: the receipt the staleness check reads. Called by
        `Store.load_asp` inside its write transaction."""
        newest = self._newest_asps(kind, value)
        if not newest or newest[0]["asp_id"] != asp_id:
            return  # a re-sent older ASP says nothing about the newest
        last = self._mark_at(kind, value, MARK_ASP_RECEIVED.format(asp_id))
        # Only the newest ASP's receipts are kept.
        self._db.execute(
            "DELETE FROM guardrail_marks WHERE identity_kind = ? AND identity_value = ? "
            "AND mark LIKE 'asp\\_received%' ESCAPE '\\' AND mark NOT LIKE ?",
            (kind, value, f"%@{asp_id}"),
        )
        if last is not None:
            self._db.execute(
                """INSERT INTO guardrail_marks (identity_kind, identity_value, mark, at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(identity_kind, identity_value, mark) DO UPDATE SET at = excluded.at""",
                (kind, value, MARK_ASP_RECEIVED_BEFORE.format(asp_id), last),
            )
        self._mark(kind, value, MARK_ASP_RECEIVED.format(asp_id), self._receive_time())

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
        self._release_held_guarded()
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
        violations = [
            v for rule in g.ALL_ASP_RULES for v in result["rules"].get(rule, {}).get("violations", [])
        ]
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
        self, interaction: Mapping[str, Any], active: list[dict[str, Any]],
        calls: Sequence[Mapping[str, Any]] = (),
    ) -> None:
        """§4.5 "On request ingest": `uploads` and `out_of_spec_calls`
        against one newly stored authenticated request, in the transaction
        that stores it. `active` is `_active_guardrails()`, read once per
        batch. An unauthenticated request never reaches here (§4.1)."""
        with self._hook_guard("request"):
            self._check_request_locked(interaction, active, calls)

    def _check_request_locked(
        self, interaction: Mapping[str, Any], active: list[dict[str, Any]],
        calls: Sequence[Mapping[str, Any]] = (),
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
        # An old capture loaded now isn't new traffic (§4.5); one stamped
        # within the collector's clock error of activation is.
        when = g._instant(interaction.get("timestamp")) or _instant(now)
        if when < _instant(version["activated_at"]) - g.CAPTURE_CLOCK_SLACK:
            return
        if self._hold_if_blocked_locked(interaction, kind, value, version, calls, now):
            return
        self._judge_request_locked(kind, value, version, interaction, calls, now)

    def _judge_request_locked(
        self, kind: str, value: str, version: Mapping[str, Any], interaction: Mapping[str, Any],
        calls: Sequence[Mapping[str, Any]], now: str,
    ) -> None:
        contract = json.loads(version["contract_json"])
        if g.DATA_ACTIONS in contract["rules"]:
            self._queue_not_offered_locked(kind, value, interaction, calls, now)
        body_kind = None
        if g.body_kinds_on() and g.carries_body(interaction):
            uploads = contract["rules"]["uploads"]
            body_kind = g.request_body_kind(
                interaction, uploads.get("body_kind_overrides", ()),
                self._api_specs_locked().get(g.normalize_host(interaction.get("host")) or ""),
            )
            body_kind = self._drip_check_locked(kind, value, contract, interaction, body_kind, now)
        result = g.evaluate_request(contract, interaction, body_kind=body_kind)
        if not result["tool_calls"]["readable"]:
            self._mark(kind, value, MARK_TOOL_CALLS_UNREADABLE, now)
        self._record_violations(
            kind, value, version["guardrail_version_id"],
            [*result["uploads"], *result["out_of_spec_calls"],
             *g.evaluate_data_actions(contract, calls, interaction)], now,
        )

    def _drip_check_locked(
        self, kind: str, value: str, contract: Mapping[str, Any], interaction: Mapping[str, Any],
        body: dict[str, Any] | None, now: str,
    ) -> dict[str, Any] | None:
        """REST uploads §3's drip check on one classified body: a
        `parameters` body that would take any budget it counts against past
        its day's bound (`parameters_budget`, else 256 KiB per entry and 1 MiB
        for the agent) is an upload instead, with the sums it was judged on,
        and adds nothing; one that fits is counted.

        The window is the 24 h before the body's capture time, and everything
        counted after it: a body judged late (its response came first, or
        OpenShell held it) can't slip under bodies already counted with
        later times. A capture time ahead of the server's clock, or none,
        reads as now, and one more than a day behind it as a day ago, so no
        stamp moves the window off what is still kept: rows are pruned by
        the server's clock, two days back. A body with no host
        stays as classified: the rule already reads it as an upload."""
        if body is None or body.get("kind") != _bk.PARAMETERS:
            return body
        host = g.normalize_host(interaction.get("host"))
        if host is None:
            return body
        clock = _instant(now)
        when = g._instant(interaction.get("timestamp"))
        when = clock if when is None or when > clock else max(when, clock - timedelta(seconds=_bk.DAY_SECONDS))
        uploads = contract["rules"]["uploads"]
        keys = g.drip_keys(host, contract["rules"]["out_of_spec_calls"]["allowed_hosts"])
        budgets, agent_budget = g.drip_budgets(uploads)
        start, at = self._receive_time(when - timedelta(seconds=_bk.DAY_SECONDS)), self._receive_time(when)
        self._db.execute(
            "DELETE FROM guardrail_parameters_bytes WHERE identity_kind = ? AND identity_value = ? AND at < ?",
            (kind, value, self._receive_time(clock - timedelta(seconds=2 * _bk.DAY_SECONDS))),
        )

        def total(key: str) -> int:
            return self._db.execute(
                "SELECT coalesce(sum(bytes), 0) FROM guardrail_parameters_bytes "
                "WHERE identity_kind = ? AND identity_value = ? AND budget_key = ? AND at > ?",
                (kind, value, key, start),
            ).fetchone()[0]

        size = int(body.get("bytes") or 0)
        sums = {key: total(key) for key in keys}
        agent = total("")
        over = [
            f"parameters volume over {_bk._bytes_text(budgets.get(key, _bk.ENTRY_BUDGET_BYTES))} a day to {key}"
            for key in keys if sums[key] + size > budgets.get(key, _bk.ENTRY_BUDGET_BYTES)
        ]
        if agent + size > agent_budget:
            over.append(f"parameters volume over {_bk._bytes_text(agent_budget)} a day for the agent")
        if over:
            return {
                **body, "kind": _bk.UPLOAD, "step": _bk.STEP_DRIP,
                "reasons": (over + list(body.get("reasons") or []))[: _bk.MAX_REASONS],
                "drip": {"entries": sums, "agent": agent, "bytes": size},
            }
        self._db.executemany(
            "INSERT INTO guardrail_parameters_bytes (identity_kind, identity_value, budget_key, at, bytes) "
            "VALUES (?, ?, ?, ?, ?)",
            [(kind, value, key, at, size) for key in ("", *keys)],
        )
        return body

    # ----------------------------------------------- blocked by OpenShell

    def _collector_sandboxes(self, kind: str, value: str) -> list[str]:
        """The agent's sandboxes `railmon openshell` has posted a policy
        for: where OpenShell's denials of its requests are reported."""
        sandboxes = self._sandbox_names(kind, value)
        if not sandboxes:
            return []
        marks = ",".join("?" * len(sandboxes))
        return [row[0] for row in self._db.execute(
            f"SELECT DISTINCT sandbox FROM openshell_sandbox_policies WHERE sandbox IN ({marks})",
            sandboxes,
        )]

    def _use_openshell_denial_locked(self, sandboxes: Sequence[str], interaction: Mapping[str, Any]) -> bool:
        """Whether OpenShell logged a denial of this very request: an HTTP
        (L7) denial in one of `sandboxes` with its host, method and path,
        within OPENSHELL_DENIAL_MATCH of its capture, that no other request
        was dropped for. The nearest such denial is marked used."""
        host = g.normalize_host(interaction.get("host"))
        method = (interaction.get("method") or "").upper()
        path = (interaction.get("path") or "").split("?", 1)[0]
        when = g._instant(interaction.get("timestamp"))
        if not sandboxes or host is None or not method or not path or when is None:
            return False
        marks = ",".join("?" * len(sandboxes))
        # Denials' `at` is stored as `_receive_time` writes it, so the window
        # is a text range; a second's slack for the capture's own rounding.
        slack = OPENSHELL_DENIAL_MATCH + timedelta(seconds=1)
        found = []
        for row in self._db.execute(
            f"SELECT d.denial_id, d.at, d.host, d.path FROM openshell_denials d "
            f"WHERE d.sandbox IN ({marks}) AND d.kind = 'http' AND upper(d.method) = ? "
            "AND d.at >= ? AND d.at <= ? "
            "AND d.denial_id NOT IN (SELECT denial_id FROM openshell_denials_used)",
            (*sandboxes, method, self._receive_time(when - slack), self._receive_time(when + slack)),
        ):
            at = g._instant(row["at"])
            if (
                at is not None and abs(at - when) <= OPENSHELL_DENIAL_MATCH
                and g.normalize_host(row["host"]) == host
                and (row["path"] or "").split("?", 1)[0] == path
            ):
                found.append((abs(at - when), row["denial_id"]))
        if not found:
            return False
        self._db.execute("INSERT INTO openshell_denials_used (denial_id) VALUES (?)", (min(found)[1],))
        return True

    def _hold_if_blocked_locked(
        self, interaction: Mapping[str, Any], kind: str, value: str, version: Mapping[str, Any],
        calls: Sequence[Mapping[str, Any]], now: str,
    ) -> bool:
        """DR-261: a request OpenShell blocked isn't judged (Lebin's DR-194
        Q1). Its supervisor answers such a request 403, but so can any
        server, so only OpenShell's own denial, from the collector, says it
        was blocked. A 403 from an agent whose sandbox the collector reports
        on is therefore not judged now: with that denial already stored it
        is dropped, and otherwise held until it arrives or OPENSHELL_HOLD
        passes. Returns whether it was dropped or held; past
        OPENSHELL_HELD_MAX held for the agent, it is judged at once."""
        if interaction.get("status_code") != 403:
            return False
        sandboxes = self._collector_sandboxes(kind, value)
        if not sandboxes:
            return False
        if self._use_openshell_denial_locked(sandboxes, interaction):
            return True
        held = self._db.execute(
            "SELECT count(*) FROM openshell_held_requests WHERE identity_kind = ? AND identity_value = ?",
            (kind, value),
        ).fetchone()[0]
        if held >= OPENSHELL_HELD_MAX:
            return False
        self._db.execute(
            """INSERT OR REPLACE INTO openshell_held_requests
                   (interaction_row, identity_kind, identity_value, guardrail_version_id,
                    held_at, calls_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (interaction["id"], kind, value, version["guardrail_version_id"], now,
             json.dumps(list(calls), ensure_ascii=False, sort_keys=True)),
        )
        return True

    def _release_held_guarded(self) -> None:
        """`_release_held_requests_locked` in a savepoint, for the write
        paths that run it: after a capture batch, an ASP, a denials post."""
        with self._hook_guard("held requests"):
            self._release_held_requests_locked()

    def _release_held_requests_locked(self) -> None:
        """Drop each held request OpenShell's denials now cover, and judge
        each one still held after OPENSHELL_HOLD as on ingest, under the
        version in force now (an Allow this meanwhile counts; turned off
        meanwhile, it isn't judged), stamped when it was held. Each in its
        own savepoint: one that fails is dropped and marks the check
        failed, so it can't block the rest."""
        now = self._receive_time()
        due = self._receive_time(_instant(now) - OPENSHELL_HOLD)
        sandboxes: dict[tuple[str, str], list[str]] = {}
        for held in self._db.execute(
            "SELECT * FROM openshell_held_requests ORDER BY interaction_row LIMIT ?",
            (OPENSHELL_RELEASE_BATCH,),
        ).fetchall():
            identity = (held["identity_kind"], held["identity_value"])
            if identity not in sandboxes:
                sandboxes[identity] = self._collector_sandboxes(*identity)
            interaction = self._db.execute(
                "SELECT * FROM interactions WHERE id = ?", (held["interaction_row"],)
            ).fetchone()
            if interaction is not None and self._use_openshell_denial_locked(
                sandboxes[identity], dict(interaction)
            ):
                self._db.execute("DELETE FROM openshell_held_requests WHERE interaction_row = ?",
                                 (held["interaction_row"],))
                continue
            if held["held_at"] > due:
                continue
            self._db.execute("DELETE FROM openshell_held_requests WHERE interaction_row = ?",
                             (held["interaction_row"],))
            active = self._active_guardrail_row(*identity)
            if interaction is None or active is None:
                continue
            self._db.execute("SAVEPOINT held_one")
            try:
                self._judge_request_locked(
                    *identity, active, dict(interaction), json.loads(held["calls_json"]), held["held_at"],
                )
            except Exception as exc:  # noqa: BLE001 - the rest still run
                self._db.execute("ROLLBACK TO held_one")
                print(f"raildash: a held request's check failed: {exc!r}", file=sys.stderr)
                self._mark(*EVERY_AGENT, MARK_CHECK_FAILED, now)
            self._db.execute("RELEASE held_one")

    def _openshell_held_locked(self, kind: str, value: str) -> dict[str, Any] | None:
        """The agent's held requests, for the panel: how many, since when."""
        row = self._db.execute(
            "SELECT count(*), min(held_at) FROM openshell_held_requests "
            "WHERE identity_kind = ? AND identity_value = ?",
            (kind, value),
        ).fetchone()
        return {"count": row[0], "since": row[1]} if row[0] else None

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
            # DR-205: a version with the data_actions rule is a v2; one
            # without stays v1, exactly as before.
            # DR-207: and one with egress_containment is a v3.
            "guardrail_contract_version": g.contract_version(rules),
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
        mine = self._owned_requests_locked(kind, value, start, locked_at)
        result = g.propose_guardrail(
            self._alignment_contract(alignment), bundle, mine,
            guardrail_version_id="grd-proposed",
            version=self._next_version_label(kind, value),
            created_at=self._receive_time(),
            openshell_policy=self._openshell_policy_locked(kind, value),
            specs=self._api_specs_locked(),
        )
        result["data_actions_blocked"] = []
        if result["guardrail"] is not None:
            # DR-205 §4.4: the proposal includes `data_actions`, so a new
            # guardrail is a v2 version. The panel asks for the proposal on
            # every poll, so it is cached until a new capture or schema
            # arrives (its inputs are the window's requests and schemas).
            # Only captures inside the window, new schema rows and new ASPs
            # (trusted hosts, declared servers) can change it; a capture
            # after the lock, or a schema seen again, can't.
            stamp = (
                alignment["alignment_version_id"],
                tuple(self._db.execute(
                    "SELECT max(id), count(*) FROM interactions WHERE authenticated = 1 "
                    "AND timestamp_ns BETWEEN ? AND ?",
                    (int(start.timestamp() * 1e9), int(locked_at.timestamp() * 1e9)),
                ).fetchone()),
                self._db.execute("SELECT count(*) FROM tool_schemas").fetchone()[0],
                tuple(self._db.execute("SELECT max(rowid), count(*) FROM asps").fetchone()),
                # A model answer arriving changes a tool's classification.
                tuple(self._db.execute("SELECT max(asked_at), count(*) FROM tool_model_answers").fetchone()),
            )
            cache = self.__dict__.setdefault("_data_actions_proposal_cache", {})
            proposal = cache.get(stamp)
            if proposal is None:
                proposal = self._data_actions_proposal_locked(mine, start, locked_at)
                cache.clear()
                cache[stamp] = proposal
            proposal = json.loads(json.dumps(proposal))
            result["guardrail"]["rules"][g.DATA_ACTIONS] = proposal["rule"]
            result["guardrail"]["guardrail_contract_version"] = g.contract_version(
                result["guardrail"]["rules"]
            )
            result["data_actions_blocked"] = proposal["blocked_until_allowed"]
        return result

    def _owned_requests_locked(
        self, kind: str, value: str, start: datetime, end: datetime,
    ) -> list[dict[str, Any]]:
        """This agent's authenticated captured requests between two instants,
        given to it the way `guardrail.request_owner` gives a request."""
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
            (int(start.timestamp() * 1e9), int(end.timestamp() * 1e9), PROPOSAL_MAX_REQUESTS),
        ).fetchall()
        mine = []
        for row in rows:
            request = dict(row)
            owner = g.request_owner(request, candidates, authenticated=True)
            if owner["decision"] == "guardrail" and self._identity_columns(owner["identity"]) == (kind, value):
                mine.append(request)
        return mine

    # ------------------------------------------------------ data actions

    def _queue_not_offered_locked(
        self, kind: str, value: str, interaction: Mapping[str, Any],
        calls: Sequence[Mapping[str, Any]], now: str,
    ) -> None:
        """§4.4 G5: an observed MCP call the endpoint's listings don't have
        (or that has no listing yet: its first may come in a later batch)
        is queued, and judged once the delay has passed (`_run_not_offered`).
        Past `MAX_PENDING` queued calls of this agent, its call is judged at
        once."""
        called = _instant(now)
        due = self._receive_time(called + das.NOT_OFFERED_DELAY)
        for call in calls:
            endpoint, wire = call.get("endpoint"), call.get("wire_tool")
            if call.get("class") != g.OBSERVED or call.get("unreadable") or not endpoint or not wire:
                continue
            if self._offered_locked(endpoint, wire, called) is True:
                continue
            queued = self._db.execute(
                "SELECT count(*) FROM data_action_pending WHERE identity_kind = ? AND identity_value = ?",
                (kind, value),
            ).fetchone()[0]
            if queued >= das.MAX_PENDING:
                self._judge_not_offered_locked(kind, value, interaction.get("interaction_id"),
                                               call["tool"], wire, endpoint, now, now)
                continue
            self._db.execute(
                """INSERT INTO data_action_pending (identity_kind, identity_value, interaction_id,
                       tool, wire_tool, endpoint, called_at, due_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (kind, value, interaction.get("interaction_id"), call["tool"], wire, endpoint, now, due),
            )

    def _run_not_offered_locked(self, now: str | None = None) -> None:
        """Judge every queued call whose delay has passed. Run from the
        write paths that arrive anyway: after a capture batch is stored
        (its own listings included) and on a heartbeat. Each call is judged
        in its own savepoint; one that fails is dropped and marks the check
        failed, so it can't block the rest."""
        current = now or self._receive_time()
        due = self._db.execute(
            "SELECT * FROM data_action_pending WHERE due_at <= ? ORDER BY pending_id LIMIT 500",
            (current,),
        ).fetchall()
        for row in due:
            self._db.execute("DELETE FROM data_action_pending WHERE pending_id = ?", (row["pending_id"],))
            self._db.execute("SAVEPOINT not_offered_one")
            try:
                self._judge_not_offered_locked(
                    row["identity_kind"], row["identity_value"], row["interaction_id"],
                    row["tool"], row["wire_tool"], row["endpoint"], row["called_at"], current,
                )
            except Exception as exc:  # noqa: BLE001 - the rest of the queue still runs
                self._db.execute("ROLLBACK TO not_offered_one")
                print(f"raildash: a not-offered check failed: {exc!r}", file=sys.stderr)
                self._mark(*EVERY_AGENT, MARK_CHECK_FAILED, current)
            self._db.execute("RELEASE not_offered_one")

    def _judge_not_offered_locked(
        self, kind: str, value: str, interaction_id: Any, tool: str, wire: str, endpoint: str,
        called_at: str, now: str,
    ) -> None:
        """The window is anchored at the call (24 hours before it), so a call
        judged late isn't held to listings that aged out meanwhile. Still no
        listing ever from the endpoint: nothing to compare, not judged."""
        if self._offered_locked(endpoint, wire, _instant(called_at)) is not False:
            return
        active = self._active_guardrail_row(kind, value)
        if active is None:
            # Turned off since the call. (A call is only queued while a
            # guardrail is active, so a newer version -- an Allow this, an
            # edit -- judges it with today's policy, and doesn't drop it.)
            return
        rule = json.loads(active["contract_json"])["rules"].get(g.DATA_ACTIONS)
        if rule is None or g.data_action_allowed(rule, tool, "not_offered"):
            return
        violation = g._violation(
            g.DATA_ACTIONS, g.data_action_item(tool, "not_offered", endpoint), g.OBSERVED,
            {"kind": "interaction", "id": interaction_id},
            kind="data_action", tool=tool, action="not_offered", endpoint=endpoint, wire_tool=wire,
            from_undeclared=False, undeclared=[],
        )
        self._record_violations(kind, value, active["guardrail_version_id"], [violation], now)

    def _data_actions_dismissed_key(self, kind: str, value: str) -> str:
        return f"data_actions_offer_dismissed:{kind}:{value}"

    def _data_actions_offer_available_locked(self, kind: str, value: str) -> bool:
        """Cheap: whether the agent would be offered *Add data actions*."""
        active = self._active_guardrail_row(kind, value)
        if active is None or g.DATA_ACTIONS in json.loads(active["contract_json"])["rules"]:
            return False
        return self._db.execute(
            "SELECT 1 FROM settings WHERE key = ?", (self._data_actions_dismissed_key(kind, value),)
        ).fetchone() is None

    def data_actions_offer(self, ref: str) -> dict[str, Any] | None:
        """The *Add data actions* proposal, computed when asked for (the
        panel asks when the offer is opened, not on every poll)."""
        with self._lock:
            kind, value = self._resolve_agent_ref(ref)
            return self._data_actions_offer_locked(kind, value)

    def _data_actions_offer_locked(self, kind: str, value: str) -> dict[str, Any] | None:
        """DR-205 §4.4: an agent whose active version is a v1 is offered
        *Add data actions*, proposed from its requests in the 24 hours before
        now, until it accepts or dismisses."""
        if not self._data_actions_offer_available_locked(kind, value):
            return None
        end = datetime.now(timezone.utc)
        start = end - g.PROPOSAL_LOOKBACK
        return self._data_actions_proposal_locked(
            self._owned_requests_locked(kind, value, start, end), start, end
        )

    def add_data_actions(self, ref: str, rule: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """**Add data actions**: a new (v2) version, the active v1 version's
        rules plus `rule`, or the offer's proposal when none is given."""
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            contract = json.loads(active["contract_json"])
            if g.DATA_ACTIONS in contract["rules"]:
                raise ValueError("the active version already has the data_actions rule")
            edited = rule is not None
            if rule is None:
                offer = self._data_actions_offer_locked(kind, value)
                if offer is None:
                    raise ValueError("no data_actions offer to accept")
                rule = offer["rule"]
            rules = {**json.loads(json.dumps(contract["rules"])), g.DATA_ACTIONS: dict(rule)}
            created = self._create_version_locked(
                kind, value, rules, derived_from=contract["derived_from"]["alignment_version_id"],
                created_by="add_data_actions", detail={"edited": edited},
            )
            return self._version_view(created, active=True)

    def dismiss_data_actions(self, ref: str) -> dict[str, Any]:
        """**Dismiss** the *Add data actions* offer: recorded, not offered again."""
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            if g.DATA_ACTIONS in json.loads(active["contract_json"])["rules"]:
                raise ValueError("the active version already has the data_actions rule")
            self._db.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (self._data_actions_dismissed_key(kind, value), self._receive_time()),
            )
            self._event(kind, value, "dismiss_data_actions", active["guardrail_version_id"], {})
            return {"agent_ref": ref, "dismissed": True}

    # ---------------------------------------------- narrow uploads (§4)

    def _narrow_dismissed_key(self, kind: str, value: str) -> str:
        return f"narrow_uploads_dismissed:{kind}:{value}"

    def _narrow_dismissed_locked(self, kind: str, value: str) -> list[str]:
        found = self._db.execute(
            "SELECT value FROM settings WHERE key = ?", (self._narrow_dismissed_key(kind, value),)
        ).fetchone()
        try:
            hosts = json.loads(found[0]) if found is not None else []
        except ValueError:
            return []
        return [h for h in hosts if isinstance(h, str)] if isinstance(hosts, list) else []

    def _narrow_offer_locked(self, kind: str, value: str, *, cached: bool = True) -> dict[str, Any] | None:
        """REST uploads §4's *narrow uploads* offer: the active version's
        upload hosts that, over the agent's requests of the last 24 hours
        (the proposal's window), were only sent `parameters` bodies, and
        that moving to `parameters_only_hosts` makes no request or stored
        row count (`guardrail.narrow_uploads_hosts`). None when there is
        nothing to offer, every such host was dismissed, or the window holds
        more requests than are read (not every one could be checked).

        The read limit counts every agent's captures in the window, since
        they are read before they are given to this one.

        The detail route asks on every poll, so the answer is kept until
        the version or the dismissals change, a row is added or
        acknowledged, or ten minutes pass (the window moves); new captures
        and repeats of a stored row (of any agent: who owns a capture is
        only known by reading it) are read at most once a minute. A kept
        offer can be out of date, never wrong to accept: accepting
        re-computes it."""
        active = self._active_guardrail_row(kind, value)
        if active is None or not g.body_kinds_on():
            return None
        end = datetime.now(timezone.utc)
        dismissed = self._narrow_dismissed_locked(kind, value)
        rows_key = tuple(self._db.execute(
            "SELECT count(*), max(row_id), max(acknowledged_at) FROM guardrail_rows "
            "WHERE identity_kind = ? AND identity_value = ?", (kind, value),
        ).fetchone())
        latest = self._db.execute("SELECT max(id) FROM interactions").fetchone()[0]
        key = (active["guardrail_version_id"], rows_key, tuple(dismissed), self._api_specs_stamp())
        cache = self.__dict__.setdefault("_narrow_offer_cache", {})
        kept = cache.get((kind, value))
        if cached and kept is not None and kept["key"] == key:
            age = end.timestamp() - kept["at"]
            if 0 <= age < NARROW_OFFER_MAX_AGE and (kept["latest"] == latest or age < NARROW_OFFER_MIN_AGE):
                return kept["offer"]
        start = end - g.PROPOSAL_LOOKBACK
        offer = None
        # The read limit is on every agent's captures, before they are given
        # to this one: past it, this agent's oldest could be missing.
        total = self._db.execute(
            "SELECT count(*) FROM interactions WHERE authenticated = 1 AND timestamp_ns BETWEEN ? AND ?",
            (int(start.timestamp() * 1e9), int(end.timestamp() * 1e9)),
        ).fetchone()[0]
        if total < PROPOSAL_MAX_REQUESTS:
            requests = self._owned_requests_locked(kind, value, start, end)
            rows = [
                self._row_view(row) for row in self._db.execute(
                    "SELECT * FROM guardrail_rows WHERE identity_kind = ? AND identity_value = ?", (kind, value),
                )
            ]
            contract = json.loads(active["contract_json"])
            hosts = [h for h in g.narrow_uploads_hosts(contract, requests, rows, self._api_specs_locked())
                     if h["host"] not in dismissed]
            if hosts:
                offer = {"hosts": hosts, "version": contract["version"],
                         "window": {"start": self._receive_time(start), "end": self._receive_time(end)}}
        cache[(kind, value)] = {"key": key, "latest": latest, "at": end.timestamp(), "offer": offer}
        return offer

    def narrow_uploads_offer(self, ref: str) -> dict[str, Any] | None:
        with self._lock:
            kind, value = self._resolve_agent_ref(ref)
            return self._narrow_offer_locked(kind, value)

    def _narrow_hosts_arg(self, hosts: Any) -> list[str]:
        if (not isinstance(hosts, list) or not hosts
                or not all(isinstance(h, str) for h in hosts) or len(set(hosts)) != len(hosts)):
            raise ValueError("hosts must be a non-empty list of distinct hosts")
        return hosts

    def narrow_uploads(self, ref: str, hosts: Any) -> dict[str, Any]:
        """**Narrow uploads**: a new version moving `hosts`, every one in the
        current offer (re-computed now, not read from the cache), from
        `uploads.allowed_hosts` to `parameters_only_hosts`."""
        hosts = self._narrow_hosts_arg(hosts)
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            offer = self._narrow_offer_locked(kind, value, cached=False)
            offered = {h["host"] for h in offer["hosts"]} if offer is not None else set()
            missing = [h for h in hosts if h not in offered]
            if missing:
                raise ValueError(f"not in the narrow uploads offer now: {', '.join(missing)}")
            contract = json.loads(active["contract_json"])
            rules = json.loads(json.dumps(contract["rules"]))
            uploads = rules["uploads"]
            uploads["allowed_hosts"] = [h for h in uploads["allowed_hosts"] if h not in hosts]
            uploads["parameters_only_hosts"] = sorted({*uploads.get("parameters_only_hosts", ()), *hosts})
            created = self._create_version_locked(
                kind, value, rules, derived_from=contract["derived_from"]["alignment_version_id"],
                created_by="narrow_uploads", detail={"hosts": hosts},
            )
            return self._version_view(created, active=True)

    def dismiss_narrow_uploads(self, ref: str, hosts: Any) -> dict[str, Any]:
        """**Dismiss** the *narrow uploads* offer for `hosts`: they aren't
        offered again for this agent; a host not dismissed still can be."""
        hosts = self._narrow_hosts_arg(hosts)
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            listed = json.loads(active["contract_json"])["rules"]["uploads"]["allowed_hosts"]
            unlisted = [h for h in hosts if h not in listed]
            if unlisted:
                raise ValueError(f"not an upload host of the active version: {', '.join(unlisted)}")
            dismissed = sorted({*self._narrow_dismissed_locked(kind, value), *hosts})
            self._db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (self._narrow_dismissed_key(kind, value), json.dumps(dismissed)),
            )
            self._event(kind, value, "dismiss_narrow_uploads", active["guardrail_version_id"], {"hosts": hosts})
            return {"agent_ref": ref, "dismissed": hosts}

    def _egress_locked(self, kind: str, value: str) -> dict[str, Any] | None:
        """The newest ASP's egress containment and declared proxy, as the
        panel's Egress line shows them (DR-207 §4.4), or None with no ASP.
        In a multi-agent sandbox it's the sandbox's, which every agent in
        it shares."""
        newest = self._newest_asps(kind, value)
        if not newest:
            return None
        bundle = parse_bundle(bytes(newest[0]["exact_bundle"]))
        # The same view the rule and the proposal read (`g._attributes`).
        attributes = g._attributes(bundle)
        reading = g.egress_reading(attributes.get(g.EGRESS_ATTRIBUTE))
        if reading is not None:
            # The rule's own stale window, so the line never shows an old
            # "contained" as current once scans stop (design §5).
            received = self._mark_at(kind, value, MARK_ASP_RECEIVED.format(newest[0]["asp_id"]))
            if received is not None:
                previous = self._mark_at(kind, value, MARK_ASP_RECEIVED_BEFORE.format(newest[0]["asp_id"]))
            else:
                previous = newest[1]["collected_at"] if len(newest) > 1 else None
            reading["stale"] = g.asp_is_stale(
                received or bundle["collected_at"], previous, self._receive_time()
            )
            reading["multi_agent"] = g.is_multi_agent(bundle)
        proxy = attributes.get(g.EGRESS_PROXY_ATTRIBUTE)
        declared = proxy.get("value") if isinstance(proxy, dict) and proxy.get("status") == "ANSWERED" else None
        return {
            "reading": reading,
            "proxy_declared": declared if isinstance(declared, dict) else None,
        }

    def _sandbox_names(self, kind: str, value: str) -> list[str]:
        """The sandbox names this agent's ASPs carry: where the collector's
        posts for it are filed (DR-249)."""
        return sorted({name for _, name in self._sandboxes(kind, value) if name})

    def _openshell_policy_locked(self, kind: str, value: str) -> dict[str, Any] | None:
        """The agent's newest OpenShell policy record, imported (DR-248) or
        posted by the collector for one of its sandboxes (DR-249), with when
        and how it arrived (`imported_at`, `source`), or None."""
        found = []
        row = self._db.execute(
            "SELECT imported_at, source, record_json FROM openshell_policies "
            "WHERE identity_kind = ? AND identity_value = ? ORDER BY policy_id DESC LIMIT 1",
            (kind, value),
        ).fetchone()
        if row is not None:
            found.append((row["imported_at"], row["source"], row["record_json"]))
        for sandbox in self._sandbox_names(kind, value):
            row = self._db.execute(
                "SELECT received_at, record_json FROM openshell_sandbox_policies "
                "WHERE sandbox = ? ORDER BY policy_id DESC LIMIT 1",
                (sandbox,),
            ).fetchone()
            if row is not None:
                found.append((row["received_at"], "collector", row["record_json"]))
        if not found:
            return None
        at, source, record = max(found, key=lambda item: item[0])
        return {**json.loads(record), "imported_at": at, "source": source}

    def record_openshell_policy(self, sandbox: str, raw: bytes) -> dict[str, Any]:
        """A policy revision `railmon openshell` read from OpenShell's
        gateway (`policy get --full -o json`) for one sandbox (DR-249).
        Read as an import is (`parse_policy`): only endpoint fields are
        kept, and a body that isn't a policy is refused and stores nothing."""
        osp.check_sandbox(sandbox)
        record = osp.parse_policy(raw)
        with self._write_transaction():
            at = self._receive_time()
            self._db.execute(
                "INSERT INTO openshell_sandbox_policies (sandbox, received_at, record_json) VALUES (?, ?, ?)",
                (sandbox, at, json.dumps(record, ensure_ascii=False, sort_keys=True)),
            )
            # The collector posts an unchanged policy again every 30 minutes,
            # so only the newest few rows are worth keeping.
            self._db.execute(
                "DELETE FROM openshell_sandbox_policies WHERE sandbox = ? AND policy_id NOT IN "
                "(SELECT policy_id FROM openshell_sandbox_policies WHERE sandbox = ? "
                "ORDER BY policy_id DESC LIMIT ?)",
                (sandbox, sandbox, OPENSHELL_POLICIES_KEPT),
            )
            return {"sandbox": sandbox, "received_at": at, "revision": record["revision"],
                    "digest": record["digest"], "endpoints": len(record["endpoints"])}

    def record_openshell_denials(self, sandbox: str, body: Any) -> dict[str, Any]:
        """Denials `railmon openshell` parsed from one sandbox's log, and the
        span it couldn't show was complete (DR-249, design §4.2). A line
        posted again (the poll windows overlap) is stored once. Rows older
        than `OPENSHELL_DENIAL_RETENTION` go. A denial is OpenShell's report,
        not a violation: nothing here changes a guardrail's state (Lebin's
        §7 Q1, 2026-10-27), and the request a denial refused, which the
        collector captured answered 403, isn't judged either (DR-261)."""
        osp.check_sandbox(sandbox)
        batch = osp.parse_denials(body)
        with self._write_transaction():
            now = self._receive_time()
            before = self._db.total_changes
            self._db.executemany(
                """INSERT OR IGNORE INTO openshell_denials
                       (sandbox, at, line_hash, kind, host, port, method, path, binary, policy, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(sandbox, d["at"], d["hash"], d["kind"], d["host"], d["port"], d["method"],
                  d["path"], d["binary"], d["policy"], d["reason"]) for d in batch["denials"]],
            )
            stored = self._db.total_changes - before
            partial = batch["partial"]
            if partial is not None:
                self._db.execute(
                    "INSERT INTO openshell_denial_gaps (sandbox, received_at, gap_from, gap_to, reasons_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (sandbox, now, partial["from"], partial["to"], json.dumps(partial["reasons"])),
                )
            cutoff = self._receive_time(_instant(now) - OPENSHELL_DENIAL_RETENTION)
            self._db.execute("DELETE FROM openshell_denials WHERE at < ?", (cutoff,))
            self._db.execute("DELETE FROM openshell_denial_gaps WHERE gap_to < ?", (cutoff,))
            self._db.execute(
                "DELETE FROM openshell_denials_used WHERE denial_id NOT IN (SELECT denial_id FROM openshell_denials)"
            )
            # A held request these denials cover is dropped (DR-261).
            self._release_held_guarded()
            return {"sandbox": sandbox, "stored": stored, "duplicates": len(batch["denials"]) - stored,
                    "partial": partial is not None}

    def _openshell_denials_locked(self, kind: str, value: str, allowed_hosts: list[str] | None) -> dict[str, Any] | None:
        """**Blocked by OpenShell** (design §4.3): the last 24 h of denials
        for the agent's sandboxes, grouped by host, port and binary, hosts
        outside the guardrail (`allowed_hosts`, the version in force's or
        the proposal's; None when there is neither) first, then the newest.
        With the spans a batch couldn't show were complete. None when the
        collector has posted nothing for any of its sandboxes in that time."""
        sandboxes = self._sandbox_names(kind, value)
        if not sandboxes:
            return None
        since = self._receive_time(_instant(self._receive_time()) - OPENSHELL_DENIALS_SHOWN)
        marks = ",".join("?" * len(sandboxes))
        rows = self._db.execute(
            f"SELECT * FROM openshell_denials WHERE sandbox IN ({marks}) AND at >= ? ORDER BY at DESC LIMIT ?",
            (*sandboxes, since, OPENSHELL_DENIALS_READ),
        ).fetchall()
        gaps = self._db.execute(
            f"SELECT gap_from, gap_to, reasons_json FROM openshell_denial_gaps "
            f"WHERE sandbox IN ({marks}) AND gap_to >= ? ORDER BY gap_to DESC LIMIT 20",
            (*sandboxes, since),
        ).fetchall()
        if not rows and not gaps:
            return None
        groups: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
        for row in rows:
            key = (row["host"], row["port"], row["binary"])
            group = groups.get(key)
            if group is None:
                host = g.normalize_host(row["host"])
                group = groups[key] = {
                    "host": row["host"], "port": row["port"], "binary": row["binary"],
                    "count": 0, "last_at": row["at"], "requests": [], "reasons": [],
                    "outside_guardrail": None if allowed_hosts is None or host is None
                    else not g.host_allowed(host, allowed_hosts),
                }
            group["count"] += 1
            request = f"{row['method']} {row['path']}" if row["method"] else None
            if request and request not in group["requests"] and len(group["requests"]) < 5:
                group["requests"].append(request)
            if row["reason"] and row["reason"] not in group["reasons"] and len(group["reasons"]) < 3:
                group["reasons"].append(row["reason"])
        ordered = sorted(groups.values(), key=lambda grp: grp["last_at"], reverse=True)
        ordered.sort(key=lambda grp: grp["outside_guardrail"] is not True)
        return {
            "groups": ordered[:OPENSHELL_DENIAL_GROUPS_SHOWN],
            "more_groups": max(0, len(ordered) - OPENSHELL_DENIAL_GROUPS_SHOWN),
            # The read stopped at OPENSHELL_DENIALS_READ: counts are at least.
            "truncated": len(rows) >= OPENSHELL_DENIALS_READ,
            "partial": [{"from": gap["gap_from"], "to": gap["gap_to"], "reasons": json.loads(gap["reasons_json"])}
                        for gap in gaps],
        }

    def _openshell_policy_view_locked(
        self, kind: str, value: str, allowed_hosts: list[str] | None = None
    ) -> dict[str, Any] | None:
        """The Egress line's OpenShell rows (DR-194 §4.3): the newest
        record and whether it is older than DR-184's longest stale window
        (`STALE_MAX`, two hours; an import has no gap between scans to
        scale it by), past which the line says "as of <time>". With
        `beyond_guardrail`, the endpoints it allows that `allowed_hosts`
        (the version in force's or the proposal's) doesn't (DR-257,
        design §4.5); None when there is no guardrail to compare with."""
        record = self._openshell_policy_locked(kind, value)
        if record is None:
            return None
        age = _instant(self._receive_time()) - _instant(record["imported_at"])
        beyond = None if allowed_hosts is None else osp.beyond_guardrail(record, allowed_hosts)
        return {**record, "stale": age > g.STALE_MAX, "beyond_guardrail": beyond}

    # ------------------------------------------------- API specs (M3)

    def _api_specs_stamp(self) -> tuple[Any, ...]:
        return tuple(self._db.execute(
            "SELECT count(*), max(imported_at), group_concat(host || ':' || sha256) "
            "FROM (SELECT host, sha256, imported_at FROM api_specs ORDER BY host)"
        ).fetchone())

    def _api_specs_locked(self) -> dict[str, dict[str, Any]]:
        """Every imported spec's index, by host. Kept parsed until a spec
        is imported or removed (judging reads it for every request)."""
        stamp = self._api_specs_stamp()
        cached = self.__dict__.get("_api_specs_cache")
        if cached is not None and cached[0] == stamp:
            return cached[1]
        specs: dict[str, dict[str, Any]] = {}
        for row in self._db.execute("SELECT host, index_json FROM api_specs"):
            try:
                index = json.loads(row["index_json"])
            except ValueError:
                continue
            # An index another RailDash version wrote is read as no spec:
            # the panel says to import it again.
            if isinstance(index, dict) and index.get("index_version") == api_specs.INDEX_VERSION:
                specs[row["host"]] = index
        self.__dict__["_api_specs_cache"] = (stamp, specs)
        return specs

    @staticmethod
    def _api_spec_host(host: Any) -> str:
        normalized = g.normalize_host(host) if isinstance(host, str) else None
        if (normalized is None or normalized != host or host.startswith("*.") or not g._is_host_pattern(host)
                or not (_HOST_NAME.fullmatch(host) or _ip_literal(host))):
            raise api_specs.SpecImportError(
                "host must be one normalized host name (lower case, no scheme, path or wildcard)")
        return normalized

    def import_api_spec(self, host: Any, raw: bytes) -> dict[str, Any]:
        """**Import an API spec** (REST uploads §4 "Specs"): index an
        OpenAPI 3.x file for one host, replacing any spec it had. Raises
        `SpecImportError` for a bad host or a file that isn't a spec, and
        stores nothing then. Requests judged from now on are classified
        with it; rows already stored keep what they were judged as."""
        host = self._api_spec_host(host)
        index = api_specs.parse_spec(raw)
        with self._write_transaction():
            at = self._receive_time()
            self._db.execute(
                "INSERT INTO api_specs (host, sha256, imported_at, index_json) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(host) DO UPDATE SET sha256 = excluded.sha256, imported_at = excluded.imported_at, "
                "index_json = excluded.index_json",
                (host, index["sha256"], at, json.dumps(index, ensure_ascii=False, sort_keys=True)),
            )
            return {"host": host, "imported_at": at, **api_specs.summary(index)}

    def api_spec_list(self) -> list[dict[str, Any]]:
        with self._lock:
            # The parsed indexes judging already keeps, not a parse per poll.
            specs = self._api_specs_locked()
            return [
                {"host": row["host"], "imported_at": row["imported_at"], "current": row["host"] in specs,
                 **api_specs.summary(specs.get(row["host"], {"sha256": row["sha256"]}))}
                for row in self._db.execute("SELECT host, sha256, imported_at FROM api_specs ORDER BY host")
            ]

    def remove_api_spec(self, host: str) -> dict[str, Any]:
        with self._write_transaction():
            found = self._db.execute("DELETE FROM api_specs WHERE host = ?", (host,)).rowcount
            if not found:
                raise KeyError(f"no API spec for {host}")
            return {"host": host, "removed": True}

    def import_openshell_policy(self, ref: str, raw: bytes) -> dict[str, Any]:
        """**Import OpenShell policy** (DR-248): store an uploaded policy as
        the agent's newest. Raises `PolicyImportError` for a file that
        isn't one, and stores nothing then, so the policy
        RailDash already held stays shown."""
        record = osp.parse_policy(raw)
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            at = self._receive_time()
            self._db.execute(
                "INSERT INTO openshell_policies (identity_kind, identity_value, imported_at, source, record_json) "
                "VALUES (?, ?, ?, 'import', ?)",
                (kind, value, at, json.dumps(record, ensure_ascii=False, sort_keys=True)),
            )
            self._event(kind, value, "import_openshell_policy", None, {
                "revision": record["revision"], "digest": record["digest"],
                "endpoints": len(record["endpoints"]),
            })
            view = self._openshell_policy_view_locked(kind, value)
            # The comparison needs the proposal; the panel's read, which
            # follows an import, carries it (DR-257).
            view.pop("beyond_guardrail")
            return {"agent_ref": ref, **view}

    def _openshell_base_locked(self, kind: str, value: str) -> dict[str, Any] | None:
        """The newest imported policy that carries static sections (an
        export starts from them, design §4.5), with when it was imported.
        The collector's posts carry none, and an import from before DR-258
        kept none, so this can be older than the policy shown, or None."""
        for row in self._db.execute(
            "SELECT imported_at, record_json FROM openshell_policies "
            "WHERE identity_kind = ? AND identity_value = ? ORDER BY policy_id DESC LIMIT ?",
            (kind, value, OPENSHELL_BASE_SCAN),
        ):
            record = json.loads(row["record_json"])
            if record.get("base"):
                return {**record, "imported_at": row["imported_at"]}
        return None

    def export_openshell_policy(self, ref: str) -> dict[str, Any]:
        """**Download as OpenShell policy** (DR-258, DR-194 M4, design
        §4.5): the guardrail version in force as an OpenShell policy file,
        on the agent's newest policy and the newest base policy it holds.
        Raises `ValueError` (409) with no version in force: a proposal isn't
        something to enforce. Read-only: nothing is stored, and nothing is
        sent to OpenShell; the user applies the file."""
        with self._lock:
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("no guardrail version is in force: lock one before exporting it")
            contract = json.loads(active["contract_json"])
            exported = osp.export_policy(
                contract["rules"],
                self._openshell_policy_locked(kind, value),
                self._openshell_base_locked(kind, value),
                agent=ref,
                version=f"{active['version']} ({active['guardrail_version_id']})",
                exported_at=self._receive_time(),
            )
            return {"agent_ref": ref, "version": active["version"],
                    "guardrail_version_id": active["guardrail_version_id"], **exported}

    def require_containment(self, ref: str, require: str = "contained") -> dict[str, Any]:
        """**Require containment** (DR-207 §4.4): a new v3 version, the
        active version's rules unchanged plus `egress_containment`. The
        user's explicit choice, so it's made even when the newest ASP
        doesn't meet it; the answer says whether the version starts
        Violated, which the panel warns about before asking."""
        if require not in EGRESS_REQUIRES:
            raise g.GuardrailValidationError(["require must be contained or allow_list_enforced"])
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            contract = json.loads(active["contract_json"])
            if contract["rules"].get(g.EGRESS) == {"require": require}:
                raise ValueError("the active version already requires this")
            rules = {**json.loads(json.dumps(contract["rules"])), g.EGRESS: {"require": require}}
            created = self._create_version_locked(
                kind, value, rules, derived_from=contract["derived_from"]["alignment_version_id"],
                created_by="require_containment", detail={"require": require},
            )
            # What the re-check actually recorded, not the raw reading: an
            # unreadable level or a stale one that meets the rule isn't a
            # violation, and a row already
            # acknowledged stays so. A multi-agent sandbox is judged on its
            # sandbox-scoped level like any other (DR-240).
            summary, _, _ = self._state_locked(kind, value, None)
            return {
                **self._version_view(created, active=True),
                "starts_violated": summary["rules"][g.EGRESS]["state"] == g.VIOLATED,
            }

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
            out_of_spec = rules.get("out_of_spec_calls")
            seeded = out_of_spec.get("seeded_from_declared") if isinstance(out_of_spec, dict) else None
            base_seeded = base_contract["rules"]["out_of_spec_calls"]["seeded_from_declared"]
            if isinstance(seeded, dict):
                for key in ("hosts", "mcp_servers"):
                    listed = seeded.get(key)
                    # Only a well-formed list is merged; anything else is
                    # left for the contract check to reject.
                    if isinstance(listed, list) and all(isinstance(v, str) for v in listed):
                        seeded[key] = sorted({*listed, *base_seeded[key]})
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
            # Requests held for OpenShell's word (DR-261) have no guardrail
            # left to be judged against.
            self._db.execute(
                "DELETE FROM openshell_held_requests WHERE identity_kind = ? AND identity_value = ?",
                (kind, value),
            )
            # A dismissed *Add data actions* offer is about the guardrail
            # turned off; a later one is offered afresh (DR-205).
            self._db.execute(
                "DELETE FROM settings WHERE key = ?", (self._data_actions_dismissed_key(kind, value),)
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

    def allow_guardrail_rows(self, ref: str, row_ids: Sequence[int]) -> dict[str, Any]:
        """**Allow all** on one rule's rows (DR-202): one new version that
        allows every listed row's item, as **Allow this** would one by one,
        recorded once in the history with the items it added.

        All or nothing: every id must be a distinct row of this agent, of
        one rule, that counts under the version in force and that Allow this
        could allow; otherwise `ValueError` and no version is created. A
        stale page (a row allowed or acknowledged since) is refused rather
        than half-applied, and the user reloads and sees what is left."""
        with self._write_transaction():
            kind, value = self._resolve_agent_ref(ref)
            active = self._active_guardrail_row(kind, value)
            if active is None:
                raise ValueError("this agent has no active guardrail")
            if not row_ids:
                raise ValueError("no rows to allow")
            if len(set(row_ids)) != len(row_ids):
                raise ValueError("a row is listed more than once")
            contract = json.loads(active["contract_json"])
            rules = contract["rules"]
            rule = None
            items = []
            for row_id in row_ids:
                row = self._db.execute(
                    "SELECT * FROM guardrail_rows WHERE row_id = ? AND identity_kind = ? "
                    "AND identity_value = ?",
                    (row_id, kind, value),
                ).fetchone()
                # Another agent's row is refused like a missing one, so the
                # answer says nothing about rows outside this agent.
                if row is None:
                    raise ValueError(f"row {row_id} is not one of this agent's rows")
                if rule is None:
                    rule = row["rule"]
                elif row["rule"] != rule:
                    raise ValueError("Allow all takes the rows of one rule")
                view = self._row_view(row)
                if not g.row_counts(contract, view):
                    raise ValueError(f"row {row_id} no longer counts; reload to see what is left")
                try:
                    # Refused exactly where Allow this on the version in
                    # force refuses, an unlistable host included, so the
                    # refusal names the row; then folded into the version
                    # being built, skipping an item an earlier row already
                    # covers so no entry is listed twice.
                    _allowed_by_one_click(contract, view)
                    if not g.item_allowed({"rules": rules}, view):
                        rules = g.with_item_allowed(rules, view)
                except ValueError as exc:
                    raise ValueError(f"row {row_id} ({row['item']}): {exc}") from exc
                items.append(row["item"])
            created = self._create_version_locked(
                kind, value, rules,
                derived_from=contract["derived_from"]["alignment_version_id"],
                created_by="allow_rows",
                detail={"rule": rule, "row_ids": list(row_ids), "items": items},
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
            newest_id = newest[0]["asp_id"]
            received = self._mark_at(kind, value, MARK_ASP_RECEIVED.format(newest_id))
            if received is not None:
                previous = self._mark_at(kind, value, MARK_ASP_RECEIVED_BEFORE.format(newest_id))
            else:
                previous = newest[1]["collected_at"] if len(newest) > 1 else None
            asp_result = g.evaluate_asp(
                contract, parse_bundle(bytes(newest[0]["exact_bundle"])),
                asp_id=newest[0]["asp_id"], previous_collected_at=previous, now=current,
                newest_received_at=received,
            )
        request_status = g.request_rules_status(
            now=current,
            last_heartbeat_at=self.latest_heartbeat_at(),
            last_unattributed_at=self._mark_at(*EVERY_AGENT, MARK_UNATTRIBUTED),
            last_tool_calls_unreadable_at=self._mark_at(kind, value, MARK_TOOL_CALLS_UNREADABLE),
            last_capture_refused_at=self.latest_capture_refusal_at(),
        )
        names = g.contract_rules(contract)
        rules = g.rule_states(asp_result, request_status, names)
        failed = self._mark_at(*EVERY_AGENT, MARK_CHECK_FAILED)
        if failed is not None and _instant(failed) >= _instant(active["activated_at"]):
            rules = {
                rule: {"state": g.UNVERIFIED, "reason": g.CHECK_FAILED, "violations": []}
                for rule in names
            }
        counting = [row for row in rows if row["counts"]]
        state = g.agent_state(
            has_active_guardrail=True, rule_results=rules, counting_rows=len(counting), rules=names,
        )
        summary = {
            "state": state,
            "rules": g.shown_rule_states(
                rules, (row["rule"] for row in counting), overflow_rule=OVERFLOW_RULE, rules=names,
            ),
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
            in_force = json.loads(active["contract_json"]) if active is not None else None
            for row in rows:
                row["allowable"] = _one_click_allowable(in_force, row)
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
            # What the denials and the policy are compared with: the version
            # in force's hosts, else the proposal's, else nothing to compare.
            allowed_hosts = (
                json.loads(active["contract_json"])["rules"]["out_of_spec_calls"]["allowed_hosts"]
                if active is not None else
                proposal["guardrail"]["rules"]["out_of_spec_calls"]["allowed_hosts"]
                if proposal is not None and proposal.get("guardrail") is not None else None
            )
            return {
                "agent_ref": ref,
                "agent_identity": self._identity_object(kind, value),
                "data_actions_offer_available": self._data_actions_offer_available_locked(kind, value),
                "narrow_uploads_offer": self._narrow_offer_locked(kind, value) if active is not None else None,
                "egress": self._egress_locked(kind, value),
                "openshell_policy": self._openshell_policy_view_locked(kind, value, allowed_hosts),
                "openshell_denials": self._openshell_denials_locked(kind, value, allowed_hosts),
                "openshell_held": self._openshell_held_locked(kind, value),
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
from . import body_kinds as _bk  # noqa: E402
from . import guardrail as g  # noqa: E402
from . import data_actions_store as das  # noqa: E402
from . import openshell_policy as osp  # noqa: E402
from . import api_specs  # noqa: E402
