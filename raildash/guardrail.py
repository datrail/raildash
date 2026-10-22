"""Pure OSS Data Guardrail v1 contract and evaluator (DR-184, milestone M1).

A guardrail is a per-agent set of four closed rules -- `uploads`,
`saved_files`, `service_ports` and `out_of_spec_calls` -- that every ASP and
every captured request of that agent is checked against. It is policy the
operator approved, kept apart from the alignment version (the baseline), so
the alignment contract and every locked baseline stay as they are. The design
is railxia/docs `design/2026-10-07-data-guardrail/data-guardrail-design.md`;
section numbers below are its. Later versions add optional rules: v2
`data_actions` (DR-205) and v3 `egress_containment` (DR-207,
`design/2026-10-11-egress-containment`).

Like `raildash.asp`, this module has no database, HTTP or UI dependency and
never reads the clock: every time it needs is an argument. Storage and the
two store hooks that call it are `raildash.guardrail_store` (M2).

The API, in the order a caller meets it:

- `guardrail_problems(version)`: the closed contract (schema plus the rules
  it cannot express); `[]` when valid.
- `propose_guardrail(...)`: the §4.4 first guardrail from a locked baseline
  and the agent's requests from the 24 h before the lock, with what would be
  a violation and why a declared list is empty.
- `evaluate_asp(guardrail, bundle, ...)`: `service_ports`, `saved_files`
  and `egress_containment` against one parsed ASP, staleness included.
- `request_owner(interaction, guardrails, ...)`: which active guardrail one
  captured request belongs to, if any (§4.3).
- `evaluate_request(guardrail, interaction, ...)`: `uploads` and
  `out_of_spec_calls` against one captured request.
- `request_rules_status(...)`: whether the two request rules can be verified
  at all now (collector heartbeat, unattributed traffic).
- `rule_states(asp_result, request_status)`: every rule's latest results
  in one map, multi-agent applied.
- `shown_rule_states(rule_results, counting_rules)`: each rule's state as
  the panel and `/api/guardrails` show it, from the same rows the agent's
  state counts.
- `item_allowed(guardrail, violation)` and `row_counts(guardrail, row)`:
  whether a version allows a stored row's item, and so whether the row
  counts toward the state under the version in force.
- `agent_state(...)`: the per-agent roll-up, Violated > Unverified > Held >
  No guardrail.
- `declared_offers(...)`: the *declared since gN* offers of the newest ASP.
- `with_item_allowed(rules, row)` and `with_declared_choice(...)`: the rules
  of the version **Allow this** or **Dismiss** creates.

and the pieces they are built from: `validate_guardrail`, `asp_is_stale`,
`is_multi_agent`, `normalize_host`, `host_matches`, `host_allowed`,
`glob_matches`, `file_kind`, `kernel_interface_path`, `saved_file_allowed`,
`listener_allowed`, `listener_item`, `normalize_mcp_server`,
`tool_call_server`, `mcp_item`, `carries_body` and `requested_tool_calls`.

Every violation is a plain dict: `rule`, `item` (the §4.5 row key: a host,
`(unknown host)`, a path, `protocol/addr/port`, a tool name, or
`mcp__<server>`), `evidence_class` (`observed` or `requested`), `source`
(`{"kind": "asp" | "interaction", "id": ...}`) and a `detail` dict with what
re-checking the item needs. A rule result is `{"state": "held" | "violated"
| "unverified", "reason": str | None, "violations": [...]}`. `reason` is
set exactly when the rule was not verified on its latest evidence: on
`unverified`, and on a `violated` rule whose evidence was stale, `PARTIAL`
or partly unreadable (the violations are real; the absence of others is
not shown). `agent_state` reads a rule as verified only without a reason.

Where the design is silent this module takes the reading that can only add
a violation or an Unverified, never a Held:

- A request `body` is empty only when it is null or the empty string. An
  empty JSON object or list still came from bytes on the wire, so it is a
  body. A stored `raw` that cannot be read counts as carrying one.
- A captured request with no decoded request at all (`request: null`) still
  happened, so for `out_of_spec_calls` it is a call to `(unknown host)`; it
  is an upload only if a body or `Content-Length` says so.
- A `max_request_bytes` key matches hosts as `allowed_hosts` does; when
  several keys match, the smallest cap applies. A request carrying a body to
  a capped host with no `request_size` is a violation: it can't be shown to
  be under the cap.
- Model-requested tool calls are read from the response body only, in the
  Anthropic, OpenAI chat and OpenAI Responses shapes, non-streamed or as a
  server-sent event stream (`requested_tool_calls` lists them). A request
  body only echoes an earlier turn, and the agent writes it, so it is not
  the model's request. A response that can't be read safely (the stored row
  unparseable, a compressed body, streamed text over 4 MiB, a body or event
  past the JSON safety bounds, an event whose data isn't JSON, or a last
  event cut mid-way) is flagged `tool_calls.readable: False`, and
  `request_rules_status` keeps both request rules Unverified for 10 minutes
  after it; a response with no body, or plain text with no `event:` or
  `data:` line, asks for nothing. The response's safety is judged apart from the request
  body, so an agent can't hide the calls by nesting its own request deep.
- An `mcp__` tool name with no `__` after its server part has no server,
  so it fails closed: it is a violation keyed by the whole tool name.
- The extracted server is compared exactly, without normalizing it first:
  agents build tool names from normalized server names, so a tool name that
  isn't normalized is not one an allowed server produced.
- `**` matches any run of characters, `/` included, so `/a/**/b` needs at
  least one segment between `a` and `b` (`/a/b` doesn't match it). A glob
  never matches more than it says.
- An ASP whose `collected_at` is ahead of `now` by more than the stale bound
  is stale too, as RailMon reads a probe heartbeat ("either way"). The same
  holds for a heartbeat ahead of `now`.
- An attribute missing from the ASP (an older rule pack), or `TEMPLATED`,
  is Unverified, like `BLIND`. A listener entry that can't be read makes the
  rule unverified (`MALFORMED_EVIDENCE`), alongside any violation a
  readable one shows.
- A v2 bundle counts as multi-agent when it lists two or more agents,
  whatever their `discovery_status`; a proposal from one is refused.
- An attributed request that matches the identity of more than one active
  guardrail is treated as unattributed, and one that matches none belongs to
  an agent without a guardrail (it is not checked, and is not unattributed).
- The window that keeps the request rules Unverified after an unattributed
  request is the fixed 10 minutes of §4.3's details, not the ASP stale bound
  its table names.
- The proposal seeds hosts only from requests the caller passes, which must
  already be the authenticated, attributed-to-this-agent captures of the
  24 h before the lock. A seeded host that isn't a valid guardrail host (an
  undecodable `Host` header) is listed as would-be rather than seeded.
- `/dev/shm` is storage, not a kernel interface: RailMon counts it as a
  temp directory beside `/tmp` (FILE_TEMP_DIRS), and a tmpfs file holds
  data like any other. So a write there is judged, while the rest of
  `/dev` is never a violation, as §4.2 says. Exempting it would let an
  agent save anything there unseen; it fails closed instead.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from .asp import (
    BUNDLE_VERSION_V2, FILE_ACCESS_ATTRIBUTE, identity_problems, only_reads_left_out, uuid_name_template,
)
from .ingest import _header, legacy_exchange
from .json_safety import (
    MAX_SAFE_JSON_BYTES,
    JSONStructureGuard,
    JSONStructureTooComplex,
    check_json_structure,
)
# A module reference, read at call time: the store calls this module from
# its ingest hooks (`raildash.guardrail_store`), so neither can import the
# other's names while it is still loading.
from . import store as _store

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "guardrail-version-v1.schema.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text())
_VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
# DR-205: v2 adds the `data_actions` rule; every v1 rule is unchanged, and a
# v1 version stays valid and is judged on its four rules.
SCHEMA_V2_PATH = SCHEMA_PATH.with_name("guardrail-version-v2.schema.json")
SCHEMA_V2: dict[str, Any] = json.loads(SCHEMA_V2_PATH.read_text())
# DR-207: v3 adds the optional `egress_containment` rule and makes
# `data_actions` optional. A version is v3 exactly when it has
# `egress_containment` (`contract_version`), so one rule set has one encoding.
SCHEMA_V3_PATH = SCHEMA_PATH.with_name("guardrail-version-v3.schema.json")
SCHEMA_V3: dict[str, Any] = json.loads(SCHEMA_V3_PATH.read_text())
_VALIDATORS = {
    1: _VALIDATOR,
    2: Draft202012Validator(SCHEMA_V2, format_checker=FormatChecker()),
    3: Draft202012Validator(SCHEMA_V3, format_checker=FormatChecker()),
}

GUARDRAIL_CONTRACT_VERSION = SCHEMA["properties"]["guardrail_contract_version"]["const"]
GUARDRAIL_CONTRACT_VERSION_V2 = SCHEMA_V2["properties"]["guardrail_contract_version"]["const"]
GUARDRAIL_CONTRACT_VERSION_V3 = SCHEMA_V3["properties"]["guardrail_contract_version"]["const"]
RULES = ("uploads", "saved_files", "service_ports", "out_of_spec_calls")
DATA_ACTIONS = "data_actions"
EGRESS = "egress_containment"
RULES_V2 = (*RULES, DATA_ACTIONS)
ASP_RULES = ("service_ports", "saved_files")
# Every rule judged on the newest ASP: v1's two, and DR-207's when a version has it.
ALL_ASP_RULES = (*ASP_RULES, EGRESS)
# The attribute `egress_containment` reads (RailMon rule pack 11), and the
# levels that are contained (egress-containment design §4.2).
EGRESS_ATTRIBUTE = "egress_containment"
EGRESS_PROXY_ATTRIBUTE = "egress_proxy_declared"
CONTAINED_LEVELS = ("allow_list_enforced", "no_network", "internal_network")
EGRESS_LEVELS = (*CONTAINED_LEVELS, "open", "host_network", "host_process")
REQUEST_RULES = ("uploads", "out_of_spec_calls")
# `request_rules_status` answers for every request rule a version can have.
ALL_REQUEST_RULES = (*REQUEST_RULES, DATA_ACTIONS)
# Real actions (data_actions.ACTIONS) and the three a row can be about
# without one: an unclassified tool, an unreadable call, and a tool its
# endpoint never offered (data-actions design §4.4).
DATA_ACTION_KINDS = ("read", "upload", "update", "delete", "execute")
DATA_ACTION_PSEUDO = ("unclassified", "unreadable", "not_offered")
# Tools the rule judges (design §2): MCP tools, local and provider-side.
JUDGED_TOOL_PREFIXES = ("mcp__", "mcp@", "provider-mcp__")


def contract_rules(contract: Mapping[str, Any] | None) -> tuple[str, ...]:
    """The rules a version has: v1's four, plus `data_actions` and
    `egress_containment` where it lists them."""
    present = (contract or {}).get("rules") or {}
    return (*RULES, *(rule for rule in (DATA_ACTIONS, EGRESS) if rule in present))


def contract_version(rules: Mapping[str, Any]) -> int:
    """The contract version a rule set is written at: v3 with
    `egress_containment`, else v2 with `data_actions`, else v1."""
    if EGRESS in rules:
        return GUARDRAIL_CONTRACT_VERSION_V3
    if DATA_ACTIONS in rules:
        return GUARDRAIL_CONTRACT_VERSION_V2
    return GUARDRAIL_CONTRACT_VERSION
LISTENERS_ATTRIBUTE = "observed_listeners"

HELD, VIOLATED, UNVERIFIED = "held", "violated", "unverified"
STATE_VIOLATED = "violated"
STATE_UNVERIFIED = "unverified"
STATE_HELD = "held"
STATE_NO_GUARDRAIL = "no_guardrail"
OBSERVED, REQUESTED = "observed", "requested"

# Unverified reasons. A BLIND/FAILED/TEMPLATED attribute's own status is the
# reason, so the panel can say which probe could not look.
MULTI_AGENT = "MULTI_AGENT"
STALE = "STALE"
PARTIAL_NO_VIOLATION = "PARTIAL"
NOT_COLLECTED = "NOT_COLLECTED"
MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
NO_HEARTBEAT = "NO_HEARTBEAT"
UNATTRIBUTED_TRAFFIC = "UNATTRIBUTED_TRAFFIC"
# A store hook failed since the version in force was made active, so some
# evidence was never judged (`raildash.guardrail_store`).
CHECK_FAILED = "CHECK_FAILED"
TOOL_CALLS_UNREADABLE = "TOOL_CALLS_UNREADABLE"
CAPTURE_REFUSED = "CAPTURE_REFUSED"
# Why one request's tool calls could not be read (`requested_tool_calls`).
UNREADABLE_CAPTURE = "UNREADABLE_CAPTURE"
RESPONSE_ENCODED = "RESPONSE_ENCODED"
RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
RESPONSE_UNSCANNABLE = "RESPONSE_UNSCANNABLE"
RESPONSE_UNPARSABLE_EVENT = "RESPONSE_UNPARSABLE_EVENT"
RESPONSE_TRUNCATED_EVENT = "RESPONSE_TRUNCATED_EVENT"
_SSE_LINE_END = re.compile(r"\r\n|\r|\n")
# How deep a stored row may nest before even its response is unreadable:
# far past the 128 levels a shown row allows, well inside what the stdlib
# decoder parses without hitting the interpreter's recursion limit.
MAX_STORED_ROW_DEPTH = 512
# How much streamed text one request's check scans. A model's streamed
# answer is far smaller; more than this is flagged, not read in part.
MAX_SCANNED_RESPONSE_BYTES = 4 * 1024 * 1024

UNKNOWN_HOST = "(unknown host)"
MCP_PREFIX = "mcp__"
# Kernel interfaces, not storage (§4.2): a write there is never a violation.
KERNEL_INTERFACE_ROOTS = ("/proc", "/sys", "/dev")
# Under /dev but storage (a tmpfs), so judged like any other path.
STORAGE_UNDER_KERNEL_ROOTS = ("/dev/shm",)
WILDCARD_ADDRESSES = frozenset({"0.0.0.0", "::"})

# §4.3 "Stale": three times the gap between the two newest ASPs, never under
# 5 minutes and never over 2 hours; with one ASP, 2 hours.
STALE_GAP_FACTOR = 3
STALE_MIN = timedelta(minutes=5)
STALE_MAX = timedelta(hours=2)
# §4.1/§4.3: `railmon collect` beats every 60 s while a tap is attached.
HEARTBEAT_WINDOW = timedelta(minutes=3)
UNATTRIBUTED_WINDOW = timedelta(minutes=10)
# Not in the design: how long one response whose tool calls couldn't be read
# keeps the request rules Unverified. The unattributed window's length, for
# the same reason: one unseen request may have held the violation.
TOOL_CALLS_UNREADABLE_WINDOW = UNATTRIBUTED_WINDOW
# A refused authenticated batch is the same kind of gap: requests we never saw.
CAPTURE_REFUSED_WINDOW = UNATTRIBUTED_WINDOW
# §4.4: hosts the agent sent a body to in this window before the lock seed
# `uploads.allowed_hosts`. The caller selects the requests; this names it.
PROPOSAL_LOOKBACK = timedelta(hours=24)
# Not in the design: §4.5 skips a capture stamped before the version was
# activated as old traffic. The collector stamps a request with
# CLOCK_MONOTONIC plus a boot time read once in whole seconds, so it can
# trail this process's wall clock by up to a second; a request made right
# after activation must not be skipped as old. A day-old replay still is.
CAPTURE_CLOCK_SLACK = timedelta(seconds=2)

UNATTRIBUTED_STATES = frozenset({"ambiguous", "unknown", "conflict"})
_MCP_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")


class GuardrailValidationError(ValueError):
    """The value is not one closed guardrail version v1."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid guardrail version: " + "; ".join(problems[:5]))


# --------------------------------------------------------------- contract


def guardrail_problems(version: Any) -> list[str]:
    """Validate the closed guardrail version v1 and the rules the schema
    cannot express: `created_at` is UTC (as `locked_at` is), every host is
    already in its normalized form so stored and compared values are one
    string, a port or byte cap is a real integer (not `80.0`), and the
    identity follows the alignment version's own rules
    (`raildash.asp.identity_problems`, which also sorts a key list)."""
    if not isinstance(version, dict):
        return ["guardrail version must be an object"]
    validator = _VALIDATORS.get(version.get("guardrail_contract_version"), _VALIDATOR)
    problems = [
        f"{'.'.join(str(part) for part in error.path) or 'guardrail'}: {error.message}"
        for error in sorted(validator.iter_errors(version), key=str)
    ]
    if problems:
        return problems
    created_at = _instant(version["created_at"])
    if created_at is None or created_at.utcoffset() != timedelta(0):
        problems.append("created_at: date-time must be UTC")
    problems.extend(identity_problems(version["agent_identity"]))
    rules = version["rules"]
    hosts = {
        "rules.uploads.allowed_hosts": rules["uploads"]["allowed_hosts"],
        "rules.uploads.max_request_bytes": list(rules["uploads"]["max_request_bytes"]),
        "rules.out_of_spec_calls.allowed_hosts": rules["out_of_spec_calls"]["allowed_hosts"],
        "rules.out_of_spec_calls.seeded_from_declared.hosts": (
            rules["out_of_spec_calls"]["seeded_from_declared"]["hosts"]
        ),
    }
    for where, values in hosts.items():
        for host in values:
            if not _is_host_pattern(host):
                problems.append(f"{where}: {host!r} is not a normalized host or *.host")
    # JSON Schema's `integer` accepts `80.0`; a port or a byte count here is
    # compared with RailMon's ints and `request_size`, so it must be one.
    for index, entry in enumerate(rules["service_ports"]["allowed"]):
        if entry["port"] != "ephemeral" and type(entry["port"]) is not int:
            problems.append(f"rules.service_ports.allowed.{index}.port: must be an integer")
    for host, cap in rules["uploads"]["max_request_bytes"].items():
        if type(cap) is not int:
            problems.append(f"rules.uploads.max_request_bytes.{host}: must be an integer")
    return problems


def validate_guardrail(version: Any) -> dict[str, Any]:
    """Return the version unchanged, or raise `GuardrailValidationError`."""
    problems = guardrail_problems(version)
    if problems:
        raise GuardrailValidationError(problems)
    return version


def _is_host_pattern(pattern: str) -> bool:
    name = pattern[2:] if pattern.startswith("*.") else pattern
    return bool(name) and "*" not in name and normalize_host(name) == name


# ------------------------------------------------------------------ hosts


def normalize_host(host: Any) -> str | None:
    """A host as §4.3 compares it: lower-cased, with any `:port`, IPv6
    brackets and trailing dot removed. `None` when nothing is left, which
    the request rules read as `(unknown host)`."""
    if not isinstance(host, str):
        return None
    text = host.strip().lower()
    if text.startswith("["):
        # `[::1]:8443` -> `::1`; a bracket never closed is not a host.
        end = text.find("]")
        text = text[1:end] if end > 0 else ""
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    # A bare IPv6 literal (two or more colons, no brackets) has no port to
    # strip: any trailing group is part of the address.
    text = text.rstrip(".")
    return text or None


def host_matches(host: str, pattern: str) -> bool:
    """One normalized host against one pattern. `*.example.com` matches any
    subdomain of `example.com` but not `example.com` itself."""
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def host_allowed(host: str | None, patterns: Iterable[str]) -> bool:
    """Whether a host (normalized here) is in a list; an unknown host never is."""
    host = normalize_host(host)
    return host is not None and any(host_matches(host, pattern) for pattern in patterns)


def _url_host(url: Any) -> str | None:
    """The host of a URL with or without a scheme, as RailMon reads a base
    URL (`url_host`): a bare `127.0.0.1:11434` is parsed, not compared whole."""
    if not isinstance(url, str) or not url.strip():
        return None
    text = url.strip()
    try:
        host = urlsplit(text if "://" in text else f"//{text}").hostname
    except ValueError:
        return None
    return normalize_host(host)


# ------------------------------------------------------------------ files


def glob_matches(pattern: str, path: str) -> bool:
    """§4.2's dialect: `*` within one segment, `**` across segments, and
    nothing else special (`?`, `[` and `{` are literal)."""
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return re.fullmatch("".join(parts), path, flags=re.DOTALL) is not None


def file_kind(path: str) -> str:
    """A path's kind, exactly the value `/api/profile`'s `file_types` uses."""
    return _store.Store._file_type(path)


def kernel_interface_path(path: str) -> bool:
    def under(root: str) -> bool:
        return path == root or path.startswith(root + "/")

    return any(map(under, KERNEL_INTERFACE_ROOTS)) and not any(map(under, STORAGE_UNDER_KERNEL_ROOTS))


def saved_file_allowed(path: str, entries: Iterable[Mapping[str, Any]]) -> bool:
    """Whether one written path is allowed: some entry's path matches it
    (exactly, for a `literal` entry) and, where that same entry lists
    `kinds`, the path's kind is one of them. A kind never permits a write
    outside its own entry's paths. Kernel interfaces are always allowed."""
    if kernel_interface_path(path):
        return True
    for entry in entries:
        pattern = entry["path"]
        matched = path == pattern if entry.get("literal") else glob_matches(pattern, path)
        if matched and ("kinds" not in entry or file_kind(path) in entry["kinds"]):
            return True
    return False


def saved_file_entry(path: str) -> dict[str, Any]:
    """The entry a proposal or **Allow this** makes for one written path:
    the path exactly, or, when its file name holds a uuid, that name with
    each run of uuids as `*` in the same directory (DR-229). An agent that
    writes `sessions.json.1.<uuid>.tmp` on every turn mints a new path each
    time, so an exact entry would be violated again on the next turn. A name
    with fewer than three letters or digits before its first uuid stays
    exact: `<dir>/*`, `<dir>/*.json` or `<dir>/.*` would allow any file,
    any file of a kind, or every hidden file in that directory."""
    template = uuid_name_template(path)
    prefix = template.rpartition("/")[2].partition("*")[0] if template is not None else ""
    if sum(character.isalnum() for character in prefix) < 3:
        return {"path": path, "literal": True}
    return {"path": template}


# ------------------------------------------------------------------ ports


def listener_allowed(listener: Mapping[str, Any], entries: Iterable[Mapping[str, Any]]) -> bool:
    """Whether one `observed_listeners` item matches an allowed entry.

    `"ephemeral"` matches only listensnoop's `ephemeral` and never a number.
    An entry without `addr` matches any address; `0.0.0.0` and `::` both
    mean every address and match each other.
    """
    protocol = listener.get("protocol")
    port = listener.get("port")
    addr = listener.get("addr")
    for entry in entries:
        if entry["protocol"] != protocol:
            continue
        if entry["port"] == "ephemeral":
            if port != "ephemeral":
                continue
        elif type(port) is not int or port != entry["port"]:
            continue
        wanted = entry.get("addr")
        if wanted is None or wanted == addr:
            return True
        if wanted in WILDCARD_ADDRESSES and addr in WILDCARD_ADDRESSES:
            return True
    return False


def listener_item(listener: Mapping[str, Any]) -> str:
    """The §4.5 row key of a listener: `protocol/addr/port`."""
    return f"{listener.get('protocol')}/{listener.get('addr')}/{listener.get('port')}"


def _readable_listener(listener: Any) -> bool:
    return (
        isinstance(listener, dict)
        and isinstance(listener.get("protocol"), str)
        and isinstance(listener.get("addr"), str)
        and (listener.get("port") == "ephemeral" or type(listener.get("port")) is int)
    )


# -------------------------------------------------------------------- MCP


def normalize_mcp_server(name: str) -> str:
    """A configured MCP server name as agents put it into tool names."""
    return _MCP_NAME_UNSAFE.sub("_", name)


def tool_call_server(tool_name: str) -> str | None:
    """The server of an `mcp__<server>__<tool>` call: the text between
    `mcp__` and the tool name's last `__`, so `mcp__github__x__y` names
    `github__x`, never `github`. `None` for a built-in tool (not judged) and
    for an `mcp__` name with no tool part (judged, and never allowed)."""
    if not tool_name.startswith(MCP_PREFIX):
        return None
    rest = tool_name[len(MCP_PREFIX):]
    end = rest.rfind("__")
    return rest[:end] if end > 0 else None


def mcp_item(tool_name: str) -> str:
    """The §4.5 row key of an `out_of_spec_calls` tool call: `mcp__<server>`,
    so every tool of one unlisted server shares a row. A name with no server
    part keys by itself."""
    server = tool_call_server(tool_name)
    return MCP_PREFIX + server if server is not None else tool_name


# --------------------------------------------------------------- requests


def _exchange(interaction: Mapping[str, Any]) -> dict[str, Any] | None:
    """The legacy exchange of a stored row's `raw` (a JSON string, as
    stored, or already parsed), or `None` when it can't be read."""
    raw = interaction.get("raw")
    if isinstance(raw, (str, bytes)):
        raw = _store.Store._safe_raw(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw)
    if not isinstance(raw, dict) or raw == _store.UNSAFE_LEGACY_CAPTURE:
        return None
    exchange = legacy_exchange(raw)
    return exchange if isinstance(exchange, dict) else None


def carries_body(interaction: Mapping[str, Any]) -> bool:
    """§4.3: the request's `body` in the stored `raw` event is present and
    not empty, or it has a `Content-Length` above zero. Unreadable is a body."""
    exchange = _exchange(interaction)
    if exchange is None:
        return True
    request = exchange.get("request")
    if not isinstance(request, dict):
        return False
    if request.get("body") not in (None, ""):
        return True
    length = _header(request.get("headers"), "content-length")
    try:
        return length is not None and int(length.strip()) > 0
    except ValueError:
        # A Content-Length that isn't a number still says a body was framed.
        return True


def _stored_raw(interaction: Mapping[str, Any]) -> dict[str, Any] | None:
    """A stored row's whole `raw` event, parsed without the 128-level depth
    bound `Store._safe_raw` applies to the row as one document.

    That bound is right for showing a row, but the request body inside it is
    the agent's own writing: an agent that nests it deeper than 128 levels
    would make the whole row unsafe and so hide the response's tool calls.
    Here the row keeps the size and token bounds and a looser depth that
    the stdlib decoder still handles; the response is then held to the
    ordinary bounds on its own (`_response_body`).
    """
    raw = interaction.get("raw")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    if isinstance(raw, str):
        if len(raw.encode("utf-8", "surrogatepass")) > MAX_SAFE_JSON_BYTES:
            return None
        try:
            JSONStructureGuard(max_depth=MAX_STORED_ROW_DEPTH).feed(raw)
            raw = json.loads(raw)
        except (JSONStructureTooComplex, ValueError, RecursionError):
            return None
    if not isinstance(raw, dict) or raw == _store.UNSAFE_LEGACY_CAPTURE:
        return None
    return raw


def _response_body(interaction: Mapping[str, Any]) -> tuple[Any, str | None]:
    """The response body, or `(None, reason)` when it can't be read safely."""
    raw = _stored_raw(interaction)
    if raw is None:
        return None, UNREADABLE_CAPTURE
    exchange = legacy_exchange(raw)
    response = exchange.get("response") if isinstance(exchange, dict) else None
    if not isinstance(response, dict):
        return None, None
    encoding = _header(response.get("headers"), "content-encoding")
    if encoding is not None and encoding.strip().lower() not in ("", "identity"):
        # Compressed bytes are not the text the agent's SDK reads.
        return None, RESPONSE_ENCODED
    body = response.get("body")
    try:
        check_json_structure(json.dumps(body))
    except (JSONStructureTooComplex, ValueError, RecursionError):
        return None, RESPONSE_UNSCANNABLE
    return body, None


def requested_tool_calls(interaction: Mapping[str, Any]) -> dict[str, Any]:
    """The tool calls the model asked for in this request's response.

    Returns `{"names": [...], "readable": bool, "reason": str | None}`,
    names in order and deduplicated. `readable: False` means the response
    could have asked for a call this can't see, so the checks drawn from
    tool calls are not verified for this request (`evaluate_request`).

    A JSON response body is read for an Anthropic `tool_use`/`tool_call`
    content block's `name`, an OpenAI chat `choices[].message.tool_calls[]
    .function.name`, and an OpenAI Responses `output[]` item of type
    `function_call`'s `name`. RailMon stores any other body as `{"raw":
    text}` (`parse_json_body`); that text is read as a server-sent event
    stream per the SSE rules: lines end only at CR LF, CR or LF (never at
    U+2028, U+2029 or U+0085, which JSON allows in a string), and an
    event's `data:` lines join with LF up to the blank line that ends it.
    Each event's data is one JSON value, and the names come
    from an Anthropic `content_block_start` whose `content_block` is a
    `tool_use`, an OpenAI chat chunk's `choices[].delta.tool_calls[]
    .function.name` (only the first chunk of each call carries it), and an
    OpenAI Responses `response.output_item.added`/`.done` whose `item` is a
    `function_call`. `[DONE]` is skipped. Any other event data that isn't
    JSON makes the response unreadable (`RESPONSE_UNPARSABLE_EVENT`); so
    does a last event with no blank line after it that doesn't parse
    (`RESPONSE_TRUNCATED_EVENT`), since the cut may have taken the call.
    Either way the names already found are kept, and a stream cut after an
    event's `event:` line, before its data, is unreadable the same way.
    Text with no `event:` or `data:` field at all (an HTML error page) is
    readable and asks for nothing.
    """
    body, reason = _response_body(interaction)
    if reason is not None:
        return {"names": [], "readable": False, "reason": reason}
    names: list[str] = []

    def add(name: Any) -> None:
        if isinstance(name, str) and name and name not in names:
            names.append(name)

    if not isinstance(body, dict):
        return {"names": [], "readable": True, "reason": None}
    text = body.get("raw") if set(body) == {"raw"} else None
    if not isinstance(text, str):
        _message_tool_calls(body, add)
        return {"names": names, "readable": True, "reason": None}
    if len(text.encode("utf-8", "surrogatepass")) > MAX_SCANNED_RESPONSE_BYTES:
        return {"names": [], "readable": False, "reason": RESPONSE_TOO_LARGE}
    # Only CR LF, CR and LF end an SSE line. `str.splitlines` also splits on
    # U+2028, U+2029 and U+0085, which JSON allows raw inside a string, and
    # so would cut one event in two and lose its call.
    lines = _SSE_LINE_END.split(text)
    # What follows the last line end is not a line; `""` there means the
    # text ended with one, not with a blank line.
    if lines[-1] == "":
        lines.pop()
    data: list[str] | None = None  # the current event's data lines
    in_event = False  # the current event has an `event` or `data` field
    saw_event = False
    unparsable = False
    for line in lines:
        if line == "":
            in_event = False
            if data is not None:
                outcome = _dispatch_event("\n".join(data), add)
                if outcome == RESPONSE_UNSCANNABLE:
                    return {"names": names, "readable": False, "reason": RESPONSE_UNSCANNABLE}
                unparsable = unparsable or outcome == RESPONSE_UNPARSABLE_EVENT
            data = None
            continue
        field, _, value = line.partition(":")
        if field in ("event", "data"):
            in_event = saw_event = True
        if field != "data":
            continue  # a comment (`:`), `event`, `id`, `retry`, or unknown
        if data is None:
            data = []
        # One space after the colon is the separator, not data.
        data.append(value[1:] if value.startswith(" ") else value)
    if not saw_event:
        # No `event:` or `data:` field at all: not an event stream (an HTML
        # error page).
        return {"names": [], "readable": True, "reason": None}
    if in_event and data is None:
        # Cut after an event's `event:` line and before its data, as
        # RailMon's own capture of a stream's first line is: the call may
        # have been in what was lost.
        return {"names": names, "readable": False, "reason": RESPONSE_TRUNCATED_EVENT}
    if data is not None:
        # The stream ended with no blank line after its last event: it was
        # cut. A complete JSON event still counts; one cut mid-way may have
        # held the call, so the names found are kept and it fails closed.
        outcome = _dispatch_event("\n".join(data), add)
        if outcome is not None:
            reason = (
                RESPONSE_UNSCANNABLE if outcome == RESPONSE_UNSCANNABLE else RESPONSE_TRUNCATED_EVENT
            )
            return {"names": names, "readable": False, "reason": reason}
    if unparsable:
        return {"names": names, "readable": False, "reason": RESPONSE_UNPARSABLE_EVENT}
    return {"names": names, "readable": True, "reason": None}


def _dispatch_event(data: str, add: Any) -> str | None:
    """Read one event's assembled data. Returns `None` when it was read or
    is the `[DONE]` sentinel, else why it couldn't be."""
    if data.strip() == "[DONE]":
        return None
    try:
        check_json_structure(data)
    except JSONStructureTooComplex:
        return RESPONSE_UNSCANNABLE
    try:
        event = json.loads(data)
    except (ValueError, RecursionError):
        return RESPONSE_UNPARSABLE_EVENT
    if isinstance(event, dict):
        _event_tool_calls(event, add)
    return None


def _message_tool_calls(body: dict[str, Any], add: Any) -> None:
    """Tool names in one non-streamed Anthropic, OpenAI chat or Responses body."""
    content = body.get("content")
    for block in content if isinstance(content, list) else []:
        if isinstance(block, dict) and block.get("type") in {"tool_use", "tool_call"}:
            add(block.get("name"))
    for choice in _dicts(body.get("choices")):
        message = choice.get("message")
        for call in _dicts(message.get("tool_calls") if isinstance(message, dict) else None):
            function = call.get("function")
            add(function.get("name") if isinstance(function, dict) else None)
    for item in _dicts(body.get("output")):
        if item.get("type") == "function_call":
            add(item.get("name"))


def _event_tool_calls(event: dict[str, Any], add: Any) -> None:
    """Tool names in one streamed event of any of the three shapes."""
    kind = event.get("type")
    if kind == "content_block_start":
        block = event.get("content_block")
        if isinstance(block, dict) and block.get("type") == "tool_use":
            add(block.get("name"))
    elif kind in ("response.output_item.added", "response.output_item.done"):
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") == "function_call":
            add(item.get("name"))
    for choice in _dicts(event.get("choices")):
        delta = choice.get("delta")
        for call in _dicts(delta.get("tool_calls") if isinstance(delta, dict) else None):
            function = call.get("function")
            add(function.get("name") if isinstance(function, dict) else None)


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _interaction_source(interaction: Mapping[str, Any]) -> dict[str, Any]:
    identifier = interaction.get("id", interaction.get("interaction_id"))
    return {"kind": "interaction", "id": identifier}


def _violation(
    rule: str, item: str, evidence_class: str, source: dict[str, Any], **detail: Any
) -> dict[str, Any]:
    return {
        "rule": rule,
        "item": item,
        "evidence_class": evidence_class,
        "source": source,
        "detail": detail,
    }


def _size_cap(host: str, caps: Mapping[str, int]) -> int | None:
    matching = [cap for pattern, cap in caps.items() if host_matches(host, pattern)]
    return min(matching) if matching else None


def evaluate_request(
    guardrail: Mapping[str, Any], interaction: Mapping[str, Any]
) -> dict[str, Any]:
    """`uploads` and `out_of_spec_calls` against one captured request.

    `interaction` is a stored `interactions` row as stored, with `raw` the
    stored JSON text (`raildash.ingest.normalise` output, or the row read
    straight from the table): `host`, `request_size` and `raw` are read. A
    `raw` already passed through `Store._safe_raw` may have been blanked by
    a deep request body, which then reads as unreadable tool calls. The
    caller has already decided, with `request_owner`, that it belongs to
    this guardrail.

    Returns `{"uploads": [...], "out_of_spec_calls": [...], "tool_calls":
    {"readable": bool, "reason": str | None}}`: each rule's violations, and
    whether the response's tool calls could be read. When they could not,
    `uploads`' `denied_tool_calls` check and `out_of_spec_calls`' MCP check
    were not made on this request, so the caller passes its time to
    `request_rules_status` as `last_tool_calls_unreadable_at`, which keeps
    both rules Unverified for a while; the host checks still ran. Whether
    the rules are verified at all is `request_rules_status`'s answer, since
    one request never makes a rule Held. One request yields at most one
    violation per (rule, item); its `detail.reasons` lists why.
    """
    rules = guardrail["rules"]
    uploads, out_of_spec = rules["uploads"], rules["out_of_spec_calls"]
    source = _interaction_source(interaction)
    host = normalize_host(interaction.get("host"))
    item = host if host is not None else UNKNOWN_HOST
    size = interaction.get("request_size")
    size = size if type(size) is int else None

    upload_reasons: list[str] = []
    body = carries_body(interaction)
    if body:
        if not host_allowed(host, uploads["allowed_hosts"]):
            upload_reasons.append("body_to_unlisted_host")
    cap = _size_cap(host, uploads["max_request_bytes"]) if host is not None else None
    if cap is not None:
        if size is None:
            if body:
                upload_reasons.append("request_size_unknown")
        elif size > cap:
            upload_reasons.append("request_size_over_cap")
    found_uploads: list[dict[str, Any]] = []
    if upload_reasons:
        found_uploads.append(
            _violation(
                "uploads", item, OBSERVED, source,
                kind="host", reasons=upload_reasons, request_size=size, max_request_bytes=cap,
                carries_body=body,
            )
        )
    calls = requested_tool_calls(interaction)
    tools = calls["names"]
    denied = set(uploads["denied_tool_calls"])
    found_uploads.extend(
        _violation("uploads", name, REQUESTED, source, kind="tool_call", tool=name)
        for name in tools
        if name in denied
    )

    found_out_of_spec: list[dict[str, Any]] = []
    if not host_allowed(host, out_of_spec["allowed_hosts"]):
        found_out_of_spec.append(
            _violation("out_of_spec_calls", item, OBSERVED, source, kind="host")
        )
    allowed_servers = set(out_of_spec["allowed_mcp_servers"])
    seen_items: set[str] = set()
    for name in tools:
        if not name.startswith(MCP_PREFIX):
            continue  # Built-in tools aren't judged (§4.3).
        server = tool_call_server(name)
        key = mcp_item(name)
        if (server is not None and server in allowed_servers) or key in seen_items:
            continue
        seen_items.add(key)
        found_out_of_spec.append(
            _violation(
                "out_of_spec_calls", key, REQUESTED, source,
                kind="mcp_server", server=server, tool=name,
            )
        )
    return {
        "uploads": found_uploads,
        "out_of_spec_calls": found_out_of_spec,
        "tool_calls": {"readable": calls["readable"], "reason": calls["reason"]},
    }


def request_owner(
    interaction: Mapping[str, Any],
    active: Iterable[Mapping[str, Any]],
    *,
    authenticated: bool,
) -> dict[str, Any]:
    """Which active guardrail one captured request is checked against (§4.3).

    `active` lists every active guardrail as `{"identity": <agent_identity>,
    "sandboxes": [(host_id, sandbox_name), ...]}`, the sandboxes being the
    ones that agent's ASPs came from. Returns `{"decision": ...}`:

    - `"ignored"`: an unauthenticated capture, which never affects a
      guardrail (§4.1), not even as unattributed traffic;
    - `"guardrail"`, with `identity`: check it against that guardrail;
    - `"unattributed"`: it can't be given to one agent, so the request rules
      of every agent are Unverified for a while (`request_rules_status`);
    - `"no_guardrail"`: an attributed request of an agent with none active.
    """
    if not authenticated:
        return {"decision": "ignored"}
    candidates = list(active)
    state = interaction.get("attribution_state")
    if state == "attributed":
        key = interaction.get("agent_key")
        sandbox = (interaction.get("agent_host_id"), interaction.get("sandbox_name"))
        matches = [
            candidate
            for candidate in candidates
            if _identity_names_key(candidate["identity"], key)
            or sandbox in {tuple(pair) for pair in candidate.get("sandboxes", ())}
        ]
        if len(matches) == 1:
            return {"decision": "guardrail", "identity": matches[0]["identity"]}
        # Two guardrails claiming one request is a conflict, not a choice.
        return {"decision": "unattributed" if matches else "no_guardrail"}
    if state is None or state in UNATTRIBUTED_STATES:
        # Every single-agent capture today has no attribution at all; it is
        # only that agent's when there is exactly one agent to give it to.
        if len(candidates) == 1:
            return {"decision": "guardrail", "identity": candidates[0]["identity"]}
        return {"decision": "unattributed" if candidates else "no_guardrail"}
    return {"decision": "unattributed" if candidates else "no_guardrail"}


def _identity_names_key(identity: Mapping[str, Any], key: Any) -> bool:
    if not isinstance(key, str) or not key:
        return False
    if identity.get("kind") == "local_agent_key":
        return identity.get("value") == key
    if identity.get("kind") == "local_agent_keys":
        return key in (identity.get("value") or [])
    return False


def request_rules_status(
    *,
    now: datetime | str,
    last_heartbeat_at: datetime | str | None,
    last_unattributed_at: datetime | str | None,
    last_tool_calls_unreadable_at: datetime | str | None,
    last_capture_refused_at: datetime | str | None = None,
) -> dict[str, dict[str, Any]]:
    """Whether `uploads` and `out_of_spec_calls` can be verified now.

    Unverified without an authenticated collector heartbeat in the last 3
    minutes (an idle agent and a dead collector look the same otherwise);
    for 10 minutes after the last authenticated request RailDash could not
    give to one agent; and for 10 minutes after the last request of this
    agent whose response's tool calls could not be read (`evaluate_request`'s
    `tool_calls.readable`), since a denied or unlisted call may be in it;
    and for 10 minutes after RailDash refused an authenticated capture batch
    (`Store.latest_capture_refusal_at`), since none of its requests was
    stored or checked. Otherwise `held`: the state of the request rules is
    their rows, which the roll-up reads separately. Times are RailDash's
    own receive times.
    """
    current = _required_instant(now, "now")
    heartbeat = _instant(last_heartbeat_at)
    unattributed = _instant(last_unattributed_at)
    unreadable = _instant(last_tool_calls_unreadable_at)
    refused = _instant(last_capture_refused_at)
    if heartbeat is None or abs(current - heartbeat) > HEARTBEAT_WINDOW:
        reason: str | None = NO_HEARTBEAT
    elif unattributed is not None and current - unattributed < UNATTRIBUTED_WINDOW:
        reason = UNATTRIBUTED_TRAFFIC
    elif unreadable is not None and current - unreadable < TOOL_CALLS_UNREADABLE_WINDOW:
        reason = TOOL_CALLS_UNREADABLE
    elif refused is not None and current - refused < CAPTURE_REFUSED_WINDOW:
        reason = CAPTURE_REFUSED
    else:
        reason = None
    return {
        rule: {"state": UNVERIFIED if reason else HELD, "reason": reason, "violations": []}
        for rule in ALL_REQUEST_RULES
    }


# -------------------------------------------------------------------- ASP


def is_multi_agent(bundle: Mapping[str, Any]) -> bool:
    """A v2 collection of two or more agents: no rule can say whose a
    sandbox-scoped listener or write was (§2 non-goals)."""
    return bundle.get("bundle_version") == BUNDLE_VERSION_V2 and len(bundle.get("agents") or []) >= 2


def _attributes(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """One single-agent view of an ASP's attributes: v1's own, or a v2
    bundle's sandbox scope (listeners, files) over its one agent's."""
    if bundle.get("bundle_version") != BUNDLE_VERSION_V2:
        return dict(bundle.get("attributes") or {})
    agents = bundle.get("agents") or []
    merged = dict(agents[0].get("attributes") or {}) if len(agents) == 1 else {}
    merged.update((bundle.get("sandbox") or {}).get("attributes") or {})
    return merged


def asp_is_stale(
    newest_collected_at: datetime | str,
    previous_collected_at: datetime | str | None,
    now: datetime | str,
) -> bool:
    """§4.3: older than three times the gap between the two newest ASPs,
    bounded to [5 min, 2 h]; with only one ASP, 2 h. The two times may be
    the last two deliveries of the newest ASP instead of collection times
    (`evaluate_asp`'s `newest_received_at`); the rule is the same."""
    newest = _required_instant(newest_collected_at, "newest_collected_at")
    current = _required_instant(now, "now")
    previous = _instant(previous_collected_at)
    if previous is None:
        bound = STALE_MAX
    else:
        bound = min(max(abs(newest - previous) * STALE_GAP_FACTOR, STALE_MIN), STALE_MAX)
    return abs(current - newest) > bound


def evaluate_asp(
    guardrail: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    asp_id: str,
    previous_collected_at: datetime | str | None,
    now: datetime | str,
    newest_received_at: datetime | str | None = None,
) -> dict[str, Any]:
    """`service_ports`, `saved_files` and, where the version has it,
    `egress_containment` (DR-207) against the newest parsed ASP.

    Staleness is judged on `newest_received_at` when the caller knows it,
    else on the bundle's own `collected_at`; `previous_collected_at` is then
    the delivery before it. RailMon re-sends an unchanged agent's previous
    bundle, `collected_at` and all (DR-157), so a fresh delivery of old
    bytes is fresh evidence that nothing changed.

    `bundle` is what `raildash.asp.parse_bundle` returns for the stored
    bytes; the caller has matched its identity to the guardrail's.
    Returns `{"multi_agent": bool, "stale": bool, "rules": {...}}`. A
    multi-agent bundle evaluates nothing and makes every rule the version
    has Unverified; `rule_states` carries that over the request rules.

    Per rule, from the attribute's status: `ANSWERED` and `ABSENT` are
    verified; `PARTIAL` is violated when a listed item breaks the rule (a
    capped list keeps what it lists) and Unverified otherwise, except that
    `saved_files` on a file list capped only by reads is verified
    (`raildash.asp.only_reads_left_out`); `BLIND`,
    `FAILED`, `TEMPLATED` and a missing attribute are Unverified. A stale
    or `PARTIAL` ASP, or one with an unreadable listener, is not verified:
    its violations stay real (`state: violated`) and `reason` says why the
    rule still is not verified.
    """
    if is_multi_agent(bundle):
        return {
            "multi_agent": True,
            "stale": False,
            "rules": {
                rule: {"state": UNVERIFIED, "reason": MULTI_AGENT, "violations": []}
                for rule in contract_rules(guardrail)
            },
        }
    stale = asp_is_stale(newest_received_at or bundle["collected_at"], previous_collected_at, now)
    attributes = _attributes(bundle)
    source = {"kind": "asp", "id": asp_id}
    rules = guardrail["rules"]
    results = {
        "service_ports": _attribute_rule(
            attributes.get(LISTENERS_ATTRIBUTE),
            lambda items: _listener_violations(items, rules["service_ports"]["allowed"], source),
            stale,
        ),
        # The rule reads writes only, and a list capped only by reads still
        # lists every write (DR-230), so that PARTIAL is complete for it.
        "saved_files": _attribute_rule(
            attributes.get(FILE_ACCESS_ATTRIBUTE),
            lambda items: _file_violations(items, rules["saved_files"]["allowed"], source),
            stale,
            complete=only_reads_left_out(attributes.get(FILE_ACCESS_ATTRIBUTE)),
        ),
    }
    if EGRESS in rules:
        results[EGRESS] = _egress_rule(attributes.get(EGRESS_ATTRIBUTE), rules[EGRESS], stale, source)
    return {"multi_agent": False, "stale": stale, "rules": results}


def egress_meets(level: Any, require: str) -> bool:
    """Whether a containment level meets a rule's `require`."""
    if require == "allow_list_enforced":
        return level == "allow_list_enforced"
    return level in CONTAINED_LEVELS


def egress_reading(attribute: Any) -> dict[str, Any] | None:
    """The newest ASP's containment as the panel shows it, or None when the
    attribute isn't there (an ASP from before RailMon's rule pack 11).
    A level is read only from an `ANSWERED` or `PARTIAL` value of the
    published shape; anything else is shown as unknown with its status."""
    if not isinstance(attribute, dict):
        return None
    status = attribute.get("status")
    value = attribute.get("value")
    reading: dict[str, Any] = {"status": status, "level": None, "contained": None}
    if status in ("ANSWERED", "PARTIAL") and isinstance(value, dict) and value.get("level") in EGRESS_LEVELS:
        # The bundle schemas close this value (v1's own, v2's held to it in
        # `raildash.asp`), but a reading is never where a bad one crashes.
        observations = value.get("observations") if isinstance(value.get("observations"), dict) else {}
        networks = [n for n in _list(observations.get("networks")) if isinstance(n, dict)]
        reading.update(
            level=value["level"],
            contained=value["level"] in CONTAINED_LEVELS and status == "ANSWERED",
            enforcer=value.get("enforcer") if isinstance(value.get("enforcer"), str) else None,
            via=value.get("via") if isinstance(value.get("via"), str) else None,
            gateway_peers=sorted({str(p) for n in networks for p in _list(n.get("gateway_peers"))}),
            reasons=[str(r) for r in _list(value.get("reasons"))],
        )
    return reading


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _egress_rule(
    attribute: Any, rule: Mapping[str, Any], stale: bool, source: dict[str, Any]
) -> dict[str, Any]:
    """`egress_containment` on the newest ASP (egress-containment design
    §4.4). `ANSWERED` is verified; `PARTIAL` is missing evidence (a network
    RailMon couldn't inspect decided it), not an observed break, so it is
    Unverified with no row, as DR-184 G3 holds for every rule; `BLIND`,
    `FAILED` and a missing attribute are Unverified. A violation on a stale
    ASP stays real and says so, like the other ASP rules."""
    if not isinstance(attribute, dict):
        return {"state": UNVERIFIED, "reason": NOT_COLLECTED, "violations": []}
    status = attribute.get("status")
    if status == "PARTIAL":
        return {"state": UNVERIFIED, "reason": PARTIAL_NO_VIOLATION, "violations": []}
    if status != "ANSWERED":
        return {"state": UNVERIFIED, "reason": status or NOT_COLLECTED, "violations": []}
    value = attribute.get("value")
    level = value.get("level") if isinstance(value, dict) else None
    if level not in EGRESS_LEVELS:
        return {"state": UNVERIFIED, "reason": MALFORMED_EVIDENCE, "violations": []}
    reason = STALE if stale else None
    if egress_meets(level, rule["require"]):
        return {"state": UNVERIFIED if reason else HELD, "reason": reason, "violations": []}
    violation = _violation(
        EGRESS, level, OBSERVED, source,
        level=level, require=rule["require"],
        reasons=[str(r) for r in _list(value.get("reasons"))][:16],
    )
    return {"state": VIOLATED, "reason": reason, "violations": [violation]}


def _attribute_rule(attribute: Any, check: Any, stale: bool, *, complete: bool = False) -> dict[str, Any]:
    """One ASP rule on its attribute. `complete` says a `PARTIAL` value is
    missing nothing the rule reads, so it is judged like `ANSWERED`."""
    if not isinstance(attribute, dict):
        return {"state": UNVERIFIED, "reason": NOT_COLLECTED, "violations": []}
    status = attribute.get("status")
    if status == "ABSENT":
        violations, malformed = [], False
    elif status in ("ANSWERED", "PARTIAL"):
        value = attribute.get("value")
        if not isinstance(value, list):
            return {"state": UNVERIFIED, "reason": MALFORMED_EVIDENCE, "violations": []}
        violations, malformed = check(value)
    else:
        return {"state": UNVERIFIED, "reason": status or NOT_COLLECTED, "violations": []}
    if malformed:
        reason: str | None = MALFORMED_EVIDENCE
    elif status == "PARTIAL" and not complete:
        # A restarted or capped probe may have missed exactly the one item
        # that breaks the rule: the failure that looks like success (§5).
        reason = PARTIAL_NO_VIOLATION
    elif stale:
        reason = STALE
    else:
        reason = None
    # Violations stay real whatever the evidence's state; the reason says
    # the rule still wasn't verified on it, so acknowledging them can't
    # turn the agent Held (`agent_state`).
    if violations:
        return {"state": VIOLATED, "reason": reason, "violations": violations}
    return {"state": UNVERIFIED if reason else HELD, "reason": reason, "violations": []}


def _listener_violations(
    items: list[Any], allowed: list[Mapping[str, Any]], source: dict[str, Any]
) -> tuple[list[dict[str, Any]], bool]:
    violations: dict[str, dict[str, Any]] = {}
    malformed = False
    for listener in items:
        if not _readable_listener(listener):
            malformed = True
            continue
        if listener_allowed(listener, allowed):
            continue
        item = listener_item(listener)
        violations.setdefault(
            item,
            _violation(
                "service_ports", item, OBSERVED, source,
                protocol=listener["protocol"], addr=listener["addr"], port=listener["port"],
                process=listener.get("process"),
            ),
        )
    return list(violations.values()), malformed


def _file_violations(
    items: list[Any], allowed: list[Mapping[str, Any]], source: dict[str, Any]
) -> tuple[list[dict[str, Any]], bool]:
    # The schema closes each item's shape, so every item here is readable.
    violations: dict[str, dict[str, Any]] = {}
    for entry in items:
        path = entry["path"]
        if not entry["write"] or saved_file_allowed(path, allowed):
            continue
        # A (path, layer) pair is two bundle entries but one §4.5 row.
        violations.setdefault(
            path,
            _violation(
                "saved_files", path, OBSERVED, source, kind=file_kind(path), layer=entry["layer"]
            ),
        )
    return list(violations.values()), False


# ----------------------------------------------------------------- roll-up


def rule_states(
    asp_result: Mapping[str, Any] | None, request_status: Mapping[str, Mapping[str, Any]],
    rules: Iterable[str] = RULES,
) -> dict[str, dict[str, Any]]:
    """Every rule's latest results: the ASP rules from `evaluate_asp`
    (Unverified `NOT_COLLECTED` when no ASP has been evaluated) and the
    request rules from `request_rules_status`, except that a multi-agent ASP
    makes every rule Unverified (multi-agent)."""
    rules = tuple(rules)
    if asp_result is not None and asp_result.get("multi_agent"):
        multi = next(iter(asp_result["rules"].values()))
        return {rule: dict(asp_result["rules"].get(rule, multi)) for rule in rules}
    states: dict[str, dict[str, Any]] = {}
    for rule in (r for r in rules if r in ALL_ASP_RULES):
        result = (asp_result or {}).get("rules", {}).get(rule)
        states[rule] = (
            dict(result)
            if result
            else {"state": UNVERIFIED, "reason": NOT_COLLECTED, "violations": []}
        )
    for rule in rules:
        if rule not in ALL_ASP_RULES:
            states[rule] = dict(request_status[rule])
    return states


def agent_state(
    *,
    has_active_guardrail: bool,
    rule_results: Mapping[str, Mapping[str, Any]],
    counting_rows: int,
    rules: Iterable[str] = RULES,
) -> str:
    """§4.5's per-agent state, highest first: `violated` (a counting row),
    `unverified` (no counting row, but some rule Unverified on its latest
    evidence), `held` (every rule verified, no counting row), and
    `no_guardrail`. A rule is verified only when its state is `held` or
    `violated` and it has no `reason`; one missing from `rule_results` is
    not. So a rule whose latest evidence was violated but whose rows no
    longer count (acknowledged or allowed) was verified, while one violated
    on stale or `PARTIAL` evidence was not, and its agent is Unverified."""
    if not has_active_guardrail:
        return STATE_NO_GUARDRAIL
    if counting_rows > 0:
        return STATE_VIOLATED
    for rule in rules:
        result = rule_results.get(rule)
        if not result or result.get("state") not in (HELD, VIOLATED) or result.get("reason"):
            return STATE_UNVERIFIED
    return STATE_HELD


def shown_rule_states(
    rule_results: Mapping[str, Mapping[str, Any]],
    counting_rules: Iterable[str],
    *,
    overflow_rule: str | None = None,
    rules: Iterable[str] = RULES,
) -> dict[str, dict[str, Any]]:
    """Each rule's state as it is shown beside its rows, read the way
    `agent_state` reads the same results and rows, so the two never
    disagree: `violated` while the rule has a counting row; otherwise
    `held` when its latest evidence was verified (`held` or `violated` with
    no reason) and `unverified` when it wasn't. A `reason` is kept wherever
    the result had one, so a counting row on unverified evidence reads
    "violated — stale".

    The latest results alone can't be shown: the request rules' result is
    only their liveness (`request_rules_status`), so their violations are
    in their rows and nowhere else, and an ASP rule's result stays
    `violated` after its rows are acknowledged or allowed.

    The overflow row (`overflow_rule`) names no rule, and an item past the
    row cap is recorded only there. So while it counts, a rule whose latest
    result is `violated` is shown violated too: its item may be one of the
    "N more"."""
    counting = set(counting_rules)
    overflowing = overflow_rule in counting
    shown: dict[str, dict[str, Any]] = {}
    for rule in rules:
        result = rule_results.get(rule) or {}
        reason = result.get("reason")
        if rule in counting or (overflowing and result.get("state") == VIOLATED):
            state = VIOLATED
        elif result.get("state") in (HELD, VIOLATED) and not reason:
            state = HELD
        else:
            state = UNVERIFIED
            reason = reason or NOT_COLLECTED
        shown[rule] = {"state": state, "reason": reason}
    return shown


def item_allowed(guardrail: Mapping[str, Any], violation: Mapping[str, Any]) -> bool:
    """Whether the version `guardrail` allows a stored violation's item,
    re-checked from its `rule`, `item` and `detail` (§4.5 "Rows and the
    version in force"). `(unknown host)` and a server-less MCP name are
    never allowed."""
    rules = guardrail["rules"]
    rule, item, detail = violation["rule"], violation["item"], violation.get("detail") or {}
    if rule == "service_ports":
        listener = {key: detail.get(key) for key in ("protocol", "addr", "port")}
        return listener_allowed(listener, rules["service_ports"]["allowed"])
    if rule == "saved_files":
        return saved_file_allowed(item, rules["saved_files"]["allowed"])
    if rule == "uploads":
        uploads = rules["uploads"]
        if detail.get("kind") == "tool_call":
            return item not in uploads["denied_tool_calls"]
        if item == UNKNOWN_HOST:
            return False
        # Re-derived from what the request was, not from the reasons the
        # version that flagged it gave: a later version can drop the host
        # from `allowed_hosts` or add a cap, and the row must count again.
        body = _row_carries_body(detail)
        if body and not host_allowed(item, uploads["allowed_hosts"]):
            return False
        cap = _size_cap(item, uploads["max_request_bytes"])
        size = detail.get("request_size")
        if cap is not None:
            if type(size) is int:
                return size <= cap
            return not body
        return True
    if rule == "out_of_spec_calls":
        out_of_spec = rules["out_of_spec_calls"]
        if detail.get("kind") == "mcp_server":
            server = detail.get("server")
            return server is not None and server in out_of_spec["allowed_mcp_servers"]
        return item != UNKNOWN_HOST and host_allowed(item, out_of_spec["allowed_hosts"])
    if rule == DATA_ACTIONS:
        if DATA_ACTIONS not in rules:
            # A v1 version has no such rule: switching back to one stops it.
            return True
        return data_action_row_allowed(rules[DATA_ACTIONS], detail)
    if rule == EGRESS:
        if EGRESS not in rules:
            # A version that doesn't require containment stops the row.
            return True
        return egress_meets(detail.get("level", item), rules[EGRESS]["require"])
    return False


def _row_carries_body(detail: Mapping[str, Any]) -> bool:
    """Whether a stored `uploads` host row's request carried a body. Rows
    record it as `carries_body`; without it (a row written before the flag),
    the reasons that only a body produces say so, and a size reason alone is
    read as a body, which can only keep the row counting."""
    flag = detail.get("carries_body")
    if isinstance(flag, bool):
        return flag
    reasons = detail.get("reasons") or []
    return bool(reasons)


def row_counts(guardrail: Mapping[str, Any] | None, row: Mapping[str, Any]) -> bool:
    """Whether one stored row counts toward Violated: unacknowledged, and
    the version in force disallows its item. An overflow row ("N more
    items") lists no item to re-check, so it counts until acknowledged."""
    if guardrail is None or row.get("acknowledged"):
        return False
    if row.get("overflow"):
        return True
    return not item_allowed(guardrail, row)


# ------------------------------------------------------------ data actions


def tool_glob_matches(pattern: str, tool: str) -> bool:
    """A `data_actions` tool pattern: `*` matches any run of characters,
    `/` included (tool names aren't paths; DR-184's path globs stop at it)."""
    regex = "".join(".*" if char == "*" else re.escape(char) for char in pattern)
    return re.fullmatch(regex, tool, flags=re.DOTALL) is not None


def data_action_allowed(rule: Mapping[str, Any], tool: str, action: str) -> bool:
    """Whether a `data_actions` rule allows one action of one tool."""
    if action == "unclassified" and rule.get("unclassified") == "allow":
        return True
    return any(
        action in entry["actions"] and tool_glob_matches(entry["tool"], tool)
        for entry in rule.get("allowed") or []
    )


def data_action_row_allowed(rule: Mapping[str, Any], detail: Mapping[str, Any]) -> bool:
    """A stored `data_actions` row, re-checked against a version: its action
    allowed, or (for a real action the schema gave, not an undeclared
    argument) no longer the tool's under the version's override."""
    tool, action = detail.get("tool"), detail.get("action")
    if not isinstance(tool, str) or not isinstance(action, str):
        return False
    if data_action_allowed(rule, tool, action):
        return True
    override = (rule.get("overrides") or {}).get(tool)
    # An upload the call's undeclared arguments made stays, whatever an
    # override says about the tool (§4.3).
    from_undeclared = detail.get("from_undeclared") or (action == "upload" and detail.get("undeclared"))
    if override is not None and action in DATA_ACTION_KINDS and not from_undeclared:
        return action not in override
    if override is not None and action == "unclassified":
        return bool(override)
    return False


def data_action_item(tool: str, action: str, endpoint: str | None) -> str:
    """A row's item, as the design names it (§4.4)."""
    if action == "unreadable":
        return f"{endpoint or '(unknown endpoint)'} · unreadable call"
    if action == "not_offered":
        return f"{tool} · not offered by {endpoint or '(unknown endpoint)'}"
    return f"{tool} · {action}"


def judged_tool(tool: str) -> bool:
    return tool.startswith(JUDGED_TOOL_PREFIXES)


def evaluate_data_actions(
    guardrail: Mapping[str, Any], calls: Iterable[Mapping[str, Any]], interaction: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """`data_actions` against one request's calls (design §4.4).

    Each call is `{tool, class, actions, unclassified, unreadable,
    undeclared, bytes, content_kinds, endpoint}` as the store worked it out
    (`DataActionsStore._calls_for_rule`): its actions from the tool's
    classification, `upload` added for an undeclared argument (`weak_read`
    and `reasons` are for the proposal; the rule doesn't read them). A version's
    override replaces the classified actions (not the undeclared upload).
    One request yields one violation per (tool, action).
    """
    rule = (guardrail.get("rules") or {}).get(DATA_ACTIONS)
    if rule is None:
        return []
    source = _interaction_source(interaction)
    found: dict[str, dict[str, Any]] = {}
    for call in calls:
        tool = call["tool"]
        if call.get("unreadable"):
            actions = [("unreadable", False)]
        elif not judged_tool(tool):
            continue
        else:
            override = (rule.get("overrides") or {}).get(tool)
            classified = list(override) if override is not None else list(call.get("classified") or [])
            actions = [(action, False) for action in classified]
            if call.get("undeclared") and "upload" not in classified:
                actions.append(("upload", True))
            if not classified and not call.get("undeclared"):
                actions = [("unclassified", False)] if rule.get("unclassified") != "allow" else []
            if call.get("not_offered"):
                actions.append(("not_offered", False))
        for action, from_undeclared in actions:
            if data_action_allowed(rule, tool, action):
                continue
            from_undeclared = from_undeclared or (action == "upload" and bool(call.get("undeclared")))
            item = data_action_item(tool, action, call.get("endpoint"))
            if item in found:
                # Observed evidence outranks the model asking (§4.3).
                if call.get("class") == OBSERVED:
                    found[item]["evidence_class"] = OBSERVED
                continue
            found[item] = _violation(
                DATA_ACTIONS, item, call.get("class") or OBSERVED, source,
                kind="data_action", tool=tool, action=action, from_undeclared=from_undeclared,
                undeclared=list(call.get("undeclared") or []),
                bytes=call.get("bytes"), content_kinds=list(call.get("content_kinds") or []),
                endpoint=call.get("endpoint"),
            )
    return list(found.values())


# ---------------------------------------------------------------- proposal


# The one glob a proposal seeds (DR-201): Python's bytecode caches. Every
# Python process writes `__pycache__/<module>.<tag>.pyc` for each module it
# imports that has none yet, so seeding only the baseline's literal paths
# made any new Python run (`python3 -m http.server`, a one-line `python3 -c`)
# a saved_files row per directory, and each rename's random temp name a
# new one (RailMon folds those to `<dir>/__pycache__/*.pyc`). The file is
# the interpreter's cache of code it imported, not data the agent saved.
# It is a shown line of the proposal like any other, so a user who wants
# those writes judged removes it before adopting. The price: an agent that
# hides data in a file named like a bytecode cache, in a __pycache__
# directory, isn't flagged under it.
BYTECODE_CACHE_ENTRY: dict[str, Any] = {"path": "**/__pycache__/*.pyc"}


def propose_guardrail(
    alignment: Mapping[str, Any],
    bundle: Mapping[str, Any],
    requests_before_lock: Iterable[Mapping[str, Any]],
    *,
    guardrail_version_id: str,
    version: str,
    created_at: str,
) -> dict[str, Any]:
    """The §4.4 first guardrail from a locked baseline.

    `alignment` is the alignment version and `bundle` its parsed ASP.
    `requests_before_lock` are the agent's authenticated captured requests
    from the 24 h before the lock (`PROPOSAL_LOOKBACK`), as stored rows.

    Returns `{"guardrail": <version> | None, "would_be_violations": [...],
    "empty_because": {...}, "reason": str | None}`. Seeding approves what
    the agent already did, so everything that would be a violation under
    the proposal (the baseline's listeners, undeclared hosts and MCP servers
    it called) is listed for the user to allow with one click, and a
    declared list left empty says why. `saved_files` is the baseline's
    written paths, each exact, after `BYTECODE_CACHE_ENTRY`, the one fixed
    glob; a path whose file name holds a uuid is seeded as that name's glob
    (`saved_file_entry`), and a written path an earlier entry already allows
    isn't listed again. A
    multi-agent baseline gets no proposal (`reason: MULTI_AGENT`).
    """
    if is_multi_agent(bundle):
        return {"guardrail": None, "would_be_violations": [], "empty_because": {}, "reason": MULTI_AGENT}
    attributes = _attributes(bundle)
    requests = list(requests_before_lock)
    source = {"kind": "asp", "id": alignment["asp"]["asp_id"]}
    would_be: list[dict[str, Any]] = []
    empty_because: dict[str, dict[str, Any]] = {}

    upload_hosts: set[str] = set()
    endpoint = attributes.get("inference_endpoint") or {}
    if endpoint.get("status") == "ANSWERED":
        host = _url_host(endpoint.get("value"))
        if host is not None and _is_host_pattern(host):
            upload_hosts.add(host)
    for request in requests:
        host = normalize_host(request.get("host"))
        if carries_body(request) and host is not None and _is_host_pattern(host):
            upload_hosts.add(host)

    files = attributes.get(FILE_ACCESS_ATTRIBUTE) or {}
    saved: list[dict[str, Any]] = [dict(BYTECODE_CACHE_ENTRY)]
    if files.get("status") in ("ANSWERED", "PARTIAL") and isinstance(files.get("value"), list):
        for path in sorted({entry["path"] for entry in files["value"] if entry["write"]}):
            if not kernel_interface_path(path) and not saved_file_allowed(path, saved):
                saved.append(saved_file_entry(path))
    elif files.get("status") != "ABSENT":
        empty_because["saved_files.allowed"] = _why_empty(files)

    listeners = attributes.get(LISTENERS_ATTRIBUTE) or {}
    if listeners.get("status") in ("ANSWERED", "PARTIAL") and isinstance(listeners.get("value"), list):
        listed, _ = _listener_violations(listeners["value"], [], source)
        would_be.extend(listed)

    declared_hosts, declared_servers = _declared_lists(attributes)
    if declared_hosts is None:
        declared_hosts = []
        empty_because["out_of_spec_calls.allowed_hosts"] = _why_empty(
            attributes.get("declared_destinations") or {}
        )
    if declared_servers is None:
        declared_servers = []
        empty_because["out_of_spec_calls.allowed_mcp_servers"] = _why_empty(
            attributes.get("mcp_servers_declared") or {}
        )

    guardrail = {
        "guardrail_contract_version": GUARDRAIL_CONTRACT_VERSION,
        "guardrail_version_id": guardrail_version_id,
        "version": version,
        "created_at": created_at,
        "agent_identity": alignment["agent_identity"],
        "derived_from": {"alignment_version_id": alignment["alignment_version_id"]},
        "rules": {
            "uploads": {
                "allowed_hosts": sorted(upload_hosts),
                "max_request_bytes": {},
                "denied_tool_calls": [],
            },
            "saved_files": {"allowed": saved},
            "service_ports": {"allowed": []},
            "out_of_spec_calls": {
                "allowed_hosts": declared_hosts,
                "allowed_mcp_servers": declared_servers,
                "seeded_from_declared": {"hosts": declared_hosts, "mcp_servers": declared_servers},
            },
        },
    }
    # DR-207 §4.4: containment is required only when the baseline was
    # contained, so adopting never starts Violated, and an agent that was
    # contained gets a regression alarm.
    egress = egress_reading(attributes.get(EGRESS_ATTRIBUTE))
    if egress is not None and egress["contained"]:
        guardrail["rules"][EGRESS] = {"require": "contained"}
        guardrail["guardrail_contract_version"] = contract_version(guardrail["rules"])
    # What the agent called before the lock that nothing declared: not
    # seeded, since surfacing it is what the rule is for.
    seen: set[str] = set()
    for request in requests:
        for found in evaluate_request(guardrail, request)["out_of_spec_calls"]:
            if found["item"] not in seen:
                seen.add(found["item"])
                would_be.append(found)
        if not carries_body(request):
            continue
        host = normalize_host(request.get("host"))
        if host is None or not _is_host_pattern(host):
            item = UNKNOWN_HOST if host is None else host
            if ("uploads", item) not in {(v["rule"], v["item"]) for v in would_be}:
                would_be.append(
                    _violation(
                        "uploads", item, OBSERVED, _interaction_source(request),
                        kind="host", reasons=["body_to_unlisted_host"],
                        request_size=request.get("request_size"), max_request_bytes=None,
                    )
                )
    return {
        "guardrail": validate_guardrail(guardrail),
        "would_be_violations": would_be,
        "empty_because": empty_because,
        "reason": None,
        "egress": egress,
    }


def _declared_lists(attributes: Mapping[str, Any]) -> tuple[list[str] | None, list[str] | None]:
    """The declared hosts and normalized MCP server names of one ASP's
    attributes, each sorted, or None where the attribute isn't `ANSWERED`
    (so it declares nothing that can be read). The proposal seeds from these
    and the custody offers what they add later, so both read them alike."""
    declared = attributes.get("declared_destinations") or {}
    hosts: list[str] | None = None
    if declared.get("status") == "ANSWERED" and isinstance(declared.get("value"), list):
        hosts = sorted(
            {
                host
                for host in (normalize_host(value) for value in declared["value"])
                if host is not None and _is_host_pattern(host)
            }
        )
    servers_attribute = attributes.get("mcp_servers_declared") or {}
    servers: list[str] | None = None
    if servers_attribute.get("status") == "ANSWERED" and isinstance(
        servers_attribute.get("value"), list
    ):
        names = (
            entry.get("name") if isinstance(entry, dict) else entry
            for entry in servers_attribute["value"]
        )
        # Two configured names that normalize alike are one item (§4.2).
        servers = sorted(
            {normalize_mcp_server(name) for name in names if isinstance(name, str) and name}
        )
    return hosts, servers


def _why_empty(attribute: Mapping[str, Any]) -> dict[str, Any]:
    """Why a declared or observed list seeded nothing: the attribute's own
    status and reason (`BLIND`/`GATEWAY_MANAGED` when only a gateway URL is
    configured, so its servers are allowed one by one as they're called)."""
    if not attribute:
        return {"status": None, "reason": NOT_COLLECTED, "note": None}
    return {
        "status": attribute.get("status"),
        "reason": attribute.get("reason"),
        "note": attribute.get("note"),
    }


# ----------------------------------------------------------------- custody


OFFER_KINDS = ("host", "mcp_server")


def declared_offers(
    guardrail: Mapping[str, Any],
    bundle: Mapping[str, Any],
    seeded_over_all_versions: Mapping[str, Iterable[str]],
) -> list[dict[str, str]]:
    """§4.5's *declared since gN* offers: each host and MCP server the
    newest ASP declares that the version in force doesn't allow and that no
    version of this agent ever recorded in `seeded_from_declared`.

    `seeded_over_all_versions` is `{"hosts": [...], "mcp_servers": [...]}`,
    the union over every version, so a declared host the user removed to
    keep it out isn't offered again, not even after a switch. A multi-agent
    ASP offers nothing, as it is evaluated for nothing. An offer is not a
    row and doesn't change the state: `[{"kind": "host" | "mcp_server",
    "value": ...}]`, hosts first, each sorted."""
    if is_multi_agent(bundle):
        return []
    hosts, servers = _declared_lists(_attributes(bundle))
    out_of_spec = guardrail["rules"]["out_of_spec_calls"]
    seen_hosts = set(seeded_over_all_versions.get("hosts") or ())
    seen_servers = set(seeded_over_all_versions.get("mcp_servers") or ())
    offers = [
        {"kind": "host", "value": host}
        for host in hosts or ()
        if host not in seen_hosts and not host_allowed(host, out_of_spec["allowed_hosts"])
    ]
    offers.extend(
        {"kind": "mcp_server", "value": server}
        for server in servers or ()
        if server not in seen_servers and server not in out_of_spec["allowed_mcp_servers"]
    )
    return offers


def with_declared_choice(
    rules: Mapping[str, Any], kind: str, value: str, *, allow: bool
) -> dict[str, Any]:
    """The rules of the version **Allow this** (`allow=True`) or **Dismiss**
    makes from a *declared since gN* offer: the item is recorded in
    `seeded_from_declared` either way, so it isn't offered again, and only
    Allow adds it to the allowed list."""
    if kind not in OFFER_KINDS:
        raise ValueError(f"offer kind must be one of {', '.join(OFFER_KINDS)}")
    updated = json.loads(json.dumps(rules))
    out_of_spec = updated["out_of_spec_calls"]
    seeded_key, allowed_key = (
        ("hosts", "allowed_hosts") if kind == "host" else ("mcp_servers", "allowed_mcp_servers")
    )
    if value not in out_of_spec["seeded_from_declared"][seeded_key]:
        out_of_spec["seeded_from_declared"][seeded_key] = sorted(
            [*out_of_spec["seeded_from_declared"][seeded_key], value]
        )
    if allow and value not in out_of_spec[allowed_key]:
        out_of_spec[allowed_key] = sorted([*out_of_spec[allowed_key], value])
    return updated


def _refuse_wildcard_host(item: str) -> None:
    # A host row's item is the request's own Host header, which the agent
    # writes: one click must not turn `*.com` into a pattern allowing a TLD.
    if "*" in item:
        raise ValueError("a wildcard host can't be allowed with one click; edit the guardrail")


def with_item_allowed(rules: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
    """The rules of the version **Allow this** makes from one stored row
    (§4.5): the row's item added to its rule, as narrowly as the row names
    it. A listener is allowed by its own protocol, address and port; a path
    as a literal entry, or as its uuid glob (`saved_file_entry`); a host by its exact name; an MCP row by its server;
    a denied tool call by taking it off `denied_tool_calls`.

    Raises `ValueError` for a row one click can't allow: the overflow row
    (it lists no item), `(unknown host)` and a server-less MCP name (never
    allowed), a host with a `*` in it (a pattern only an edit adds), and an
    `uploads` row over a size cap, where the cap is the
    user's to change with an edit, not to drop with a click."""
    if row.get("overflow"):
        raise ValueError("the overflow row lists no item to allow; acknowledge it instead")
    rule, item, detail = row["rule"], row["item"], row.get("detail") or {}
    updated = json.loads(json.dumps(rules))
    if rule == "service_ports":
        entry = {key: detail.get(key) for key in ("protocol", "addr", "port")}
        if not _readable_listener(entry):
            raise ValueError("this listener row can't be read back into a port entry")
        updated["service_ports"]["allowed"].append(entry)
        return updated
    if rule == "saved_files":
        updated["saved_files"]["allowed"].append(saved_file_entry(item))
        return updated
    if item == UNKNOWN_HOST:
        raise ValueError("a request with no host can't be allowed")
    if rule == "uploads":
        uploads = updated["uploads"]
        if detail.get("kind") == "tool_call":
            uploads["denied_tool_calls"] = [n for n in uploads["denied_tool_calls"] if n != item]
            return updated
        _refuse_wildcard_host(item)
        if not host_allowed(item, uploads["allowed_hosts"]):
            uploads["allowed_hosts"] = sorted([*uploads["allowed_hosts"], item])
        if not item_allowed({"rules": updated}, row):
            # Listing the host doesn't lift a size cap; changing one is an edit.
            raise ValueError("this upload is over the host's size cap; edit the cap instead")
        return updated
    if rule == "out_of_spec_calls":
        out_of_spec = updated["out_of_spec_calls"]
        if detail.get("kind") == "mcp_server":
            server = detail.get("server")
            if server is None:
                raise ValueError("this tool name names no MCP server, so it can't be allowed")
            if server not in out_of_spec["allowed_mcp_servers"]:
                out_of_spec["allowed_mcp_servers"] = sorted(
                    [*out_of_spec["allowed_mcp_servers"], server]
                )
            return updated
        _refuse_wildcard_host(item)
        if not host_allowed(item, out_of_spec["allowed_hosts"]):
            out_of_spec["allowed_hosts"] = sorted([*out_of_spec["allowed_hosts"], item])
        return updated
    if rule == DATA_ACTIONS:
        if DATA_ACTIONS not in updated:
            raise ValueError("this version has no data_actions rule")
        tool, action = detail.get("tool"), detail.get("action")
        if not isinstance(tool, str) or action not in (*DATA_ACTION_KINDS, *DATA_ACTION_PSEUDO):
            raise ValueError("this data-action row can't be read back into a tool and action")
        if "*" in tool:
            # The name is the agent's own; as an entry it would be a glob.
            raise ValueError("a tool name with * can only be allowed by an edit")
        if action == "unreadable" and not detail.get("endpoint"):
            # Calls past the cap name no endpoint: allowing them would allow
            # them everywhere.
            raise ValueError("calls past the cap name no endpoint; acknowledge them instead")
        allowed = updated[DATA_ACTIONS]["allowed"]
        # Exactly this tool and action: an entry for the same literal tool
        # gains the action; a glob entry is the user's to edit.
        for entry in allowed:
            if entry["tool"] == tool:
                if action not in entry["actions"]:
                    entry["actions"] = [
                        a for a in (*DATA_ACTION_KINDS, *DATA_ACTION_PSEUDO)
                        if a in {*entry["actions"], action}
                    ]
                return updated
        allowed.append({"tool": tool, "actions": [action]})
        return updated
    if rule == EGRESS:
        # The row is the agent not being contained; "allowing" it would be
        # dropping the requirement, which is an edit, not one click.
        raise ValueError("an uncontained agent can't be allowed; edit the version to stop requiring containment")
    raise ValueError(f"unknown rule {rule!r}")


# ------------------------------------------------------------------- time


def _instant(value: datetime | str | None) -> datetime | None:
    """An aware datetime from one, or from an RFC 3339 string; else None."""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _required_instant(value: datetime | str, where: str) -> datetime:
    parsed = _instant(value)
    if parsed is None:
        raise ValueError(f"{where}: must be a timezone-aware date-time")
    return parsed
