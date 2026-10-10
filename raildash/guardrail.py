"""Pure OSS Data Guardrail v1 contract and evaluator (DR-184, milestone M1).

A guardrail is a per-agent set of four closed rules -- `uploads`,
`saved_files`, `service_ports` and `out_of_spec_calls` -- that every ASP and
every captured request of that agent is checked against. It is policy the
operator approved, kept apart from the alignment version (the baseline), so
the alignment contract and every locked baseline stay as they are. The design
is railxia/docs `design/2026-10-07-data-guardrail/data-guardrail-design.md`;
section numbers below are its.

Like `raildash.asp`, this module has no database, HTTP or UI dependency and
never reads the clock: every time it needs is an argument. Nothing calls it
yet (M2 adds storage and the two store hooks), so backing it out is a revert.

The API, in the order a caller meets it:

- `guardrail_problems(version)`: the closed contract (schema plus the rules
  it cannot express); `[]` when valid.
- `propose_guardrail(...)`: the §4.4 first guardrail from a locked baseline
  and the agent's requests from the 24 h before the lock, with what would be
  a violation and why a declared list is empty.
- `evaluate_asp(guardrail, bundle, ...)`: `service_ports` and `saved_files`
  against one parsed ASP, staleness included.
- `request_owner(interaction, guardrails, ...)`: which active guardrail one
  captured request belongs to, if any (§4.3).
- `evaluate_request(guardrail, interaction, ...)`: `uploads` and
  `out_of_spec_calls` against one captured request.
- `request_rules_status(...)`: whether the two request rules can be verified
  at all now (collector heartbeat, unattributed traffic).
- `rule_states(asp_result, request_status)`: the four rules' latest results
  in one map, multi-agent applied.
- `item_allowed(guardrail, violation)` and `row_counts(guardrail, row)`:
  whether a version allows a stored row's item, and so whether the row
  counts toward the state under the version in force.
- `agent_state(...)`: the per-agent roll-up, Violated > Unverified > Held >
  No guardrail.

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
| "unverified", "reason": str | None, "violations": [...]}`.

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
- Model-requested tool calls are read from the response body only: an
  Anthropic `tool_use`/`tool_call` content block's `name`, and an OpenAI
  `choices[].message.tool_calls[].function.name`. A request body only
  echoes an earlier turn, and the agent writes it, so it is not the model's
  request. A response the capture could not decode yields none, which is
  why an unreadable capture never makes the request rules Held by itself
  (`request_rules_status` decides that from liveness).
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
  rule Unverified (`MALFORMED_EVIDENCE`) unless a readable one is a
  violation.
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
- Writes under `/dev` include `/dev/shm`, as §4.2 says: never a violation.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from .asp import BUNDLE_VERSION_V2, FILE_ACCESS_ATTRIBUTE, identity_problems
from .ingest import _header, legacy_exchange
from .store import UNSAFE_LEGACY_CAPTURE, Store

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "guardrail-version-v1.schema.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text())
_VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

GUARDRAIL_CONTRACT_VERSION = SCHEMA["properties"]["guardrail_contract_version"]["const"]
RULES = ("uploads", "saved_files", "service_ports", "out_of_spec_calls")
ASP_RULES = ("service_ports", "saved_files")
REQUEST_RULES = ("uploads", "out_of_spec_calls")
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

UNKNOWN_HOST = "(unknown host)"
MCP_PREFIX = "mcp__"
# Kernel interfaces, not storage (§4.2): a write there is never a violation.
KERNEL_INTERFACE_ROOTS = ("/proc", "/sys", "/dev")
WILDCARD_ADDRESSES = frozenset({"0.0.0.0", "::"})

# §4.3 "Stale": three times the gap between the two newest ASPs, never under
# 5 minutes and never over 2 hours; with one ASP, 2 hours.
STALE_GAP_FACTOR = 3
STALE_MIN = timedelta(minutes=5)
STALE_MAX = timedelta(hours=2)
# §4.1/§4.3: `railmon collect` beats every 60 s while a tap is attached.
HEARTBEAT_WINDOW = timedelta(minutes=3)
UNATTRIBUTED_WINDOW = timedelta(minutes=10)
# §4.4: hosts the agent sent a body to in this window before the lock seed
# `uploads.allowed_hosts`. The caller selects the requests; this names it.
PROPOSAL_LOOKBACK = timedelta(hours=24)

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
    string, and the identity follows the alignment version's own rules
    (`raildash.asp.identity_problems`, which also sorts a key list)."""
    if not isinstance(version, dict):
        return ["guardrail version must be an object"]
    problems = [
        f"{'.'.join(str(part) for part in error.path) or 'guardrail'}: {error.message}"
        for error in sorted(_VALIDATOR.iter_errors(version), key=str)
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
    return Store._file_type(path)


def kernel_interface_path(path: str) -> bool:
    return any(path == root or path.startswith(root + "/") for root in KERNEL_INTERFACE_ROOTS)


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
        raw = Store._safe_raw(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw)
    if not isinstance(raw, dict) or raw == UNSAFE_LEGACY_CAPTURE:
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


def requested_tool_calls(interaction: Mapping[str, Any]) -> list[str]:
    """Tool names the model asked for in this response, in order, deduplicated."""
    exchange = _exchange(interaction)
    response = exchange.get("response") if exchange else None
    body = response.get("body") if isinstance(response, dict) else None
    if not isinstance(body, dict):
        return []
    names: list[str] = []

    def add(name: Any) -> None:
        if isinstance(name, str) and name and name not in names:
            names.append(name)

    content = body.get("content")
    for block in content if isinstance(content, list) else []:
        if isinstance(block, dict) and block.get("type") in {"tool_use", "tool_call"}:
            add(block.get("name"))
    choices = body.get("choices")
    for choice in choices if isinstance(choices, list) else []:
        message = choice.get("message") if isinstance(choice, dict) else None
        calls = message.get("tool_calls") if isinstance(message, dict) else None
        for call in calls if isinstance(calls, list) else []:
            function = call.get("function") if isinstance(call, dict) else None
            add(function.get("name") if isinstance(function, dict) else None)
    return names


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
) -> dict[str, list[dict[str, Any]]]:
    """`uploads` and `out_of_spec_calls` against one captured request.

    `interaction` is a stored `interactions` row (`raildash.ingest.normalise`
    output, or `Store.interaction`'s): `host`, `request_size` and `raw` are
    read. The caller has already decided, with `request_owner`, that it
    belongs to this guardrail. Returns each rule's violations; whether the
    rules are verified at all is `request_rules_status`'s answer, since one
    request never makes a rule Held. One request yields at most one
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
    if carries_body(interaction):
        if not host_allowed(host, uploads["allowed_hosts"]):
            upload_reasons.append("body_to_unlisted_host")
    cap = _size_cap(host, uploads["max_request_bytes"]) if host is not None else None
    if cap is not None:
        if size is None:
            if carries_body(interaction):
                upload_reasons.append("request_size_unknown")
        elif size > cap:
            upload_reasons.append("request_size_over_cap")
    found_uploads: list[dict[str, Any]] = []
    if upload_reasons:
        found_uploads.append(
            _violation(
                "uploads", item, OBSERVED, source,
                kind="host", reasons=upload_reasons, request_size=size, max_request_bytes=cap,
            )
        )
    tools = requested_tool_calls(interaction)
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
    return {"uploads": found_uploads, "out_of_spec_calls": found_out_of_spec}


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
) -> dict[str, dict[str, Any]]:
    """Whether `uploads` and `out_of_spec_calls` can be verified now.

    Unverified without an authenticated collector heartbeat in the last 3
    minutes (an idle agent and a dead collector look the same otherwise), or
    for 10 minutes after the last authenticated request RailDash could not
    give to one agent. Otherwise `held`: the state of the request rules is
    their rows, which the roll-up reads separately. Times are RailDash's
    own receive times.
    """
    current = _required_instant(now, "now")
    heartbeat = _instant(last_heartbeat_at)
    unattributed = _instant(last_unattributed_at)
    if heartbeat is None or abs(current - heartbeat) > HEARTBEAT_WINDOW:
        reason: str | None = NO_HEARTBEAT
    elif unattributed is not None and current - unattributed < UNATTRIBUTED_WINDOW:
        reason = UNATTRIBUTED_TRAFFIC
    else:
        reason = None
    return {
        rule: {"state": UNVERIFIED if reason else HELD, "reason": reason, "violations": []}
        for rule in REQUEST_RULES
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
    bounded to [5 min, 2 h]; with only one ASP, 2 h."""
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
) -> dict[str, Any]:
    """`service_ports` and `saved_files` against the newest parsed ASP.

    `bundle` is what `raildash.asp.parse_bundle` returns for the stored
    bytes; the caller has matched its identity to the guardrail's.
    Returns `{"multi_agent": bool, "stale": bool, "rules": {...}}`. A
    multi-agent bundle evaluates nothing and makes all four rules
    Unverified; `rule_states` carries that over the request rules.

    Per rule, from the attribute's status: `ANSWERED` and `ABSENT` are
    verified; `PARTIAL` is violated when a listed item breaks the rule (a
    capped list keeps what it lists) and Unverified otherwise; `BLIND`,
    `FAILED`, `TEMPLATED` and a missing attribute are Unverified. A stale
    ASP is Unverified unless it shows a violation, which stays real.
    """
    if is_multi_agent(bundle):
        return {
            "multi_agent": True,
            "stale": False,
            "rules": {
                rule: {"state": UNVERIFIED, "reason": MULTI_AGENT, "violations": []}
                for rule in RULES
            },
        }
    stale = asp_is_stale(bundle["collected_at"], previous_collected_at, now)
    attributes = _attributes(bundle)
    source = {"kind": "asp", "id": asp_id}
    rules = guardrail["rules"]
    results = {
        "service_ports": _attribute_rule(
            attributes.get(LISTENERS_ATTRIBUTE),
            lambda items: _listener_violations(items, rules["service_ports"]["allowed"], source),
            stale,
        ),
        "saved_files": _attribute_rule(
            attributes.get(FILE_ACCESS_ATTRIBUTE),
            lambda items: _file_violations(items, rules["saved_files"]["allowed"], source),
            stale,
        ),
    }
    return {"multi_agent": False, "stale": stale, "rules": results}


def _attribute_rule(attribute: Any, check: Any, stale: bool) -> dict[str, Any]:
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
    if violations:
        return {"state": VIOLATED, "reason": None, "violations": violations}
    if malformed:
        reason: str | None = MALFORMED_EVIDENCE
    elif status == "PARTIAL":
        # A restarted or capped probe may have missed exactly the one item
        # that breaks the rule: the failure that looks like success (§5).
        reason = PARTIAL_NO_VIOLATION
    elif stale:
        reason = STALE
    else:
        reason = None
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
    asp_result: Mapping[str, Any] | None, request_status: Mapping[str, Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    """All four rules' latest results: the ASP rules from `evaluate_asp`
    (Unverified `NOT_COLLECTED` when no ASP has been evaluated) and the
    request rules from `request_rules_status`, except that a multi-agent ASP
    makes every rule Unverified (multi-agent)."""
    if asp_result is not None and asp_result.get("multi_agent"):
        return {rule: dict(asp_result["rules"][rule]) for rule in RULES}
    states: dict[str, dict[str, Any]] = {}
    for rule in ASP_RULES:
        result = (asp_result or {}).get("rules", {}).get(rule)
        states[rule] = (
            dict(result)
            if result
            else {"state": UNVERIFIED, "reason": NOT_COLLECTED, "violations": []}
        )
    for rule in REQUEST_RULES:
        states[rule] = dict(request_status[rule])
    return states


def agent_state(
    *,
    has_active_guardrail: bool,
    rule_results: Mapping[str, Mapping[str, Any]],
    counting_rows: int,
) -> str:
    """§4.5's per-agent state, highest first: `violated` (a counting row),
    `unverified` (no counting row, but some rule Unverified on its latest
    evidence), `held` (every rule verified, no counting row), and
    `no_guardrail`. A rule missing from `rule_results` is Unverified; a rule
    whose latest evidence was violated but whose rows no longer count (they
    were acknowledged or allowed) was still verified."""
    if not has_active_guardrail:
        return STATE_NO_GUARDRAIL
    if counting_rows > 0:
        return STATE_VIOLATED
    for rule in RULES:
        result = rule_results.get(rule)
        if not result or result.get("state") not in (HELD, VIOLATED):
            return STATE_UNVERIFIED
    return STATE_HELD


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
        reasons = detail.get("reasons") or []
        if "body_to_unlisted_host" in reasons and not host_allowed(item, uploads["allowed_hosts"]):
            return False
        cap = _size_cap(item, uploads["max_request_bytes"])
        size = detail.get("request_size")
        if cap is not None and ("request_size_unknown" in reasons or "request_size_over_cap" in reasons):
            return type(size) is int and size <= cap
        return True
    if rule == "out_of_spec_calls":
        out_of_spec = rules["out_of_spec_calls"]
        if detail.get("kind") == "mcp_server":
            server = detail.get("server")
            return server is not None and server in out_of_spec["allowed_mcp_servers"]
        return item != UNKNOWN_HOST and host_allowed(item, out_of_spec["allowed_hosts"])
    return False


def row_counts(guardrail: Mapping[str, Any] | None, row: Mapping[str, Any]) -> bool:
    """Whether one stored row counts toward Violated: unacknowledged, and
    the version in force disallows its item. An overflow row ("N more
    items") lists no item to re-check, so it counts until acknowledged."""
    if guardrail is None or row.get("acknowledged"):
        return False
    if row.get("overflow"):
        return True
    return not item_allowed(guardrail, row)


# ---------------------------------------------------------------- proposal


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
    declared list left empty says why. A multi-agent baseline gets no
    proposal (`reason: MULTI_AGENT`).
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
    saved: list[dict[str, Any]] = []
    if files.get("status") in ("ANSWERED", "PARTIAL") and isinstance(files.get("value"), list):
        for path in sorted({entry["path"] for entry in files["value"] if entry["write"]}):
            if not kernel_interface_path(path):
                saved.append({"path": path, "literal": True})
    elif files.get("status") != "ABSENT":
        empty_because["saved_files.allowed"] = _why_empty(files)

    listeners = attributes.get(LISTENERS_ATTRIBUTE) or {}
    if listeners.get("status") in ("ANSWERED", "PARTIAL") and isinstance(listeners.get("value"), list):
        listed, _ = _listener_violations(listeners["value"], [], source)
        would_be.extend(listed)

    declared = attributes.get("declared_destinations") or {}
    declared_hosts: list[str] = []
    if declared.get("status") == "ANSWERED" and isinstance(declared.get("value"), list):
        declared_hosts = sorted(
            {
                host
                for host in (normalize_host(value) for value in declared["value"])
                if host is not None and _is_host_pattern(host)
            }
        )
    else:
        empty_because["out_of_spec_calls.allowed_hosts"] = _why_empty(declared)
    servers = attributes.get("mcp_servers_declared") or {}
    declared_servers: list[str] = []
    if servers.get("status") == "ANSWERED" and isinstance(servers.get("value"), list):
        names = (
            entry.get("name") if isinstance(entry, dict) else entry for entry in servers["value"]
        )
        # Two configured names that normalize alike are one item (§4.2).
        declared_servers = sorted(
            {normalize_mcp_server(name) for name in names if isinstance(name, str) and name}
        )
    else:
        empty_because["out_of_spec_calls.allowed_mcp_servers"] = _why_empty(servers)

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
    }


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
