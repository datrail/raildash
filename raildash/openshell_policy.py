"""An OpenShell sandbox's network policy, imported (DR-194 M2, DR-248).

The user uploads what `openshell sandbox get <name> --policy-only` prints
(YAML), or one of the CLI's JSON views of the same policy (`sandbox get -o
json`, `policy get --full -o json`). RailDash keeps OpenShell's record beside
the agent's ASP, never inside it: the operator writes the policy, so it is
*declared, by the operator* and changes nothing the ASP, a baseline or a
guardrail version holds.

`parse_policy` reads an upload into a record of the network endpoints and
the static sections an export starts from (DR-258), field by field from an
allow-list, so a credential an upload carries (a middleware's config,
signing settings) never reaches storage. Anything that
isn't a readable policy raises `PolicyImportError`; a parse failure is never
read as a policy with no endpoints.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

import yaml

from . import guardrail as g

# The policy-only YAML of a large effective policy is a few KiB; this leaves
# room for hundreds of endpoints and bounds what the YAML parser is given.
MAX_POLICY_BYTES = 256 * 1024
MAX_ENDPOINTS = 2_000
# OpenShell's own prefix for the rules attached providers contribute
# (`openshell-policy`'s PROVIDER_RULE_NAME_PREFIX); the rest of the key is
# the provider's name, lower-cased with `-` as `_`.
PROVIDER_RULE_PREFIX = "_provider_"
# The access presets that let a request carry a body; `read-only` allows
# GET, HEAD and OPTIONS only.
BODY_ACCESS = frozenset({"read-write", "full"})
BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE", "*"})
# Protocols whose requests are bodies by construction, whatever the access
# preset: a read-only GraphQL query is still a POST with a body.
BODY_PROTOCOLS = frozenset({"mcp", "json-rpc", "jsonrpc", "graphql", "websocket"})
# The static sections OpenShell fixes at sandbox creation (filesystem,
# Landlock, process identity), kept so an export can start from the sandbox's
# own base policy (design §4.5). Field by field like the endpoints: paths and
# settings, never a credential. A field outside this list is dropped and named
# in `base.dropped`, so the export can say what it left out.
BASE_FIELDS: dict[str, dict[str, type]] = {
    "filesystem_policy": {"include_workdir": bool, "read_only": list, "read_write": list},
    "landlock": {"compatibility": str},
    "process": {"run_as_user": str, "run_as_group": str},
}
MAX_BASE_PATHS = 1_000
# Why a policy host isn't seeded into a guardrail list (§4.4).
NOT_REPRESENTABLE_HOSTLESS = "allowed_ips only, no host"
NOT_REPRESENTABLE_WILDCARD = "a wildcard form DR-184's host lists can't express"


class PolicyImportError(Exception):
    """An upload that isn't a readable OpenShell policy. The message says
    what was wrong, for the import's error line. Not a `ValueError`, which
    the guardrail routes answer with 409 (a state refusal): this is 422."""


class _Loader(yaml.SafeLoader):
    """Safe YAML without aliases (OpenShell never writes one, and expanding
    them is the cheap way to blow up memory) or duplicate keys (OpenShell's
    own loader rejects them, so a file with one isn't its output)."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.constructor.ConstructorError(
                None, None, "YAML aliases are not accepted", event.start_mark
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError:
                raise yaml.constructor.ConstructorError(
                    None, None, "a mapping key must be a scalar", key_node.start_mark
                ) from None
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _load(raw: bytes) -> tuple[str, Any]:
    if not raw.strip():
        raise PolicyImportError("the file is empty")
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyImportError(f"the file is over {MAX_POLICY_BYTES // 1024} KiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyImportError("the file is not UTF-8 text") from exc
    if text.lstrip().startswith("Error:"):
        # The CLI's error output saved in the policy's place (2>&1), e.g.
        # for a sandbox that doesn't exist; stdout alone is empty then.
        raise PolicyImportError(
            f"not an OpenShell policy but OpenShell's error output: {_first_line(text)[:200]}"
        )
    try:
        if text.lstrip().startswith("{"):
            try:
                return "json", json.loads(text, object_pairs_hook=_unique_keys)
            except ValueError as exc:
                raise PolicyImportError(f"not valid JSON: {exc}") from exc
        try:
            return "yaml", yaml.load(text, Loader=_Loader)  # noqa: S506 -- a SafeLoader subclass
        except yaml.YAMLError as exc:
            raise PolicyImportError(f"not valid YAML: {_first_line(str(exc))}") from exc
    except RecursionError as exc:
        raise PolicyImportError("nested too deeply to be a policy") from exc


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else text


def parse_policy(raw: bytes) -> dict[str, Any]:
    """One upload as the record RailDash stores, or `PolicyImportError`.

    The record: `format` (`yaml`/`json`), `revision` (OpenShell's policy
    version, from a JSON view; the YAML carries none), `policy_source`
    (`sandbox`/`global`, from a JSON view), `sandbox`, `digest` (sha256 of
    the endpoints, so two uploads of one policy compare equal),
    `endpoints`, one per endpoint of every rule, sorted by rule key, and
    `base`, the static sections an export starts from (`_base`; None when
    the upload carries none, as the collector's posts don't)."""
    form, document = _load(raw)
    meta: dict[str, Any] = {"revision": None, "policy_source": None, "sandbox": None}
    if not isinstance(document, dict):
        # The commonest wrong file: the CLI's error text saved in its place
        # (`Error: × ... sandbox not found`) reads as one YAML string.
        shown = _first_line(document) if isinstance(document, str) else type(document).__name__
        raise PolicyImportError(f"not an OpenShell policy (the file holds {shown[:120]!r})")
    if form == "json" and "network_policies" not in document:
        # A JSON view wraps the policy; without one (`policy get` without
        # `--full`, say) there is nothing to read, not an empty policy.
        if not isinstance(document.get("policy"), dict):
            raise PolicyImportError(
                "a JSON view with no `policy` in it (use `openshell policy get <name> --full -o json`)"
            )
        # `sandbox get -o json` names the version `current_policy_version`,
        # `policy get -o json` names it `active_version`, and `policy get
        # --global -o json` just `version`, with `scope: global`.
        for field in ("active_version", "current_policy_version", "version"):
            revision = document.get(field)
            if isinstance(revision, int) and not isinstance(revision, bool) and revision > 0:
                meta["revision"] = revision
                break
        source = document.get("policy_source", document.get("scope"))
        if source in ("sandbox", "global"):
            meta["policy_source"] = source
        sandbox = document.get("sandbox", document.get("name"))
        if isinstance(sandbox, str) and sandbox:
            meta["sandbox"] = sandbox[:253]
        document = document["policy"]
    elif "version" not in document and "network_policies" not in document:
        raise PolicyImportError(
            "not an OpenShell policy: no `version` or `network_policies` "
            "(upload `openshell sandbox get <name> --policy-only`)"
        )
    version = document.get("version", 1)
    if isinstance(version, bool) or version != 1:
        raise PolicyImportError(f"policy version {version!r} is not one this RailDash reads (1)")
    rules = document.get("network_policies", {})
    if rules is None:
        rules = {}
    if not isinstance(rules, dict):
        raise PolicyImportError("`network_policies` is not a mapping of rules")
    endpoints = []
    for key in sorted(rules, key=str):
        endpoints.extend(_rule_endpoints(key, rules[key]))
        if len(endpoints) > MAX_ENDPOINTS:
            raise PolicyImportError(f"more than {MAX_ENDPOINTS} endpoints")
    digest = hashlib.sha256(
        json.dumps(endpoints, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {"format": form, **meta, "digest": digest, "endpoints": endpoints, "base": _base(document)}


def _base(document: Mapping[str, Any]) -> dict[str, Any] | None:
    """The upload's static sections as `{"sections": {...}, "dropped":
    [...]}`, only `BASE_FIELDS`' fields. A field of another name or of the
    wrong shape is dropped (and named), never stored: the import is about
    the network rules, and a section RailDash only carries forward doesn't
    refuse it. None when the upload has no static section at all."""
    sections: dict[str, dict[str, Any]] = {}
    dropped: list[str] = []
    for section, fields in BASE_FIELDS.items():
        value = document.get(section)
        if value is None:
            continue
        if not isinstance(value, dict):
            dropped.append(section)
            continue
        kept: dict[str, Any] = {}
        for field in sorted(value, key=str):
            item = value[field]
            kind = fields.get(field) if isinstance(field, str) else None
            if kind is list:
                ok = (isinstance(item, list) and len(item) <= MAX_BASE_PATHS
                      and all(isinstance(path, str) and 0 < len(path) <= 4096 for path in item))
            elif kind is str:
                ok = isinstance(item, str) and 0 < len(item) <= 256
            else:
                ok = kind is bool and isinstance(item, bool)
            if ok:
                kept[field] = list(item) if kind is list else item
            else:
                dropped.append(f"{section}.{field}")
        sections[section] = kept
    for key in sorted(document, key=str):
        if key not in BASE_FIELDS and key not in ("version", "network_policies"):
            dropped.append(str(key)[:64])
    if not sections:
        return None
    return {"sections": sections, "dropped": dropped}


def _rule_endpoints(key: Any, rule: Any) -> list[dict[str, Any]]:
    where = f"network_policies.{key}"
    if not isinstance(key, str) or not key:
        raise PolicyImportError(f"{where}: a rule key must be a non-empty string")
    if not isinstance(rule, dict):
        raise PolicyImportError(f"{where}: not a mapping")
    name = rule.get("name") or key
    if not isinstance(name, str):
        raise PolicyImportError(f"{where}.name: not a string")
    binaries = []
    for index, binary in enumerate(_list(rule.get("binaries"), f"{where}.binaries")):
        # A policy writes `- path: ...`; a provider profile's scalar form
        # is accepted too.
        path = binary.get("path") if isinstance(binary, dict) else binary
        if not isinstance(path, str) or not path:
            raise PolicyImportError(f"{where}.binaries[{index}]: no path")
        binaries.append(path)
    provider = key[len(PROVIDER_RULE_PREFIX):] if key.startswith(PROVIDER_RULE_PREFIX) else None
    out = []
    for index, endpoint in enumerate(_list(rule.get("endpoints"), f"{where}.endpoints")):
        out.append(_endpoint(endpoint, f"{where}.endpoints[{index}]", key, name, provider, binaries))
    return out


def _list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyImportError(f"{where}: not a list")
    return value


def _string(endpoint: Mapping[str, Any], field: str, where: str) -> str | None:
    value = endpoint.get(field)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise PolicyImportError(f"{where}.{field}: not a string")
    return value


def _port(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise PolicyImportError(f"{where}: {value!r} is not a TCP port")
    return value


def _endpoint(
    endpoint: Any, where: str, key: str, name: str, provider: str | None, binaries: list[str]
) -> dict[str, Any]:
    if not isinstance(endpoint, dict):
        raise PolicyImportError(f"{where}: not a mapping")
    host = _string(endpoint, "host", where)
    ports = [_port(p, f"{where}.ports") for p in _list(endpoint.get("ports"), f"{where}.ports")]
    if endpoint.get("port") not in (None, 0):
        ports.insert(0, _port(endpoint["port"], f"{where}.port"))
    allowed_ips = []
    for index, ip in enumerate(_list(endpoint.get("allowed_ips"), f"{where}.allowed_ips")):
        if not isinstance(ip, str) or not ip:
            raise PolicyImportError(f"{where}.allowed_ips[{index}]: not an address")
        allowed_ips.append(ip)
    if host is None and not allowed_ips:
        raise PolicyImportError(f"{where}: neither a host nor allowed_ips")
    protocol = _string(endpoint, "protocol", where)
    enforcement = _string(endpoint, "enforcement", where)
    access = _string(endpoint, "access", where)
    rules = [_rule_text(r, f"{where}.rules[{i}]") for i, r in enumerate(_list(endpoint.get("rules"), f"{where}.rules"))]
    deny = _list(endpoint.get("deny_rules"), f"{where}.deny_rules")
    return {
        "rule": key,
        "rule_name": name,
        "provider": provider,
        "host": host,
        "ports": sorted(set(ports)),
        "path": _string(endpoint, "path", where),
        "protocol": protocol,
        # Enforcement applies to inspected (L7) endpoints; OpenShell's
        # default for one is `enforce`. An L4 endpoint has none.
        "enforcement": (enforcement or "enforce") if protocol else None,
        "access": access,
        "rules": rules,
        "deny_rules": len(deny),
        "allowed_ips": allowed_ips,
        "binaries": binaries,
        "body_allowed": _body_allowed(protocol, enforcement, access, rules),
    }


def _rule_text(rule: Any, where: str) -> str:
    """One allow rule as a short line: `GET /repos/**`, `tools/call
    search_docs`. Only names and globs, never a value a rule matches on."""
    allow = rule.get("allow") if isinstance(rule, dict) else None
    if not isinstance(allow, dict):
        raise PolicyImportError(f"{where}: no allow")
    method = allow.get("method") or allow.get("command") or allow.get("operation_type") or "*"
    if not isinstance(method, str):
        raise PolicyImportError(f"{where}.method: not a string")
    target = allow.get("tool") if allow.get("tool") is not None else allow.get("path")
    if isinstance(target, dict) and isinstance(target.get("any"), list):
        target = "{" + ", ".join(str(t) for t in target["any"]) + "}"
    return f"{method} {target}".strip() if isinstance(target, str) and target else method


def _body_allowed(
    protocol: str | None, enforcement: str | None, access: str | None, rules: list[str]
) -> bool:
    """Whether OpenShell lets a request to this endpoint carry a body: an
    L4 endpoint passes any bytes, `audit` only logs a denial, a protocol
    whose requests are bodies (GraphQL, MCP) always does, and an inspected
    REST one through its access preset or an allow rule for a body method."""
    if not protocol or enforcement == "audit" or protocol in BODY_PROTOCOLS:
        return True
    if access is not None:
        return access in BODY_ACCESS
    return any(rule.split(" ", 1)[0].upper() in BODY_METHODS for rule in rules)


def endpoint_host_pattern(endpoint: Mapping[str, Any]) -> str | None:
    """The endpoint's host as DR-184's lists write it (exact or `*.`), or
    None when it can't be one (`not_representable` says why)."""
    host = endpoint.get("host")
    if not isinstance(host, str):
        return None
    pattern = host.strip().lower().rstrip(".")
    if pattern.startswith("**."):
        pattern = pattern[1:]
    return pattern if g._is_host_pattern(pattern) else None


def not_representable(endpoint: Mapping[str, Any]) -> str | None:
    if endpoint.get("host") is None:
        return NOT_REPRESENTABLE_HOSTLESS
    if endpoint_host_pattern(endpoint) is None:
        return NOT_REPRESENTABLE_WILDCARD
    return None


def covering_endpoints(record: Mapping[str, Any], host: str) -> list[dict[str, Any]]:
    """The record's endpoints whose host covers a normalized host."""
    out = []
    for endpoint in record["endpoints"]:
        pattern = endpoint_host_pattern(endpoint)
        if pattern is not None and g.host_matches(host, pattern):
            out.append(endpoint)
    return out


def refuses_body(record: Mapping[str, Any], host: str) -> bool:
    """Whether the policy covers a host and every endpoint covering it
    refuses a request body (§4.4: being allowed to write isn't evidence
    that the agent writes, and a body OpenShell refuses never left)."""
    covering = covering_endpoints(record, host)
    return bool(covering) and not any(endpoint["body_allowed"] for endpoint in covering)


def endpoint_label(endpoint: Mapping[str, Any]) -> str:
    """`host:port`, or the addresses of a hostless endpoint."""
    where = endpoint.get("host") or "any host in " + ", ".join(endpoint.get("allowed_ips") or [])
    ports = ",".join(str(port) for port in endpoint.get("ports") or [])
    return f"{where}:{ports}" if ports else where


def pattern_covered(pattern: str, allowed: Iterable[str]) -> bool:
    """Whether a list's patterns allow every host one pattern matches: an
    exact host as `host_matches` reads it, a wildcard only by a wildcard at
    or above it (`*.github.com` covers `*.api.github.com`, never the other
    way, and `api.github.com` covers no wildcard)."""
    if not pattern.startswith("*."):
        return any(g.host_matches(pattern, other) for other in allowed)
    suffix = pattern[1:]
    return any(other.startswith("*.") and (suffix == other[1:] or suffix.endswith(other[1:]))
               for other in allowed)


def beyond_guardrail(record: Mapping[str, Any], allowed_hosts: list[str]) -> list[dict[str, Any]]:
    """Design §4.5's comparison (DR-257): each endpoint the policy allows
    whose host the guardrail's `out_of_spec_calls.allowed_hosts` doesn't
    cover, as `{endpoint, rule, provider, reason}`. `reason` is None for a
    host outside the list, or `not_representable`'s answer for one that
    can't be compared (it is never read as covered). The guardrail has no
    ports, so a covered host is covered on every port. Context only: it
    judges nothing and changes no state."""
    out = []
    for endpoint in record["endpoints"]:
        reason = not_representable(endpoint)
        if reason is None and pattern_covered(endpoint_host_pattern(endpoint), allowed_hosts):
            continue
        out.append({"endpoint": endpoint_label(endpoint), "rule": endpoint["rule"],
                    "provider": endpoint["provider"], "reason": reason})
    return out


def proposal_seed(record: Mapping[str, Any]) -> dict[str, Any]:
    """What a proposal takes from the policy (§4.4): the host patterns for
    `out_of_spec_calls.allowed_hosts`, and the endpoints that can't be one.
    `withheld_upload_hosts` is filled in while the proposal reads the
    window's requests."""
    hosts: dict[str, list[str]] = {}
    unrepresentable = []
    for endpoint in record["endpoints"]:
        reason = not_representable(endpoint)
        if reason is not None:
            unrepresentable.append(
                {"rule": endpoint["rule"], "endpoint": endpoint_label(endpoint), "reason": reason}
            )
            continue
        rules = hosts.setdefault(endpoint_host_pattern(endpoint), [])
        if endpoint["rule"] not in rules:
            rules.append(endpoint["rule"])
    return {
        "hosts": sorted(hosts),
        "host_rules": hosts,
        "not_representable": unrepresentable,
        "withheld_upload_hosts": set(),
    }


def seed_view(
    seed: Mapping[str, Any], record: Mapping[str, Any], upload_hosts: list[str]
) -> dict[str, Any]:
    """The proposal's `openshell`: which hosts came from the policy and from
    which of its rules, with the policy's revision (None for a YAML upload,
    which carries none; the panel then names it by when it was imported),
    its digest and its import time."""
    return {
        "revision": record.get("revision"),
        "digest": record["digest"],
        "imported_at": record.get("imported_at"),
        "policy_source": record.get("policy_source"),
        "hosts": [{"host": host, "rules": seed["host_rules"][host]} for host in seed["hosts"]],
        "upload_hosts": [host for host in upload_hosts if covering_endpoints(record, host)],
        "withheld_upload_hosts": sorted(seed["withheld_upload_hosts"]),
        "not_representable": seed["not_representable"],
    }


# ------------------------------------------------------------- the collector

# DR-249 (DR-194 M3): what `railmon openshell` posts. A sandbox is named as
# OpenShell names it (container_ref's SANDBOX_NAME in RailMon).
SANDBOX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
MAX_DENIALS_PER_POST = 2_000
# Why a batch can't show it holds every denial (design §4.2).
PARTIAL_REASONS = ("first_poll", "gap", "full_buffer", "poll_failed")
DENIAL_KINDS = ("net", "http")
_HASH = re.compile(r"^[0-9a-f]{16,64}$")
_TEXT_LIMITS = {"host": 253, "method": 32, "path": 2048, "binary": 4096, "policy": 253, "reason": 1024}


def check_sandbox(name: str) -> str:
    if not SANDBOX_NAME.match(name):
        raise PolicyImportError("not an OpenShell sandbox name")
    return name


def _instant_text(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise PolicyImportError(f"{where}: not a date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyImportError(f"{where}: not a date-time") from exc
    if parsed.tzinfo is None:
        raise PolicyImportError(f"{where}: no time zone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_denials(body: Any) -> dict[str, Any]:
    """One collector post of denials, checked: `{"denials": [...],
    "partial": None | {"from", "to", "reasons"}}`. Each denial is what the
    collector parsed from one `DENIED` line of the sandbox's log: `at`,
    `hash` (the line's, which dedupes a line seen twice), `kind`
    (`net`/`http`) and the line's host, port, method, path, binary, policy
    and reason, each optional. Raises `PolicyImportError`."""
    if not isinstance(body, dict) or set(body) - {"denials", "partial"}:
        raise PolicyImportError("the body must be {\"denials\": [...], \"partial\": ...}")
    denials = body.get("denials")
    if not isinstance(denials, list) or len(denials) > MAX_DENIALS_PER_POST:
        raise PolicyImportError(f"denials must be a list of at most {MAX_DENIALS_PER_POST}")
    out = []
    for index, denial in enumerate(denials):
        where = f"denials[{index}]"
        if not isinstance(denial, dict) or set(denial) - {"at", "hash", "kind", *_TEXT_LIMITS, "port"}:
            raise PolicyImportError(f"{where}: unknown fields")
        if denial.get("kind") not in DENIAL_KINDS:
            raise PolicyImportError(f"{where}.kind: net or http")
        if not isinstance(denial.get("hash"), str) or not _HASH.match(denial["hash"]):
            raise PolicyImportError(f"{where}.hash: hex")
        row = {"at": _instant_text(denial.get("at"), f"{where}.at"), "hash": denial["hash"], "kind": denial["kind"]}
        for field, limit in _TEXT_LIMITS.items():
            value = denial.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > limit):
                raise PolicyImportError(f"{where}.{field}: a string of at most {limit}")
            row[field] = value
        port = denial.get("port")
        row["port"] = None if port is None else _port(port, f"{where}.port")
        out.append(row)
    partial = body.get("partial")
    if partial is not None:
        if not isinstance(partial, dict) or set(partial) - {"from", "to", "reasons"}:
            raise PolicyImportError("partial: {\"from\", \"to\", \"reasons\"}")
        reasons = partial.get("reasons")
        if not isinstance(reasons, list) or not reasons or any(r not in PARTIAL_REASONS for r in reasons):
            raise PolicyImportError(f"partial.reasons: some of {', '.join(PARTIAL_REASONS)}")
        partial = {
            "from": None if partial.get("from") is None else _instant_text(partial["from"], "partial.from"),
            "to": _instant_text(partial.get("to"), "partial.to"),
            "reasons": sorted(set(reasons)),
        }
    return {"denials": out, "partial": partial}


# ---------------------------------------------------------------- the export

# DR-258 (DR-194 M4, design §4.5): the guardrail in force as an OpenShell
# policy the user applies. Lebin's §7 Q2 (2026-10-27): a policy generated
# from the ASP baseline is the first step towards enforcement.
EXPORT_PORT = 443
EXPORT_RULE_PREFIX = "raildash_"
_RULE_KEY_UNSAFE = re.compile(r"[^a-z0-9_]")
# Destinations OpenShell's network policy never authorizes (its Network
# Rules page: "loopback, link-local, or unspecified"); loopback inside the
# sandbox needs no rule. A rule for one would be meaningless.
LOOPBACK_HOSTS = frozenset({"localhost", "::1"})


def _loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTS or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_link_local or address.is_unspecified


# Anything that could end a `#` comment line: an imported value written into
# the header must stay inside it, never become YAML of its own.
_HEADER_UNSAFE = re.compile(r"[\x00-\x1f\x7f\u0085\u2028\u2029]")


def _host_endpoints(record: Mapping[str, Any] | None, host: str) -> list[dict[str, Any]]:
    """The policy's endpoints for one guardrail host: those whose host
    pattern is that host, or covers it, or (for a guardrail wildcard) falls
    under it. Where an export takes a host's ports and binaries from."""
    if record is None:
        return []
    out = []
    for endpoint in record["endpoints"]:
        pattern = endpoint_host_pattern(endpoint)
        if pattern is None:
            continue
        if pattern == host or g.host_matches(host, pattern) or (
            host.startswith("*.") and g.host_matches(pattern.removeprefix("*."), host)
        ):
            out.append(endpoint)
    return out


def _rule_key(host: str, taken: set[str]) -> str:
    stem = EXPORT_RULE_PREFIX + (_RULE_KEY_UNSAFE.sub("_", host.replace("*.", "any.").lower()) or "host")
    key, n = stem, 2
    while key in taken:
        key, n = f"{stem}_{n}", n + 1
    taken.add(key)
    return key


def _denied_tools(denied_tool_calls: Iterable[str]) -> set[str]:
    """The tool part of each denied `mcp__<server>__<tool>` name: what an
    MCP endpoint's `tools/call` rules name. RailDash can't tie a server name
    to an endpoint, so a tool is dropped from every MCP endpoint by name."""
    out = set()
    for name in denied_tool_calls:
        server = g.tool_call_server(name)
        if server is not None:
            out.add(name[len(g.MCP_PREFIX) + len(server) + 2:])
    return out


def _mcp_rules(endpoint: Mapping[str, Any], denied: set[str]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """An MCP endpoint's allow rules back from their stored text (`method`,
    or `method tool`, or `method {a, b}`), never wider than the policy's:
    `(rules, dropped, still_allowed)`. A rule naming one denied tool is
    dropped; a set loses its denied tools (and is dropped when none is
    left). A rule that allows a denied tool through a glob or with no tool
    at all can't be narrowed by an allow rule, so it is kept and the
    denied tools it still allows are named."""
    rules: list[dict[str, Any]] = []
    dropped: list[str] = []
    still: list[str] = []
    for text in endpoint["rules"]:
        method, _, tool = text.partition(" ")
        if tool.startswith("{"):
            names = sorted({t.strip() for t in tool.strip("{}").split(",") if t.strip()})
            kept = [n for n in names if n not in denied]
            dropped.extend(n for n in names if n in denied)
            if kept:
                rules.append({"allow": {"method": method, "tool": {"any": kept}}})
                if method in ("tools/call", "*"):
                    still.extend(d for d in sorted(denied)
                                 if any("*" in n and fnmatch.fnmatchcase(d, n) for n in kept))
            continue
        if tool and "*" not in tool:
            if tool in denied:
                dropped.append(tool)
            else:
                rules.append({"allow": {"method": method, "tool": tool}})
            continue
        rules.append({"allow": {"method": method, "tool": tool}} if tool else {"allow": {"method": method}})
        if method in ("tools/call", "*"):
            still.extend(n for n in sorted(denied) if not tool or fnmatch.fnmatchcase(n, tool))
    return rules, dropped, still


def _ports(endpoint: dict[str, Any], ports: list[int]) -> None:
    if len(ports) == 1:
        endpoint["port"] = ports[0]
    elif ports:
        endpoint["ports"] = ports


def _header_line(text: str) -> str:
    return "# " + _HEADER_UNSAFE.sub(" ", text) + "\n"


def export_policy(
    rules: Mapping[str, Any],
    record: Mapping[str, Any] | None,
    base_record: Mapping[str, Any] | None,
    *,
    agent: str,
    version: str,
    exported_at: str,
) -> dict[str, Any]:
    """Design §4.5: `rules` (a guardrail version's) as an OpenShell policy.

    Starts from `base_record`'s static sections (the newest import that
    carried them), else `version: 1` alone, and writes `network_policies`
    only. Each `out_of_spec_calls.allowed_hosts` host (but loopback, which
    never leaves the sandbox) gets an endpoint on
    the ports `record` (the newest policy) gives it, else 443: `protocol:
    rest`, `enforcement: audit`, `access: read-only`, or `read-write` where
    `uploads.allowed_hosts` allows a body. In an enforced allow-list every
    captured request already passed the policy, so its port is one of
    those. Ports the policy passes only at L4 stay L4 (a second endpoint),
    a host's own rules win over a wildcard's, and a pin to `allowed_ips`
    every source endpoint has is kept. Binaries are the policy's for that host,
    else all of its binaries: the capture records no executable path (plan
    M4). An HTTP MCP endpoint the policy holds for an allowed host keeps its
    tool rules, minus the tools `uploads.denied_tool_calls` names
    (`_mcp_rules`), and then takes the place of a REST endpoint unless the
    policy had one there too. Whatever couldn't be carried is a gap.

    Answers `{"policy", "gaps", "text"}`: the policy as a mapping, what it
    couldn't carry, and the YAML file with the gaps in its header comment."""
    out_of_spec = rules["out_of_spec_calls"]
    uploads = rules["uploads"]
    gaps = [
        "The guardrail has no ports: each host takes the ports the current policy gives it, else 443.",
        "A body isn't a method: a GET with a body passes OpenShell and still trips the uploads rule.",
        "uploads.max_request_bytes, service_ports and saved_files have no OpenShell field; "
        "RailDash still judges them.",
        "MCP servers are named by the agent's config, not by host: allowed_mcp_servers and "
        "data_actions stay RailDash's to judge; a stdio or provider-side MCP server never crosses "
        "the network.",
        "Rules are rebuilt from what RailDash keeps of the policy: access presets, deny rules, "
        "parameter matchers and an MCP endpoint's mcp settings are not carried over.",
    ]
    all_binaries = sorted({b for e in (record or {}).get("endpoints", []) for b in e["binaries"]})
    denied = _denied_tools(uploads.get("denied_tool_calls", []))
    taken: set[str] = set()
    network: dict[str, Any] = {}
    no_binary, widened, wildcards = [], [], []
    emitted_mcp: set[int] = set()
    loopback = sorted({h for h in [*out_of_spec["allowed_hosts"], *uploads["allowed_hosts"]] if _loopback(h)})
    if loopback:
        gaps.append("Loopback, link-local and unspecified addresses never take a rule (loopback stays "
                    "inside the sandbox): " + ", ".join(loopback) + ".")
    for host in sorted(h for h in out_of_spec["allowed_hosts"] if not _loopback(h)):
        related = _host_endpoints(record, host)
        own = [e for e in related if endpoint_host_pattern(e) == host]
        binaries = (sorted({b for e in own for b in e["binaries"]})
                    or sorted({b for e in related for b in e["binaries"]}))
        if not binaries and all_binaries:
            binaries = all_binaries
            widened.append(host)
        if not binaries:
            no_binary.append(host)
        if host.startswith("*."):
            wildcards.append(host)
        # An MCP endpoint is carried for its own host only, once; the host
        # then gets a REST endpoint only where the policy had one too.
        mcp_here = [e for e in related if e["protocol"] == "mcp" and endpoint_host_pattern(e) == host]
        rest = [e for e in related if e["protocol"] != "mcp"
                and (not mcp_here or endpoint_host_pattern(e) == host)]
        # The host's own rules win over a wildcard's that also covers it.
        rest = [e for e in rest if endpoint_host_pattern(e) == host] or rest
        if rest or not mcp_here:
            # Ports the policy inspects (L7) take a REST endpoint; ports it
            # passes as plain bytes (L4) stay L4, so non-HTTP traffic isn't
            # put through an HTTP parser.
            l7_ports = sorted({p for e in rest if e["protocol"] is not None for p in e["ports"]})
            l4_ports = sorted({p for e in rest if e["protocol"] is None for p in e["ports"]} - set(l7_ports))
            # A port-less L4 endpoint stays port-less and L4, as written.
            l4_bare = bool(rest) and not l7_ports and not l4_ports and all(e["protocol"] is None for e in rest)
            if not l7_ports and not l4_ports and not l4_bare:
                l7_ports = [EXPORT_PORT]
            # A pin holds only when every endpoint the host came from had one.
            pin = sorted({ip for e in rest for ip in e["allowed_ips"]}) if rest and all(
                e["allowed_ips"] for e in rest) else None
            endpoints = []
            if l7_ports:
                endpoint: dict[str, Any] = {"host": host}
                _ports(endpoint, l7_ports)
                if pin:
                    endpoint["allowed_ips"] = pin
                writes = pattern_covered(host, uploads["allowed_hosts"])
                endpoint.update(protocol="rest", enforcement="audit",
                                access="read-write" if writes else "read-only")
                endpoints.append(endpoint)
            if l4_ports or l4_bare:
                endpoint = {"host": host}
                _ports(endpoint, l4_ports)
                if pin:
                    endpoint["allowed_ips"] = pin
                endpoints.append(endpoint)
                where = f"{host}:{','.join(map(str, l4_ports))}" if l4_ports else host
                gaps.append(f"{where} stays L4 as in the policy: "
                            "no access preset, so uploads aren't limited there.")
            key = _rule_key(host, taken)
            rule: dict[str, Any] = {"name": key.replace("_", "-"), "endpoints": endpoints}
            if binaries:
                rule["binaries"] = [{"path": b} for b in binaries]
            network[key] = rule
        for mcp in mcp_here:
            if id(mcp) in emitted_mcp:
                continue
            emitted_mcp.add(id(mcp))
            tool_rules, dropped, still = _mcp_rules(mcp, denied)
            mcp_endpoint: dict[str, Any] = {"host": mcp["host"]}
            if mcp["path"]:
                mcp_endpoint["path"] = mcp["path"]
            _ports(mcp_endpoint, mcp["ports"])
            if mcp["allowed_ips"]:
                mcp_endpoint["allowed_ips"] = list(mcp["allowed_ips"])
            mcp_endpoint.update(protocol="mcp", enforcement="audit", rules=tool_rules)
            mcp_key = _rule_key(f"{host}_mcp", taken)
            mcp_rule: dict[str, Any] = {"name": mcp_key.replace("_", "-"), "endpoints": [mcp_endpoint]}
            if mcp["binaries"] or binaries:
                mcp_rule["binaries"] = [{"path": b} for b in (mcp["binaries"] or binaries)]
            network[mcp_key] = mcp_rule
            if dropped:
                gaps.append(f"MCP rule {mcp['rule']}: no tools/call for {', '.join(sorted(set(dropped)))}, "
                            "which the guardrail denies (matched by tool name on every MCP endpoint).")
            if not tool_rules:
                gaps.append(f"MCP rule {mcp['rule']}: no allow rule is left to carry over; "
                            "add its rules (or an access preset) by hand.")
            if still:
                gaps.append(f"MCP rule {mcp['rule']}: a rule allowing every tool or a glob still allows "
                            f"{', '.join(sorted(set(still)))}, which the guardrail denies; narrow it by hand.")
    if widened:
        gaps.append("No policy rule names the binaries for " + ", ".join(widened)
                    + ": every binary the policy names is allowed there instead.")
    if no_binary:
        gaps.append("No binary is known for " + ", ".join(no_binary) + ": OpenShell lets no process "
                    "use a rule without one. Add `binaries` before applying it, or import the "
                    "sandbox's policy first.")
    if wildcards:
        gaps.append("The guardrail's " + ", ".join(wildcards) + " matches subdomains at any depth; "
                    "check how your OpenShell version matches `*.` and use `**.` if it is one label only.")
    only_uploads = sorted(h for h in uploads["allowed_hosts"]
                          if not pattern_covered(h, out_of_spec["allowed_hosts"]) and not _loopback(h))
    if only_uploads:
        gaps.append("Upload hosts the guardrail doesn't allow calls to are left out: " + ", ".join(only_uploads) + ".")
    for endpoint in (record or {}).get("endpoints", []):
        reason = not_representable(endpoint)
        if reason is not None:
            gaps.append(f"Not carried over from rule {endpoint['rule']}: {endpoint_label(endpoint)} ({reason}).")
    if base_record is not None and base_record.get("base"):
        base = base_record["base"]
        policy: dict[str, Any] = {"version": 1, **{k: dict(v) for k, v in base["sections"].items()}}
        mark = f"revision {base_record['revision']}" if base_record.get("revision") else "no revision"
        source = f"the sandbox policy imported {base_record.get('imported_at')} ({mark})"
        if base["dropped"]:
            gaps.append("Base fields RailDash doesn't keep, so not carried over: " + ", ".join(base["dropped"]) + ".")
    else:
        policy = {"version": 1}
        source = "no base policy (none imported): add your sandbox's filesystem_policy, landlock and process sections"
        gaps.append("No base policy is held, so the static sections are missing: import "
                    "`openshell sandbox get <name> --policy-only` first, or merge network_policies by hand.")
    policy["network_policies"] = network
    header = [
        f"OpenShell policy exported by RailDash from guardrail {version} for {agent}, {exported_at}.",
        f"Based on {source}; only network_policies is replaced.",
        "Every L7 endpoint is enforcement: audit (OpenShell logs, doesn't block). The guardrail",
        "was proposed from what the agent was seen doing, so switch an endpoint to enforce knowingly.",
        "Apply: note the current revision (openshell policy list <sandbox>), then",
        "  openshell policy set <sandbox> --policy <this file> --wait",
        "Roll back: openshell policy get <sandbox> --rev <N> --base --output json | jq -e .policy > before.json",
        "  openshell policy set <sandbox> --policy before.json --wait",
        "Not exported:",
        *(f"- {gap}" for gap in gaps),
    ]
    text = "".join(_header_line(line) for line in header) + yaml.safe_dump(
        policy, sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    return {"policy": policy, "gaps": gaps, "text": text}
