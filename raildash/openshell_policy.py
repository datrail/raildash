"""An OpenShell sandbox's network policy, imported (DR-194 M2, DR-248).

The user uploads what `openshell sandbox get <name> --policy-only` prints
(YAML), or one of the CLI's JSON views of the same policy (`sandbox get -o
json`, `policy get --full -o json`). RailDash keeps OpenShell's record beside
the agent's ASP, never inside it: the operator writes the policy, so it is
*declared, by the operator* and changes nothing the ASP, a baseline or a
guardrail version holds.

`parse_policy` reads an upload into a record of the network endpoints only,
field by field from an allow-list, so a credential an upload carries (a
middleware's config, signing settings) never reaches storage. Anything that
isn't a readable policy raises `PolicyImportError`; a parse failure is never
read as a policy with no endpoints.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

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
    the endpoints, so two uploads of one policy compare equal) and
    `endpoints`, one per endpoint of every rule, sorted by rule key."""
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
    return {"format": form, **meta, "digest": digest, "endpoints": endpoints}


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
