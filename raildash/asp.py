"""Pure ASP v1 validation, identity binding, and deterministic comparison.

This module deliberately has no database, HTTP, or UI dependency.  RailDash's
later custody layer can therefore validate exact RailMon bytes and compare two
immutable observations without making an unauthenticated mutation surface part
of the contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .json_safety import check_json_structure

# The published v1 and v2 schemas, vendored byte-for-byte from the pinned
# RailMon version (tests/test_asp.py asserts neither copy has drifted). They
# are the single source of truth for the evidence bundle's structure; only
# the rules they cannot express live in code below (`_semantic_problems`,
# `_semantic_problems_v2`).
SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "evidence-bundle-v1.schema.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text())
_VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

# RailMon's grouping of attributes into static and dynamic agent data
# (DR-193), vendored the same way. A dynamic attribute says where this copy
# runs now, so its value is left out of every comparison: a restart, move or
# recreate is not drift (`_comparison_attributes`). The producer sends it;
# leaving it out is ours.
ATTRIBUTE_GROUPS_PATH = Path(__file__).resolve().parent / "schemas" / "attribute-groups.json"
DYNAMIC_ATTRIBUTES = frozenset(json.loads(ATTRIBUTE_GROUPS_PATH.read_text())["dynamic"])

SCHEMA_V2_PATH = Path(__file__).resolve().parent / "schemas" / "evidence-bundle-v2.schema.json"
SCHEMA_V2: dict[str, Any] = json.loads(SCHEMA_V2_PATH.read_text())
_VALIDATOR_V2 = Draft202012Validator(SCHEMA_V2, format_checker=FormatChecker())
# v2's generic attribute definition leaves an ANSWERED `deployment` value
# unconstrained; it is held to v1's shape, because it is the same identity.
_DEPLOYMENT_VALUE_VALIDATOR = Draft202012Validator(
    {**SCHEMA["$defs"]["deployment_value"], "$schema": SCHEMA["$schema"]}
)
# DR-154: the same holds for `observed_file_access`, which v1 publishes as
# `file_access_value` and v2 carries sandbox-scoped with no shape of its own.
_FILE_ACCESS_VALUE_VALIDATOR = Draft202012Validator(
    {**SCHEMA["$defs"]["file_access_value"], "$schema": SCHEMA["$schema"]}
)
# DR-207: and for `egress_containment` (`egress_containment_value`), wherever
# a v2 bundle carries it: RailMon writes it sandbox-scoped, and the guardrail
# reads a lone agent's scope under the sandbox's.
_EGRESS_VALUE_VALIDATOR = Draft202012Validator(
    {**SCHEMA["$defs"]["egress_containment_value"], "$schema": SCHEMA["$schema"]}
)
EGRESS_ATTRIBUTE = "egress_containment"
FILE_ACCESS_ATTRIBUTE = "observed_file_access"
FILE_ACCESS_VALUED_STATUSES = frozenset({"ANSWERED", "PARTIAL"})
# The bound the v1 schema's top-level `$comment` names as code-only: the value
# as compact JSON with non-ASCII escaped, which is how RailMon writes it.
FILE_ACCESS_VALUE_MAX_BYTES = 256 * 1024

BUNDLE_VERSION = SCHEMA["properties"]["bundle_version"]["const"]
BUNDLE_VERSION_V2 = SCHEMA_V2["properties"]["bundle_version"]["const"]
DEFAULT_AGENT_KEY = "default"
ALIGNMENT_CONTRACT_VERSION = 1
DRIFT_CONTRACT_VERSION = 1
# DR-109: comparing two evidence-bundle v2 collections. Contract v1 stays
# exactly what a v1 comparison emits; v2 adds the `agent_key` scope every
# change carries (null for the shared sandbox scope) and the AGENT_* changes.
# DR-169's window lists change when `value` counts as changed, not the shape.
DRIFT_CONTRACT_VERSION_V2 = 2
# The shipped redacted RailMon sample is about 5 KiB.  The contract suite's
# valid 1,000-attribute high-cardinality bundle is about 432 KiB, so 1 MiB gives
# it more than 2x headroom while avoiding the webhook's much larger interaction
# allowance.  That allowance exists for escaped request/response payloads that
# ASPs do not contain.
MAX_ASP_BUNDLE_BYTES = 1 * 1024 * 1024
MAX_DRIFT_CHANGES = 500
MAX_DRIFT_RESULT_BYTES = 256 * 1024
DEFAULT_DRIFT_PAGE_SIZE = 100
MAX_DRIFT_PAGE_SIZE = 500
MAX_AGENT_KEY_CHARS = 128

DEPLOYMENT_ENV_KEYS = ("RAIL_DEPLOYMENT", "RAIL_NAMESPACE")
DEPLOYMENT_COMPOSE_KEYS = (
    "com.docker.compose.project",
    "com.docker.compose.service",
)
DEPLOYMENT_KEYS = frozenset((*DEPLOYMENT_ENV_KEYS, *DEPLOYMENT_COMPOSE_KEYS))
DEPLOYMENT_VALUE_MAX_BYTES = 253
IDENTITY_KINDS = frozenset(
    {"deployment_environment", "deployment_compose", "local_agent_key", "local_agent_keys"}
)
_V2_AGENT_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
NON_COMPARABLE_REASONS = frozenset(
    {
        "IDENTITY_MISMATCH",
        "CONTRACT_MISMATCH",
        "INVALID_BUNDLE",
        "ALIGNMENT_INTEGRITY_FAILED",
        "NO_ACTIVE_ALIGNMENT",
    }
)
AGENT_FIELD_ORDER = ("discovery_status",)
ATTRIBUTE_FIELD_ORDER = (
    "value",
    "status",
    "reason",
    "tier",
    "authored_by",
    "method",
    "note",
    "attestation_ref",
)
SOURCE_FIELD_ORDER = ("attempted", "reached", "reason", "window_seconds")
ATTESTATION_FIELD_ORDER = (
    "root",
    "claim",
    "subject",
    "verified_at",
    "verifier_version",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class BundleValidationError(ValueError):
    """The received bytes are not one Evidence Bundle Schema v1 or v2 document."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid evidence bundle: " + "; ".join(problems[:5]))


class IdentityRequiredError(ValueError):
    """An unkeyed bundle needs the local operator's explicit identity claim."""


MULTI_AGENT_KEY_REQUIRED = "MULTI_AGENT_KEY_REQUIRED"


class MultiAgentKeyRequiredError(IdentityRequiredError):
    """An unkeyed v1 bundle for a sandbox that already has keyed v2 history.

    The multi-agent design (§5) names a partially configured multi-agent
    container falling back to one identity as the failure that most
    resembles success, and has an unkeyed evidence upload for that sandbox
    rejected with `MULTI_AGENT_KEY_REQUIRED` (DR-234)."""

    code = MULTI_AGENT_KEY_REQUIRED

    def __init__(self, host_id: str, sandbox_name: str):
        super().__init__(
            f"{MULTI_AGENT_KEY_REQUIRED}: sandbox {sandbox_name!r} on host {host_id!r} "
            "already has keyed multi-agent (evidence bundle v2) history; an unkeyed v1 "
            "bundle for it is refused rather than filed as another agent. Send a v2 "
            "collection, or this v1 bundle with an explicit non-default agent_key"
        )


def is_explicit_agent_key(agent_key: str | None) -> bool:
    """Whether a caller-supplied key names one agent: non-empty and not the
    reserved compatibility key `default` (design §4.1)."""
    return isinstance(agent_key, str) and bool(agent_key.strip()) and (
        agent_key.strip() != DEFAULT_AGENT_KEY
    )


def bundle_digest(raw: bytes) -> str:
    """SHA-256 over the exact bytes received, without JSON reserialization."""
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def parse_bundle(raw: bytes) -> dict[str, Any]:
    """Bound, decode, parse, and validate one exact evidence-bundle payload."""
    if not isinstance(raw, bytes):
        raise TypeError("evidence bundle must be bytes")
    if len(raw) > MAX_ASP_BUNDLE_BYTES:
        raise BundleValidationError(
            [f"bundle exceeds the {MAX_ASP_BUNDLE_BYTES}-byte input bound"]
        )
    try:
        check_json_structure(raw)
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BundleValidationError([f"bundle is not bounded UTF-8 JSON: {exc}"]) from exc
    problems = bundle_problems(value)
    if problems:
        raise BundleValidationError(problems)
    return value


def bundle_problems(bundle: Any) -> list[str]:
    """Validate the published v1 or v2 schema plus the rules it cannot express.

    `bundle_version` is checked before either schema runs, not by them: a v2
    body run through the v1 validator (or vice versa) fails every top-level
    field at once — `sandbox`/`agents` as unknown properties on one side,
    `inputs_attempted`/`attributes` as missing ones on the other — which
    buries the one fact that matters (the version this sink does not
    support) under noise that looks like a malformed bundle of the wrong
    version rather than an unsupported one.
    """
    if not isinstance(bundle, dict):
        return ["bundle must be an object"]
    version = bundle.get("bundle_version")
    if version == BUNDLE_VERSION:
        return _schema_problems(_VALIDATOR, bundle) + _semantic_problems(bundle)
    if version == BUNDLE_VERSION_V2:
        return _schema_problems(_VALIDATOR_V2, bundle) + _semantic_problems_v2(bundle)
    return [
        f"bundle_version: this RailDash only accepts evidence bundle v{BUNDLE_VERSION} "
        f"or v{BUNDLE_VERSION_V2}, got {version!r}"
    ]


def _schema_problems(validator: Draft202012Validator, bundle: Any) -> list[str]:
    return [
        f"{'.'.join(str(part) for part in error.path) or 'bundle'}: {error.message}"
        for error in sorted(validator.iter_errors(bundle), key=str)
    ]


def _common_semantic_problems(bundle: dict[str, Any]) -> tuple[list[str], set[str]]:
    """The checks v1 and v2 share: `collected_at` is UTC, and no two
    attestations share an id. Returns the problems and the attestation ids."""
    problems: list[str] = []
    collected_at = bundle.get("collected_at")
    if isinstance(collected_at, str):
        try:
            parsed = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None and (parsed.tzinfo is None or parsed.utcoffset() != timedelta(0)):
            problems.append("collected_at: date-time must be UTC")
    attestations = bundle.get("attestations")
    attestation_ids: set[str] = set()
    for index, entry in enumerate(attestations if isinstance(attestations, list) else []):
        if not isinstance(entry, dict):
            continue
        identifier = entry.get("id")
        if not isinstance(identifier, str):
            continue
        if identifier in attestation_ids:
            problems.append(f"attestations[{index}].id: duplicate attestation id")
        else:
            attestation_ids.add(identifier)
    return problems, attestation_ids


def _deployment_byte_problems(value: Any, where: str) -> list[str]:
    """A deployment value's strings, measured in UTF-8 bytes (`maxLength`
    counts code points)."""
    if not isinstance(value, dict):
        return []
    return [
        f"{where}.{key}: exceeds byte bound"
        for key, item in value.items()
        if isinstance(item, str) and len(item.encode("utf-8")) > DEPLOYMENT_VALUE_MAX_BYTES
    ]


def _semantic_problems(bundle: dict[str, Any]) -> list[str]:
    """The rules the published schema cannot express, or deliberately
    doesn't: every attestation_ref names a real attestation; two attestations
    never share an id (`uniqueItems` checks whole-item equality, not one
    field); a deployment value's byte length is measured in UTF-8 bytes,
    which `maxLength` cannot — it counts Unicode code points;
    `collected_at` must be UTC, which RailDash requires but the shared
    schema's `format: date-time` (any offset, per RFC 3339) does not — this
    predates the shared schema and is kept for the same reason `_date_time`
    still enforces it on `locked_at`; and an `observed_file_access` value's
    byte bound (its shape is the schema's own `file_access_value`)."""
    problems, attestation_ids = _common_semantic_problems(bundle)
    attributes = bundle.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    problems.extend(_attestation_ref_problems("attributes", attributes, attestation_ids))
    deployment = attributes.get("deployment")
    if isinstance(deployment, dict) and deployment.get("status") == "ANSWERED":
        problems.extend(
            _deployment_byte_problems(deployment.get("value"), "attributes.deployment.value")
        )
    problems.extend(
        _file_access_byte_problems(attributes.get(FILE_ACCESS_ATTRIBUTE), "attributes")
    )
    return problems


def _file_access_byte_problems(attribute: Any, where: str) -> list[str]:
    """An ANSWERED or PARTIAL `observed_file_access` value's byte bound."""
    if not isinstance(attribute, dict) or attribute.get("status") not in FILE_ACCESS_VALUED_STATUSES:
        return []
    size = len(json.dumps(attribute.get("value"), separators=(",", ":")))
    if size > FILE_ACCESS_VALUE_MAX_BYTES:
        return [f"{where}.{FILE_ACCESS_ATTRIBUTE}.value: exceeds byte bound"]
    return []


def _attestation_ref_problems(
    where: str, attributes: Any, attestation_ids: set[str]
) -> list[str]:
    """Every `attestation_ref` in one attribute map must name a real attestation."""
    problems: list[str] = []
    attributes = attributes if isinstance(attributes, dict) else {}
    for name, attribute in attributes.items():
        if not isinstance(attribute, dict):
            continue
        reference = attribute.get("attestation_ref")
        if reference is not None and reference not in attestation_ids:
            problems.append(f"{where}.{name}.attestation_ref: does not resolve")
    return problems


def _egress_value_problems(where: str, attributes: Any) -> list[str]:
    """An ANSWERED or PARTIAL `egress_containment` value in a v2 scope, held
    to v1's `egress_containment_value` (DR-207)."""
    attribute = attributes.get(EGRESS_ATTRIBUTE) if isinstance(attributes, dict) else None
    if not isinstance(attribute, dict) or attribute.get("status") not in FILE_ACCESS_VALUED_STATUSES:
        return []
    return [
        f"{where}.{EGRESS_ATTRIBUTE}.value"
        + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.path)
        + f": {error.message}"
        for error in _EGRESS_VALUE_VALIDATOR.iter_errors(attribute.get("value"))
    ]


def _semantic_problems_v2(bundle: dict[str, Any]) -> list[str]:
    """The rules the published v2 schema cannot express (per its own
    `$comment`): every `attestation_ref`, in `sandbox.attributes` or any
    agent's `attributes`, names a real attestation; two attestations never
    share an id; `agents[].agent_key` is sorted ascending, unique, and never
    the reserved `"default"` (kept for the unkeyed v1-compatible path); and
    `collected_at` must be UTC, for the same reason v1 requires it (see
    `_semantic_problems`); and an ANSWERED sandbox `deployment` value has
    v1's shape and byte bound, since it resolves to the same identity; and
    an ANSWERED or PARTIAL sandbox `observed_file_access` value has v1's
    `file_access_value` shape and its byte bound (DR-154); and an ANSWERED
    or PARTIAL `egress_containment` value, in any scope, has v1's
    `egress_containment_value` shape (DR-207)."""
    problems, attestation_ids = _common_semantic_problems(bundle)

    sandbox = bundle.get("sandbox")
    sandbox_attributes = sandbox.get("attributes") if isinstance(sandbox, dict) else None
    problems.extend(_attestation_ref_problems("sandbox.attributes", sandbox_attributes, attestation_ids))
    deployment = (sandbox_attributes or {}).get("deployment") if isinstance(sandbox_attributes, dict) else None
    if isinstance(deployment, dict) and deployment.get("status") == "ANSWERED":
        value = deployment.get("value")
        for error in _DEPLOYMENT_VALUE_VALIDATOR.iter_errors(value):
            problems.append(f"sandbox.attributes.deployment.value: {error.message}")
        problems.extend(_deployment_byte_problems(value, "sandbox.attributes.deployment.value"))
    file_access = (
        sandbox_attributes.get(FILE_ACCESS_ATTRIBUTE)
        if isinstance(sandbox_attributes, dict)
        else None
    )
    if isinstance(file_access, dict) and file_access.get("status") in FILE_ACCESS_VALUED_STATUSES:
        for error in _FILE_ACCESS_VALUE_VALIDATOR.iter_errors(file_access.get("value")):
            location = "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.path)
            problems.append(
                f"sandbox.attributes.{FILE_ACCESS_ATTRIBUTE}.value{location}: {error.message}"
            )
        problems.extend(_file_access_byte_problems(file_access, "sandbox.attributes"))
    problems.extend(_egress_value_problems("sandbox.attributes", sandbox_attributes))

    agents = bundle.get("agents")
    agent_keys: list[str] = []
    for index, agent in enumerate(agents if isinstance(agents, list) else []):
        if not isinstance(agent, dict):
            continue
        agent_key = agent.get("agent_key")
        if isinstance(agent_key, str):
            agent_keys.append(agent_key)
            # The schema's `pattern` is a search, where `$` also matches
            # before a trailing newline; the key becomes an identity.
            if not _V2_AGENT_KEY.fullmatch(agent_key):
                problems.append(f"agents[{index}].agent_key: invalid agent_key")
        problems.extend(
            _attestation_ref_problems(
                f"agents[{index}].attributes", agent.get("attributes"), attestation_ids
            )
        )
        problems.extend(_egress_value_problems(f"agents[{index}].attributes", agent.get("attributes")))
    if agent_keys != sorted(agent_keys):
        problems.append("agents: agent_key values must be sorted ascending")
    if len(set(agent_keys)) != len(agent_keys):
        problems.append("agents: agent_key values must be unique")
    if DEFAULT_AGENT_KEY in agent_keys:
        problems.append(
            f"agents: agent_key must not be {DEFAULT_AGENT_KEY!r} "
            "(reserved for the unkeyed v1-compatible path)"
        )
    return problems


def resolve_identity(
    bundle: dict[str, Any], agent_key: str | None = None
) -> dict[str, Any]:
    """Resolve identity by contract precedence, never by resemblance.

    v2's shared `deployment` fact (when present) lives in `sandbox.attributes`
    rather than the bundle's own top-level `attributes` (see the v2 schema's
    `$comment`), so the deployment-identity precedence below reads from
    whichever the bundle's version actually carries. Below deployment
    identity, a v2 bundle never needs the caller's `agent_key` fallback:
    every one of its agents already carries its own `agent_key` (validated
    sorted, unique, and non-default by `_semantic_problems_v2`), so the whole
    bundle's identity is that keyed set — distinct from v1's single unkeyed
    `local_agent_key`, which is why it is a separate identity kind rather than
    a single-item case of it.
    """
    is_v2 = bundle.get("bundle_version") == BUNDLE_VERSION_V2
    attributes = bundle["sandbox"]["attributes"] if is_v2 else bundle["attributes"]
    deployment = attributes.get("deployment") or {}
    value = deployment.get("value") if deployment.get("status") == "ANSWERED" else {}
    value = value if isinstance(value, dict) else {}
    if all(key in value for key in DEPLOYMENT_ENV_KEYS):
        return {
            "kind": "deployment_environment",
            "value": {
                "deployment": value["RAIL_DEPLOYMENT"],
                "namespace": value["RAIL_NAMESPACE"],
            },
        }
    if all(key in value for key in DEPLOYMENT_COMPOSE_KEYS):
        return {
            "kind": "deployment_compose",
            "value": {
                "host_id": bundle["host_id"],
                "project": value["com.docker.compose.project"],
                "service": value["com.docker.compose.service"],
            },
        }
    if is_v2:
        return {
            "kind": "local_agent_keys",
            "value": [agent["agent_key"] for agent in bundle["agents"]],
        }
    if not isinstance(agent_key, str) or not agent_key:
        raise IdentityRequiredError("unkeyed bundle requires a local agent_key")
    if agent_key != agent_key.strip():
        raise IdentityRequiredError("agent_key must not have surrounding whitespace")
    if len(agent_key) > MAX_AGENT_KEY_CHARS:
        raise IdentityRequiredError(
            f"agent_key exceeds {MAX_AGENT_KEY_CHARS} characters"
        )
    return {"kind": "local_agent_key", "value": agent_key}


def alignment_problems(alignment: Any) -> list[str]:
    """Validate the closed alignment-version v1 object used by comparison.

    Contract v1 of the alignment object covers both evidence-bundle
    versions: only `contract.bundle_version` and the identity kind differ.
    """
    if not isinstance(alignment, dict):
        return ["alignment version must be an object"]
    required = {
        "alignment_contract_version",
        "alignment_version_id",
        "version",
        "locked_at",
        "agent_identity",
        "contract",
        "asp",
    }
    problems: list[str] = []
    if set(alignment) != required:
        problems.append("alignment version fields do not match contract v1")
    if alignment.get("alignment_contract_version") != ALIGNMENT_CONTRACT_VERSION:
        problems.append("alignment_contract_version: must be 1")
    for key in ("alignment_version_id", "version"):
        _non_empty_string(alignment.get(key), key, problems)
    _date_time(alignment.get("locked_at"), "locked_at", problems)
    problems.extend(identity_problems(alignment.get("agent_identity")))
    contract = alignment.get("contract")
    if not isinstance(contract, dict) or set(contract) != {
        "bundle_version",
        "rule_pack_version",
    }:
        problems.append("contract: must contain only bundle_version and rule_pack_version")
    elif contract.get("bundle_version") not in (
        BUNDLE_VERSION,
        BUNDLE_VERSION_V2,
    ) or not _positive_integer(
        contract.get("rule_pack_version")
    ):
        problems.append("contract: unsupported bundle or rule-pack version")
    asp = alignment.get("asp")
    if not isinstance(asp, dict) or set(asp) != {"asp_id", "digest"}:
        problems.append("asp: must contain only asp_id and digest")
    else:
        _non_empty_string(asp.get("asp_id"), "asp.asp_id", problems)
        if not isinstance(asp.get("digest"), str) or not _DIGEST.fullmatch(
            asp["digest"]
        ):
            problems.append("asp.digest: must be a lowercase sha256 digest")
    return problems


def compare_alignment(
    alignment: dict[str, Any],
    baseline_raw: bytes,
    current_raw: bytes,
    *,
    current_agent_key: str | None = None,
) -> dict[str, Any]:
    """Compare exact bytes to one active alignment, returning a redacted result."""
    problems = alignment_problems(alignment)
    if problems:
        raise ValueError("invalid alignment version: " + "; ".join(problems[:5]))
    is_v2 = alignment["contract"]["bundle_version"] == BUNDLE_VERSION_V2
    contract_version = DRIFT_CONTRACT_VERSION_V2 if is_v2 else DRIFT_CONTRACT_VERSION

    def not_comparable(reason: str) -> dict[str, Any]:
        return _not_comparable(reason, contract_version)

    if bundle_digest(baseline_raw) != alignment["asp"]["digest"]:
        return not_comparable("ALIGNMENT_INTEGRITY_FAILED")
    try:
        baseline = parse_bundle(baseline_raw)
        current = parse_bundle(current_raw)
    except BundleValidationError:
        return not_comparable("INVALID_BUNDLE")

    expected_contract = alignment["contract"]
    for bundle in (baseline, current):
        if (
            bundle["bundle_version"] != expected_contract["bundle_version"]
            or bundle["rule_pack_version"] != expected_contract["rule_pack_version"]
        ):
            return not_comparable("CONTRACT_MISMATCH")

    expected_identity = alignment["agent_identity"]
    baseline_key = (
        expected_identity["value"]
        if expected_identity["kind"] == "local_agent_key"
        else None
    )
    try:
        baseline_identity = resolve_identity(baseline, baseline_key)
        current_identity = resolve_identity(current, current_agent_key)
    except IdentityRequiredError:
        return not_comparable("IDENTITY_MISMATCH")
    if baseline_identity != expected_identity:
        return not_comparable("ALIGNMENT_INTEGRITY_FAILED")
    if current_identity != expected_identity:
        return not_comparable("IDENTITY_MISMATCH")

    changes = _bundle_changes_v2(baseline, current) if is_v2 else _bundle_changes(baseline, current)
    total = len(changes)
    result = {
        "drift_contract_version": contract_version,
        "comparable": True,
        "has_drift": bool(changes),
        "reason": None,
        "change_count": total,
        "changes": [],
        "truncated": False,
    }
    for change in changes[:MAX_DRIFT_CHANGES]:
        result["changes"].append(change)
        if _serialized_size(result) > MAX_DRIFT_RESULT_BYTES:
            result["changes"].pop()
            break
    result["truncated"] = len(result["changes"]) < total
    return result


def _serialized_size(value: dict[str, Any]) -> int:
    """Return the compact UTF-8 wire size used for the public JSON result."""
    return len(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def _not_comparable(reason: str, contract_version: int) -> dict[str, Any]:
    if reason not in NON_COMPARABLE_REASONS:
        raise ValueError(f"unknown non-comparable reason: {reason}")
    return {
        "drift_contract_version": contract_version,
        "comparable": False,
        "has_drift": None,
        "reason": reason,
        "change_count": 0,
        "changes": [],
        "truncated": False,
    }


def _bundle_changes(
    baseline: dict[str, Any], current: dict[str, Any]
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    # The producer repeats copy identity in container_identity's value, and a
    # dynamic attribute's value is where this copy runs. Preserve their
    # evidence qualifiers as drift, but omit only those copy-specific values
    # after the explicit logical-identity gate (`_comparison_attributes`).
    baseline_attributes, current_attributes = _window_attributes(
        _comparison_attributes(baseline["attributes"]),
        _comparison_attributes(current["attributes"]),
        implied=V1_WINDOW_LISTS,
    )
    changes.extend(
        _map_changes(
            baseline_attributes,
            current_attributes,
            "ATTRIBUTE",
            ATTRIBUTE_FIELD_ORDER,
        )
    )
    changes.extend(
        _map_changes(
            baseline["inputs_attempted"],
            current["inputs_attempted"],
            "SOURCE",
            SOURCE_FIELD_ORDER,
        )
    )
    changes.extend(_attestation_changes(baseline, current))
    return changes


def _attestation_changes(
    baseline: dict[str, Any], current: dict[str, Any]
) -> list[dict[str, Any]]:
    """Changes to the bundle's attestations, matched by id."""
    return _map_changes(
        {entry["id"]: entry for entry in baseline.get("attestations", [])},
        {entry["id"]: entry for entry in current.get("attestations", [])},
        "ATTESTATION",
        ATTESTATION_FIELD_ORDER,
        ignored_fields={"id"},
    )


def _scope_changes(
    scope: dict[str, Any], baseline: dict[str, Any], current: dict[str, Any]
) -> list[dict[str, Any]]:
    """One v2 scope's attribute and source changes, each tagged with the
    scope's `agent_key` (null for the shared sandbox scope)."""
    changes = _map_changes(
        *_window_attributes(
            _comparison_attributes(baseline["attributes"]),
            _comparison_attributes(current["attributes"]),
        ),
        "ATTRIBUTE",
        ATTRIBUTE_FIELD_ORDER,
    )
    changes.extend(
        _map_changes(
            baseline["inputs_attempted"],
            current["inputs_attempted"],
            "SOURCE",
            SOURCE_FIELD_ORDER,
        )
    )
    return [{**scope, **change} for change in changes]


def _bundle_changes_v2(
    baseline: dict[str, Any], current: dict[str, Any]
) -> list[dict[str, Any]]:
    """Compare two evidence-bundle v2 collections scope by scope (DR-109).

    The shared sandbox scope comes first, then every agent in `agent_key`
    order, then the collection's attestations -- the same per-scope order v1
    uses for its one scope. An agent present on only one side is one
    AGENT_ADDED/AGENT_REMOVED change, not a removal of each of its
    attributes; an agent whose `discovery_status` moved (an `available`
    agent RailMon can no longer find is `not_found`) is AGENT_CHANGED,
    followed by whatever its attributes and sources did as a result.
    """
    changes = _scope_changes({"agent_key": None}, baseline["sandbox"], current["sandbox"])
    baseline_agents = {agent["agent_key"]: agent for agent in baseline["agents"]}
    current_agents = {agent["agent_key"]: agent for agent in current["agents"]}
    for key in sorted(baseline_agents.keys() - current_agents.keys()):
        changes.append({"agent_key": key, "type": "AGENT_REMOVED", "name": key, "fields": []})
    for key in sorted(current_agents.keys() - baseline_agents.keys()):
        changes.append({"agent_key": key, "type": "AGENT_ADDED", "name": key, "fields": []})
    for key in sorted(baseline_agents.keys() & current_agents.keys()):
        before, after = baseline_agents[key], current_agents[key]
        fields = [field for field in AGENT_FIELD_ORDER if before[field] != after[field]]
        if fields:
            changes.append(
                {"agent_key": key, "type": "AGENT_CHANGED", "name": key, "fields": fields}
            )
        changes.extend(_scope_changes({"agent_key": key}, before, after))
    changes.extend(
        {"agent_key": None, **change} for change in _attestation_changes(baseline, current)
    )
    return changes


# The lists RailMon's composer windows in v2 (`compose_evidence_bundle_v2.
# WINDOW_LISTS`, which says consumers hard-code it; Rail Center's
# `alignment._WINDOW_LISTS` is the same table). A v1 bundle carries the same
# lists from the same collector but its schema has no `window` member, so a
# v1 comparison reads them by this table: otherwise a re-scan of an unchanged
# agent that saw fewer hosts, or the same hosts a different number of times,
# would be drift (DR-217, found by RC-411).
V1_WINDOW_LISTS: dict[str, dict[str, list[str]]] = {
    "tool_names": {},
    "observed_destinations": {"ignore": ["count", "error_count"]},
    "undeclared_destinations": {},
    "observed_listeners": {},
    "observed_ingress_peers": {},
    "observed_file_access": {"union": ["exec", "read", "write"]},
}


def _comparison_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    # A copy-specific value is never drift; its evidence qualifiers still are
    # (DR-118), so a probe that stops answering is reported.
    projected = dict(attributes)
    for name in ("container_identity", *sorted(DYNAMIC_ATTRIBUTES)):
        attribute = projected.get(name)
        if isinstance(attribute, dict):
            projected[name] = {key: value for key, value in attribute.items() if key != "value"}
    return projected


def _window_attributes(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    implied: dict[str, dict[str, list[str]]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project attributes that hold a collector's window (DR-169) for comparison.

    Such a list holds only what the collector's window saw, so its value is
    drift only when the current window saw something the baseline did not:
    a new item, or a `union` key newly true. A quieter window is not. One
    declaration covers both sides, the current reading's if it has one, so
    items are keyed the same way; the member itself is never drift. A v2
    reading without a `window` on either side is compared exactly; v1 cannot
    declare one, so its window lists come from `implied` (DR-217).
    """
    baseline, current = dict(baseline), dict(current)
    for name in baseline.keys() & current.keys():
        before, after = baseline[name], current[name]
        window = after.get("window", before.get("window", (implied or {}).get(name)))
        if window is None:
            continue
        before = {key: value for key, value in before.items() if key != "window"}
        after = {key: value for key, value in after.items() if key != "window"}
        before_value, after_value = before.get("value"), after.get("value")
        if name == FILE_ACCESS_ATTRIBUTE:
            before_value, after_value = _comparable_file_access(before, after_value)
        if not _window_value_drift(before_value, after_value, window):
            before.pop("value", None)
            after.pop("value", None)
        baseline[name], current[name] = before, after
    return baseline, current


# DR-229 (railmon#97): a file named with a fresh uuid each time, such as
# OpenClaw's `sessions.json.1.<uuid>.tmp` written on every turn, outside the
# temp directories RailMon folds. Within one windowed file-access comparison
# each uuid in a file's name reads as `*`, so the same file written again
# under a new uuid is not newly written. The directory and the rest of the
# name still count. The price, as for RailMon's temp names: a new file named
# like one already in the baseline but for its uuid is aligned. A run of
# uuids is one `*`: two `*` side by side would be a `**`, which as a
# guardrail glob crosses directories.
_UUIDS = re.compile(r"(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})+")
# RailMon's note on a file list whose cap left reads out, whatever its
# reason (railmon `tools/scan/evidence_bundle.py`, unchanged through rule pack 12).
# A reworded note only turns the rule off, which reports drift, not less.
_READS_LEFT_OUT = "more distinct files than the cap (reads are left out first)"
_FILES_MAY_BE_MISSING = ": files may be missing from this list"


def only_reads_left_out(attribute: Any) -> bool:
    """Whether `observed_file_access` is `PARTIAL` only because RailMon's cap
    left reads out (DR-230): reason `SIZE_CAP_EXCEEDED`, and the note's one
    gap is the read cap. RailMon keeps every write and exec ahead of reads,
    and names any other gap in that note (a write or exec past the cap, a
    path it could not name, a probe restart, stale or lost events), so such
    a list still lists every file written. Anything else is False."""
    if not isinstance(attribute, dict) or attribute.get("status") != "PARTIAL":
        return False
    note = attribute.get("note")
    return (
        attribute.get("reason") == "SIZE_CAP_EXCEEDED"
        and isinstance(note, str)
        and _FILES_MAY_BE_MISSING in note
        and note.partition(_FILES_MAY_BE_MISSING)[0] == _READS_LEFT_OUT
    )


def uuid_name_template(path: str) -> str | None:
    """`path` with each run of uuids in its file name made `*`, or None when the
    name has none, or the path already has a `*` (RailMon's own templates),
    which as a guardrail glob would match more than it says."""
    if "*" in path:
        return None
    directory, slash, name = path.rpartition("/")
    templated = _UUIDS.sub("*", name)
    return directory + slash + templated if templated != name else None


def _comparable_file_access(
    baseline: dict[str, Any], current_value: Any
) -> tuple[Any, Any]:
    """Both `observed_file_access` values as a windowed comparison reads them.

    Each uuid in a file name is folded (`uuid_name_template`). And when the
    baseline's list left reads out at RailMon's cap, a current read-only
    entry it doesn't list is dropped if it sorts after the baseline's last
    listed read-only entry: RailMon keeps every write and exec, then reads by
    (path, layer), so whether its window saw it is unknown, and an unknown
    is not drift. One that sorts before that entry would have been listed,
    so it is still newly seen. Entries are taken as RailMon sent
    them, before folding, since that is the order its cap used.
    """
    before = baseline.get("value")
    if not isinstance(before, list) or not isinstance(current_value, list):
        return before, current_value

    def read_only(entry: dict[str, Any]) -> bool:
        return entry.get("write") is not True and entry.get("exec") is not True

    def key(entry: dict[str, Any]) -> tuple[str, bool]:
        return (entry["path"], entry.get("layer") is True)

    entries = [entry for entry in before if isinstance(entry, dict) and isinstance(entry.get("path"), str)]
    if (
        baseline.get("status") == "PARTIAL"
        and _READS_LEFT_OUT in str(baseline.get("note") or "")
    ):
        listed = {key(entry) for entry in entries}
        last_read = max((key(entry) for entry in entries if read_only(entry)), default=None)
        current_value = [
            entry for entry in current_value
            if not (
                isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and read_only(entry)
                and key(entry) not in listed
                and (last_read is None or key(entry) > last_read)
            )
        ]

    def folded(value: list[Any]) -> list[Any]:
        return [
            {**entry, "path": uuid_name_template(entry["path"]) or entry["path"]}
            if isinstance(entry, dict) and isinstance(entry.get("path"), str) else entry
            for entry in value
        ]

    return folded(before), folded(current_value)


def _window_value_drift(before: Any, after: Any, window: dict[str, Any]) -> bool:
    # A window that saw nothing is ABSENT with a null value: an empty list.
    before = [] if before is None else before
    after = [] if after is None else after
    if not isinstance(before, list) or not isinstance(after, list):
        return before != after
    ignore = set(window.get("ignore", ()))
    union = set(window.get("union", ()))

    def seen(items: list[Any]) -> dict[str, set[str]]:
        # Item identity without its counts and union flags -> flags seen true.
        found: dict[str, set[str]] = {}
        for item in items:
            flags: set[str] = set()
            if isinstance(item, dict):
                flags = {key for key in union if item.get(key) is True}
                item = {key: value for key, value in item.items() if key not in ignore | union}
            found.setdefault(json.dumps(item, sort_keys=True), set()).update(flags)
        return found

    previous = seen(before)
    return any(
        key not in previous or not flags <= previous[key]
        for key, flags in seen(after).items()
    )


def _map_changes(
    baseline: dict[str, Any],
    current: dict[str, Any],
    prefix: str,
    field_order: tuple[str, ...],
    *,
    ignored_fields: set[str] | None = None,
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    ignored_fields = ignored_fields or set()
    baseline_names = set(baseline)
    current_names = set(current)
    for name in sorted(baseline_names - current_names):
        changes.append({"type": f"{prefix}_REMOVED", "name": name, "fields": []})
    for name in sorted(current_names - baseline_names):
        changes.append({"type": f"{prefix}_ADDED", "name": name, "fields": []})
    for name in sorted(baseline_names & current_names):
        before = baseline[name]
        after = current[name]
        if before == after:
            continue
        fields = [
            field
            for field in field_order
            if field not in ignored_fields and before.get(field) != after.get(field)
        ]
        changes.append({"type": f"{prefix}_CHANGED", "name": name, "fields": fields})
    return changes


def identity_problems(identity: Any) -> list[str]:
    if not isinstance(identity, dict) or set(identity) != {"kind", "value"}:
        return ["agent_identity: must contain only kind and value"]
    kind = identity.get("kind")
    if kind not in IDENTITY_KINDS:
        return ["agent_identity.kind: unsupported"]
    value = identity.get("value")
    if kind == "local_agent_keys":
        if (
            not isinstance(value, list)
            or not value
            or any(not isinstance(key, str) or not _V2_AGENT_KEY.fullmatch(key) for key in value)
            or value != sorted(set(value))
        ):
            return ["agent_identity.value: invalid local agent_key list"]
        return []
    if kind == "local_agent_key":
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > MAX_AGENT_KEY_CHARS
        ):
            return ["agent_identity.value: invalid local agent_key"]
        return []
    required = (
        {"deployment", "namespace"}
        if kind == "deployment_environment"
        else {"host_id", "project", "service"}
    )
    if not isinstance(value, dict) or set(value) != required:
        return ["agent_identity.value: fields do not match identity kind"]
    if any(not isinstance(item, str) or not item for item in value.values()):
        return ["agent_identity.value: every identity field must be non-empty"]
    return []


def _non_empty_string(value: Any, where: str, problems: list[str]) -> None:
    if not isinstance(value, str) or not value:
        problems.append(f"{where}: must be a string of at least 1 characters")


def _date_time(value: Any, where: str, problems: list[str]) -> None:
    if not isinstance(value, str):
        problems.append(f"{where}: must be an RFC 3339 date-time")
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        problems.append(f"{where}: must be an RFC 3339 date-time")
        return
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        problems.append(f"{where}: date-time must be UTC")


def _positive_integer(value: Any) -> bool:
    return type(value) is int and value >= 1
