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

# The published v1 schema, vendored byte-for-byte from the pinned RailMon
# version (tests/test_asp.py asserts the copy hasn't drifted). It is the
# single source of truth for the evidence bundle's structure; only the rules
# it cannot express live in code below (`_semantic_problems`).
SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "evidence-bundle-v1.schema.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text())
_VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

BUNDLE_VERSION = SCHEMA["properties"]["bundle_version"]["const"]
ALIGNMENT_CONTRACT_VERSION = 1
DRIFT_CONTRACT_VERSION = 1
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
    {"deployment_environment", "deployment_compose", "local_agent_key"}
)
NON_COMPARABLE_REASONS = frozenset(
    {
        "IDENTITY_MISMATCH",
        "CONTRACT_MISMATCH",
        "INVALID_BUNDLE",
        "ALIGNMENT_INTEGRITY_FAILED",
        "NO_ACTIVE_ALIGNMENT",
    }
)
CHANGE_TYPES = frozenset(
    {
        "ATTRIBUTE_ADDED",
        "ATTRIBUTE_REMOVED",
        "ATTRIBUTE_CHANGED",
        "SOURCE_ADDED",
        "SOURCE_REMOVED",
        "SOURCE_CHANGED",
        "ATTESTATION_ADDED",
        "ATTESTATION_REMOVED",
        "ATTESTATION_CHANGED",
    }
)
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
    """The received bytes are not one Evidence Bundle Schema v1 document."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid evidence bundle: " + "; ".join(problems[:5]))


class IdentityRequiredError(ValueError):
    """An unkeyed bundle needs the local operator's explicit identity claim."""


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
    """Validate the published v1 schema plus the two rules it cannot express."""
    if not isinstance(bundle, dict):
        return ["bundle must be an object"]
    problems = [
        f"{'.'.join(str(part) for part in error.path) or 'bundle'}: {error.message}"
        for error in sorted(_VALIDATOR.iter_errors(bundle), key=str)
    ]
    problems.extend(_semantic_problems(bundle))
    return problems


def _semantic_problems(bundle: dict[str, Any]) -> list[str]:
    """The rules the published schema cannot express, or deliberately
    doesn't: every attestation_ref names a real attestation; two attestations
    never share an id (`uniqueItems` checks whole-item equality, not one
    field); a deployment value's byte length is measured in UTF-8 bytes,
    which `maxLength` cannot — it counts Unicode code points; and
    `collected_at` must be UTC, which RailDash requires but the shared
    schema's `format: date-time` (any offset, per RFC 3339) does not — this
    predates the shared schema and is kept for the same reason `_date_time`
    still enforces it on `locked_at`."""
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
    attributes = bundle.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    for name, attribute in attributes.items():
        if not isinstance(attribute, dict):
            continue
        reference = attribute.get("attestation_ref")
        if reference is not None and reference not in attestation_ids:
            problems.append(f"attributes.{name}.attestation_ref: does not resolve")
    deployment = attributes.get("deployment")
    if isinstance(deployment, dict) and deployment.get("status") == "ANSWERED":
        value = deployment.get("value")
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, str) and len(item.encode("utf-8")) > DEPLOYMENT_VALUE_MAX_BYTES:
                    problems.append(f"attributes.deployment.value.{key}: exceeds byte bound")
    return problems


def resolve_identity(
    bundle: dict[str, Any], agent_key: str | None = None
) -> dict[str, Any]:
    """Resolve identity by contract precedence, never by resemblance."""
    deployment = bundle["attributes"].get("deployment") or {}
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
    """Validate the closed alignment-version v1 object used by comparison."""
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
        _bounded_string(alignment.get(key), key, 1, None, problems)
    _date_time(alignment.get("locked_at"), "locked_at", problems)
    problems.extend(_identity_problems(alignment.get("agent_identity")))
    contract = alignment.get("contract")
    if not isinstance(contract, dict) or set(contract) != {
        "bundle_version",
        "rule_pack_version",
    }:
        problems.append("contract: must contain only bundle_version and rule_pack_version")
    elif contract.get("bundle_version") != BUNDLE_VERSION or not _positive_integer(
        contract.get("rule_pack_version")
    ):
        problems.append("contract: unsupported bundle or rule-pack version")
    asp = alignment.get("asp")
    if not isinstance(asp, dict) or set(asp) != {"asp_id", "digest"}:
        problems.append("asp: must contain only asp_id and digest")
    else:
        _bounded_string(asp.get("asp_id"), "asp.asp_id", 1, None, problems)
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
    if bundle_digest(baseline_raw) != alignment["asp"]["digest"]:
        return _not_comparable("ALIGNMENT_INTEGRITY_FAILED")
    try:
        baseline = parse_bundle(baseline_raw)
        current = parse_bundle(current_raw)
    except BundleValidationError:
        return _not_comparable("INVALID_BUNDLE")

    expected_contract = alignment["contract"]
    for bundle in (baseline, current):
        if (
            bundle["bundle_version"] != expected_contract["bundle_version"]
            or bundle["rule_pack_version"] != expected_contract["rule_pack_version"]
        ):
            return _not_comparable("CONTRACT_MISMATCH")

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
        return _not_comparable("IDENTITY_MISMATCH")
    if baseline_identity != expected_identity:
        return _not_comparable("ALIGNMENT_INTEGRITY_FAILED")
    if current_identity != expected_identity:
        return _not_comparable("IDENTITY_MISMATCH")

    changes = _bundle_changes(baseline, current)
    total = len(changes)
    result = {
        "drift_contract_version": DRIFT_CONTRACT_VERSION,
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


def _not_comparable(reason: str) -> dict[str, Any]:
    if reason not in NON_COMPARABLE_REASONS:
        raise ValueError(f"unknown non-comparable reason: {reason}")
    return {
        "drift_contract_version": DRIFT_CONTRACT_VERSION,
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
    # The producer repeats copy identity in this attribute's value. Preserve
    # its evidence qualifiers as drift, but omit only that copy-specific value
    # after the explicit logical-identity gate.
    baseline_attributes = _comparison_attributes(baseline["attributes"])
    current_attributes = _comparison_attributes(current["attributes"])
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
    baseline_attestations = {entry["id"]: entry for entry in baseline.get("attestations", [])}
    current_attestations = {entry["id"]: entry for entry in current.get("attestations", [])}
    changes.extend(
        _map_changes(
            baseline_attestations,
            current_attestations,
            "ATTESTATION",
            ATTESTATION_FIELD_ORDER,
            ignored_fields={"id"},
        )
    )
    return changes


def _comparison_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    projected = dict(attributes)
    container_identity = projected.get("container_identity")
    if isinstance(container_identity, dict):
        projected["container_identity"] = {
            key: value
            for key, value in container_identity.items()
            if key != "value"
        }
    return projected


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


def _identity_problems(identity: Any) -> list[str]:
    if not isinstance(identity, dict) or set(identity) != {"kind", "value"}:
        return ["agent_identity: must contain only kind and value"]
    kind = identity.get("kind")
    if kind not in IDENTITY_KINDS:
        return ["agent_identity.kind: unsupported"]
    value = identity.get("value")
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


def _bounded_string(
    value: Any,
    where: str,
    minimum: int,
    maximum: int | None,
    problems: list[str],
) -> None:
    if not isinstance(value, str) or len(value) < minimum:
        problems.append(f"{where}: must be a string of at least {minimum} characters")
    elif maximum is not None and len(value) > maximum:
        problems.append(f"{where}: exceeds {maximum} characters")


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
