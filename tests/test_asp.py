from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from raildash.asp import (
    MAX_DRIFT_CHANGES,
    BundleValidationError,
    IdentityRequiredError,
    alignment_problems,
    bundle_digest,
    compare_alignment,
    parse_bundle,
    resolve_identity,
)

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMAS = Path(__file__).parents[1] / "raildash" / "schemas"
BASELINE_RAW = (FIXTURES / "evidence-bundle-v1.json").read_bytes()


def bundle() -> dict:
    return copy.deepcopy(parse_bundle(BASELINE_RAW))


def raw(value: dict, *, sort_keys: bool = True, indent: int | None = None) -> bytes:
    return json.dumps(value, sort_keys=sort_keys, indent=indent, ensure_ascii=False).encode()


def alignment(
    baseline_raw: bytes = BASELINE_RAW,
    *,
    identity: dict | None = None,
    rule_pack_version: int = 1,
) -> dict:
    baseline = parse_bundle(baseline_raw)
    return {
        "alignment_contract_version": 1,
        "alignment_version_id": "aspver-fixture-v1",
        "version": "v1.0",
        "locked_at": "2026-09-24T00:01:00Z",
        "agent_identity": identity or resolve_identity(baseline),
        "contract": {
            "bundle_version": 1,
            "rule_pack_version": rule_pack_version,
        },
        "asp": {"asp_id": "asp-fixture-001", "digest": bundle_digest(baseline_raw)},
    }


def validate(schema_name: str, value: dict) -> None:
    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def test_real_railmon_fixture_passes_the_vendored_schema_and_runtime_validator():
    parsed = parse_bundle(BASELINE_RAW)
    validate("evidence-bundle-v1.schema.json", parsed)
    assert parsed["attributes"]["deployment"]["value"] == {
        "RAIL_DEPLOYMENT": "payments-agent",
        "RAIL_NAMESPACE": "production",
    }


def test_schema_and_runtime_both_restrict_windows_to_the_runtime_source():
    changed = bundle()
    changed["inputs_attempted"]["manifest"]["window_seconds"] = 60
    with pytest.raises(ValidationError):
        validate("evidence-bundle-v1.schema.json", changed)
    with pytest.raises(BundleValidationError, match="window_seconds"):
        parse_bundle(raw(changed))


@pytest.mark.parametrize(
    ("mutation", "problem"),
    [
        (lambda item: item.update(bundle_version=2), "bundle_version"),
        (lambda item: item["inputs_attempted"].pop("repo"), "four sources"),
        (
            lambda item: item["attributes"]["deployment"]["value"].update(
                unexpected="value"
            ),
            "unknown key",
        ),
        (
            lambda item: item["attributes"]["approval_policy"].pop("reason"),
            "reason",
        ),
        (
            lambda item: item["attributes"]["declared_destinations"].update(
                method=7
            ),
            "method",
        ),
        (
            lambda item: item["inputs_attempted"]["manifest"].update(
                window_seconds=60
            ),
            "window_seconds",
        ),
        (lambda item: item.update(collected_at="2026-09-24T01:00:00+01:00"), "UTC"),
    ],
)
def test_malformed_bundles_fail_closed(mutation, problem):
    changed = bundle()
    mutation(changed)
    with pytest.raises(BundleValidationError, match=problem):
        parse_bundle(raw(changed))


def test_digest_is_over_exact_received_bytes_not_parsed_json():
    compact = raw(bundle(), sort_keys=True)
    pretty = raw(bundle(), sort_keys=False, indent=2)
    assert json.loads(compact) == json.loads(pretty)
    assert bundle_digest(compact) != bundle_digest(pretty)


def test_identity_precedence_is_environment_then_host_scoped_compose():
    value = bundle()
    value["attributes"]["deployment"]["value"].update(
        {
            "com.docker.compose.project": "ignored-project",
            "com.docker.compose.service": "ignored-service",
        }
    )
    assert resolve_identity(value) == {
        "kind": "deployment_environment",
        "value": {"deployment": "payments-agent", "namespace": "production"},
    }

    del value["attributes"]["deployment"]["value"]["RAIL_NAMESPACE"]
    assert resolve_identity(value) == {
        "kind": "deployment_compose",
        "value": {
            "host_id": "fixture-host",
            "project": "ignored-project",
            "service": "ignored-service",
        },
    }


def test_unkeyed_or_half_keyed_bundle_requires_explicit_local_agent_key():
    value = bundle()
    value["attributes"]["deployment"]["value"] = {
        "RAIL_DEPLOYMENT": "half-only"
    }
    with pytest.raises(IdentityRequiredError, match="requires"):
        resolve_identity(value)
    assert resolve_identity(value, "developer-agent") == {
        "kind": "local_agent_key",
        "value": "developer-agent",
    }
    with pytest.raises(IdentityRequiredError, match="whitespace"):
        resolve_identity(value, " developer-agent ")


def test_local_agent_key_is_enforced_end_to_end_for_unkeyed_copies():
    baseline = bundle()
    current = bundle()
    baseline["attributes"]["deployment"]["value"] = {
        "RAIL_DEPLOYMENT": "half-only"
    }
    current["attributes"]["deployment"]["value"] = {
        "RAIL_DEPLOYMENT": "half-only"
    }
    baseline_raw = raw(baseline)

    active = alignment(
        baseline_raw,
        identity={"kind": "local_agent_key", "value": "developer-agent"},
    )
    result = compare_alignment(
        active,
        baseline_raw,
        raw(current),
        current_agent_key="developer-agent",
    )
    assert result["comparable"] is True
    assert result["has_drift"] is False

    mismatch = compare_alignment(
        active,
        baseline_raw,
        raw(current),
        current_agent_key="different-agent",
    )
    assert mismatch["comparable"] is False
    assert mismatch["reason"] == "IDENTITY_MISMATCH"


def test_exact_replay_is_aligned_after_copy_identity_fields_change():
    current = bundle()
    current.update(
        bundle_id="bnd-fixture-002",
        collected_at="2026-09-24T00:05:00Z",
        host_id="fixture-host-2",
        sandbox_name="fixture-agent-2",
    )
    current["attributes"]["container_identity"]["value"] = {
        "host_id": "fixture-host-2",
        "sandbox_name": "fixture-agent-2",
    }
    result = compare_alignment(alignment(), BASELINE_RAW, raw(current))
    validate("drift-result-v1.schema.json", result)
    assert result == {
        "drift_contract_version": 1,
        "comparable": True,
        "has_drift": False,
        "reason": None,
        "change_count": 0,
        "changes": [],
        "truncated": False,
    }


def test_attribute_qualifiers_and_sources_produce_stable_redacted_changes():
    current = bundle()
    current["attributes"]["tool_names"] = {
        "value": ["shell.run", "s3.object.get"],
        "status": "PARTIAL",
        "reason": "GATEWAY_MANAGED",
        "tier": "observed",
        "authored_by": "none",
        "method": "AgentSight window",
        "note": current["attributes"]["tool_names"]["note"],
    }
    current["inputs_attempted"]["runtime"]["window_seconds"] = 300
    result = compare_alignment(alignment(), BASELINE_RAW, raw(current))

    assert result["has_drift"] is True
    assert result["changes"] == [
        {
            "type": "ATTRIBUTE_CHANGED",
            "name": "tool_names",
            "fields": ["value", "status", "reason", "authored_by", "method"],
        },
        {
            "type": "SOURCE_CHANGED",
            "name": "runtime",
            "fields": ["window_seconds"],
        },
    ]
    serialized = json.dumps(result)
    assert "shell.run" not in serialized
    assert "s3.object.get" not in serialized


def test_attribute_and_attestation_add_remove_change_are_sorted():
    baseline = bundle()
    baseline["attestations"] = [
        {
            "id": "att-2",
            "root": "sigstore/fulcio",
            "claim": "image_provenance",
            "subject": "sha256:redacted",
            "verified_at": "2026-09-24T00:00:00Z",
            "verifier_version": "cosign/2.4.1",
        }
    ]
    baseline["attributes"]["old_attribute"] = {
        "value": True,
        "status": "ANSWERED",
        "tier": "observed",
        "authored_by": "none",
    }
    baseline_raw = raw(baseline)
    current = copy.deepcopy(baseline)
    del current["attributes"]["old_attribute"]
    current["attributes"]["new_attribute"] = {
        "value": False,
        "status": "ANSWERED",
        "tier": "observed",
        "authored_by": "none",
    }
    current["attestations"][0]["verifier_version"] = "cosign/2.5.0"
    current["attestations"].append(
        {
            "id": "att-1",
            "root": "customer/root",
            "claim": "agent_release",
            "subject": "release-1",
            "verified_at": "2026-09-24T00:02:00Z",
            "verifier_version": "verifier/1",
        }
    )
    result = compare_alignment(alignment(baseline_raw), baseline_raw, raw(current))
    assert result["changes"] == [
        {"type": "ATTRIBUTE_REMOVED", "name": "old_attribute", "fields": []},
        {"type": "ATTRIBUTE_ADDED", "name": "new_attribute", "fields": []},
        {"type": "ATTESTATION_ADDED", "name": "att-1", "fields": []},
        {
            "type": "ATTESTATION_CHANGED",
            "name": "att-2",
            "fields": ["verifier_version"],
        },
    ]


def test_key_order_and_formatting_do_not_create_drift_after_integrity_gate():
    current = bundle()
    current = dict(reversed(list(current.items())))
    result = compare_alignment(
        alignment(), BASELINE_RAW, raw(current, sort_keys=False, indent=4)
    )
    assert result["comparable"] is True
    assert result["has_drift"] is False


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("integrity", "ALIGNMENT_INTEGRITY_FAILED"),
        ("invalid", "INVALID_BUNDLE"),
        ("contract", "CONTRACT_MISMATCH"),
        ("identity", "IDENTITY_MISMATCH"),
    ],
)
def test_compatibility_gate_never_turns_failure_into_no_drift(change, reason):
    active = alignment()
    baseline_raw = BASELINE_RAW
    current = bundle()
    if change == "integrity":
        baseline_raw += b"\n"
    elif change == "invalid":
        current["attributes"]["tool_names"]["status"] = "UNKNOWN"
    elif change == "contract":
        current["rule_pack_version"] = 2
    else:
        current["attributes"]["deployment"]["value"]["RAIL_NAMESPACE"] = "staging"
    result = compare_alignment(active, baseline_raw, raw(current))
    assert result["comparable"] is False
    assert result["has_drift"] is None
    assert result["reason"] == reason


def test_alignment_contract_and_output_schemas_are_closed_and_versioned():
    active = alignment()
    assert alignment_problems(active) == []
    validate("alignment-version-v1.schema.json", active)
    for name in (
        "active-binding-v1.schema.json",
        "alignment-version-v1.schema.json",
        "drift-result-v1.schema.json",
        "evidence-bundle-v1.schema.json",
    ):
        schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)

    binding = {
        "binding_contract_version": 1,
        "agent_identity": active["agent_identity"],
        "alignment_version_id": active["alignment_version_id"],
        "switched_at": "2026-09-24T00:02:00Z",
    }
    validate("active-binding-v1.schema.json", binding)


def test_result_detail_is_bounded_without_losing_total_count():
    current = bundle()
    for index in range(MAX_DRIFT_CHANGES + 1):
        current["attributes"][f"added_{index:04d}"] = {
            "value": index,
            "status": "ANSWERED",
            "tier": "observed",
            "authored_by": "none",
        }
    result = compare_alignment(alignment(), BASELINE_RAW, raw(current))
    assert result["change_count"] == MAX_DRIFT_CHANGES + 1
    assert len(result["changes"]) == MAX_DRIFT_CHANGES
    assert result["truncated"] is True
    validate("drift-result-v1.schema.json", result)
