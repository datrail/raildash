from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from raildash.asp import (
    DEFAULT_DRIFT_PAGE_SIZE,
    DEPLOYMENT_KEYS,
    MAX_ASP_BUNDLE_BYTES,
    MAX_DRIFT_CHANGES,
    MAX_DRIFT_PAGE_SIZE,
    MAX_DRIFT_RESULT_BYTES,
    SCHEMA,
    BundleValidationError,
    IdentityRequiredError,
    alignment_problems,
    bundle_digest,
    bundle_problems,
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


def _sibling_railmon_schema() -> Path | None:
    """A sibling RailMon checkout, if one is present next to this repo: the
    workspace's `repo/datrail/{railmon,raildash}` layout, or dev-toolkits'
    flat sibling clone under `$RAIL_WORKSPACE_HOME`. Both put RailMon two
    directories up from this repo's own root. Standalone CI for this repo
    alone checks out only raildash, so it has neither — the drift check
    below skips there rather than failing for a reason outside the test's
    control (see its skip message)."""
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [repo_root.parent / "railmon" / "schemas" / "evidence-bundle-v1.schema.json"]
    workspace_home = os.environ.get("RAIL_WORKSPACE_HOME")
    if workspace_home:
        candidates.append(Path(workspace_home) / "railmon" / "schemas" / "evidence-bundle-v1.schema.json")
    return next((path for path in candidates if path.is_file()), None)


def test_vendored_schema_is_byte_for_byte_identical_to_railmon():
    railmon_schema = _sibling_railmon_schema()
    if railmon_schema is None:
        pytest.skip(
            "no sibling RailMon checkout found next to this repo (checked "
            "../railmon and $RAIL_WORKSPACE_HOME/railmon) — can't check for "
            "drift from here; this repo's own standalone CI has the same gap"
        )
    vendored = SCHEMAS / "evidence-bundle-v1.schema.json"
    assert vendored.read_bytes() == railmon_schema.read_bytes(), (
        "raildash/schemas/evidence-bundle-v1.schema.json has drifted from "
        "RailMon's copy — re-vendor it byte-for-byte from the pinned "
        "RailMon version"
    )


def test_deployment_keys_match_the_schemas_closed_set():
    # DEPLOYMENT_ENV_KEYS/DEPLOYMENT_COMPOSE_KEYS name the same four keys the
    # vendored schema's deployment_value $def closes over. Nothing else ties
    # the two together now that the schema enforces the closed set directly.
    assert set(DEPLOYMENT_KEYS) == set(SCHEMA["$defs"]["deployment_value"]["properties"])


def test_duplicate_attestation_id_is_rejected():
    # uniqueItems checks whole-item equality, not one field, so two
    # attestations sharing an id (everything else differing) is a rule only
    # code can enforce — the schema alone would accept it.
    changed = bundle()
    changed["attestations"] = [
        {
            "id": "att-1",
            "root": "sha256:aaaa",
            "claim": "cosign-verified",
            "subject": "sha256:aaaa",
            "verified_at": "2026-09-24T00:00:00Z",
            "verifier_version": "cosign/2.4.0",
        },
        {
            "id": "att-1",
            "root": "sha256:bbbb",
            "claim": "cosign-verified",
            "subject": "sha256:bbbb",
            "verified_at": "2026-09-24T00:00:01Z",
            "verifier_version": "cosign/2.4.0",
        },
    ]
    problems = bundle_problems(changed)
    assert any("duplicate attestation id" in p for p in problems), problems


@pytest.mark.parametrize("bad_attributes", [["not", "a", "dict"], "oops", True])
def test_a_wrong_typed_attributes_field_is_reported_not_a_crash(bad_attributes):
    # _semantic_problems used to reach `.items()`/`.get(...)` on whatever
    # `attributes` or `attestations` held without checking its type first —
    # a truthy non-dict/non-list value raised instead of being reported.
    changed = bundle()
    changed["attributes"] = bad_attributes
    problems = bundle_problems(changed)
    assert any("attributes" in p for p in problems), problems


def test_a_non_list_attestations_field_is_reported_not_a_crash():
    changed = bundle()
    changed["attestations"] = 42
    problems = bundle_problems(changed)
    assert any("attestations" in p for p in problems), problems


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
        (lambda item: item["inputs_attempted"].pop("repo"), "repo"),
        (
            lambda item: item["attributes"]["deployment"]["value"].update(
                unexpected="value"
            ),
            "unexpected",
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


def test_container_identity_qualifier_change_is_still_drift():
    current = bundle()
    current["attributes"]["container_identity"]["method"] = "new-collector"
    result = compare_alignment(alignment(), BASELINE_RAW, raw(current))
    assert result["comparable"] is True
    assert result["has_drift"] is True
    assert result["changes"] == [
        {
            "type": "ATTRIBUTE_CHANGED",
            "name": "container_identity",
            "fields": ["method"],
        }
    ]


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


def test_measured_bundle_headroom_and_request_bound_are_explicit():
    # The checked-in fixture is a real redacted RailMon bundle.  This expanded
    # fixture models a high-cardinality observation without manufacturing a
    # second schema: every added entry is a valid evidence attribute.
    representative = bundle()
    for index in range(1_000):
        representative["attributes"][f"representative_{index:04d}"] = {
            "value": [f"destination-{item:03d}.example" for item in range(10)],
            "status": "ANSWERED",
            "tier": "observed",
            "authored_by": "none",
            "method": "representative high-cardinality collection",
        }
    representative_raw = raw(representative)
    assert len(BASELINE_RAW) < 16 * 1024
    assert 128 * 1024 < len(representative_raw) < MAX_ASP_BUNDLE_BYTES // 2
    assert parse_bundle(representative_raw)["bundle_version"] == 1

    with pytest.raises(BundleValidationError, match=str(MAX_ASP_BUNDLE_BYTES)):
        parse_bundle(b" " * (MAX_ASP_BUNDLE_BYTES + 1))


def test_result_has_serialized_byte_bound_and_shared_pagination_limits():
    current = bundle()
    # Long attribute names make the byte cap bind before the count cap while
    # keeping the result redacted and the input below its independent limit.
    for index in range(MAX_DRIFT_CHANGES):
        current["attributes"][f"changed_{index:04d}_" + ("x" * 700)] = {
            "value": index,
            "status": "ANSWERED",
            "tier": "observed",
            "authored_by": "none",
        }
    result = compare_alignment(alignment(), BASELINE_RAW, raw(current))
    wire = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()

    assert result["change_count"] == MAX_DRIFT_CHANGES
    assert len(result["changes"]) < result["change_count"]
    assert result["truncated"] is True
    assert len(wire) <= MAX_DRIFT_RESULT_BYTES
    assert (DEFAULT_DRIFT_PAGE_SIZE, MAX_DRIFT_PAGE_SIZE) == (100, 500)
    validate("drift-result-v1.schema.json", result)
