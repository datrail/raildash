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
    DYNAMIC_ATTRIBUTES,
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
            "bundle_version": baseline["bundle_version"],
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


def _railmon_schema(name: str) -> Path | None:
    """RailMon's copy of a schema, if a RailMon checkout is reachable.

    `$RAILMON_SCHEMAS_DIR` if set (CI checks RailMon's `schemas/` out and
    points this at it), and only that. Otherwise a sibling checkout -- the workspace's
    `repo/datrail/{railmon,raildash}` layout -- at `../railmon`; and
    dev-toolkits' flat clone under `$RAIL_WORKSPACE_HOME/railmon`.
    """
    schemas_dir = os.environ.get("RAILMON_SCHEMAS_DIR")
    if schemas_dir:
        # Explicit, so no fallback: a wrong path must not quietly compare
        # against some other, possibly stale, checkout instead.
        path = Path(schemas_dir) / name
        return path if path.is_file() else None
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [repo_root.parent / "railmon" / "schemas" / name]
    workspace_home = os.environ.get("RAIL_WORKSPACE_HOME")
    if workspace_home:
        candidates.append(Path(workspace_home) / "railmon" / "schemas" / name)
    return next((path for path in candidates if path.is_file()), None)


def _running_in_ci() -> bool:
    return os.environ.get("CI", "").strip().lower() in {"1", "true", "yes"}


@pytest.mark.parametrize(
    "name", ["evidence-bundle-v1.schema.json", "evidence-bundle-v2.schema.json", "attribute-groups.json"]
)
def test_vendored_schema_is_byte_for_byte_identical_to_railmon(name: str):
    railmon_schema = _railmon_schema(name)
    if railmon_schema is None:
        message = (
            f"no RailMon schemas found ($RAILMON_SCHEMAS_DIR if set, otherwise "
            f"../railmon/schemas and $RAIL_WORKSPACE_HOME/railmon/schemas) -- "
            f"can't check {name} for drift"
        )
        # A skip is fine on a laptop with only this repo cloned; in CI it
        # would hide the one check that ties this copy to its producer, so
        # there it is a failure of the CI setup, not a reason to pass.
        if _running_in_ci():
            pytest.fail(message + "; CI must check RailMon out and set RAILMON_SCHEMAS_DIR")
        pytest.skip(message)
    vendored = SCHEMAS / name
    assert vendored.read_bytes() == railmon_schema.read_bytes(), (
        f"raildash/schemas/{name} has drifted from RailMon's copy "
        f"({railmon_schema}) -- re-vendor it byte-for-byte"
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
        # 2 is now a supported version (DR-109 M1), so a v1-shaped bundle
        # claiming it fails v2's schema instead -- an unsupported version
        # number is the case that stays a clean "bundle_version" refusal.
        (lambda item: item.update(bundle_version=3), "bundle_version"),
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


SANDBOX_ATTRIBUTE_NAMES = ("container_identity", "image_digest", "mounts", "deployment")


def _v2_bundle(*, agent_key: str = "executor") -> dict:
    """A minimal, schema-valid evidence bundle v2 (DR-109), split into one
    shared sandbox scope plus one keyed agent scope exactly the way
    `compose_evidence_bundle_v2.py`'s real composer splits its
    `SANDBOX_ATTRIBUTES` set — so `deployment` lands in `sandbox.attributes`,
    same as a real RailMon-composed bundle, not in the agent's."""
    changed = bundle()
    changed["bundle_version"] = 2
    inputs = changed.pop("inputs_attempted")
    attributes = changed.pop("attributes")
    sandbox_attributes = {
        name: attributes.pop(name) for name in SANDBOX_ATTRIBUTE_NAMES if name in attributes
    }
    changed["sandbox"] = {"inputs_attempted": inputs, "attributes": sandbox_attributes}
    changed["agents"] = [
        {
            "agent_key": agent_key,
            "discovery_status": "available",
            "inputs_attempted": inputs,
            "attributes": attributes,
        },
    ]
    return changed


def test_a_v2_bundle_passes_the_vendored_v2_schema_structurally():
    validate("evidence-bundle-v2.schema.json", _v2_bundle())


def test_a_v2_agent_railmon_cannot_scope_is_accepted_not_refused():
    # RailMon marks every agent-scoped attribute of an available agent with no
    # scan.config_roots BLIND/MULTI_AGENT_SCOPE_UNRESOLVED (railmon#31). A
    # vendored schema one reason behind refused that whole real collection.
    value = _v2_bundle()
    agent = value["agents"][0]
    agent["attributes"] = {
        name: {
            "value": None,
            "status": "BLIND",
            "reason": "MULTI_AGENT_SCOPE_UNRESOLVED",
            "tier": attribute.get("tier", "observed"),
        }
        for name, attribute in agent["attributes"].items()
    }
    assert agent["attributes"], "fixture must carry agent-scoped attributes"
    validate("evidence-bundle-v2.schema.json", value)
    assert bundle_problems(value) == []


def test_a_v2_bundle_is_accepted_and_deployment_identity_resolves_from_sandbox():
    # DR-109 M1: RailDash now consumes v2, not just refuses it by name.
    value = _v2_bundle()
    assert bundle_problems(value) == []
    parsed = parse_bundle(raw(value))
    assert resolve_identity(parsed) == {
        "kind": "deployment_environment",
        "value": {"deployment": "payments-agent", "namespace": "production"},
    }


def test_a_v2_bundle_with_no_deployment_identity_resolves_to_its_agent_keys():
    value = _v2_bundle()
    value["sandbox"]["attributes"]["deployment"]["status"] = "ABSENT"
    value["sandbox"]["attributes"]["deployment"]["value"] = None
    del value["sandbox"]["attributes"]["deployment"]["authored_by"]
    assert bundle_problems(value) == []
    assert resolve_identity(parse_bundle(raw(value))) == {
        "kind": "local_agent_keys",
        "value": ["executor"],
    }


def test_an_unsupported_bundle_version_is_refused_by_name_not_by_schema_noise():
    # A version this RailDash does not understand at all is refused with one
    # clear reason naming both versions it does accept, not the dozen
    # "unknown property"/"required field missing" errors either validator
    # would otherwise raise across every field the wrong version doesn't have.
    value = _v2_bundle()
    value["bundle_version"] = 3
    problems = bundle_problems(value)
    assert problems == [
        "bundle_version: this RailDash only accepts evidence bundle v1 or v2, got 3"
    ]

    with pytest.raises(BundleValidationError, match=r"^invalid evidence bundle: bundle_version.*only accepts.*v1.*v2"):
        parse_bundle(raw(value))


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda v: v["agents"].append({**v["agents"][0], "agent_key": "aardvark"}), "sorted ascending"),
        (lambda v: v["agents"].append({**v["agents"][0]}), "must be unique"),
        (lambda v: v["agents"][0].__setitem__("agent_key", "default"), "must not be 'default'"),
    ],
)
def test_v2_agent_key_rules_the_schema_cannot_express(mutate, expected):
    value = _v2_bundle()
    mutate(value)
    problems = bundle_problems(value)
    assert any(expected in problem for problem in problems), problems


def test_v2_attestation_ref_must_resolve_in_either_scope():
    value = _v2_bundle()
    value["sandbox"]["attributes"]["image_digest"]["attestation_ref"] = "missing"
    problems = bundle_problems(value)
    assert any(
        problem == "sandbox.attributes.image_digest.attestation_ref: does not resolve"
        for problem in problems
    ), problems

    value = _v2_bundle()
    value["agents"][0]["attributes"]["framework_identity"]["attestation_ref"] = "missing"
    problems = bundle_problems(value)
    assert any(
        problem == "agents[0].attributes.framework_identity.attestation_ref: does not resolve"
        for problem in problems
    ), problems


def _keys_only_v2(*keys: str) -> dict:
    """A v2 collection with no deployment identity, so it resolves to its
    sorted agent keys (`local_agent_keys`)."""
    value = _v2_bundle()
    value["sandbox"]["attributes"]["deployment"]["status"] = "ABSENT"
    value["sandbox"]["attributes"]["deployment"]["value"] = None
    del value["sandbox"]["attributes"]["deployment"]["authored_by"]
    template = value["agents"][0]
    value["agents"] = [{**copy.deepcopy(template), "agent_key": key} for key in sorted(keys)]
    return value


def test_a_v2_alignment_compares_scope_by_scope_under_contract_v2():
    # DR-109: locking a multi-agent collection used to be refused outright.
    baseline_raw = raw(_keys_only_v2("executor", "planner"))
    active = alignment(baseline_raw)
    assert alignment_problems(active) == []
    assert active["agent_identity"] == {"kind": "local_agent_keys", "value": ["executor", "planner"]}

    same = compare_alignment(active, baseline_raw, baseline_raw)
    validate("drift-result-v2.schema.json", same)
    assert same["drift_contract_version"] == 2
    assert same["has_drift"] is False

    current = _keys_only_v2("executor", "planner")
    current["bundle_id"] = "bnd-fixture-v2-next"
    current["agents"][1]["discovery_status"] = "not_found"
    current["agents"][1]["attributes"].pop("tool_names")
    result = compare_alignment(active, baseline_raw, raw(current))
    validate("drift-result-v2.schema.json", result)
    assert result["changes"] == [
        {"agent_key": "planner", "type": "AGENT_CHANGED", "name": "planner", "fields": ["discovery_status"]},
        {"agent_key": "planner", "type": "ATTRIBUTE_REMOVED", "name": "tool_names", "fields": []},
    ]


def test_a_changed_agent_key_set_is_a_different_identity_not_drift():
    # With no deployment identity the declared keys *are* the identity, so a
    # manifest that declares another agent is a different subject. Agents
    # that disappear at runtime stay declared and show up as not_found.
    baseline_raw = raw(_keys_only_v2("executor", "planner"))
    result = compare_alignment(
        alignment(baseline_raw), baseline_raw, raw(_keys_only_v2("executor"))
    )
    validate("drift-result-v2.schema.json", result)
    assert result["reason"] == "IDENTITY_MISMATCH"


def test_a_v1_comparison_still_emits_contract_v1_exactly():
    result = compare_alignment(alignment(), BASELINE_RAW, BASELINE_RAW)
    validate("drift-result-v1.schema.json", result)
    assert result["drift_contract_version"] == 1


@pytest.mark.parametrize(
    "value",
    [[], ["planner", "executor"], ["executor", "executor"], ["Executor"], "executor"],
)
def test_a_local_agent_keys_identity_must_be_a_sorted_unique_key_list(value):
    active = alignment(raw(_keys_only_v2("executor")))
    active["agent_identity"]["value"] = value
    assert "agent_identity.value: invalid local agent_key list" in alignment_problems(active)


@pytest.mark.parametrize("keys", [("executor",), ("executor", "planner")])
def test_a_v2_alignment_and_its_binding_pass_the_published_schemas(keys):
    active = alignment(raw(_keys_only_v2(*keys)))
    validate("alignment-version-v1.schema.json", active)
    validate(
        "active-binding-v1.schema.json",
        {
            "binding_contract_version": 1,
            "agent_identity": active["agent_identity"],
            "alignment_version_id": active["alignment_version_id"],
            "switched_at": "2026-09-24T00:02:00Z",
        },
    )
    Draft202012Validator.check_schema(
        json.loads((SCHEMAS / "drift-result-v2.schema.json").read_text(encoding="utf-8"))
    )


def test_a_v2_agent_key_with_a_trailing_newline_is_refused():
    # The schema pattern is a search, where `$` matches before a final "\n";
    # the key would otherwise become an identity no alignment accepts.
    value = _keys_only_v2("executor")
    value["agents"][0]["agent_key"] = "executor\n"
    assert "agents[0].agent_key: invalid agent_key" in bundle_problems(value)


@pytest.mark.parametrize("namespace", ["", " ", 7])
def test_a_v2_deployment_value_is_held_to_the_v1_shape(namespace):
    value = _v2_bundle()
    value["sandbox"]["attributes"]["deployment"]["value"]["RAIL_NAMESPACE"] = namespace
    assert any(
        problem.startswith("sandbox.attributes.deployment.value")
        for problem in bundle_problems(value)
    )


# DR-169: RailMon's optional `window` member on a v2 attribute marks a list
# that holds only what the observation window saw.
DESTINATIONS_WINDOW = {"ignore": ["count", "error_count"]}
FILES_WINDOW = {"union": ["exec", "read", "write"]}


def _destination(host: str, count: int = 1) -> dict:
    return {"host": host, "port": 443, "count": count, "error_count": 0}


def _file(path: str, **flags: bool) -> dict:
    return {"path": path, "layer": False, "read": False, "write": False, "exec": False, **flags}


def _windowed_v2(destinations: list, files: list, *, window: bool = True) -> dict:
    value = _keys_only_v2("executor")
    agent = value["agents"][0]["attributes"]
    agent["observed_destinations"] = {
        "value": destinations, "status": "ANSWERED", "tier": "observed", "authored_by": "none",
    }
    value["sandbox"]["attributes"]["observed_file_access"] = {
        "value": files, "status": "ANSWERED", "tier": "observed", "authored_by": "none",
    }
    if window:
        agent["observed_destinations"]["window"] = DESTINATIONS_WINDOW
        value["sandbox"]["attributes"]["observed_file_access"]["window"] = FILES_WINDOW
    return value


def _window_drift(baseline: dict, current: dict) -> list:
    baseline_raw = raw(baseline)
    current = copy.deepcopy(current)
    current["bundle_id"] = "bnd-fixture-v2-next"
    result = compare_alignment(alignment(baseline_raw), baseline_raw, raw(current))
    validate("drift-result-v2.schema.json", result)
    assert result["drift_contract_version"] == 2
    assert result["comparable"] is True, result["reason"]
    return [(change["agent_key"], change["type"], change["name"], change["fields"])
            for change in result["changes"]]


@pytest.mark.parametrize(
    "window", [{}, DESTINATIONS_WINDOW, FILES_WINDOW, {"ignore": ["count"], "union": ["read"]}]
)
def test_the_vendored_v2_schema_accepts_a_window(window):
    value = _windowed_v2([_destination("a.example")], [], window=False)
    value["agents"][0]["attributes"]["observed_destinations"]["window"] = window
    validate("evidence-bundle-v2.schema.json", value)
    assert bundle_problems(value) == []


@pytest.mark.parametrize(
    "window",
    [None, [], {"counting": ["count"]}, {"ignore": "count"}, {"ignore": [1]},
     {"ignore": [""]}, {"union": ["read", "read"]}],
)
def test_the_vendored_v2_schema_rejects_a_malformed_window(window):
    value = _windowed_v2([_destination("a.example")], [], window=False)
    value["agents"][0]["attributes"]["observed_destinations"]["window"] = window
    with pytest.raises(ValidationError):
        validate("evidence-bundle-v2.schema.json", value)
    assert any("observed_destinations.window" in p for p in bundle_problems(value))


def test_v1_has_no_window_member():
    value = bundle()
    value["attributes"]["tool_names"]["window"] = {}
    assert any("window" in p for p in bundle_problems(value))


def test_a_quieter_window_and_its_counts_are_not_drift():
    baseline = _windowed_v2(
        [_destination("a.example", 9), _destination("b.example")],
        [_file("/etc/hosts", read=True), _file("/tmp/out", write=True, read=True)],
    )
    current = _windowed_v2(
        [_destination("a.example", 1)], [_file("/tmp/out", read=True)]
    )
    assert _window_drift(baseline, current) == []
    # A window seen on one side only covers both: a baseline locked before
    # RailMon emitted the member compares the same way, and the member is
    # never itself drift.
    assert _window_drift(_windowed_v2(*_lists(baseline), window=False), current) == []
    assert _window_drift(baseline, _windowed_v2(*_lists(current), window=False)) == []


def _lists(value: dict) -> tuple[list, list]:
    return (value["agents"][0]["attributes"]["observed_destinations"]["value"],
            value["sandbox"]["attributes"]["observed_file_access"]["value"])


def test_something_newly_seen_in_the_window_is_drift():
    baseline = _windowed_v2([_destination("a.example")], [_file("/etc/hosts", read=True)])
    new_host = _windowed_v2([_destination("c.example")], [_file("/etc/hosts", read=True)])
    assert _window_drift(baseline, new_host) == [
        ("executor", "ATTRIBUTE_CHANGED", "observed_destinations", ["value"]),
    ]
    newly_written = _windowed_v2([_destination("a.example")], [_file("/etc/hosts", write=True)])
    assert _window_drift(baseline, newly_written) == [
        (None, "ATTRIBUTE_CHANGED", "observed_file_access", ["value"]),
    ]
    new_file = _windowed_v2([], [_file("/etc/passwd")])
    assert _window_drift(baseline, new_file) == [
        (None, "ATTRIBUTE_CHANGED", "observed_file_access", ["value"]),
    ]


def test_a_windowed_attribute_still_drifts_on_its_qualifiers():
    baseline = _windowed_v2([_destination("a.example")], [])
    current = copy.deepcopy(baseline)
    current["agents"][0]["attributes"]["observed_destinations"]["status"] = "PARTIAL"
    current["agents"][0]["attributes"]["observed_destinations"]["reason"] = "NO_SOURCE_ACCESS"
    current["agents"][0]["attributes"]["observed_destinations"]["value"] = []
    assert _window_drift(baseline, current) == [
        ("executor", "ATTRIBUTE_CHANGED", "observed_destinations", ["status", "reason"]),
    ]


def test_without_a_window_a_list_is_compared_exactly_as_before():
    baseline = _windowed_v2(
        [_destination("a.example", 9)], [_file("/tmp/out", write=True)], window=False
    )
    current = _windowed_v2([_destination("a.example", 1)], [_file("/tmp/out")], window=False)
    assert _window_drift(baseline, current) == [
        (None, "ATTRIBUTE_CHANGED", "observed_file_access", ["value"]),
        ("executor", "ATTRIBUTE_CHANGED", "observed_destinations", ["value"]),
    ]


def test_a_window_that_saw_nothing_is_an_empty_list_not_a_value_change():
    baseline = _windowed_v2([_destination("a.example")], [])
    current = copy.deepcopy(baseline)
    destinations = current["agents"][0]["attributes"]["observed_destinations"]
    destinations.update(status="ABSENT", value=None, method="no destination seen in the window")
    del destinations["authored_by"]
    fields = ["status", "authored_by", "method"]
    assert _window_drift(baseline, current) == [
        ("executor", "ATTRIBUTE_CHANGED", "observed_destinations", fields),
    ]
    assert _window_drift(current, baseline) == [
        ("executor", "ATTRIBUTE_CHANGED", "observed_destinations", ["value", *fields]),
    ]


# DR-193: RailMon carries dynamic agent data and publishes which attributes
# hold it; RailDash leaves their values out of every comparison.
def _instance(hostname: str, pid: int) -> dict:
    return {
        "value": {"hostname": hostname, "process": {"pid": pid, "cwd": "/work"}},
        "status": "ANSWERED", "tier": "observed", "authored_by": "none",
    }


def test_the_vendored_groups_name_agent_instance_dynamic():
    assert DYNAMIC_ATTRIBUTES == {"agent_instance"}


def test_a_v1_dynamic_value_is_never_drift_but_its_qualifiers_are():
    baseline = bundle()
    baseline["attributes"]["agent_instance"] = _instance("3f2a9c", 17)
    current = copy.deepcopy(baseline)
    current["attributes"]["agent_instance"] = _instance("9b8d7e", 23)
    baseline_raw = raw(baseline)
    result = compare_alignment(alignment(baseline_raw), baseline_raw, raw(current))
    assert (result["comparable"], result["changes"]) == (True, [])
    # As for container_identity (DR-118): a probe that stops answering is drift.
    current["attributes"]["agent_instance"]["status"] = "PARTIAL"
    current["attributes"]["agent_instance"]["reason"] = "NO_SOURCE_ACCESS"
    result = compare_alignment(alignment(baseline_raw), baseline_raw, raw(current))
    assert result["changes"] == [
        {"type": "ATTRIBUTE_CHANGED", "name": "agent_instance", "fields": ["status", "reason"]}
    ]
    # Present on one side only is a change, as for any attribute: RailMon
    # always emits it, ANSWERED or ABSENT.
    del current["attributes"]["agent_instance"]
    result = compare_alignment(alignment(baseline_raw), baseline_raw, raw(current))
    assert [change["type"] for change in result["changes"]] == ["ATTRIBUTE_REMOVED"]


def test_a_v2_dynamic_value_is_never_drift_and_a_static_one_still_is():
    baseline = _windowed_v2([_destination("a.example")], [])
    baseline["agents"][0]["attributes"]["agent_instance"] = _instance("3f2a9c", 17)
    current = copy.deepcopy(baseline)
    current["agents"][0]["attributes"]["agent_instance"] = _instance("9b8d7e", 23)
    assert _window_drift(baseline, current) == []
    current["agents"][0]["attributes"]["tool_names"]["value"] = ["shell.run"]
    assert _window_drift(baseline, current) == [
        ("executor", "ATTRIBUTE_CHANGED", "tool_names", ["value"]),
    ]
