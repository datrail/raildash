"""HTTP write routes for ASP custody (DR-120).

Every route here wraps the same `Store` method the `raildash asp ...` CLI
already calls -- these tests exercise the HTTP contract layered on top: the
local-token gate on every write (and on the two reads that carry exact
evidence), and each response shape a UI or a delivering client depends on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.store import Store

ASP_FIXTURE = Path(__file__).parent / "fixtures" / "evidence-bundle-v1.json"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = Store(tmp_path / "test.db")
    monkeypatch.setattr(app_module, "store", store)
    yield TestClient(app_module.app)
    store.close()


def auth():
    return {"X-RailDash-Token": app_module.LOCAL_TOKEN}


def changed_bundle(bundle_id: str, destination: str) -> bytes:
    value = json.loads(ASP_FIXTURE.read_bytes())
    value["bundle_id"] = bundle_id
    value["collected_at"] = "2026-09-24T01:00:00Z"
    value["attributes"]["declared_destinations"]["value"] = [destination]
    return json.dumps(value, sort_keys=True).encode()


def unkeyed_bundle() -> bytes:
    value = json.loads(ASP_FIXTURE.read_bytes())
    value["bundle_id"] = "bnd-unkeyed"
    value["attributes"]["deployment"]["status"] = "ABSENT"
    value["attributes"]["deployment"]["value"] = None
    del value["attributes"]["deployment"]["authored_by"]
    return json.dumps(value, sort_keys=True).encode()


# ------------------------------------------------------------------- ingest


def test_ingest_requires_the_local_token(client):
    res = client.post("/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes())
    assert res.status_code == 403


def test_ingest_accepts_and_dedups_by_content_digest(client):
    raw = ASP_FIXTURE.read_bytes()
    first = client.post("/v1/evidence-bundles", content=raw, headers=auth())
    assert first.status_code == 202
    body = first.json()
    assert body == {"accepted": True, "asp_id": body["asp_id"], "duplicate": False}
    assert body["asp_id"].startswith("asp-")

    replay = client.post("/v1/evidence-bundles", content=raw, headers=auth())
    assert replay.status_code == 202
    assert replay.json() == {"accepted": True, "asp_id": body["asp_id"], "duplicate": True}


def test_ingest_rejects_bundle_id_reused_with_different_bytes(client):
    raw = ASP_FIXTURE.read_bytes()
    client.post("/v1/evidence-bundles", content=raw, headers=auth())
    collision = json.loads(raw)
    collision["sandbox_name"] = "a-different-copy"
    res = client.post(
        "/v1/evidence-bundles",
        content=json.dumps(collision).encode(),
        headers=auth(),
    )
    assert res.status_code == 409


def test_ingest_rejects_a_malformed_body(client):
    res = client.post("/v1/evidence-bundles", content=b"not json at all", headers=auth())
    assert res.status_code == 422


def test_ingest_bounds_body_size(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_EVIDENCE_BUNDLE_BYTES", 16)
    res = client.post("/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth())
    assert res.status_code == 413


def test_ingest_requires_agent_key_for_an_unkeyed_bundle_then_accepts_it(client):
    raw = unkeyed_bundle()
    unresolved = client.post("/v1/evidence-bundles", content=raw, headers=auth())
    assert unresolved.status_code == 422

    resolved = client.post(
        "/v1/evidence-bundles",
        params={"agent_key": "agent-one"},
        content=raw,
        headers=auth(),
    )
    assert resolved.status_code == 202
    assert resolved.json()["duplicate"] is False


def test_ingest_accepts_agent_key_as_a_header_too(client):
    raw = unkeyed_bundle()
    resolved = client.post(
        "/v1/evidence-bundles",
        content=raw,
        headers={**auth(), "X-RailDash-Agent-Key": "agent-one"},
    )
    assert resolved.status_code == 202


# --------------------------------------------------------- lock / switch / accept


def test_lock_requires_token_then_locks(client):
    loaded = client.post(
        "/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth()
    ).json()

    assert client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}
    ).status_code == 403

    locked = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth()
    )
    assert locked.status_code == 201
    assert locked.json()["version"] == "v1.0"


def test_lock_rejects_a_reused_version_and_a_missing_asp(client):
    loaded = client.post(
        "/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth()
    ).json()
    client.post(f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth())

    dup = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth()
    )
    assert dup.status_code == 409

    missing = client.post(
        "/api/asps/asp-does-not-exist/lock", json={"version": "v9.0"}, headers=auth()
    )
    assert missing.status_code == 404

    bad_body = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": 5}, headers=auth()
    )
    assert bad_body.status_code == 422


def test_switch_requires_token_then_activates(client):
    loaded = client.post(
        "/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth()
    ).json()
    version = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth()
    ).json()

    assert client.post(
        f"/api/alignments/{version['alignment_version_id']}/switch"
    ).status_code == 403

    switched = client.post(
        f"/api/alignments/{version['alignment_version_id']}/switch", headers=auth()
    )
    assert switched.status_code == 200
    assert switched.json()["alignment_version_id"] == version["alignment_version_id"]

    assert client.get(f"/api/asps/{loaded['asp_id']}/state").json()["state"] == "ALIGNED"

    missing = client.post("/api/alignments/aspver-does-not-exist/switch", headers=auth())
    assert missing.status_code == 404


def test_accept_drift_locks_and_switches_in_one_call(client):
    loaded = client.post(
        "/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth()
    ).json()
    version = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth()
    ).json()
    client.post(f"/api/alignments/{version['alignment_version_id']}/switch", headers=auth())

    changed = client.post(
        "/v1/evidence-bundles",
        content=changed_bundle("bnd-drift", "private.example"),
        headers=auth(),
    ).json()
    assert client.get(f"/api/asps/{changed['asp_id']}/state").json()["state"] == "DRIFT_DETECTED"

    assert client.post(
        f"/api/asps/{changed['asp_id']}/accept-drift", json={"version": "v2.0"}
    ).status_code == 403

    accepted = client.post(
        f"/api/asps/{changed['asp_id']}/accept-drift",
        json={"version": "v2.0"},
        headers=auth(),
    )
    assert accepted.status_code == 201
    body = accepted.json()
    assert body["alignment_version"]["version"] == "v2.0"
    assert body["binding"]["alignment_version_id"] == body["alignment_version"]["alignment_version_id"]

    assert client.get(f"/api/asps/{changed['asp_id']}/state").json()["state"] == "ALIGNED"


# ------------------------------------------------------ bundle / drift/explained


def test_bundle_and_drift_explained_are_token_gated_and_carry_values(client):
    loaded = client.post(
        "/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth()
    ).json()
    version = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth()
    ).json()
    client.post(f"/api/alignments/{version['alignment_version_id']}/switch", headers=auth())
    changed = client.post(
        "/v1/evidence-bundles",
        content=changed_bundle("bnd-explained", "private.example"),
        headers=auth(),
    ).json()

    assert client.get(f"/api/asps/{loaded['asp_id']}/bundle").status_code == 403
    bundle = client.get(f"/api/asps/{loaded['asp_id']}/bundle", headers=auth())
    assert bundle.status_code == 200
    assert bundle.json()["bundle_id"] == "bnd-fixture-001"
    assert client.get("/api/asps/asp-does-not-exist/bundle", headers=auth()).status_code == 404

    assert client.get(f"/api/asps/{changed['asp_id']}/drift/explained").status_code == 403
    explained = client.get(
        f"/api/asps/{changed['asp_id']}/drift/explained", headers=auth()
    )
    assert explained.status_code == 200
    payload = explained.json()
    assert payload["has_drift"] is True
    change = next(c for c in payload["changes"] if c["name"] == "declared_destinations")
    assert change["current"]["value"] == ["private.example"]
    assert change["baseline"]["value"] is None
    assert (
        client.get("/api/asps/asp-does-not-exist/drift/explained", headers=auth()).status_code
        == 404
    )


def _v2_collection(bundle_id: str, *, executor_status: str = "available") -> bytes:
    """A RailMon-shaped v2 collection (DR-109): one sandbox scope, two
    agents, deployment identity from the shared sandbox scope."""
    value = json.loads(ASP_FIXTURE.read_bytes())
    value["bundle_id"] = bundle_id
    value["bundle_version"] = 2
    inputs = value.pop("inputs_attempted")
    attributes = value.pop("attributes")
    sandbox = {
        name: attributes.pop(name)
        for name in ("container_identity", "image_digest", "mounts", "deployment")
    }
    value["sandbox"] = {"inputs_attempted": inputs, "attributes": sandbox}
    value["agents"] = [
        {"agent_key": key, "discovery_status": "available", "inputs_attempted": inputs,
         "attributes": json.loads(json.dumps(attributes))}
        for key in ("executor", "planner")
    ]
    if executor_status != "available":
        value["collected_at"] = "2026-09-24T06:00:00Z"
        value["agents"][0]["discovery_status"] = executor_status
        value["agents"][0]["attributes"] = {}
    return json.dumps(value, sort_keys=True).encode()


def test_a_v2_collection_locks_over_http_and_drift_is_scoped_to_one_agent(client):
    loaded = client.post(
        "/v1/evidence-bundles", content=_v2_collection("bnd-http-v2"), headers=auth()
    ).json()
    locked = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth()
    )
    assert locked.status_code == 201
    client.post(
        f"/api/alignments/{locked.json()['alignment_version_id']}/switch", headers=auth()
    )
    assert client.get(f"/api/asps/{loaded['asp_id']}/state").json()["state"] == "ALIGNED"

    gone = client.post(
        "/v1/evidence-bundles",
        content=_v2_collection("bnd-http-v2-gone", executor_status="not_found"),
        headers=auth(),
    ).json()
    assert client.get(f"/api/asps/{gone['asp_id']}/state").json()["state"] == "DRIFT_DETECTED"
    redacted = client.get(f"/api/asps/{gone['asp_id']}/drift").json()
    assert redacted["drift_contract_version"] == 2
    assert {c["agent_key"] for c in redacted["changes"]} == {"executor"}
    explained = client.get(
        f"/api/asps/{gone['asp_id']}/drift/explained", headers=auth()
    ).json()
    first = explained["changes"][0]
    assert (first["type"], first["baseline"], first["current"]) == (
        "AGENT_CHANGED",
        {"discovery_status": "available"},
        {"discovery_status": "not_found"},
    )


# --------------------------------------------------------- retention / prune


def test_retention_get_is_unauthenticated_but_set_and_prune_are_gated(client):
    baseline = client.get("/api/settings/asp-retention").json()
    assert baseline["keep_count"] > 0 and baseline["max_age_days"] > 0

    loaded = client.post(
        "/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth()
    ).json()
    client.post(
        "/v1/evidence-bundles",
        content=changed_bundle("bnd-prune-a", "a.example"),
        headers=auth(),
    )
    client.post(
        "/v1/evidence-bundles",
        content=changed_bundle("bnd-prune-b", "b.example"),
        headers=auth(),
    )
    assert client.get("/api/asps").json()["total"] == 3

    assert client.post(
        "/api/settings/asp-retention", json={"keep_count": 2, "max_age_days": 30}
    ).status_code == 403
    saved = client.post(
        "/api/settings/asp-retention",
        json={"keep_count": 2, "max_age_days": 30},
        headers=auth(),
    )
    assert saved.status_code == 200
    assert saved.json() == {"keep_count": 2, "max_age_days": 30}
    # Saving alone does not retroactively prune.
    assert client.get("/api/asps").json()["total"] == 3
    assert client.get("/api/settings/asp-retention").json() == {
        "keep_count": 2,
        "max_age_days": 30,
    }

    bad = client.post(
        "/api/settings/asp-retention",
        json={"keep_count": 0, "max_age_days": 30},
        headers=auth(),
    )
    assert bad.status_code == 422

    assert client.post("/api/asps/prune").status_code == 403
    pruned = client.post("/api/asps/prune", headers=auth())
    assert pruned.status_code == 200
    assert pruned.json()["removed"] == 1
    assert client.get("/api/asps").json()["total"] == 2
    # The oldest of the three (loaded first) is the one retention drops.
    remaining = {item["asp_id"] for item in client.get("/api/asps").json()["items"]}
    assert loaded["asp_id"] not in remaining


def test_prune_accepts_a_one_off_override_without_changing_the_saved_setting(client):
    client.post("/v1/evidence-bundles", content=ASP_FIXTURE.read_bytes(), headers=auth())
    client.post(
        "/v1/evidence-bundles",
        content=changed_bundle("bnd-override-a", "a.example"),
        headers=auth(),
    )
    client.post(
        "/v1/evidence-bundles",
        content=changed_bundle("bnd-override-b", "b.example"),
        headers=auth(),
    )
    assert client.get("/api/asps").json()["total"] == 3

    pruned = client.post(
        "/api/asps/prune", params={"keep_count": 1, "max_age_days": 30}, headers=auth()
    )
    assert pruned.status_code == 200
    assert pruned.json()["removed"] == 2
    # The one-off override was not persisted.
    assert client.get("/api/settings/asp-retention").json()["keep_count"] != 1


# ------------------------------------- DR-234: unkeyed v1 after keyed v2


def _v1_variant(bundle_id: str, *, deployment: str, sandbox_name: str | None = None) -> bytes:
    """The v1 fixture with one of the three identity shapes a v1 bundle can
    carry: `environment` (RAIL_DEPLOYMENT/RAIL_NAMESPACE, as the fixture
    ships), `compose` (the host-scoped Compose labels) or `none`."""
    value = json.loads(ASP_FIXTURE.read_bytes())
    value["bundle_id"] = bundle_id
    if sandbox_name is not None:
        value["sandbox_name"] = sandbox_name
    attribute = value["attributes"]["deployment"]
    if deployment == "compose":
        attribute["value"] = {
            "com.docker.compose.project": "agents",
            "com.docker.compose.service": "shared-agents",
        }
    elif deployment == "none":
        attribute["status"] = "ABSENT"
        attribute["value"] = None
        del attribute["authored_by"]
    return json.dumps(value, sort_keys=True).encode()


def _with_v2_history(client) -> None:
    res = client.post(
        "/v1/evidence-bundles", content=_v2_collection("bnd-dr234-v2"), headers=auth()
    )
    assert res.status_code == 202


def _asp_count(client) -> int:
    return client.get("/api/asps").json()["total"]


def _assert_multi_agent_key_required(res) -> None:
    assert res.status_code == 422
    body = res.json()
    assert body["code"] == "MULTI_AGENT_KEY_REQUIRED"
    assert body["detail"].startswith("MULTI_AGENT_KEY_REQUIRED: ")


@pytest.mark.parametrize("deployment", ["environment", "compose", "none"])
def test_an_unkeyed_v1_bundle_for_a_sandbox_with_v2_history_is_refused(client, deployment):
    """Design §5: once a sandbox has keyed v2 history, an unkeyed v1 bundle
    for it is a partially configured multi-agent container falling back to
    one identity. It is refused, not filed as a new or separate agent --
    whatever deployment identity it carries."""
    _with_v2_history(client)
    before = _asp_count(client)
    res = client.post(
        "/v1/evidence-bundles",
        content=_v1_variant(f"bnd-dr234-{deployment}", deployment=deployment),
        headers=auth(),
    )
    _assert_multi_agent_key_required(res)
    assert _asp_count(client) == before


def test_the_reserved_default_key_does_not_key_a_v1_bundle_after_v2_history(client):
    _with_v2_history(client)
    for how in ({"params": {"agent_key": "default"}},
                {"headers": {"X-RailDash-Agent-Key": "default"}}):
        res = client.post(
            "/v1/evidence-bundles",
            content=_v1_variant("bnd-dr234-default", deployment="none"),
            **{**how, "headers": {**auth(), **how.get("headers", {})}},
        )
        _assert_multi_agent_key_required(res)


@pytest.mark.parametrize("deployment", ["environment", "compose", "none"])
def test_a_keyed_v1_bundle_is_still_accepted_after_v2_history(client, deployment):
    """RailMon's per-agent fallback, when the shared scan fails, sends each
    agent its own v1 bundle with `?agent_key=`: that is keyed, so it lands."""
    _with_v2_history(client)
    res = client.post(
        "/v1/evidence-bundles",
        params={"agent_key": "planner"},
        content=_v1_variant(f"bnd-dr234-keyed-{deployment}", deployment=deployment),
        headers=auth(),
    )
    assert res.status_code == 202
    assert res.json()["duplicate"] is False


def test_resending_a_stored_unkeyed_v1_bundle_after_v2_history_is_a_replay(client):
    """RailMon resends an unchanged bundle's exact bytes. A v1 stored before
    the sandbox's first v2 collection is still answered as a duplicate, not
    refused: RailDash already holds it."""
    raw = _v1_variant("bnd-dr234-replay", deployment="environment")
    first = client.post("/v1/evidence-bundles", content=raw, headers=auth())
    assert first.status_code == 202
    _with_v2_history(client)
    before = _asp_count(client)
    again = client.post("/v1/evidence-bundles", content=raw, headers=auth())
    assert again.status_code == 202
    assert again.json()["duplicate"] is True
    assert _asp_count(client) == before


def test_unkeyed_v1_without_v2_history_is_unchanged(client):
    """A single-agent stack never sent v2, so nothing about it changes: a
    deployment identity still keys the bundle, and a bundle with none still
    gets the plain local-agent_key 422."""
    for deployment in ("environment", "compose"):
        res = client.post(
            "/v1/evidence-bundles",
            content=_v1_variant(f"bnd-dr234-single-{deployment}", deployment=deployment),
            headers=auth(),
        )
        assert res.status_code == 202
    res = client.post(
        "/v1/evidence-bundles",
        content=_v1_variant("bnd-dr234-single-none", deployment="none"),
        headers=auth(),
    )
    assert res.status_code == 422
    assert "code" not in res.json()
    assert "requires a local agent_key" in res.json()["detail"]


def test_v2_history_only_refuses_unkeyed_v1_for_the_same_sandbox(client):
    """The refusal is per sandbox (host_id + sandbox_name), not global."""
    _with_v2_history(client)
    res = client.post(
        "/v1/evidence-bundles",
        content=_v1_variant("bnd-dr234-other", deployment="compose", sandbox_name="other-agent"),
        headers=auth(),
    )
    assert res.status_code == 202


def test_store_and_cli_refuse_the_same_unkeyed_v1_bundle(client, tmp_path, capsys):
    """The refusal lives in `Store.load_asp`, so `raildash asp load` (no
    HTTP) refuses it too, under the same code."""
    from raildash import cli
    from raildash.asp import MULTI_AGENT_KEY_REQUIRED, MultiAgentKeyRequiredError

    store = app_module.store
    store.load_asp(_v2_collection("bnd-dr234-store-v2"))
    with pytest.raises(MultiAgentKeyRequiredError) as raised:
        store.load_asp(_v1_variant("bnd-dr234-store", deployment="compose"))
    assert raised.value.code == MULTI_AGENT_KEY_REQUIRED
    assert store.load_asp(
        _v1_variant("bnd-dr234-store", deployment="compose"), agent_key="planner"
    )["replayed"] is False

    path = tmp_path / "unkeyed.json"
    path.write_bytes(_v1_variant("bnd-dr234-cli", deployment="environment"))
    store.close()
    code = cli.main(["--db", str(tmp_path / "test.db"), "asp", "load", str(path)])
    assert code == 1
    assert "MULTI_AGENT_KEY_REQUIRED" in capsys.readouterr().err


# ------------------- DR-243: an explicit agent_key in a multi-agent sandbox


def _ingest(client, raw: bytes, agent_key: str | None = None):
    return client.post(
        "/v1/evidence-bundles",
        params={"agent_key": agent_key} if agent_key is not None else {},
        content=raw,
        headers=auth(),
    )


def _identity_of(client, asp_id: str) -> dict:
    asps = client.get("/api/asps", params={"limit": 100}).json()["items"]
    return next(asp["agent_identity"] for asp in asps if asp["asp_id"] == asp_id)


@pytest.mark.parametrize("deployment", ["environment", "compose"])
def test_keyed_v1_fallback_bundles_in_a_multi_agent_sandbox_land_per_agent(client, deployment):
    """RailMon's per-agent fallback (shared scan failed) sends each agent of
    one container its own v1 bundle with `?agent_key=`. The container's
    deployment identity is shared by every agent in it, so in a sandbox with
    v2 history the explicit key is the more specific identity and wins;
    otherwise both agents' ASPs would interleave under one identity."""
    _with_v2_history(client)
    landed = {}
    for key in ("executor", "planner"):
        res = _ingest(client, _v1_variant(f"bnd-dr243-{deployment}-{key}", deployment=deployment), key)
        assert res.status_code == 202
        landed[key] = _identity_of(client, res.json()["asp_id"])
    assert landed == {
        "executor": {"kind": "local_agent_key", "value": "executor"},
        "planner": {"kind": "local_agent_key", "value": "planner"},
    }


def test_a_keyed_v1_bundle_without_v2_history_keeps_its_deployment_identity(client):
    """A single-agent sandbox (no v2 history) keeps today's precedence, so
    no locked baseline moves: the deployment identity wins over the key."""
    res = _ingest(client, _v1_variant("bnd-dr243-single", deployment="compose"), "planner")
    assert res.status_code == 202
    assert _identity_of(client, res.json()["asp_id"]) == {
        "kind": "deployment_compose",
        "value": {"host_id": json.loads(ASP_FIXTURE.read_bytes())["host_id"],
                  "project": "agents", "service": "shared-agents"},
    }


def test_a_v1_bundle_stored_before_v2_history_replays_under_its_stored_identity(client):
    """An exact replay keeps resolving to the identity it was stored under:
    a keyed bundle filed under its deployment identity before the sandbox
    went multi-agent is still a duplicate afterwards, not a 409."""
    raw = _v1_variant("bnd-dr243-replay", deployment="compose")
    first = _ingest(client, raw, "planner")
    assert first.status_code == 202
    _with_v2_history(client)
    again = _ingest(client, raw, "planner")
    assert again.status_code == 202
    assert again.json() == {**first.json(), "duplicate": True}


def test_a_keyed_replay_under_another_key_is_still_refused(client):
    """The replay check still refuses filing the same bytes under a
    different agent: stored as `planner`, resent as `executor`, is a 409."""
    _with_v2_history(client)
    raw = _v1_variant("bnd-dr243-other-key", deployment="compose")
    assert _ingest(client, raw, "planner").status_code == 202
    assert _ingest(client, raw, "planner").json()["duplicate"] is True
    res = _ingest(client, raw, "executor")
    assert res.status_code == 409


def test_a_locked_keyed_fallback_asp_compares_the_next_keyed_fallback(client):
    """A baseline locked from a keyed fallback bundle that also carries
    Compose labels compares the agent's next fallback bundle, not
    ALIGNMENT_INTEGRITY_FAILED or IDENTITY_MISMATCH."""
    _with_v2_history(client)
    baseline = _ingest(client, _v1_variant("bnd-dr243-lock-a", deployment="compose"), "planner")
    locked = client.post(
        f"/api/asps/{baseline.json()['asp_id']}/lock", json={"version": "v1.0"}, headers=auth()
    )
    assert locked.status_code == 201
    switched = client.post(
        f"/api/alignments/{locked.json()['alignment_version_id']}/switch", headers=auth()
    )
    assert switched.status_code == 200
    value = json.loads(_v1_variant("bnd-dr243-lock-b", deployment="compose"))
    value["attributes"]["declared_destinations"]["value"] = ["moved.example"]
    current = _ingest(client, json.dumps(value, sort_keys=True).encode(), "planner")
    drift = client.get(f"/api/asps/{current.json()['asp_id']}/drift").json()
    assert drift["comparable"] is True
    assert drift["has_drift"] is True
