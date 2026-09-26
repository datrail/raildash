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
