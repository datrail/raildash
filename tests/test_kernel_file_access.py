"""DR-154: RailMon's kernel-observed file access, validated, shown and compared.

RailMon's filesnoop folds the files a sandbox opened into the evidence
bundle's `observed_file_access` attribute (tier `observed`). RailDash holds
the value to the published shape, shows it beside the files a capture's tool
calls asked for without merging the two, and reports a newly written path as
drift.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.asp import (
    FILE_ACCESS_VALUE_MAX_BYTES,
    SCHEMA,
    bundle_problems,
)
from raildash.ingest import normalise
from raildash.store import MAX_KERNEL_FILE_SOURCES, Store

ASP_FIXTURE = Path(__file__).parent / "fixtures" / "evidence-bundle-v1.json"
READ = {"path": "/workspace/config.json", "read": True, "write": False, "exec": False, "layer": False}
WROTE = {"path": "/workspace/exfil.txt", "read": False, "write": True, "exec": False, "layer": False}
METHOD = "filesnoop events: each regular file a process in the sandbox opened"


def file_access(files, status="ANSWERED"):
    """The attribute as RailMon's scanner writes it."""
    if status == "ABSENT":
        return {"value": None, "status": "ABSENT", "tier": "observed", "method": METHOD}
    if status == "BLIND":
        return {"value": None, "status": "BLIND", "reason": "NOT_COLLECTED_BY_PACK",
                "tier": "observed", "note": "no filesnoop event file was provided to this scan"}
    field = {"value": files, "status": status, "tier": "observed", "authored_by": "none",
             "method": METHOD}
    if status == "PARTIAL":
        field.update(reason="NO_SOURCE_ACCESS",
                     note="filesnoop restarted 1 time (what opened while it was down is missing)")
    return field


def bundle(bundle_id, files=(READ,), *, status="ANSWERED", sandbox="fixture-agent",
           host="fixture-host", collected_at="2026-09-24T00:00:00Z", attribute=True):
    value = json.loads(ASP_FIXTURE.read_bytes())
    value["bundle_id"] = bundle_id
    value["host_id"] = host
    value["sandbox_name"] = sandbox
    value["collected_at"] = collected_at
    value["rule_pack_version"] = 4
    if attribute:
        value["attributes"]["observed_file_access"] = file_access(list(files), status)
    return value


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True).encode()


def v2(value):
    """The same facts as a v2 collection, with the attribute sandbox-scoped."""
    value = copy.deepcopy(value)
    value["bundle_version"] = 2
    inputs = value.pop("inputs_attempted")
    attributes = value.pop("attributes")
    shared = ("container_identity", "image_digest", "mounts", "deployment", "observed_file_access")
    value["sandbox"] = {
        "inputs_attempted": inputs,
        "attributes": {name: attributes.pop(name) for name in shared if name in attributes},
    }
    value["agents"] = [{"agent_key": "planner", "discovery_status": "available",
                        "inputs_attempted": inputs, "attributes": attributes}]
    return value


# ------------------------------------------------------------------ the shape


def test_the_vendored_schema_publishes_the_value_shape():
    shape = SCHEMA["$defs"]["file_access_value"]
    assert shape["maxItems"] == 512
    assert shape["items"]["required"] == ["path", "read", "write", "exec", "layer"]
    assert shape["items"]["properties"]["path"]["maxLength"] == 1024


@pytest.mark.parametrize("status", ["ANSWERED", "PARTIAL", "ABSENT", "BLIND"])
def test_every_status_railmon_writes_is_accepted(status):
    for value in (bundle("bnd-ok", status=status), v2(bundle("bnd-ok", status=status))):
        assert bundle_problems(value) == []


@pytest.mark.parametrize(
    "files, words",
    [
        ([dict(WROTE, pid=7)], "Additional properties"),
        ([dict(WROTE, write="yes")], "is not of type 'boolean'"),
        ([{k: v for k, v in WROTE.items() if k != "layer"}], "'layer' is a required property"),
        ([dict(WROTE, path="")], "should be non-empty"),
        ([dict(WROTE, path="/" + "x" * 1024)], "is too long"),
        ([WROTE] * 513, "is too long"),
        ({"path": "/x"}, "is not of type 'array'"),
    ],
)
@pytest.mark.parametrize("status", ["ANSWERED", "PARTIAL"])
def test_a_value_off_the_published_shape_is_rejected_in_v1_and_v2(files, words, status):
    value = bundle("bnd-bad", status=status)
    value["attributes"]["observed_file_access"]["value"] = files
    problems = bundle_problems(value)
    assert any("observed_file_access" in p and words in p for p in problems), problems
    problems = bundle_problems(v2(value))
    assert any("sandbox.attributes.observed_file_access.value" in p and words in p
               for p in problems), problems


def test_the_byte_bound_the_schema_cannot_state_is_held_in_code():
    # 60 entries of 1,000 escaped non-ASCII characters: inside every schema
    # bound, but about 360 KiB as RailMon writes it.
    huge = [dict(WROTE, path=f"/{i}" + "é" * 1000) for i in range(60)]
    assert len(json.dumps(huge, separators=(",", ":"))) > FILE_ACCESS_VALUE_MAX_BYTES
    value = bundle("bnd-huge", huge)
    assert any("observed_file_access.value: exceeds byte bound" in p for p in bundle_problems(value))
    assert any("observed_file_access.value: exceeds byte bound" in p for p in bundle_problems(v2(value)))
    fits = bundle("bnd-fits", huge[:30])
    assert bundle_problems(fits) == []


# ------------------------------------------------------------- the profile


@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = Store(tmp_path / "test.db")
    monkeypatch.setattr(app_module, "store", store)
    yield TestClient(app_module.app)
    store.close()


def auth():
    return {"X-RailDash-Token": app_module.LOCAL_TOKEN}


def capture(session_id, *, agent_ref=None, path="/workspace/notes.md"):
    """One captured call whose tool use asks to read `path`."""
    row = {
        "interaction_id": f"{session_id}-1",
        "request": {"method": "POST", "path": "/v1/messages",
                    "headers": {"host": "api.anthropic.com"},
                    "body": {"model": "claude-sonnet-5", "messages": []}},
        "response": {"status_code": 200, "body": {"content": [
            {"type": "tool_use", "id": f"{session_id}-t", "name": "Read",
             "input": {"file_path": path}},
        ]}},
    }
    if agent_ref:
        row.update(runtime_identity_version=1, agent_ref=agent_ref,
                   attribution={"state": "attributed", "method": "process_target"})
    app_module.store.upsert_session(session_id, agent="agent", source="test")
    app_module.store.add_interactions(session_id, [normalise(row)])


def load(value, agent_key="files-agent"):
    return app_module.store.load_asp(encode(value), agent_key=agent_key)["asp_id"]


def kernel(client, session_id, **params):
    response = client.get("/api/profile/kernel-file-access",
                          params={"session_id": session_id, **params}, headers=auth())
    assert response.status_code == 200, response.text
    return response.json()


def test_the_list_is_token_gated_and_needs_a_session(client):
    capture("s")
    assert client.get("/api/profile/kernel-file-access",
                      params={"session_id": "s"}).status_code == 403
    assert client.get("/api/profile/kernel-file-access",
                      params={"session_id": "nope"}, headers=auth()).status_code == 404


def test_a_capture_naming_its_sandbox_gets_that_sandboxs_latest_asp(client):
    capture("s", agent_ref={"host_id": "h1", "sandbox_name": "box", "agent_key": "planner"})
    load(bundle("bnd-old", [READ], host="h1", sandbox="box"))
    newest = load(bundle("bnd-new", [READ, WROTE], host="h1", sandbox="box",
                         collected_at="2026-09-24T01:00:00Z"))
    load(bundle("bnd-other", [WROTE], host="h1", sandbox="elsewhere"))

    data = kernel(client, "s")
    assert data["matched_by"] == "sandbox"
    assert data["attribute"] == "observed_file_access"
    [source] = data["sources"]
    assert source["asp_id"] == newest
    assert source["subject"] == {"host_id": "h1", "sandbox_name": "box"}
    evidence = source["evidence"]
    assert (evidence["status"], evidence["tier"], evidence["authored_by"]) == (
        "ANSWERED", "observed", "none")
    assert evidence["files"] == [READ, WROTE]
    # Scoped by the agent filter, like the profile: another agent's rows
    # name no sandbox here, so this capture falls back to every sandbox.
    assert kernel(client, "s", agent_key="planner")["matched_by"] == "sandbox"
    assert kernel(client, "s", agent_key="someone-else")["matched_by"] == "latest"


def test_the_asked_list_and_the_kernel_list_stay_separate(client):
    capture("s", path="/workspace/notes.md")
    load(bundle("bnd", [WROTE]))
    profile = client.get("/api/profile", params={"session_id": "s"}).json()["observed"]
    assert [item["value"] for item in profile["file_access"]] == ["/workspace/notes.md"]
    assert "/workspace/exfil.txt" not in json.dumps(profile)
    files = kernel(client, "s")["sources"][0]["evidence"]["files"]
    assert [entry["path"] for entry in files] == ["/workspace/exfil.txt"]


def test_an_unnamed_capture_gets_every_sandboxs_latest_and_says_so(client):
    capture("s")
    assert kernel(client, "s") == {
        "session_id": "s", "agent_key": None, "attribute": "observed_file_access",
        "matched_by": "latest", "sources": [], "sources_truncated": False,
    }
    first = load(bundle("bnd-a", [READ], sandbox="a"))
    second = load(bundle("bnd-b", [WROTE], sandbox="b"))
    data = kernel(client, "s")
    assert data["matched_by"] == "latest"
    assert {s["asp_id"] for s in data["sources"]} == {first, second}


def test_statuses_and_older_rule_packs_come_through_as_they_are(client):
    capture("s")
    load(bundle("bnd-partial", [WROTE], status="PARTIAL", sandbox="partial"))
    load(bundle("bnd-absent", status="ABSENT", sandbox="absent"))
    load(bundle("bnd-blind", status="BLIND", sandbox="blind"))
    load(bundle("bnd-old-pack", sandbox="old", attribute=False))
    by_sandbox = {s["subject"]["sandbox_name"]: s for s in kernel(client, "s")["sources"]}
    partial = by_sandbox["partial"]["evidence"]
    assert (partial["status"], partial["reason"], partial["files"]) == (
        "PARTIAL", "NO_SOURCE_ACCESS", [WROTE])
    assert "restarted" in partial["note"]
    assert by_sandbox["absent"]["evidence"]["files"] == []
    assert by_sandbox["blind"]["evidence"]["reason"] == "NOT_COLLECTED_BY_PACK"
    assert by_sandbox["old"]["evidence"] is None


def test_a_v2_collection_is_read_from_the_sandbox_scope(client):
    capture("s", agent_ref={"host_id": "fixture-host", "sandbox_name": "fixture-agent",
                            "agent_key": "planner"})
    load(v2(bundle("bnd-v2", [WROTE])), agent_key=None)
    [source] = kernel(client, "s")["sources"]
    assert source["contract"]["bundle_version"] == 2
    assert source["evidence"]["files"] == [WROTE]


def test_the_number_of_sandboxes_is_bounded(client):
    capture("s")
    for index in range(MAX_KERNEL_FILE_SOURCES + 2):
        load(bundle(f"bnd-{index}", sandbox=f"box-{index}"), agent_key=f"agent-{index}")
    data = kernel(client, "s")
    assert len(data["sources"]) == MAX_KERNEL_FILE_SOURCES
    assert data["sources_truncated"] is True


# ---------------------------------------------------------------- drift


def test_a_newly_written_path_is_drift_on_this_attribute_alone(client):
    baseline = load(bundle("bnd-base", [READ]))
    version = app_module.store.lock_alignment(baseline, "v1.0")
    app_module.store.switch_alignment(version["alignment_version_id"])

    same = load(bundle("bnd-same", [READ], collected_at="2026-09-24T01:00:00Z"))
    assert client.get(f"/api/asps/{same}/state").json()["state"] == "ALIGNED"

    wrote = load(bundle("bnd-wrote", [READ, WROTE], collected_at="2026-09-24T02:00:00Z"))
    state = client.get(f"/api/asps/{wrote}/state").json()
    assert state["state"] == "DRIFT_DETECTED"
    assert [(c["type"], c["name"], c["fields"]) for c in state["drift"]["changes"]] == [
        ("ATTRIBUTE_CHANGED", "observed_file_access", ["value"])
    ]
    explained = client.get(f"/api/asps/{wrote}/drift/explained", headers=auth()).json()
    [change] = explained["changes"]
    assert change["baseline"]["value"] == [READ]
    assert change["current"]["value"] == [READ, WROTE]

    # A file only read before, now written: the entry's `write` turned true.
    rewritten = load(bundle("bnd-rewrite", [dict(READ, write=True)],
                           collected_at="2026-09-24T03:00:00Z"))
    assert client.get(f"/api/asps/{rewritten}/state").json()["state"] == "DRIFT_DETECTED"


def test_a_stored_bundle_that_no_longer_validates_is_that_sandboxs_error(client, monkeypatch):
    # A bundle stored under an older vendored schema can fail this one. ASPs
    # are immutable in the database, so the stricter validation is simulated.
    from raildash import store as store_module
    from raildash.asp import BundleValidationError, parse_bundle

    capture("s")
    good = load(bundle("bnd-good", [WROTE], sandbox="good"))
    stale = load(bundle("bnd-stale", [READ], sandbox="stale"))

    def stricter(raw):
        if b"bnd-stale" in raw:
            raise BundleValidationError(["attributes.observed_file_access.value: stricter now"])
        return parse_bundle(raw)

    monkeypatch.setattr(store_module, "parse_bundle", stricter)
    by_id = {s["asp_id"]: s for s in kernel(client, "s")["sources"]}
    assert by_id[stale]["evidence"] is None
    assert "does not pass" in by_id[stale]["error"]
    assert by_id[good]["error"] is None
    assert by_id[good]["evidence"]["files"] == [WROTE]
