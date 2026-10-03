"""ASP history, raw download, idempotent baseline/accept, and CLI-beside-server.

The dashboard lists every received ASP, lets any of them become the baseline,
and hands back the exact bytes RailMon delivered. None of that may need the
server stopped, so the last tests run the CLI against a live `raildash serve`.
"""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from urllib.request import Request, urlopen

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.store import Store

ROOT = Path(__file__).parent.parent
ASP_FIXTURE = Path(__file__).parent / "fixtures" / "evidence-bundle-v1.json"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = Store(tmp_path / "test.db")
    monkeypatch.setattr(app_module, "store", store)
    yield TestClient(app_module.app)
    store.close()


def auth():
    return {"X-RailDash-Token": app_module.LOCAL_TOKEN}


def changed_bundle(bundle_id: str, destination: str, collected_at: str) -> bytes:
    value = json.loads(ASP_FIXTURE.read_bytes())
    value["bundle_id"] = bundle_id
    value["collected_at"] = collected_at
    value["attributes"]["declared_destinations"]["value"] = [destination]
    return json.dumps(value, sort_keys=True).encode()


def ingest(client, raw: bytes) -> dict:
    res = client.post("/v1/evidence-bundles", content=raw, headers=auth())
    assert res.status_code == 202, res.text
    return res.json()


def alignment_rows(client) -> list[dict]:
    return client.get("/api/alignments").json()["items"]


# ------------------------------------------------------------------ history


def test_history_lists_newest_first_with_baseline_locked_and_candidate(client):
    first = ingest(client, ASP_FIXTURE.read_bytes())
    second = ingest(client, changed_bundle("bnd-2", "two.example", "2026-09-24T01:00:00Z"))
    third = ingest(client, changed_bundle("bnd-3", "three.example", "2026-09-24T02:00:00Z"))

    empty = client.get("/api/asps/history").json()
    assert [i["asp_id"] for i in empty["items"]] == [
        third["asp_id"], second["asp_id"], first["asp_id"]
    ]
    assert {i["status"] for i in empty["items"]} == {"candidate"}
    assert [i["latest_for_agent"] for i in empty["items"]] == [True, False, False]

    # Lock the oldest as the baseline straight from the history.
    made = client.post(
        f"/api/asps/{first['asp_id']}/baseline", json={"version": "v1.0"}, headers=auth()
    )
    assert made.status_code == 201
    client.post(
        f"/api/asps/{second['asp_id']}/lock", json={"version": "v2.0"}, headers=auth()
    )

    history = client.get("/api/asps/history").json()
    by_id = {i["asp_id"]: i for i in history["items"]}
    assert history["total"] == 3
    assert by_id[first["asp_id"]]["status"] == "baseline"
    assert by_id[first["asp_id"]]["locked_versions"][0]["version"] == "v1.0"
    assert by_id[second["asp_id"]]["status"] == "locked"
    assert by_id[third["asp_id"]]["status"] == "candidate"
    # Activating v1.0 compared the newest ASP with it.
    assert by_id[third["asp_id"]]["comparison"] == {
        "against_version": "v1.0",
        "state": "DRIFT_DETECTED",
        "change_count": 1,
    }
    assert "three.example" not in json.dumps(history)
    assert "digest" not in json.dumps(history)

    page = client.get("/api/asps/history", params={"limit": 1, "offset": 1}).json()
    assert [i["asp_id"] for i in page["items"]] == [second["asp_id"]]


def test_an_older_asp_can_become_the_baseline_again(client):
    first = ingest(client, ASP_FIXTURE.read_bytes())
    client.post(f"/api/asps/{first['asp_id']}/baseline", json={"version": "v1.0"}, headers=auth())
    newer = ingest(client, changed_bundle("bnd-new", "new.example", "2026-09-24T01:00:00Z"))
    client.post(f"/api/asps/{newer['asp_id']}/baseline", json={"version": "v2.0"}, headers=auth())
    assert client.get(f"/api/asps/{newer['asp_id']}/state").json()["state"] == "ALIGNED"

    # Back to the older one: no label needed, nothing new locked.
    back = client.post(f"/api/asps/{first['asp_id']}/baseline", json={}, headers=auth())
    assert back.status_code == 200
    assert back.json()["locked"] is False
    assert back.json()["switched"] is True
    assert back.json()["alignment_version"]["version"] == "v1.0"
    assert len(alignment_rows(client)) == 2
    assert client.get(f"/api/asps/{newer['asp_id']}/state").json()["state"] == "DRIFT_DETECTED"


def test_baseline_route_is_token_gated_and_validates(client):
    loaded = ingest(client, ASP_FIXTURE.read_bytes())
    url = f"/api/asps/{loaded['asp_id']}/baseline"
    assert client.post(url, json={"version": "v1.0"}).status_code == 403
    assert client.post(url, json={}, headers=auth()).status_code == 409  # needs a label
    assert client.post(url, json={"version": 3}, headers=auth()).status_code == 422
    assert client.post(
        "/api/asps/asp-nope/baseline", json={"version": "v1.0"}, headers=auth()
    ).status_code == 404
    assert alignment_rows(client) == []


# ---------------------------------------------------- idempotent accept/lock


def test_accepting_the_same_drift_twice_locks_it_once(client):
    first = ingest(client, ASP_FIXTURE.read_bytes())
    client.post(f"/api/asps/{first['asp_id']}/baseline", json={"version": "v1.0"}, headers=auth())
    drifted = ingest(client, changed_bundle("bnd-d", "d.example", "2026-09-24T01:00:00Z"))

    accepted = client.post(
        f"/api/asps/{drifted['asp_id']}/accept-drift", json={"version": "v2.0"}, headers=auth()
    )
    assert accepted.status_code == 201
    again = client.post(
        f"/api/asps/{drifted['asp_id']}/accept-drift", json={"version": "v2.0"}, headers=auth()
    )
    assert again.status_code == 200
    assert again.json()["locked"] is False
    assert again.json()["switched"] is False
    assert (
        again.json()["alignment_version"]["alignment_version_id"]
        == accepted.json()["alignment_version"]["alignment_version_id"]
    )
    assert again.json()["binding"] == accepted.json()["binding"]

    # Switch away and accept again under a fresh label: it re-activates the
    # existing v2.0 instead of locking the same evidence as v3.0.
    v1 = next(v for v in alignment_rows(client) if v["version"] == "v1.0")
    client.post(f"/api/alignments/{v1['alignment_version_id']}/switch", headers=auth())
    third = client.post(
        f"/api/asps/{drifted['asp_id']}/accept-drift", json={"version": "v3.0"}, headers=auth()
    )
    assert third.status_code == 200
    assert third.json()["alignment_version"]["version"] == "v2.0"
    assert third.json()["switched"] is True
    assert sorted(v["version"] for v in alignment_rows(client)) == ["v1.0", "v2.0"]
    assert client.get(f"/api/asps/{drifted['asp_id']}/state").json()["state"] == "ALIGNED"


def test_locking_an_already_locked_asp_again_is_refused(client):
    loaded = ingest(client, ASP_FIXTURE.read_bytes())
    client.post(f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v1.0"}, headers=auth())
    again = client.post(
        f"/api/asps/{loaded['asp_id']}/lock", json={"version": "v9.0"}, headers=auth()
    )
    assert again.status_code == 409
    assert "already locked as v1.0" in again.json()["detail"]
    assert len(alignment_rows(client)) == 1


# --------------------------------------------------------------- raw bytes


def test_raw_download_returns_the_exact_received_bytes(client):
    # Unusual but valid formatting: indentation, key order, escaped and raw
    # non-ASCII, a trailing newline. Any reserialization would change these.
    value = json.loads(ASP_FIXTURE.read_bytes())
    value["bundle_id"] = "bnd-raw-é"
    raw = (
        json.dumps(value, indent=3, ensure_ascii=False)
        .replace('"bundle_version"', '"bundle_version"  ')
        .encode("utf-8")
        + b"\r\n"
    )
    loaded = ingest(client, raw)
    url = f"/api/asps/{loaded['asp_id']}/raw"

    assert client.get(url).status_code == 403
    res = client.get(url, headers=auth())
    assert res.status_code == 200
    assert res.content == raw
    assert hashlib.sha256(res.content).hexdigest() == hashlib.sha256(raw).hexdigest()
    assert res.headers["content-type"].startswith("application/json")
    assert res.headers["content-disposition"] == (
        f'attachment; filename="{loaded["asp_id"]}.json"'
    )
    assert res.headers["cache-control"] == "no-store"
    assert client.get("/api/asps/asp-nope/raw", headers=auth()).status_code == 404

    # The download is a valid upload: re-sending it is the same ASP.
    assert ingest(client, res.content) == {
        "accepted": True, "asp_id": loaded["asp_id"], "duplicate": True
    }


def test_index_names_the_database_for_copyable_commands(client):
    html = client.get("/").text
    path = str(Path(app_module.store.path).resolve())
    assert f'<meta name="raildash-db" content="{path}">' in html


# ----------------------------------------------------- CLI beside a server


def _free_port() -> int:
    with closing(socket.socket()) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _cli(database: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "raildash.cli", "--db", str(database), *args],
        cwd=ROOT, text=True, capture_output=True, timeout=60,
    )


def test_asp_cli_commands_work_while_raildash_serve_is_running(tmp_path):
    database = tmp_path / "raildash.db"
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    server = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                with urlopen(f"{url}/webhook/health", timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline or server.poll() is not None:
                    raise AssertionError("RailDash did not start")
                time.sleep(0.05)

        loaded = _cli(database, "asp", "load", str(ASP_FIXTURE))
        assert loaded.returncode == 0, loaded.stderr
        asp_id = json.loads(loaded.stdout)["asp_id"]

        made = _cli(database, "asp", "baseline", asp_id, "--version", "v1.0")
        assert made.returncode == 0, made.stderr
        version_id = json.loads(made.stdout)["alignment_version"]["alignment_version_id"]
        again = _cli(database, "asp", "baseline", asp_id, "--version", "v2.0")
        assert again.returncode == 0, again.stderr
        assert json.loads(again.stdout)["locked"] is False

        switched = _cli(database, "asp", "switch", version_id)
        assert switched.returncode == 0, switched.stderr
        listed = _cli(database, "asp", "list")
        assert listed.returncode == 0, listed.stderr
        assert len(json.loads(listed.stdout)["alignment_versions"]) == 1

        # The running server sees what the CLI wrote, and can still write.
        with urlopen(f"{url}/api/asps/{asp_id}/state", timeout=5) as response:
            assert json.loads(response.read())["state"] == "ALIGNED"
        token = (tmp_path / "raildash.db.token").read_text().strip()
        changed = changed_bundle("bnd-live", "live.example", "2026-09-24T03:00:00Z")
        request = Request(
            f"{url}/v1/evidence-bundles", data=changed, method="POST",
            headers={"X-RailDash-Token": token, "Content-Type": "application/json"},
        )
        with urlopen(request, timeout=5) as response:
            assert response.status == 202

        exported = tmp_path / "out" / "exported.json"
        exported.parent.mkdir(mode=0o700)
        result = _cli(database, "asp", "export", asp_id, str(exported))
        assert result.returncode == 0, result.stderr
        assert exported.read_bytes() == ASP_FIXTURE.read_bytes()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
