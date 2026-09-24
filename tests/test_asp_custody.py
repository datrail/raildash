from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from raildash.asp import parse_bundle
from raildash.cli import main
from raildash.store import Store


FIXTURE = Path(__file__).parent / "fixtures" / "evidence-bundle-v1.json"


def changed_bundle(*, bundle_id: str, destination: str | None = None) -> bytes:
    value = copy.deepcopy(parse_bundle(FIXTURE.read_bytes()))
    value["bundle_id"] = bundle_id
    value["collected_at"] = "2026-09-24T01:00:00Z"
    if destination is not None:
        value["attributes"]["declared_destinations"]["value"] = [destination]
    return json.dumps(value, sort_keys=True).encode()


def test_load_is_exact_idempotent_and_rejects_bundle_id_collision(tmp_path):
    store = Store(tmp_path / "raildash.db")
    raw = FIXTURE.read_bytes()
    first = store.load_asp(raw)
    replay = store.load_asp(raw)

    assert first["asp_id"] == replay["asp_id"]
    assert first["replayed"] is False
    assert replay["replayed"] is True
    assert store.asp_exact_bytes(first["asp_id"]) == raw

    collision = json.loads(raw)
    collision["sandbox_name"] = "different-copy"
    with pytest.raises(ValueError, match="bundle_id"):
        store.load_asp(json.dumps(collision).encode())
    store.close()


def test_replay_cannot_silently_change_an_operator_asserted_identity(tmp_path):
    value = json.loads(FIXTURE.read_bytes())
    value["attributes"]["deployment"]["value"] = {"RAIL_DEPLOYMENT": "half"}
    raw = json.dumps(value).encode()
    store = Store(tmp_path / "raildash.db")
    store.load_asp(raw, agent_key="agent-one")
    with pytest.raises(ValueError, match="different agent identity"):
        store.load_asp(raw, agent_key="agent-two")
    store.close()


def test_lock_switch_compare_and_redacted_page(tmp_path):
    store = Store(tmp_path / "raildash.db")
    baseline = store.load_asp(FIXTURE.read_bytes())
    version = store.lock_alignment(baseline["asp_id"], "v1.0")
    binding = store.switch_alignment(version["alignment_version_id"])
    current = store.load_asp(
        changed_bundle(bundle_id="bnd-custody-current", destination="private.example")
    )

    state = store.asp_state(current["asp_id"])
    assert state is not None
    assert binding["alignment_version_id"] == version["alignment_version_id"]
    assert state["state"] == "DRIFT_DETECTED"
    assert state["drift"]["has_drift"] is True
    assert "private.example" not in json.dumps(state)

    page = store.drift_page(current["asp_id"], limit=1)
    assert page is not None
    assert page["limit"] == 1
    assert len(page["changes"]) == 1
    assert "private.example" not in json.dumps(page)
    store.close()


def test_switch_recomputes_latest_asp_against_the_new_active_version(tmp_path):
    store = Store(tmp_path / "raildash.db")
    first = store.load_asp(FIXTURE.read_bytes())
    first_version = store.lock_alignment(first["asp_id"], "v1.0")
    store.switch_alignment(first_version["alignment_version_id"])
    changed = store.load_asp(
        changed_bundle(bundle_id="bnd-switch-current", destination="changed.example")
    )
    assert store.asp_state(changed["asp_id"])["state"] == "DRIFT_DETECTED"

    changed_version = store.lock_alignment(changed["asp_id"], "v2.0")
    store.switch_alignment(changed_version["alignment_version_id"])
    assert store.asp_state(changed["asp_id"])["state"] == "ALIGNED"
    assert store.drift_page(changed["asp_id"])["has_drift"] is False

    store.switch_alignment(first_version["alignment_version_id"])
    assert store.asp_state(changed["asp_id"])["state"] == "DRIFT_DETECTED"
    assert store.drift_detail(changed["asp_id"])["alignment_version_id"] == (
        first_version["alignment_version_id"]
    )
    store.close()


def test_drift_page_distinguishes_retained_detail_from_total_changes(tmp_path):
    store = Store(tmp_path / "raildash.db")
    baseline = store.load_asp(FIXTURE.read_bytes())
    version = store.lock_alignment(baseline["asp_id"], "v1.0")
    store.switch_alignment(version["alignment_version_id"])
    value = json.loads(FIXTURE.read_bytes())
    value["bundle_id"] = "bnd-truncated-detail"
    value["collected_at"] = "2026-09-24T03:00:00Z"
    for index in range(501):
        value["attributes"][f"added_{index:03d}"] = {
            "value": index,
            "status": "ANSWERED",
            "tier": "observed",
            "authored_by": "none",
        }
    current = store.load_asp(json.dumps(value).encode())

    page = store.drift_page(current["asp_id"], limit=20, offset=500)
    assert page["change_count"] == 501
    assert page["available_change_count"] == 500
    assert page["changes"] == []
    assert page["truncated"] is True
    store.close()


def test_alignment_and_locked_asp_are_immutable(tmp_path):
    path = tmp_path / "raildash.db"
    store = Store(path)
    asp = store.load_asp(FIXTURE.read_bytes())
    version = store.lock_alignment(asp["asp_id"], "v1.0")

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._db.execute("UPDATE asps SET host_id = 'changed'")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._db.execute("DELETE FROM asps WHERE asp_id = ?", (asp["asp_id"],))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._db.execute(
            "UPDATE alignment_versions SET version = 'v2.0' WHERE alignment_version_id = ?",
            (version["alignment_version_id"],),
        )
    store.close()


def test_retention_never_prunes_locked_asp(tmp_path):
    store = Store(tmp_path / "raildash.db")
    locked = store.load_asp(FIXTURE.read_bytes())
    store.lock_alignment(locked["asp_id"], "v1.0")
    unlocked = store.load_asp(changed_bundle(bundle_id="bnd-unlocked"))

    assert store.prune_asp_history(keep_count=0, max_age_days=0) == 1
    assert store.asp_exact_bytes(locked["asp_id"]) == FIXTURE.read_bytes()
    assert store.asp_exact_bytes(unlocked["asp_id"]) is None
    store.close()


def test_configured_default_retention_runs_after_load(tmp_path, monkeypatch):
    monkeypatch.setenv("RAILDASH_ASP_RETENTION_COUNT", "1")
    monkeypatch.setenv("RAILDASH_ASP_RETENTION_DAYS", "30")
    store = Store(tmp_path / "raildash.db")
    store.load_asp(FIXTURE.read_bytes())
    newest = store.load_asp(changed_bundle(bundle_id="bnd-newest"))
    assert [item["asp_id"] for item in store.asp_summaries()] == [newest["asp_id"]]
    store.close()


def test_automatic_retention_rejects_zero_before_opening_database(tmp_path, monkeypatch):
    monkeypatch.setenv("RAILDASH_ASP_RETENTION_COUNT", "0")
    with pytest.raises(RuntimeError, match="positive integer"):
        Store(tmp_path / "raildash.db")


def test_database_and_export_are_owner_only(tmp_path):
    path = tmp_path / "raildash.db"
    store = Store(path)
    asp = store.load_asp(FIXTURE.read_bytes())
    store.close()
    assert path.stat().st_mode & 0o777 == 0o600

    output = tmp_path / "bundle.json"
    assert main(["--db", str(path), "asp", "export", asp["asp_id"], str(output)]) == 0
    assert output.read_bytes() == FIXTURE.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o600


def test_owner_only_drift_export_contains_full_evidence(tmp_path):
    path = tmp_path / "raildash.db"
    store = Store(path)
    baseline = store.load_asp(FIXTURE.read_bytes())
    version = store.lock_alignment(baseline["asp_id"], "v1.0")
    store.switch_alignment(version["alignment_version_id"])
    current = store.load_asp(
        changed_bundle(bundle_id="bnd-private-detail", destination="private.example")
    )
    store.close()

    output = tmp_path / "drift.json"
    assert main(
        ["--db", str(path), "asp", "drift-export", current["asp_id"], str(output)]
    ) == 0
    detail = json.loads(output.read_text())
    assert detail["current"]["attributes"]["declared_destinations"]["value"] == [
        "private.example"
    ]
    assert output.stat().st_mode & 0o777 == 0o600


def test_unsafe_database_and_export_parents_are_rejected(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(RuntimeError, match="group/other writable"):
        Store(unsafe / "raildash.db")

    safe_db = tmp_path / "raildash.db"
    store = Store(safe_db)
    asp = store.load_asp(FIXTURE.read_bytes())
    store.close()
    assert main(
        ["--db", str(safe_db), "asp", "export", asp["asp_id"], str(unsafe / "out.json")]
    ) == 1


def test_cli_load_lock_switch_and_list_round_trip(tmp_path, capsys):
    db = tmp_path / "raildash.db"
    assert main(["--db", str(db), "asp", "load", str(FIXTURE)]) == 0
    loaded = json.loads(capsys.readouterr().out)
    assert loaded["asp_id"].startswith("asp-")

    assert main(["--db", str(db), "asp", "lock", loaded["asp_id"], "--version", "v1.0"]) == 0
    version = json.loads(capsys.readouterr().out)
    assert main(["--db", str(db), "asp", "switch", version["alignment_version_id"]]) == 0
    capsys.readouterr()
    assert main(["--db", str(db), "asp", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["asps"][0]["asp_id"] == loaded["asp_id"]
    assert listed["alignment_versions"][0]["active"] is True


def test_standalone_acceptance_oracle_passes_without_exposing_evidence_values():
    root = Path(__file__).parents[1]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(root)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "raildash.acceptance",
            "--fixture",
            "tests/fixtures/evidence-bundle-v1.json",
        ],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )
    report = json.loads(result.stdout)
    assert report["acceptance"] == "passed"
    assert all(report["checks"].values())
    assert "acceptance-change.example" not in result.stdout
    assert "sha256:" not in result.stdout


def test_acceptance_oracle_refuses_an_existing_database(tmp_path):
    database = tmp_path / "existing.db"
    database.touch()
    with pytest.raises(SystemExit):
        from raildash.acceptance import main

        old_argv = sys.argv
        try:
            sys.argv = [
                "raildash-asp-acceptance",
                "--fixture",
                str(FIXTURE),
                "--database",
                str(database),
            ]
            main()
        finally:
            sys.argv = old_argv
