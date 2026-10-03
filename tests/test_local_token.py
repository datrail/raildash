"""The local write token survives a restart (DR-156).

RailMon delivers evidence bundles unattended with the token it was configured
with, so a RailDash restart must not invalidate it. Each "restart" below is a
fresh interpreter importing `raildash.app` against the same database, the same
as `raildash serve` or the container's uvicorn starting again.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from raildash import app as app_module

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "evidence-bundle-v1.json"

# Starts RailDash's app against RAILDASH_DB, prints the token it settled on,
# and, given a token in argv, pushes the fixture bundle the way RailMon does.
_START = """
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from raildash import app
print(app.LOCAL_TOKEN)
if len(sys.argv) > 1:
    response = TestClient(app.app).post(
        "/v1/evidence-bundles?agent_key=restart-test",
        content=Path(sys.argv[2]).read_bytes(),
        headers={"X-RailDash-Token": sys.argv[1]},
    )
    print(response.status_code)
app.store.close()
"""


def start(db: Path, *argv: str, token_env: str | None = None) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment["RAILDASH_DB"] = str(db)
    environment.pop("RAILDASH_TOKEN", None)
    if token_env is not None:
        environment["RAILDASH_TOKEN"] = token_env
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT), *filter(None, environment.get("PYTHONPATH", "").split(os.pathsep))]
    )
    return subprocess.run(
        [sys.executable, "-c", _START, *argv],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_restart_keeps_the_token_and_a_railmon_push_with_it_is_accepted(tmp_path):
    db = tmp_path / "raildash.db"
    first = start(db)
    assert first.returncode == 0, first.stderr
    token = first.stdout.split()[0]
    token_file = Path(f"{db}.token")
    assert token_file.read_text() == token
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert f"generated and written to {token_file}" in first.stderr
    assert token not in first.stderr

    second = start(db, token, str(FIXTURE))
    assert second.returncode == 0, second.stderr
    restarted_token, status = second.stdout.split()
    assert restarted_token == token
    assert status == "202"
    assert f"reused from {token_file}" in second.stderr


def test_a_stale_token_is_still_rejected_after_restart(tmp_path):
    db = tmp_path / "raildash.db"
    assert start(db).returncode == 0
    after = start(db, "not-the-token-" + "x" * 16, str(FIXTURE))
    assert after.returncode == 0, after.stderr
    assert after.stdout.split()[1] == "403"


def test_env_override_wins_and_is_written_for_co_located_scripts(tmp_path):
    db = tmp_path / "raildash.db"
    assert start(db).returncode == 0
    configured = "configured-token-0123456789"

    run = start(db, configured, str(FIXTURE), token_env=configured)
    assert run.returncode == 0, run.stderr
    token, status = run.stdout.split()
    assert token == configured
    assert status == "202"
    assert "from RAILDASH_TOKEN" in run.stderr
    assert Path(f"{db}.token").read_text() == configured

    # And it stays stable once the override is gone again.
    later = start(db)
    assert later.stdout.split()[0] == configured


@pytest.mark.parametrize("bad", ["short", "has spaces in it 0123456789", 'quote"0123456789abcdef'])
def test_unusable_env_token_fails_loudly(tmp_path, bad):
    with pytest.raises(RuntimeError, match="RAILDASH_TOKEN"):
        app_module.resolve_local_token(str(tmp_path / "r.db"), {"RAILDASH_TOKEN": bad})


def test_unusable_token_file_is_replaced_and_tightened(tmp_path):
    db = tmp_path / "r.db"
    token_file = Path(f"{db}.token")
    token_file.write_text("short\n")
    token_file.chmod(0o644)
    token, source = app_module.resolve_local_token(str(db), {})
    assert token != "short" and len(token) >= app_module.MIN_TOKEN_CHARS
    assert token_file.read_text() == token
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert source.startswith("generated")


def test_existing_token_file_is_reused_with_trailing_newline_and_tightened(tmp_path):
    db = tmp_path / "r.db"
    token_file = Path(f"{db}.token")
    token_file.write_text("hand-written-token-0123456789\n")
    token_file.chmod(0o644)
    token, source = app_module.resolve_local_token(str(db), {})
    assert token == "hand-written-token-0123456789"
    assert source.startswith("reused")
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600


def test_symlinked_token_file_is_not_followed(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("attacker-chosen-token-0123456789")
    db = tmp_path / "r.db"
    Path(f"{db}.token").symlink_to(target)
    token, _ = app_module.resolve_local_token(str(db), {})
    assert token != "attacker-chosen-token-0123456789"
    assert target.read_text() == "attacker-chosen-token-0123456789"


def test_in_memory_database_gets_a_random_token(tmp_path):
    token, source = app_module.resolve_local_token(":memory:", {})
    assert len(token) >= app_module.MIN_TOKEN_CHARS
    assert "in-memory" in source
