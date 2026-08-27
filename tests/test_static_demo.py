"""Deterministic, hosting-ready export of the synthetic fixture demo."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parent.parent
BUILDER = ROOT / "tools" / "build_static_demo.py"


def build(output: Path) -> None:
    subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=ROOT,
        check=True,
    )


def digest_tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_static_demo_build_is_reproducible(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"

    build(first)
    build(second)

    assert digest_tree(first) == digest_tree(second)


def test_static_demo_contains_only_fixture_data_and_static_assets(tmp_path):
    output = tmp_path / "site"
    build(output)

    assert {path.name for path in output.iterdir()} == {
        ".nojekyll",
        ".raildash-static-demo",
        "app.css",
        "app.js",
        "fixture-data.json",
        "index.html",
        "profile.json",
    }
    html = (output / "index.html").read_text()
    js = (output / "app.js").read_text()
    payload = json.loads((output / "fixture-data.json").read_text())
    rendered = json.dumps(payload)

    assert "Static fixture demo" in html
    assert "No live capture" in html
    assert "RAIL_DASH_STATIC_DEMO" in html
    assert "filterStaticInteractions" in js
    assert "filtered.slice(offset, offset + limit)" in js
    assert payload["fixture"] == "tests/fixtures/capture.jsonl"
    assert payload["sessions"][0]["interaction_count"] == 8
    assert len(payload["interactions"]) == 8
    assert "github.com/datrail" not in rendered
    assert "REDACTED-BY-RAILMON" not in rendered


def test_static_demo_rebuild_removes_unknown_stale_content(tmp_path):
    output = tmp_path / "site"
    build(output)
    (output / "stale-private.txt").write_text("must not survive")

    build(output)

    assert not (output / "stale-private.txt").exists()
    assert {path.name for path in output.iterdir()} == {
        ".nojekyll",
        ".raildash-static-demo",
        "app.css",
        "app.js",
        "fixture-data.json",
        "index.html",
        "profile.json",
    }


def test_static_demo_refuses_an_unowned_nonempty_output(tmp_path):
    output = tmp_path / "unowned"
    output.mkdir()
    existing = output / "index.html"
    existing.write_text("keep me")

    result = subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert result.returncode != 0
    assert existing.read_text() == "keep me"


def test_static_demo_profile_matches_the_versioned_observed_contract(tmp_path):
    output = tmp_path / "site"
    build(output)

    profile = json.loads((output / "profile.json").read_text())

    assert profile["schema_version"] == "1.0"
    assert profile["source"] == "raildash-observed"
    assert profile["authoritative"] is False
    assert profile["session"]["id"] == "fixture-demo"
