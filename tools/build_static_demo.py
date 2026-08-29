#!/usr/bin/env python3
"""Build a deterministic static RailDash site from the synthetic fixture."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raildash.ingest import normalise, read_jsonl  # noqa: E402
from raildash.store import Store  # noqa: E402

STATIC = ROOT / "raildash" / "static"
FIXTURE = ROOT / "tests" / "fixtures" / "capture.jsonl"
MARKER = ".raildash-static-demo"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def validate_output(output: Path) -> None:
    if output.exists() and not output.is_dir():
        raise ValueError(f"output exists and is not a directory: {output}")
    if not output.exists():
        return
    children = list(output.iterdir())
    if children and not (output / MARKER).is_file():
        raise ValueError(
            "refusing to replace a nonempty directory not created by this builder: "
            f"{output}"
        )


def render(output: Path) -> None:
    output.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="raildash-static-demo-") as temp:
        store = Store(Path(temp) / "fixture.db")
        items, _ = read_jsonl(str(FIXTURE))
        session_id = "fixture-demo"
        store.upsert_session(session_id, agent="synthetic-agent", source="fixture")
        store.add_interactions(session_id, [normalise(item) for item in items])

        interactions = store.interactions(session_id=session_id, limit=500)["items"]
        profile = store.observed_profile(session_id)
        assert profile is not None
        payload = {
            "fixture": "tests/fixtures/capture.jsonl",
            "sessions": store.sessions(),
            "overview": store.overview(session_id),
            "profile": profile,
            "filters": {
                "hosts": store.distinct("host", session_id),
                "methods": store.distinct("method", session_id),
            },
            "interactions": interactions,
            "details": {
                str(row["id"]): store.investigation(row["id"])
                for row in interactions
            },
        }
        store.close()

    html = (STATIC / "index.html").read_text()
    html = html.replace('href="/app.css"', 'href="./app.css"')
    html = html.replace('src="/app.js"', 'src="./app.js"')
    html = html.replace(
        '<script src="./app.js"></script>',
        '<script>window.RAIL_DASH_STATIC_DEMO = true;</script>\n'
        '<script src="./app.js"></script>',
    )
    (output / "index.html").write_text(html)
    (output / "app.css").write_bytes((STATIC / "app.css").read_bytes())
    (output / "app.js").write_bytes((STATIC / "app.js").read_bytes())
    (output / ".nojekyll").write_text("")
    (output / MARKER).write_text("synthetic fixture build\n")
    write_json(output / "fixture-data.json", payload)
    write_json(output / "profile.json", profile)


def build(output: Path) -> None:
    if output.is_symlink():
        raise ValueError(f"refusing symlink output: {output}")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    validate_output(output)

    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    backup: Path | None = None
    try:
        # mkdtemp creates the directory; render expects to create it itself.
        stage.rmdir()
        render(stage)
        if output.exists():
            backup = Path(
                tempfile.mkdtemp(prefix=f".{output.name}.previous.", dir=output.parent)
            )
            backup.rmdir()
            os.replace(output, backup)
        try:
            os.replace(stage, output)
        except BaseException:
            if backup is not None and backup.exists() and not output.exists():
                os.replace(backup, output)
            raise
        if backup is not None:
            shutil.rmtree(backup)
            backup = None
    finally:
        if stage.exists():
            shutil.rmtree(stage)
        # If replacement and rollback both fail, leave the backup in place for
        # recovery instead of turning a filesystem error into data loss.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.output)
    print(f"built static fixture demo: {args.output.resolve()}")


if __name__ == "__main__":
    main()
