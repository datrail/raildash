"""`raildash` — serve the dashboard, or load a capture into it.

    raildash serve                      # http://127.0.0.1:8000
    raildash load capture.jsonl         # import a RailMon --output file
    raildash load capture.jsonl --serve # import, then open the dashboard on it

`load` exists because RailMon's normal output is a file. Requiring a live
webhook to see a capture would mean the report can only be read while the
thing being reported on is still running, which is the opposite of useful.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .ingest import normalise, read_jsonl
from .store import Store

DEFAULT_DB = "raildash.db"


def _session_id_for(path: Path) -> str:
    """Name the imported session after the file.

    Re-importing the same file therefore lands in the same session and the
    dedup index makes it a no-op, rather than accumulating a new near-identical
    session on every run.
    """
    return f"file:{path.name}"


def cmd_load(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"raildash: no such file: {path}", file=sys.stderr)
        return 2

    interactions, skipped = read_jsonl(str(path))
    if not interactions:
        print(
            f"raildash: {path} held no interactions"
            + (f" ({skipped} unparseable line(s))" if skipped else ""),
            file=sys.stderr,
        )
        return 1

    session_id = args.session_id or _session_id_for(path)
    store = Store(args.db)
    store.upsert_session(session_id, agent=args.agent or "", source=str(path))
    rows = [normalise(i) for i in interactions]
    inserted = store.add_interactions(session_id, rows)
    store.close()

    duplicate = len(rows) - inserted
    print(f"loaded {inserted} interaction(s) into session {session_id!r} ({args.db})")
    if duplicate:
        print(f"  {duplicate} already present, skipped")
    if skipped:
        # Loudly, not as a footnote: a truncated capture means the tail of what
        # the agent did is missing, which changes what the dashboard is showing.
        print(f"  {skipped} line(s) could not be parsed and were skipped")

    if args.serve:
        return cmd_serve(args)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print(
            "raildash: uvicorn is not installed — pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    # The app reads this at import, so it has to be set before the import below.
    os.environ["RAILDASH_DB"] = args.db
    from . import app as app_module

    print(f"raildash: database {args.db}")
    print(f"raildash: dashboard http://{args.host}:{args.port}/")
    uvicorn.run(app_module.app, host=args.host, port=args.port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raildash",
        description="Local dashboard for RailMon captures. No control plane required.",
    )
    parser.add_argument(
        "--db",
        default=os.environ.get("RAILDASH_DB", DEFAULT_DB),
        help=f"SQLite database path (default: {DEFAULT_DB})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the dashboard")
    # 127.0.0.1, not 0.0.0.0. The database holds captured agent traffic —
    # prompts, tool arguments, response bodies. Binding every interface by
    # default would publish that to the local network on first run. The
    # container overrides it explicitly, where the network namespace is the
    # boundary instead.
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=cmd_serve)

    load = sub.add_parser("load", help="import a RailMon JSONL capture")
    load.add_argument("file", help="path to RailMon's --output file")
    load.add_argument("--session-id", help="override the session name")
    load.add_argument("--agent", help="label the capture with an agent name")
    load.add_argument(
        "--serve", action="store_true", help="serve the dashboard after loading"
    )
    load.add_argument("--host", default="127.0.0.1")
    load.add_argument("--port", type=int, default=8000)
    load.set_defaults(func=cmd_load)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
