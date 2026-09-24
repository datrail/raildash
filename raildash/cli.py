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
import json
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


def _open_store(args: argparse.Namespace) -> Store:
    try:
        return Store(args.db)
    except Exception as exc:
        print(f"raildash: cannot open database exclusively: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def cmd_asp_load(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"raildash: no such file: {path}", file=sys.stderr)
        return 2
    try:
        raw = path.read_bytes()
        store = _open_store(args)
        result = store.load_asp(raw, agent_key=args.agent_key)
        store.close()
    except (OSError, ValueError) as exc:
        print(f"raildash: ASP load failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_asp_list(args: argparse.Namespace) -> int:
    store = _open_store(args)
    result = {
        "asps": store.asp_summaries(),
        "alignment_versions": store.alignment_summaries(),
    }
    store.close()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_asp_lock(args: argparse.Namespace) -> int:
    try:
        store = _open_store(args)
        result = store.lock_alignment(args.asp_id, args.version)
        store.close()
    except (KeyError, ValueError) as exc:
        print(f"raildash: ASP lock failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_asp_switch(args: argparse.Namespace) -> int:
    try:
        store = _open_store(args)
        result = store.switch_alignment(args.alignment_version_id)
        store.close()
    except KeyError as exc:
        print(f"raildash: ASP switch failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_asp_export(args: argparse.Namespace) -> int:
    output = Path(args.output)
    try:
        if output.exists():
            print(f"raildash: refusing to overwrite: {output}", file=sys.stderr)
            return 1
        parent_mode = output.resolve().parent.stat().st_mode
        if parent_mode & 0o022:
            print("raildash: export parent must not be group/other writable", file=sys.stderr)
            return 1
        store = _open_store(args)
        raw = store.asp_exact_bytes(args.asp_id)
        store.close()
        if raw is None:
            print("raildash: no such ASP", file=sys.stderr)
            return 1
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    except OSError as exc:
        print(f"raildash: ASP export failed: {exc}", file=sys.stderr)
        return 1
    print(f"exported {args.asp_id} to {output}")
    return 0


def cmd_asp_drift_export(args: argparse.Namespace) -> int:
    output = Path(args.output)
    try:
        if output.exists():
            print(f"raildash: refusing to overwrite: {output}", file=sys.stderr)
            return 1
        if output.resolve().parent.stat().st_mode & 0o022:
            print("raildash: export parent must not be group/other writable", file=sys.stderr)
            return 1
        store = _open_store(args)
        detail = store.drift_detail(args.asp_id)
        store.close()
        if detail is None:
            print("raildash: no drift result for ASP", file=sys.stderr)
            return 1
        payload = json.dumps(detail, indent=2, ensure_ascii=False).encode()
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
    except OSError as exc:
        print(f"raildash: drift export failed: {exc}", file=sys.stderr)
        return 1
    print(f"exported full drift evidence for {args.asp_id} to {output}")
    return 0


def cmd_asp_prune(args: argparse.Namespace) -> int:
    try:
        store = _open_store(args)
        removed = store.prune_asp_history(
            keep_count=args.keep_count, max_age_days=args.max_age_days
        )
        store.close()
    except ValueError as exc:
        print(f"raildash: ASP prune failed: {exc}", file=sys.stderr)
        return 1
    print(f"pruned {removed} unlocked ASP(s); locked history was preserved")
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

    asp = sub.add_parser("asp", help="manage immutable Agent Security Profiles")
    asp_sub = asp.add_subparsers(dest="asp_command", required=True)

    asp_load = asp_sub.add_parser("load", help="validate and retain an evidence bundle")
    asp_load.add_argument("file")
    asp_load.add_argument("--agent-key", help="explicit identity for an otherwise unkeyed bundle")
    asp_load.set_defaults(func=cmd_asp_load)

    asp_list = asp_sub.add_parser("list", help="review stored ASP and alignment metadata")
    asp_list.set_defaults(func=cmd_asp_list)

    asp_lock = asp_sub.add_parser("lock", help="lock one stored ASP as an immutable alignment version")
    asp_lock.add_argument("asp_id")
    asp_lock.add_argument("--version", required=True)
    asp_lock.set_defaults(func=cmd_asp_lock)

    asp_switch = asp_sub.add_parser("switch", help="make an alignment version active")
    asp_switch.add_argument("alignment_version_id")
    asp_switch.set_defaults(func=cmd_asp_switch)

    asp_export = asp_sub.add_parser("export", help="export exact ASP evidence to a private file")
    asp_export.add_argument("asp_id")
    asp_export.add_argument("output")
    asp_export.set_defaults(func=cmd_asp_export)

    drift_export = asp_sub.add_parser(
        "drift-export", help="export full baseline/current evidence to a private file"
    )
    drift_export.add_argument("asp_id")
    drift_export.add_argument("output")
    drift_export.set_defaults(func=cmd_asp_drift_export)

    prune = asp_sub.add_parser(
        "prune", help="prune unlocked ASPs using independent count and age bounds"
    )
    prune.add_argument("--keep-count", type=int, default=100)
    prune.add_argument("--max-age-days", type=int, default=30)
    prune.set_defaults(func=cmd_asp_prune)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
