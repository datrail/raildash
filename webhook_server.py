#!/usr/bin/env python3
"""Compatibility entry point.

RailDash used to be this one file: a demo server that held captures in a dict
and rendered a table. The dashboard now lives in the `raildash` package, with
persistence and a UI, but the way people start it was documented here — in
this module's own docstring, in `openapi.yaml`, and in the previous
Dockerfile's CMD:

    uvicorn webhook_server:app --host 0.0.0.0 --port 8000

so that keeps working and means what it always did. Every route is unchanged
in path and meaning. Two deliberate differences, both visible:

  * `POST /webhook/http-interactions` also returns `stored`, alongside
    `received`. They differ when a sender retries, and reporting only
    `received` made a redelivery look like data loss. RailMon's sink checks
    the HTTP status and does not read the body, so nothing breaks on it.
  * `GET /webhook/sessions/{id}` returns 404 for a session that does not
    exist, rather than 200 with an `error` key — which is what `openapi.yaml`
    already promised.

New work should use `raildash serve`, or import `raildash.app:app`.
"""

from raildash.app import app

__all__ = ["app"]


if __name__ == "__main__":
    from raildash.cli import main

    raise SystemExit(main(["serve", "--host", "0.0.0.0", "--port", "8000"]))
