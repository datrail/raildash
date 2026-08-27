# RailDash

A local view of what an agent actually did.

RailDash reads a [RailMon](https://github.com/datrail/railmon) capture and
shows the traffic in it: which hosts the agent reached, what it sent, what came
back, which calls failed, and where it called a tool. **It needs no control
plane.** If you have installed only the open-source components, this is the
thing that shows you the report.

## Quick start

One command from a clean checkout. No cloud, no account, no Rail Center — and
no other component running, not even RailMon. You need Python 3.10+ with the
`venv` module, and `make`. On Debian and Ubuntu (WSL included) `venv` is a
separate package — if the first run fails with *"ensurepip is not
available"*, install the package that error names (for example
`sudo apt install python3.14-venv`) and run `make demo` again.

```bash
git clone https://github.com/datrail/raildash.git
cd raildash
make demo
```

`make demo` builds a virtualenv, installs the two dependencies (FastAPI and
uvicorn), loads `tests/fixtures/capture.jsonl` — a small capture shaped
exactly like RailMon's output — into a local `demo.db`, and serves the
dashboard.

Open <http://127.0.0.1:8000/>. **You should see** a populated dashboard, not
an empty one: 8 interactions across 4 hosts, 3 failures and 2 tool calls in
the summary; a host list topped by `api.anthropic.com`; and an interaction
log whose status codes include a 429, a 403 and a 500 — the 500, against
`exfil.attacker.net`, is the fixture's deliberately alarming row. Two rows
are flagged `1 tool` and four are flagged `x-rail`. If that is what you see,
it works.

## Installing

```bash
pip install -e .

# a capture you already have
raildash load capture.jsonl --serve

# or leave it running and point RailMon at it
raildash serve
```

Without installing, every command below also works as
`python -m raildash.cli …` once `pip install -r requirements.txt` has run.

Then open <http://127.0.0.1:8000/>.

## Getting a capture into it

RailMon has two outputs and RailDash takes both.

**A file** — the usual case, and the one that still works after the run is
over:

```bash
sudo railmon collect --mode http --output capture.jsonl
raildash load capture.jsonl
```

Re-loading the same file is a no-op rather than a duplicate: interactions are
keyed on RailMon's content-hashed `interaction_id`.

**A live webhook** — the dashboard updates while the agent runs:

```bash
sudo railmon collect --mode http \
  --webhook http://127.0.0.1:8000/webhook/http-interactions
```

## Running both together (DR-81)

The two sections above are RailMon and RailDash run and wired by hand. This
repo also ships a `docker compose` stack that does both automatically, with
both wirings active at once:

```bash
git clone https://github.com/datrail/raildash.git
cd raildash
make stack
```

`make stack` clones `datrail/railmon` into `./railmon` (this repo has no
RailMon source of its own — see `docker-compose.yml`'s header for why that is
a clone-as-bootstrap step rather than a reason to vendor a copy), builds both
images, and brings the stack up: RailMon runs its own local quickstart demo
(a real, local, offline HTTPS exchange it generates and taps itself — see
RailMon's `tools/local-demo/README.md` — not a connection to any real agent),
posting to this dashboard's webhook *and* writing to a file RailDash then
imports, so a first run shows something without anything else having to be
running first.

**You should see**, a few seconds after `docker compose ps` prints: RailMon's
container ran once and exited 0 (expected — the demo capture finishes and
stops, it is not a long-running collector), the file-import step reporting
`6 already present, skipped`, and <http://127.0.0.1:8000> showing **6
interactions** against `127.0.0.1:8443`, all `POST`, all `200`, across
`/v1/demo` and `/v1/demo/other`.

Six, from three requests, is correct and worth understanding before you read
it as a bug. RailMon's demo taps by process name (`--comm python3`), and both
ends of the exchange — `demo_server.py` and `demo_client.py` — are `python3`,
so each request is captured twice: once as the client sent it, once as the
server received it. They are two genuine observations of one exchange, with
different `pid`s, not one row written twice. In the interaction log they show
as pairs sharing a timestamp to the millisecond. See RailMon's
`tools/local-demo/README.md` for why the demo filters that broadly.

**Double-counting would look like 12, not 6** — and that is what the two
ingestion paths would produce if they were wired naively. The file-import
step reporting `6 already present, skipped` is the dedup working: the webhook
delivered those 6 while RailMon ran, and the import then recognised every one
rather than adding a second copy. `make stack-test` asserts this
automatically (stored count == `capture.jsonl` line count) rather than
leaving it to be eyeballed.

Both wirings land on the same interactions without double-counting only
because they are told the same session id — `DEMO_SESSION_ID` in the
`Makefile` is the single source, reaching RailMon as `RAILMON_SESSION_ID` and
the import step as `--session-id`. The JSONL file carries no session id of its
own, and this dashboard's dedup index is `(session_id, interaction_id)`, not
`interaction_id` alone. Wiring the two paths up with mismatched session ids —
which is what happens if you copy this pattern without also fixing the session
id — silently doubles every count instead of erroring.

`make stack` briefly stops the dashboard to run that import, and you will see
it in the output. That follows directly from the single-process rule in
**Storage** above: RailDash holds an exclusive SQLite lock, so `raildash load`
cannot open the database while `raildash serve` has it, wherever that database
lives. Pausing the server makes the import the sole owner for those few
seconds, which keeps the file path on `raildash load` — RailDash's real
documented import command — rather than faking it by POSTing the file to the
webhook. The pause happens during setup, before anyone has opened the
dashboard. The alternative the Storage section names, a separate `--db` path,
would defeat the point here: the two ingestion paths have to land in one
database to be deduplicated against each other.

Those numbers describe a first run on empty volumes. `make stack-down` stops
the stack but keeps them, and RailMon's capture file appends rather than
truncating, so a second `make stack` shows both runs — 12 interactions, not 6,
and correctly so. `make stack-clean` removes the volumes and the cloned
`railmon/`, which is what makes the counts above true again. `make stack-test`
always tears its volumes down, so its assertion does not depend on what ran
before it.

Stopping RailMon (`docker compose stop railmon`) leaves the dashboard serving
what it already has, same as the "no control plane" reasoning above — the file
path is passive and the webhook path only ever pushed.

## What it shows

| | |
| --- | --- |
| **Summary** | interactions, distinct hosts, failures and failure rate, tool calls, latency, bytes each way |
| **Where the agent went** | every host, ranked, with its failure count and average latency — click one to filter the log |
| **Interaction log** | one row per request/response pair, filterable by host, method, status class, and failures only |
| **Detail** | the full exchange in both directions; credential headers are redacted before storage, while bodies remain exactly as RailMon captured them |

Two flags on a row are worth knowing. `n tool` counts `tool_use` blocks in the
exchange, which is the closest thing in the payload to *the agent took an
action*. `x-rail` means the request carried a ticket — **whether**, never the
value.

## What it does not do

- **No control plane.** It does not register agents, issue tickets, or score
  posture. DR-9's ticket text describes that view; this is the other one, and
  the one an OSS-only install can actually populate — with no proxy or gateway
  in the deployment there are no refusals to display.
- **No authentication.** It binds `127.0.0.1` by default for that reason. The
  database holds captured prompts, tool arguments and response bodies; do not
  put it on a shared interface without something in front of it.
- **No log ingestion.** It reads interactions, not agent stdout.

## Storage

SQLite, at `./raildash.db` — override with `--db` or `RAILDASH_DB`. It
persists because the question "what did the agent do" is normally asked after
something has already gone wrong, and an in-memory store can only answer it if
you still have the process.

One process owns a database at a time. RailDash keeps an exclusive SQLite lock
so an older process cannot write unredacted rows around a schema migration; use
a separate `--db` path if you intentionally run another process.

On first open, version 0.2.0 removes credential headers left by older RailDash
databases and purges the active SQLite/WAL files. That cannot reach backups,
volume snapshots, or exported copies: delete those separately and rotate any
credential that may have been captured before upgrading.

## Docker

```bash
docker build -t raildash .
docker run --rm -p 127.0.0.1:8000:8000 -v raildash-data:/data raildash
```

The image binds `0.0.0.0`, where the network namespace is the boundary and the
operator chooses what to publish. The example maps it only onto the host's
loopback interface because RailDash has no authentication and contains captured
request and response bodies. Without the volume it forgets on restart.

Unlike `make demo`, a fresh container starts empty: the image ships no
fixture, so a first run shows an empty dashboard until a capture arrives —
via the webhook, or by mounting a directory with a capture in it and loading
it with `docker exec <container> python -m raildash.cli load <file>`.

## Development

```bash
make test     # pytest + py_compile
make lint     # static check of the three front-end files
make demo     # load the test fixture and serve it
```

`tests/fixtures/capture.jsonl` is shaped exactly like RailMon's output,
including the two fields that are routinely null in a real capture — a
`request` whose HTTP/2 HEADERS frame was never decoded, and a `latency_ms`
with no paired request. Both are ordinary; both have tests.

The front end is three static files with no build step. `make lint` checks
what a build step otherwise would: that every CSS token is defined, every id
the script reaches for exists, and no code path assigns markup — captured
traffic is untrusted input, so every value reaches the page via `textContent`.

## Compatibility

`uvicorn webhook_server:app` still starts the server and every `/webhook/*`
route keeps its path and meaning. Two visible differences:
`POST /webhook/http-interactions` also returns `stored` alongside `received`,
which distinguishes a retry from a first delivery, and
`GET /webhook/sessions/{id}` returns 404 for a missing session rather than 200
with an `error` key.

## License

MIT; see [LICENSE](LICENSE).
