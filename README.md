# RailDash

A local view of what an agent actually did.

RailDash reads a [RailMon](https://github.com/datrail/railmon) capture and
shows the traffic in it: which hosts the agent reached, what it sent, what came
back, which calls failed, and where it called a tool. **It needs no control
plane.** If you have installed only the open-source components, this is the
thing that shows you the report.

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

## What it shows

| | |
| --- | --- |
| **Summary** | interactions, distinct hosts, failures and failure rate, tool calls, latency, bytes each way |
| **Where the agent went** | every host, ranked, with its failure count and average latency — click one to filter the log |
| **Interaction log** | one row per request/response pair, filterable by host, method, status class, and failures only |
| **Detail** | the full exchange — headers and bodies both ways, exactly as RailMon captured them |

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

## Docker

```bash
docker build -t raildash .
docker run --rm -p 8000:8000 -v raildash-data:/data raildash
```

The image binds `0.0.0.0`, where the network namespace is the boundary and the
operator chooses what to publish. Without the volume it forgets on restart.

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
