# Security Policy

RailDash receives captured agent traffic from RailMon over a webhook and shows
it in a local dashboard. The interactions it holds are request and response
bodies from somebody's agent, unredacted — so the data in a running RailDash is
as sensitive as the traffic that produced it.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Email **yusheng@railxia.com** with `SECURITY` in the subject.

GitHub's private vulnerability reporting is not available here yet — it is a
public-repository feature and these repos are still private. It becomes the
preferred channel once that changes.

Please include what an attacker can do (not only what is wrong), the version or
commit, the smallest reproduction you have, and whether you have told anyone
else.

## What to expect

| | |
| --- | --- |
| Acknowledgement | within 3 working days |
| First assessment | within 10 working days |
| Progress | at least every 10 working days until it closes |

We ask for **90 days** before public disclosure and will usually be much
faster. We will credit you unless you would rather not be named, and if we
disagree that a report is a vulnerability we will say so plainly rather than
let it go quiet.

## What this repository actually is, today

Read this before reporting — the component is smaller than its name suggests,
and a report against a capability it does not have costs us both time.

RailDash has two unauthenticated write routes:

```
POST /webhook/events              raw SSL events from RailMon
POST /webhook/http-interactions   parsed HTTP interactions
```

The dashboard, its `/api/*` query routes, the compatibility
`/webhook/sessions*` reads, and FastAPI's OpenAPI pages can read the resulting
SQLite database. The write routes accept UTF-8 JSON only, cap a request at 16
MiB, a batch at 1,000 items, JSON structure at 2,200,000 tokens, a scalar at 8
MiB, and nesting at 128 levels. RailMon splits a default batch using its actual
serialized size, including JSON escaping, before posting. The independent
limits prevent the wire allowance from becoming an unbounded Python object
tree. Parsing runs outside the async event loop. Credential headers — including
the `x-rail` ticket — are redacted before the raw interaction is persisted.

It does **not** register agents, issue tickets, evaluate policy, or record
gateway refusals. Standing in for the control plane is what DR-9 asks it to
become; it is not what this code does. There is no ticket-minting or signing
surface here to attack, because there is no ticket-minting surface at all.

Known and deliberate, in the current scope:

- **No authentication and no authorisation.** Any caller that can reach the
  port can post interactions and read every session.
- **No tenancy.** `GET /webhook/sessions/{id}` returns any session to any
  caller.
- **No source authentication.** A process that can reach either webhook can
  submit fabricated capture data. Browsers cannot use a CORS-simple
  `text/plain` request to do so, but another local process can.
- **State is persisted in SQLite.** Deleting the database (or using an
  unmounted container filesystem) deletes the stored capture; restarting the
  process does not.
- **One process owns one database.** RailDash holds an exclusive SQLite lock so
  a second or older process cannot write around a credential migration. Run one
  process per database; additional processes need separate database paths.

When a database created by a version before 0.2.0 is first opened, RailDash
redacts credential headers in bounded batches, enables SQLite secure deletion,
and truncates the WAL before marking the migration complete. This removes the
old bytes from the active database files. It cannot erase copies outside those
files — backups, volume snapshots, exported captures, and filesystem snapshots
must be deleted separately, and any credential that may have reached one
should be rotated.

The README calls these out as gaps to close before this is a production
dashboard, and they are — they are not a permanent design contract. But they
*are* the current state, so reporting "RailDash has no authentication" tells us
what we already say.

## What is in scope

- Anything that reaches beyond the process: command injection, path traversal,
  reading files off the host, SSRF out of the webhook handlers.
- Anything that makes RailDash appear to have verified something it did not —
  a stand-in that quietly looks trustworthy is worse than one that is obviously
  not.
- Denial of service that a single request within the documented body and batch
  limits can cause, or a way to bypass either limit.
- Anything in the dashboard's HTML output that lets captured traffic execute in
  a viewer's browser. Captured data is attacker-influenced by definition — an
  agent talks to the open internet — so it must never be rendered as markup.

Out of scope: the three deliberate gaps above, and vulnerabilities in FastAPI,
Uvicorn or other dependencies (report those upstream; we will help).

## Deployment expectation

RailDash is built to run locally alongside the components it displays. The CLI
binds `127.0.0.1` by default. The image binds `0.0.0.0` inside its container so
a published port can reach it, but the documented `docker run` maps that port
to host loopback only. With no authentication, anything that can reach the port
can read every captured interaction; keep it on loopback or behind something
that authenticates until the gaps above are closed.
