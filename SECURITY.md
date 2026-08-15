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

RailDash currently serves six routes and nothing else:

```
POST /webhook/events              raw SSL events from RailMon
POST /webhook/http-interactions   parsed HTTP interactions
GET  /webhook/sessions            list captured sessions
GET  /webhook/sessions/{id}       one session
GET  /webhook/health
GET  /                            the dashboard
```

It does **not** register agents, issue tickets, evaluate policy, or record
gateway refusals. Standing in for the control plane is what DR-9 asks it to
become; it is not what this code does. There is no ticket-minting or signing
surface here to attack, because there is no ticket-minting surface at all.

Known and deliberate, in the current scope:

- **No authentication and no authorisation.** Any caller that can reach the
  port can post interactions and read every session.
- **No tenancy.** `GET /webhook/sessions/{id}` returns any session to any
  caller.
- **State is in process memory** and is lost on restart. Nothing is persisted.

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
- Denial of service that a single well-formed request can cause. The
  unbounded in-memory session store is a plausible route and worth a report if
  you can make it bite in practice.
- Anything in the dashboard's HTML output that lets captured traffic execute in
  a viewer's browser. Captured data is attacker-influenced by definition — an
  agent talks to the open internet — so it must never be rendered as markup.

Out of scope: the three deliberate gaps above, and vulnerabilities in FastAPI,
Uvicorn or other dependencies (report those upstream; we will help).

## Deployment expectation

RailDash is built to run locally alongside the components it displays. It binds
`0.0.0.0` by default, which is convenient inside a container and wrong on a
shared network — with no authentication, anything that can reach the port can
read every captured interaction. Bind it to localhost or keep it behind
something that authenticates until the gaps above are closed.
