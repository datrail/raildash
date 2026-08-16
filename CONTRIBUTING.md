# Contributing to RailDash

RailDash is the local dashboard for [DatRail](https://github.com/datrail). It
receives captured traffic from RailMon over a webhook and shows it.

**What it is today and what it is meant to become are different**, and it is
worth knowing which you are working on. Today it serves six routes — two
webhook intakes, two session reads, health, and the dashboard. DR-9 asks it to
also stand in for the control plane in the offline bundle: accepting
registrations, issuing tickets, and recording gateway refusals. None of that
exists yet.

## The constraint that will shape the control-plane work

**Components must not be able to tell RailDash from Rail Center.** No code
change, no branch, no different request shape, no special-casing. If a
contribution requires a component to behave differently when talking to
RailDash, it is the wrong shape — raise an issue and we will find another way.

That cuts both directions: RailDash must accept the contracts RailScan and the
gateway already speak, and must not invent one of its own that Rail Center does
not serve.

## Two honest limitations, not bugs

Please do not "fix" these in passing without discussing it first — they are the
current scope, and the README records the first of them:

- state is in process memory and is lost on restart;
- there is no authentication and no tenancy, so any caller that reaches the
  port can read every session.

Both should close before this is a production dashboard. Neither is a secret,
and neither is a useful vulnerability report — see [SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn webhook_server:app --host 0.0.0.0 --port 8000
```

```bash
pip install -r requirements-dev.txt
make test
```

The API contract is in [`openapi.yaml`](openapi.yaml). If you change a route,
change that file in the same commit — it is what the other components are
written against.

## On the UI

RailDash is scanned and operated, not read. Two things are worth keeping:
summary before detail, and state encoded in more than colour — a chip carries a
glyph and a word, because a traffic-light palette is not separable by hue alone
for a colour-blind reader.

There is a design proposal for what DR-9 asks this dashboard to become — see
the open pull request on branch `DR-9-control-plane-ui-proposal`. It is a
proposal, not a decision, and is not on `master` yet.

## Sending a change

- One coherent change per pull request; the message says *why*.
- Branch from `master`, **sign off your commits** (`git commit -s`,
  [DCO](https://developercertificate.org/)), no CLA.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md).
