# Contributing to RailDash

RailDash is the local dashboard for [DatRail](https://github.com/datrail). It
receives captured traffic from RailMon (a capture file or a webhook) and shows
it. It also keeps the evidence bundles RailMon's scanner delivers as Agent
Security Profiles, which you can lock as baselines and check for drift. It
needs no cloud account or control plane.

## Contracts are shared, not invented here

RailDash speaks the contracts the other DatRail components already speak:
RailMon's webhook and evidence-bundle formats, and the shape of Rail Center's
`POST /v1/evidence-bundles`. A component must not need code changes or special
cases to talk to RailDash. If a contribution requires that, it is the wrong
shape. Open an issue and we will find another way.

## Known limitations, not bugs

Please do not "fix" these in passing without discussing it first. They are the
current scope, and the README and SECURITY.md record them:

- the webhook intake and the read routes have no authentication and no
  tenancy, so any caller that reaches the port can post captures and read
  every session (Agent Security Profile writes and exact-evidence reads do
  need the local write token);
- one process owns one SQLite database.

Neither is a secret, and neither is a useful vulnerability report. See
[SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
raildash serve            # http://127.0.0.1:8000/
```

```bash
pip install -r requirements-dev.txt
make test
```

`raildash/schemas/evidence-bundle-v*.schema.json` and
`raildash/schemas/attribute-groups.json` are byte-for-byte copies of
[RailMon's](https://github.com/datrail/railmon/tree/master/schemas), and a test
compares them. Point it at a RailMon checkout with
`RAILMON_SCHEMAS_DIR=<railmon>/schemas` (a sibling `../railmon` checkout is
found on its own). Without one, the test skips locally. In CI it checks
RailMon's default branch out and the test fails, never skips, if the schemas
are missing.

The API contract is in [`openapi.yaml`](openapi.yaml). If you change a route,
change that file in the same commit — it is what the other components are
written against.

## On the UI

RailDash is scanned and operated, not read. Two things are worth keeping:
summary before detail, and state encoded in more than colour — a chip carries a
glyph and a word, because a traffic-light palette is not separable by hue alone
for a colour-blind reader.

## Sending a change

- One coherent change per pull request; the message says *why*.
- Branch from `master`, **sign off your commits** (`git commit -s`,
  [DCO](https://developercertificate.org/)), no CLA.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md).
