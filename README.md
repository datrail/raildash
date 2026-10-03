# RailDash

RailDash is a local dashboard for traffic captured by
[RailMon](https://github.com/datrail/railmon). It shows destinations, requests,
responses, failures, tool calls, and `x-rail` presence without requiring a
cloud account or Rail Center.

It also keeps the evidence bundles RailMon's scanner delivers as Agent
Security Profiles (ASPs): what an agent is set up to use and was observed
doing. You can lock an ASP as a baseline and see later drift from it. These
terms are defined in the
[DatRail glossary](https://github.com/datrail/datrail-project/blob/master/docs/glossary.md).

## Quick start

Python 3.10+ with `venv` and `make` is required:

```bash
git clone https://github.com/datrail/raildash.git
cd raildash
make demo
```

Open <http://127.0.0.1:8000/>. The demo imports the safe sample capture at
[`tests/fixtures/capture.jsonl`](tests/fixtures/capture.jsonl), so a populated
dashboard is visible immediately.

Install the CLI to load your own RailMon capture:

```bash
pip install -e .
raildash load capture.jsonl --serve
```

Or receive live interactions. Start RailDash, then point RailMon's collector
at its webhook:

```bash
raildash serve
docker run --rm --privileged --pid host --network host railmon collect \
  --mode http --webhook http://127.0.0.1:8000/webhook/http-interactions
```

`railmon collect` is the RailMon container image's command, so it exists only
inside that container (`railmon` here is an image built from the
[RailMon](https://github.com/datrail/railmon) repository). There is no `sudo
railmon collect` on the host. A native RailMon build runs the collector binary
directly with the same `--mode`/`--webhook` flags and no `collect` command;
see RailMon's README.

## Running the full stack

To run RailMon and RailDash together, use
[datrail-project](https://github.com/datrail/datrail-project#quick-start):
clone it with `--recursive` and run `docker compose up -d`, which builds both
images from source.
[INSTALL.md](https://github.com/datrail/datrail-project/blob/master/INSTALL.md)
covers prerequisites, platform support, settings (including the RailDash
token), published images, verification, and troubleshooting.

## Architecture

```mermaid
flowchart LR
  agent[Agent] --> railmon[RailMon]
  railmon -->|JSONL file or webhook| raildash[RailDash]
  raildash --> sqlite[(SQLite)]
  browser[Local browser] --> raildash
```

The CLI imports JSONL captures or starts a FastAPI service. Interactions are
stored in SQLite and served by a static browser UI. Re-importing the same
capture is idempotent because records use RailMon's content-derived
`interaction_id`.

## Security

Captured request and response bodies can contain sensitive data. RailDash has
no application authentication or tenancy in this release: keep it on loopback
or behind an authenticated boundary, protect its database and backups, and do
not publish raw captures. Credential headers are redacted, but bodies are not.
Read [SECURITY.md](SECURITY.md) and report vulnerabilities privately through
GitHub Security Advisories.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
make test
```

## ASP v1 local custody

RailDash retains validated RailMon evidence bundles as immutable ASPs and can
lock any stored ASP as an alignment version. Every one of these steps works
from either the CLI or the live dashboard. The dashboard does not need the
server stopped, and the CLI is an optional thin wrapper over the same
underlying calls:

```bash
raildash asp load evidence-bundle.json
raildash asp list
raildash asp lock asp-... --version v1.0
raildash asp switch aspver-...
```

For a bundle without a complete deployment or host-scoped Compose identity,
pass `--agent-key NAME` to `asp load` (HTTP: `?agent_key=NAME` or an
`X-RailDash-Agent-Key` header, see below). Replaying identical bytes is
idempotent; reusing a bundle ID with different bytes is rejected. `asp export`
preserves the exact received bytes, and `asp drift-export` writes full
baseline/current evidence. Both refuse public output directories and create
owner-only files. Use `asp prune --keep-count 100 --max-age-days 30` to apply
retention bounds; the same bounds run automatically after each load. Set
`RAILDASH_ASP_RETENTION_COUNT`/`RAILDASH_ASP_RETENTION_DAYS`, or persist a
change with `raildash asp retention-set --keep-count N --max-age-days N` (or
the dashboard's retention settings panel) so it survives a restart without
re-exporting an env var. Locked versions and their ASPs are never pruned.

### HTTP: evidence-bundle ingest

`POST /v1/evidence-bundles` is RailDash's counterpart to Rail Center's own
`POST /v1/evidence-bundles` — same path and general shape (raw bytes in, a
202 with a `duplicate` flag on accept), RailDash's own dedup semantics
(content digest, not a client-asserted id). A scanner (RailMon's, or any
script) can deliver a bundle without the CLI:

```python
import requests

requests.post(
    "http://127.0.0.1:8000/v1/evidence-bundles",
    params={"agent_key": "optional-explicit-identity"},
    data=raw_bundle_bytes,          # exact bytes, not reserialized, not multipart
    headers={"X-RailDash-Token": token},  # see "Local write safety" below
).raise_for_status()
```

Bounded to `RAILDASH_MAX_EVIDENCE_BUNDLE_BYTES` (default 1,048,576 bytes,
mirroring Rail Center's `MAX_EVIDENCE_BUNDLE_BYTES`). Responses: `202
{"accepted": true, "asp_id": "asp-...", "duplicate": bool}` on accept; `409`
if an id/identity already names different stored bytes; `422` for a
malformed or unresolvable bundle.

### HTTP: the rest of custody, and local write safety

`GET /api/asps`, `/api/alignments`, and per-ASP `state`/`drift` stay
unauthenticated, redacted metadata (change names and field names, never
evidence values or digests) — unchanged from before. Everything that mutates
custody state, plus the two reads that carry exact evidence
(`GET /api/asps/{asp_id}/bundle`, `GET /api/asps/{asp_id}/drift/explained`,
which is the per-attribute old/new/tier detail behind the dashboard's "drift
explained" view), requires a local write token as an `X-RailDash-Token`
header:

| Route | CLI equivalent |
| --- | --- |
| `POST /v1/evidence-bundles` | `asp load` |
| `POST /api/asps/{asp_id}/lock` `{"version": "..."}` | `asp lock` |
| `POST /api/alignments/{id}/switch` | `asp switch` |
| `POST /api/asps/{asp_id}/accept-drift` `{"version": "..."}` | `asp lock` + `asp switch` in one call |
| `GET`/`POST /api/settings/asp-retention` | `asp retention-set` |
| `POST /api/asps/prune` | `asp prune` |
| `GET /api/asps/{asp_id}/bundle` | `asp export` |
| `GET /api/asps/{asp_id}/drift/explained` | `asp drift-export` |

The token is stable across restarts, so a RailMon configured once keeps
delivering after RailDash restarts. RailDash takes it from, in order:

1. `RAILDASH_TOKEN`, if set (at least 16 characters of `A-Z a-z 0-9 - _ . ~ +
   / =`, e.g. `openssl rand -base64 32`) — handy when RailMon's
   `RAIL_RAILDASH_TOKEN` is set from the same secret before either starts;
2. otherwise `<db path>.token` from a previous start;
3. otherwise a new random token, written 0600 to `<db path>.token`
   (gitignored, alongside the database; `/data/raildash.db.token` in the
   container).

At startup RailDash logs where the token came from (`raildash: local write
token reused from raildash.db.token`), never the token itself — read it with
`cat raildash.db.token`. To rotate it, delete that file (or change
`RAILDASH_TOKEN`) and restart, then give RailMon the new value.

RailDash injects the token into the page it serves itself (a
`<meta name="raildash-token">` tag), so the dashboard's own fetch calls
attach it automatically — same-origin only, so a cross-site page cannot read
it and cannot forge a write even though a browser will happily send
loopback requests. This is the same pattern Jupyter's notebook server uses,
and it is why the token is a CSRF defense as well as an access control.

`serve` still binds `127.0.0.1` by default; that has not changed. Passing
`--host 0.0.0.0` (or any non-loopback address) is a deliberate, documented
opt-in to reach RailDash from another host, and the token requirement still
applies unchanged — exposing the port does not by itself expose the write
routes.

### Multi-agent collections (evidence bundle v2)

RailMon run with `--target-manifest` delivers one evidence-bundle v2
collection per scan: a shared sandbox scope plus one scope per declared
agent. It locks, switches and drifts exactly like a v1 bundle. Its drift
results use `drift_contract_version: 2`, where every change carries an
`agent_key`: `null` for the sandbox scope and attestations, otherwise the
agent the change happened in. Three change types are new:

| Change | Meaning |
| --- | --- |
| `AGENT_CHANGED` `["discovery_status"]` | A declared agent's discovery moved, e.g. `available` → `not_found` when its process is gone. Its attribute and source changes follow, scoped to it. |
| `AGENT_ADDED` / `AGENT_REMOVED` | The collection gained or lost an agent scope. This happens only under a deployment identity (`RAIL_DEPLOYMENT`/`RAIL_NAMESPACE` or the compose labels). With no deployment identity, the sorted agent keys *are* the identity. A manifest that declares a different set of agents is then a new subject with no alignment of its own, offered for locking, and the old subject's card receives no new ASPs. Set a deployment identity to see a manifest change as drift. |

A v1 bundle compared with a v2 baseline (or the reverse) is
`CONTRACT_MISMATCH`. v1 comparisons still emit contract v1 unchanged.
Schemas: `raildash/schemas/drift-result-v1.schema.json` and
`drift-result-v2.schema.json`.

The existing capture and `/api/profile` paths are unchanged. The pure
validator/comparator and versioned JSON Schemas live under `raildash.asp`
and `raildash/schemas/`.

Run `make asp-acceptance` for the deterministic replay, controlled-drift,
version-switch, and incompatible-rule-pack flow. The clean-build and live demo
handoff is documented in [`docs/asp-v1-acceptance.md`](docs/asp-v1-acceptance.md).

The OpenAPI contract is [`openapi.yaml`](openapi.yaml). The compose files that
run RailDash alongside RailMon live in
[datrail-project](https://github.com/datrail/datrail-project).

## Related projects

- [RailMon](https://github.com/datrail/railmon) captures agent traffic.
- [DatRail Proxy](https://github.com/datrail/proxy) injects `x-rail` tickets.
- [DatRail Gateway](https://github.com/datrail/gateway) enforces policy.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
