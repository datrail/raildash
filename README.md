# RailDash

RailDash is a local dashboard for traffic captured by
[RailMon](https://github.com/datrail/railmon). It shows destinations, requests,
responses, failures, tool calls, and `x-rail` presence without requiring a
cloud account or Rail Center.

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

Or receive live interactions:

```bash
raildash serve
sudo railmon collect --mode http \
  --webhook http://127.0.0.1:8000/webhook/http-interactions
```

## Running the full stack

To run RailMon and RailDash together, or to install from published images, see
**[INSTALL.md](https://github.com/datrail/datrail-project/blob/master/INSTALL.md)** — the full install guide, covering the source-built
stack (`make stack-local`), the registry stack (`make stack`), platform support,
verification, and troubleshooting.

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
lock any stored ASP as an alignment version. Stop the server before each
database-owner operation:

```bash
raildash asp load evidence-bundle.json
raildash asp list
raildash asp lock asp-... --version v1.0
raildash asp switch aspver-...
```

For a bundle without a complete deployment or host-scoped Compose identity,
pass `--agent-key NAME` to `asp load`. Replaying identical bytes is idempotent;
reusing a bundle ID with different bytes is rejected. `asp export` preserves
the exact received bytes, and `asp drift-export` writes full baseline/current
evidence. Both refuse public output directories and create owner-only files.
Use `asp prune --keep-count 100 --max-age-days 30` to apply the default
independent retention bounds; the same defaults run after each load. Set
`RAILDASH_ASP_RETENTION_COUNT` and `RAILDASH_ASP_RETENTION_DAYS` independently
to change them. Locked versions and their ASPs are never pruned.

Read-only `/api/asps`, `/api/alignments`, and per-ASP state/drift routes expose
bounded metadata and redacted change names only. Evidence values and digests
remain on the owner-only CLI. The existing capture and `/api/profile` paths
are unchanged. The pure validator/comparator and versioned JSON Schemas live
under `raildash.asp` and `raildash/schemas/`.

The OpenAPI contract is [`openapi.yaml`](openapi.yaml). The compose files that
run RailDash alongside RailMon live in
[datrail-project](https://github.com/datrail/datrail-project).

## Related projects

- [RailMon](https://github.com/datrail/railmon) captures agent traffic.
- [DatRail Proxy](https://github.com/datrail/proxy) injects `x-rail` tickets.
- [DatRail Gateway](https://github.com/datrail/gateway) enforces policy.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
