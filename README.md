# RailDash

> **Just want to run DatRail?** Start at
> [datrail-project](https://github.com/datrail/datrail-project#quick-start):
> one `docker compose up -d` runs RailMon, RailDash and a demo agent
> together. This README covers RailDash on its own.

RailDash is a local dashboard for agents watched by
[RailMon](https://github.com/datrail/railmon). It needs no cloud account or
Rail Center.

- **Agent Security Profiles (ASPs).** RailDash keeps each evidence bundle
  RailMon's scanner delivers as an ASP: what an agent is set up to use and
  was observed doing. You lock an ASP as the agent's baseline in the UI,
  and RailDash shows drift from it as later scans arrive.
- **Data Guardrail.** Rules adopted from a baseline cover allowed uploads,
  saved-file kinds, no service ports, out-of-spec API/MCP calls, what each
  MCP tool call may do with data (read, upload, update, delete, execute) and,
  optionally, contained egress. RailDash checks them as evidence arrives and
  shows each agent's state: held, violated, unverified or no guardrail.
- **Traffic.** The captured calls themselves: destinations, requests,
  responses, failures, tool calls and `x-rail` presence.

These terms are defined in the
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

The capture webhooks (`/webhook/http-interactions`, `/webhook/events`) stay
open. A batch that also carries the local write token in `X-RailDash-Token`
(see "Local write safety" below) is stored as *authenticated*; one without it,
or with a wrong one, is stored exactly as before and marked unauthenticated.
Captures loaded with `raildash load` are unauthenticated too. The Data
Guardrail judges authenticated captures only. A collector that sends the
token also posts `POST /webhook/heartbeat` (token required) every 60 s while
at least one tap is attached, with `{"collector_id", "taps_attached",
"sent_at"}`; RailDash keeps the last one per collector, timed by its own
clock, so a dead collector is not mistaken for an idle agent. When a batch
that carries the token is refused with any 4xx (too large, too deep, not
valid JSON, the wrong shape or content type), RailDash records the time:
none of that traffic was stored, so the guardrail's request rules can't read
Held for a while after it. A refused
batch without the token is not recorded. Neither the mark, the heartbeats nor
the refusals are shown on an unauthenticated read route.

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
lock any stored ASP as an alignment version. Every workflow except locking
without activating works from either the CLI or the live dashboard, and
neither needs the server stopped: the CLI is an optional thin wrapper over
the same underlying calls and can run against the database while `raildash
serve` is using it. The dashboard's lock buttons lock and activate in one
step (`asp baseline`); locking without activating (`asp lock`) is a CLI and
HTTP operation:

```bash
raildash asp load evidence-bundle.json
raildash asp list
raildash asp baseline asp-... --version v1.0   # lock if needed, then activate
raildash asp lock asp-... --version v1.0
raildash asp switch aspver-...
```

The dashboard lists every received ASP newest first, marked as the current
baseline, locked, or a candidate. Any of them can be made the baseline from
that list, and each can be downloaded exactly as it was received. Making an
ASP the baseline, or accepting a drifted one, is idempotent: an ASP is locked
at most once, so repeating the action reuses its alignment version.

### Files: asked and kernel-observed

A capture's profile lists the files its tool calls *asked* to read or write
(**Files · asked**, from the captured conversation). Beside it,
**Files · kernel-observed** lists what RailMon's file probe (`railmon files`) saw the sandbox
actually open: the `observed_file_access` attribute (path, read, write, exec,
layer) of the latest ASP received for each sandbox the capture names, or, for
a capture that names no sandbox (a single-agent RailMon), the latest ASP of
every sandbox, said as such. The two are never merged: one is what the model
requested, the other what the kernel observed. The list comes from
`GET /api/profile/kernel-file-access?session_id=...` (token-gated, since the
paths are evidence values).

`observed_file_access` takes part in drift like any attribute. When it
changes, the drift view lists the paths by what changed (newly written, run,
read or opened; no longer written, run, read or opened) instead of two raw
lists. A window list (see evidence bundle v2 below) lists only what is
newly seen, since a quieter window is not something stopped.

Two things about the file list are not drift either. A uuid in a file's
name compares as `*`: an agent that writes `sessions.json.1.<uuid>.tmp`
every turn writes the same file each time. The directory, the rest of the
name and the access still count, and a new file named like a baseline one
but for its uuid is aligned. And RailMon caps the list at 512 entries,
keeping every write and run, then reads by path. When the baseline's list
says reads were left out, a read that sorts after its last listed read
could not have been listed, so whether the baseline saw it is unknown and
it isn't drift. A new read past that point is not reported; a read that
sorts before it, and any new write or run, still is.

The value of an attribute RailMon publishes as *dynamic*
(`raildash/schemas/attribute-groups.json`, vendored from RailMon) never takes
part in drift. Today that is `agent_instance`, where this copy runs: the
agent container's hostname, id and host pid, and the scan's own fqdn, pid and
working directory. A restart, move or recreate changes them. Everything but
its value still counts, as for `container_identity`, so a probe that stops
answering is drift. The ASP keeps the value; "Inspect evidence" shows it.

For a bundle without a complete deployment or host-scoped Compose identity,
pass `--agent-key NAME` to `asp load` (HTTP: `?agent_key=NAME` or an
`X-RailDash-Agent-Key` header, see below). A deployment identity wins over
the key, except in a multi-agent sandbox (see "Multi-agent collections"
below). Replaying identical bytes is
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

`POST /v1/evidence-bundles` takes a bundle's raw bytes and answers 202 with
a `duplicate` flag, deduplicating by content digest rather than a
client-asserted id. These are the same bytes Rail Center takes on
`POST /v1/agents/register`. A scanner (RailMon's, or any script) can deliver
a bundle without the CLI:

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
malformed or unresolvable bundle, or `422` with `"code":
"MULTI_AGENT_KEY_REQUIRED"` for an unkeyed v1 bundle sent to a multi-agent
sandbox (see "Multi-agent collections" below).

### HTTP: the rest of custody, and local write safety

`GET /api/asps`, `/api/asps/history`, `/api/alignments`, per-ASP
`state`/`drift`, and `GET /api/settings/asp-retention` are unauthenticated,
redacted metadata (counts, change names and field names, never evidence
values or digests). Everything that mutates
custody state, plus the five reads that carry exact evidence
(`GET /api/asps/{asp_id}/bundle`, `GET /api/asps/{asp_id}/raw`,
`GET /api/asps/{asp_id}/drift/explained`,
which is the per-attribute old/new/tier detail the dashboard shows under a
drifted ASP's change list, and `GET /api/profile/kernel-file-access`, described under
"Files: asked and kernel-observed" above, and a guardrail's detail, described
under "HTTP: the Data Guardrail" below), requires a local write token as
an `X-RailDash-Token` header:

| Route | CLI equivalent |
| --- | --- |
| `POST /v1/evidence-bundles` | `asp load` |
| `POST /api/asps/{asp_id}/lock` `{"version": "..."}` | `asp lock` |
| `POST /api/alignments/{id}/switch` | `asp switch` |
| `POST /api/asps/{asp_id}/baseline` `{"version": "..."}` | `asp baseline` (lock if needed, then switch) |
| `POST /api/asps/{asp_id}/accept-drift` `{"version": "..."}` | `asp baseline` |
| `POST /api/settings/asp-retention` | `asp retention-set` |
| `POST /api/asps/prune` | `asp prune` |
| `GET /api/asps/{asp_id}/bundle` | `asp export` |
| `GET /api/asps/{asp_id}/raw` (exact received bytes) | `asp export` |
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

### HTTP: the Data Guardrail

The guardrail checks every ASP and every authenticated capture of an agent
against the rules the user adopted: allowed uploads, saved-file kinds, no
service ports, no out-of-spec calls, and the data actions each MCP tool may
take (the
[glossary](https://github.com/datrail/datrail-project/blob/master/docs/glossary.md#data-guardrail)
defines these five), plus contained egress when required (**Egress
containment** below). The store checks them as
evidence arrives, whichever way it arrives. Every guardrail route needs the
token, including both reads:

| Route | What it does |
| --- | --- |
| `GET /api/guardrails` | each agent's state (`held`, `violated`, `unverified`, `no_guardrail`), without item values |
| `GET /api/guardrails/{agent_ref}` | state, rows, *declared since gN* offers, versions, history, and the proposal before one is adopted |
| `POST /api/alignments/{id}/guardrail` `{}` or `{"rules": {...}}` | Adopt the proposal, or the proposal as edited |
| `POST /api/guardrail-versions/{id}/edit` `{"rules": {...}}` | Edit: a new version from the active one |
| `POST /api/guardrail-versions/{id}/switch` | Switch to an earlier version |
| `POST /api/guardrails/{agent_ref}/turn-off` | Turn off (No guardrail) |
| `POST /api/guardrail-rows/{row_id}/acknowledge` | Acknowledge a row; a later hit re-opens it |
| `POST /api/guardrail-rows/{row_id}/allow` | Allow this: a new version that allows the row's item |
| `POST /api/guardrails/{agent_ref}/allow-rows` `{"row_ids": [...]}` | Allow all: one new version that allows several of one rule's rows; all or nothing |
| `POST /api/guardrails/{agent_ref}/offers/allow` or `.../dismiss` `{"kind": "host", "value": "..."}` | Allow or dismiss a newly declared host or MCP server |
| `GET /api/guardrails/{agent_ref}/data-actions-offer` | `{"offer": ...}`: the *Add data actions* proposal for an agent whose guardrail predates the rule, or `null` |
| `POST /api/guardrails/{agent_ref}/data-actions` `{}` or `{"rule": {...}}` | Add data actions: a new version with the active rules plus `data_actions`, as proposed or as edited |
| `POST /api/guardrails/{agent_ref}/data-actions/dismiss` `{}` | Dismiss the *Add data actions* offer; it isn't offered again |
| `GET /api/data-actions/tool?name=...` | One tool's classification (actions, reasons) and the schemas behind it, for the panel's **Why** |
| `POST /api/guardrails/{agent_ref}/egress-containment` `{}` or `{"require": "allow_list_enforced"}` | Require containment: a new version that requires the agent's egress be contained; `starts_violated` says whether the newest ASP already fails it |

The proposal allows each written path of the baseline exactly, plus one
glob it always shows: `**/__pycache__/*.pyc`, Python's bytecode caches.
Any Python process writes those for the modules it imports, so without it
every new Python command in the agent would be a `saved_files` row. Remove
it before adopting if you want those writes judged; a file named like a
bytecode cache in a `__pycache__` directory isn't flagged while it's there.
A guardrail adopted before RailDash seeded this line doesn't have it;
**Edit** adds it.

A written path whose file name holds a uuid after at least three letters
or digits is the one exception to "exactly": the proposal allows that name
with `*` for the uuid, in the same directory, and **Allow this** on such a
row does the same. An agent that writes `sessions.json.1.<uuid>.tmp` every
turn would otherwise have a new row every turn. The `*` matches any text in
that place, so a file in that directory with the same text around it isn't
flagged either. A name with less before its uuid (`<uuid>.json`,
`.<uuid>`) stays exact, since its glob would allow nearly any file in the
directory.

**Egress containment.** Each agent's panel has an
**Egress** line read from RailMon's `egress_containment`, an observed level:
- Contained: an OpenShell sandbox's enforced allow-list, no network, or
  internal networks only, naming any container that is the way out. The
  line says the agent *should not* reach outside hosts itself: the level is
  read from Docker's configuration, not tested with a connection.
- Open: the agent can reach any host, is on the host's network, or is a host
  process.

A proxy the container's environment declares (`egress_proxy_declared`) is
shown beside the line, and never counts. A version can require containment
with the optional `egress_containment` rule (`{"require": "contained"}` or
`"allow_list_enforced"`). Such a version is contract v3. The proposal
includes the rule only when the baseline was contained, and **Require
containment** adds it to any version. An ASP from before RailMon's rule pack
11 leaves the line unknown and the rule Unverified.

Containment is a property of the sandbox, so in a multi-agent sandbox
(evidence bundle v2 with two or more agents) the line and the rule read the
sandbox scope's `egress_containment`, which every agent in it shares. The
rule is Held, Violated or Unverified there exactly as for one agent, with
the same stale window. Every other rule stays Unverified in a multi-agent
sandbox, since it can't say which agent a listener, write or request was.

**Which calls a reply asks for.** A model's reply asks for a call with an
Anthropic `tool_use` block, an OpenAI Chat `tool_calls` entry, or an OpenAI
Responses `function_call` or `custom_tool_call`, whole or streamed. Codex's
code mode gives the model one tool, `exec`, whose JavaScript calls every
other tool as `tools.<name>(…)`, so each tool the script names counts as
asked for, without its arguments. A script that reaches a tool through a
name it builds at run time (`tools[name]`, `tools` handed on whole, `eval`)
makes that request's tool calls unreadable, and the uploads and out-of-spec
rules that read them stay Unverified for a while.

**The data-action classifier's model step.** Deterministic rules classify
each MCP tool's data actions from its name and schema. A tool they leave
unclassified can also be asked of a model, which is off unless both of these
are set:

| Variable | Meaning |
| --- | --- |
| `RAILDASH_CLASSIFIER_MODEL_URL` | An OpenAI-compatible API base URL, a local model's or a provider's, e.g. `http://127.0.0.1:11434/v1`. |
| `RAILDASH_CLASSIFIER_MODEL` | The model to ask. |
| `RAILDASH_CLASSIFIER_API_KEY_FILE` | Optional: a file holding the API key. It is never logged and is sent only to that URL. |

Only a tool's schema is sent (its name, description and argument schema),
never a captured value. A redirect is refused, not followed, so the key
can't reach another host; with `HTTP_PROXY` set, a plain `http://` URL goes
through that proxy, so use `https://` or `NO_PROXY` for a remote model. The answer counts only when every action is from
the closed set, and its `read` is weak. Until an answer arrives the tool is
`unclassified`, the safe direction.

**Downgrading.** `0.2.0-rc.1` is the first published RailDash with the
Data Guardrail, including `data_actions` (contract v2) and
`egress_containment` (contract v3); `0.1.0` has no guardrail and ignores
it. A source build from between the two may know contract v1 only: before
running one on the same database, switch each agent to a version without
those rules, or **Turn off**.

`RAILDASH_GUARDRAIL_MAX_OPEN_ROWS` (default 1000) caps the unacknowledged
rows per agent before further items count in one overflow row, and
`RAILDASH_GUARDRAIL_ACK_RETENTION_DAYS` (default 30) is how long an
acknowledged row is kept after its last hit.

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

An attribute whose reading declares RailMon's optional `window` member
(the v2 schema's `$defs.attribute.properties.window`) holds only
what the collector's observation window saw, so its list is compared as a
window: an item the current window did not see is not a removal, the
`ignore` keys (traffic counts such as a destination's `count`) are not part
of an item, and a `union` key (such as a file's `write`) is drift only when
it turns true. A new item or a newly-true `union` key is the usual
`ATTRIBUTE_CHANGED` with `value` in its `fields`; a window that saw less is
no change at all, and the member itself is never drift. The current
reading's declaration is used, else the baseline's, so a baseline locked
before RailMon emitted it compares the same way. Status and the other
qualifiers are still compared exactly, and a v2 reading without a window on
either side is compared exactly as before. The emitted shape is unchanged,
so this stays `drift_contract_version: 2`.

A v1 bundle cannot declare a `window`, but a single RailMon scan writes v1
with the same window lists. So a v1 comparison reads the six lists RailMon
windows in v2 (`tool_names`, `observed_destinations`,
`undeclared_destinations`, `observed_listeners`, `observed_ingress_peers`
and `observed_file_access`) by the declarations RailMon gives them there
(`V1_WINDOW_LISTS`, checked against RailMon's composer in CI). A re-scan of
an unchanged agent that saw fewer hosts, or the same hosts a different
number of times, is not drift.

Once a sandbox (`host_id` + `sandbox_name`) has a stored v2 collection,
RailDash refuses a v1 bundle for it that names no explicit agent key: `422
{"detail": "MULTI_AGENT_KEY_REQUIRED: ...", "code":
"MULTI_AGENT_KEY_REQUIRED"}`, and nothing is stored. That holds even when
the bundle carries a deployment identity that would key it in a
single-agent stack: a multi-agent container falling back to one identity
would otherwise be filed as another agent and look like success. A v1
bundle keyed with `?agent_key=NAME` (or the header, or `asp load
--agent-key`) is still accepted; that is how RailMon delivers each agent
when its shared scan fails. It is filed under that key, even when it also
carries a deployment identity: every agent in the container shares that
identity, so filing under it would mix their ASPs into one agent and show
false drift. The reserved `default` key does not count. A sandbox that has
never sent v2 is unaffected: there the deployment identity still wins over
a key, so no locked baseline moves. Resending a bundle already stored is
still answered as a replay under the identity it was stored under, even if
the sandbox gained v2 history since. Resending a bundle stored under a key
with a different key is a `409`; one stored under its deployment identity
is still that identity's replay, whatever key comes with it. A sandbox that goes back to a
single agent keeps refusing unkeyed v1, because its v2 history stays: give
RailMon a key (`RAIL_AGENT_KEY` or `--agent-key`), and lock a new baseline
from the keyed ASPs.

A v1 bundle compared with a v2 baseline (or the reverse) is
`CONTRACT_MISMATCH`. v1 comparisons still emit contract v1 unchanged.
Schemas: `raildash/schemas/drift-result-v1.schema.json` and
`drift-result-v2.schema.json`.

The existing capture and `/api/profile` paths are unchanged. The pure
validator/comparator and versioned JSON Schemas live under `raildash.asp`
and `raildash/schemas/`.

The Data Guardrail's contract is
`raildash/schemas/guardrail-version-v1.schema.json` (v2 adds `data_actions`,
v3 `egress_containment`), and its pure evaluator
is `raildash.guardrail`. Its storage and the two ingest hooks that call it
are `raildash.guardrail_store`, served by the routes under "HTTP: the Data
Guardrail" above. The dashboard's Data Guardrail panel, beside the alignment
panel, shows each agent's state and rows and offers every action: adopt the
proposal (as is or edited), Allow this, Acknowledge, Allow or Dismiss a
declared host, Edit, Switch and Turn off. Where two or more of a rule's
counting rows can be allowed with one click, **Allow all N** allows them in
one version instead of one per row; rows it can't allow (the overflow row,
a request with no host, a wildcard host, a tool name with no MCP server, an
upload over a size cap) stay, and the panel says how many.

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
