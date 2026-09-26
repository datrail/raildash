# ASP v1 acceptance and maintainer handoff

Run the acceptance oracle from a clean Python 3.10+ environment:

```bash
python -m venv /tmp/raildash-asp-v1-venv
/tmp/raildash-asp-v1-venv/bin/pip install .
/tmp/raildash-asp-v1-venv/bin/raildash-asp-acceptance
```

It uses the checked-in redacted RailMon evidence fixture and a temporary
owner-only SQLite database. A passing JSON result proves:

- exact-byte replay is idempotent and aligned;
- a controlled evidence change produces `DRIFT_DETECTED`;
- switching to the changed ASP's alignment version produces `ALIGNED`;
- switching back restores the prior drift result; and
- a rule-pack mismatch produces `COMPARISON_UNAVAILABLE` with
  `CONTRACT_MISMATCH`, never a false clean result.

No evidence values or digests are printed. Pass `--database` only with a new
path beneath a private parent when the acceptance records need to be retained;
the oracle refuses an existing database so it cannot alter operational state.

For a live demonstration, run `raildash serve` and drive the whole flow from
the Agent Security Profile alignment panel against real RailMon evidence:
drop an evidence bundle on the upload box (or deliver it to
`POST /v1/evidence-bundles`), lock it as a baseline, switch versions, and
accept a drifted state as a new baseline -- none of it needs the server
stopped or the CLI, per DR-120 (`raildash asp load`/`list`/`lock`/`switch`
remain equivalent CLI commands over the same calls). The panel shows the same
aligned, drifted, or comparison-unavailable outcomes, now with the
per-attribute old/new detail behind "drift explained"; exact evidence needs
either the CLI/file access or the dashboard's local write token, never an
unauthenticated read.

## Published-install gate

The published acceptance leg is complete only after a released RailDash image
or package contains the merged ASP v1 commits. A wheel installs the
`raildash-asp-acceptance` command and its redacted fixture. A container includes
the same module and fixture, so run `python -m raildash.acceptance` inside it.
Then repeat the live flow with RailMon and capture the alignment panel. A
source checkout, passing CI image build, or an older published tag is not
evidence for this gate.

As of 2026-09-26, neither published tag qualifies yet: `raildash:0.1.0`
predates ASP v1 entirely (no `/api/asps`, `/api/alignments`, or
`/v1/evidence-bundles` route — confirmed live, both 404), and
`railmon:0.1.0-m3` predates DR-121/DR-83 (`scan --help` on that tag has no
`--raildash-url`/`--interval`). Cutting the new tags each repo needs is a
release-state call, not something a build/verification session decides.
Everything below the "clean-build" line has instead been run against both
repos' *current source*, containerized the same way (current `master`'s own
Dockerfile, no registry pull) — see `.local/dr110-published-verify-20260926/`
in the workspace repo for the full transcript and captured API state.

## Maintainer pairing handoff runbook

The one M4 acceptance step that structurally needs two people ("reproduce it
together" — see `log/needs-yusheng.md` history) is a live walkthrough of the
same flow this doc already automates solo. This section is the script for
that session, so it can start immediately once a maintainer has time — no
prep beyond having Docker.

**Prerequisites:** Docker Engine (or Podman with a Docker-compatible socket),
`make` optional. No cloud account, no Rail Center.

**1. Clean-build both images from source**, from sibling checkouts of this
repo and `railmon` (matches `datrail-project`'s `make stack-local` — see its
`INSTALL.md`):

```bash
docker build -t raildash:handoff .        # from this repo's root
docker build -t railmon:handoff ../railmon  # from a sibling railmon checkout
```

**2. Start RailDash, note its token:**

```bash
docker network create raildash-handoff
docker run -d --name raildash --network raildash-handoff \
  -p 127.0.0.1:8000:8000 raildash:handoff
TOKEN=$(docker exec raildash cat /data/raildash.db.token)
```

Open <http://127.0.0.1:8000/> — the alignment panel is empty.

**3. Deliver real evidence automatically**, on an interval, exactly the way a
long-running agent would be observed:

```bash
docker run -d --name railmon --network raildash-handoff \
  -e RAIL_RAILDASH_TOKEN="$TOKEN" -e RAIL_HOST_ID=handoff-host \
  railmon:handoff scan --mode self --agent-key handoff-agent \
  --raildash-url http://raildash:8000 --interval 10
```

Refresh the dashboard: new ASPs appear every 10s without restarting anything
(the standing "periodic automated scanning, not manual restarts" decision,
DR-83).

**4. From the panel** (not the CLI, to exercise the actual handoff path a
user takes): lock the first ASP as a baseline, confirm it becomes the active
alignment. Then change something real in the environment RailMon is watching
(e.g. `docker exec railmon sh -c 'export ANTHROPIC_MODEL=changed-model'` --
or simplest, stop `railmon`, restart it with a different
`ANTHROPIC_MODEL`/`ANTHROPIC_BASE_URL` env var, and let the next interval
tick deliver) and watch the next delivered ASP show **DRIFT_DETECTED** with
the per-attribute "drift explained" detail. Accept it as a new baseline
version, switch back to the original, and confirm the drift result is
restored rather than recomputed differently.

**5. Teardown:** `docker rm -f raildash railmon && docker network rm raildash-handoff`
— nothing here mutates anything outside the two throwaway containers.

If this session's own dry run using these exact steps disagreed with what
you see, that is itself the finding to report — the automated oracle
(`make asp-acceptance`) and this manual walkthrough are meant to agree.
