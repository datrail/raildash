# Installing DatRail (RailMon + RailDash)

DatRail's local bundle runs two components together from one command:

- **RailMon** — a CLI daemon that taps live agent traffic at the kernel level (eBPF) and records interactions to JSONL and/or a webhook.
- **RailDash** — a local dashboard (FastAPI + SQLite) that imports RailMon's capture and serves it at `http://127.0.0.1:8000`.

Everything runs locally: no cloud account, no Rail Center, no auth. The stack binds to `127.0.0.1` only and stores data in Docker volumes.

## Prerequisites

- **Docker Engine with Compose v2.** The RailMon container runs `--privileged` with `pid=host` (required for the eBPF tap), so your Docker daemon must allow privileged containers.
- **`make` and `git`.**
- **An x86_64 machine.** See the platform matrix below — this is a hard requirement for capture.
- For Option A only: local checkouts of both repos (see that section).

### Platform support

| Platform | Capture | Notes |
| --- | --- | --- |
| **Linux (x86_64, native)** | Supported | Real kernel with BTF; the tap sees host processes. |
| **Windows via WSL2 (x86_64)** | Supported — verified reference setup | WSL2 provides a real Linux kernel with BTF. |
| **macOS (Intel, Docker Desktop)** | Limited | Docker Desktop runs containers in a Linux VM, so the tap cannot see the Mac's own processes — only what runs inside that VM. The bundled demo runs entirely in-container and works; tapping a real local agent does not. |
| **Apple Silicon / arm64** | Not supported | AgentSight (the tap) publishes no arm64 build. An arm64 image exists but lacks the tap binary, so `collect` and `demo` cannot capture; `scan`, `skills`, and `forward` still work. |

## Option A — build from source (`make stack-local`)

Builds both images from your own source checkouts — nothing is cloned for you, and nothing is pulled from a registry.

1. Clone both repos as siblings:

```bash
   git clone https://github.com/datrail/railmon.git
   git clone https://github.com/datrail/raildash.git
```

   RailDash expects the railmon checkout as a sibling directory (`../railmon`) by default. If yours lives elsewhere, point at it with `RAILMON_SRC`:

```bash
   make stack-local RAILMON_SRC=/path/to/railmon
```

2. From the raildash checkout, bring the stack up:

```bash
   cd raildash
   make stack-local
```

3. This builds both images from your checkouts, starts the stack, generates demo traffic through the tap, then imports the capture into RailDash. **During the import the dashboard briefly stops and restarts — this is expected** (see Troubleshooting).

4. Open **http://127.0.0.1:8000**.

## Option B — from published images (`make stack`)

Pulls both images from GHCR at explicit tags. There is deliberately no default — the stack refuses to run an unpinned `:latest` privileged container, and errors out if either tag is missing:

```bash
cd raildash
make stack RAILMON_TAG=v0.1.0-m2 RAILDASH_TAG=v0.1.0
```

The leading `v` is fine — the Makefile strips it when resolving the image tag. `make stack-down` and `make stack-logs` work for either mode without repeating the tags.

## Verify the install — what you should see

In either mode, a few seconds after the stack comes up:

- **RailMon's container ran once and exited 0.** Expected — the demo capture finishes and stops; it is not a long-running collector. Only the raildash service stays `Up` in `docker compose ps`.
- **The file-import step reports `6 already present, skipped`** — the webhook path already delivered every interaction, so the file path had nothing to insert. This is the dedup working, with both paths wired.
- **http://127.0.0.1:8000** shows **6 interactions** against `127.0.0.1:8443`, all `POST`, all `200`, across `/v1/demo` and `/v1/demo/other`.

Six interactions from three requests is correct, not a bug — see Troubleshooting.

### Teardown

- `make stack-down` stops the stack but **keeps the volumes** — the capture and database survive, so a second run shows the first run's rows too.
- `make stack-clean` removes the volumes as well — the full reset that makes the first-run numbers above true again.

## Troubleshooting

**The dashboard pauses or drops connections during a file import.** Expected. RailDash's SQLite database allows exactly one opener, so the stack stops the server, runs the import as the sole opener, and restarts it, waiting for health. If the dashboard seems down right after starting the stack, give it ~30 seconds. A file cannot be imported while the server is running — this is a component limitation, not a broken install.

**"6 interactions but I only made 3 requests."** Also expected. RailMon's demo taps by process name (`--comm python3`), and both ends of the exchange — `demo_server.py` and `demo_client.py` — are `python3`, so each request is captured twice: once as the client sent it, once as the server received it. Two genuine observations of one exchange (different `pid`s), not one row written twice — double-counting would show 12.

**More than 6 interactions on a second run.** `make stack-down` keeps the volumes, and RailMon appends to the capture. Run `make stack-clean` for a fresh start that matches the first-run numbers.

**`no RailMon checkout at ../railmon`.** Option A can't find the railmon source. Clone `datrail/railmon` as a sibling of the raildash checkout, or set `RAILMON_SRC=/path/to/railmon`.

**`the RailMon at … does not honour RAILMON_WEBHOOK_URL / RAILMON_SESSION_ID`.** Your railmon checkout is out of date. Update it to the current `master`. Without the demo env passthrough the webhook path never fires and the stack silently runs at half of what it claims.

**Empty capture on macOS or arm64.** See the platform matrix — on macOS Docker Desktop the tap can't see host processes, and on arm64 there is no tap binary at all.

**Import fails but the dashboard is up.** By design a failed import does not leave the stack down. Check `make stack-logs` for the cause.
