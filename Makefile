.PHONY: test lint serve demo static-demo clean

VENV := .venv
PY   := $(VENV)/bin/python

# The venv build must not leave a half-made .venv behind. The directory is
# the make target, so if creation or the install fails partway (no
# python3-venv package, a dropped network) and the directory survives, every
# later run treats it as built, skips pip install, and fails somewhere less
# explicable — `raildash: uvicorn is not installed` on a machine that never
# got as far as installing anything.
$(VENV):
	python3 -m venv $(VENV) && $(VENV)/bin/pip install -q -r requirements-dev.txt || { rm -rf $(VENV); exit 1; }

test: $(VENV)
	$(PY) -m py_compile webhook_server.py raildash/*.py
	$(PY) -m pytest -q

# The front end ships as three static files with no build step, so the check
# that matters is that they parse and that every id the script reaches for
# exists in the markup — the failure mode is a silent null, not an error.
lint: $(VENV)
	$(PY) tools/check_static.py

serve: $(VENV)
	$(PY) -m raildash.cli serve

# Load the test fixture and open the dashboard on it. The quickest way to see
# what RailDash does without capturing anything first.
demo: $(VENV)
	$(PY) -m raildash.cli --db demo.db load tests/fixtures/capture.jsonl --serve

# Deterministic, synthetic-data-only site. This builds files for a future
# static host; it does not publish or deploy them.
static-demo: $(VENV)
	$(PY) tools/build_static_demo.py --output dist/static-demo

clean:
	rm -rf $(VENV) .pytest_cache **/__pycache__ demo.db raildash.db *.db-wal *.db-shm dist

# ---------------------------------------------------------------- DR-81 stack
# RailMon + RailDash together, from one command, in two modes (BDL-F5):
#
#   make stack-local                              build from source checkouts
#   make stack RAILMON_TAG=v0.1.1 RAILDASH_TAG=v0.1.0
#                                                 run the published images
#
# Local-built mode assumes the component repos are already checked out:
# raildash is this directory, railmon a sibling (override with RAILMON_SRC).
# Registry mode pulls ghcr.io/datrail/{railmon,raildash} at the tags you name.
# See README.md "Running both together".
.PHONY: stack stack-local stack-test stack-logs stack-down stack-clean \
	railmon-src-check _stack-up

RAILMON_SRC ?= ../railmon
export RAILMON_SRC

# One source of truth for the session id both ingestion paths use. RailMon
# gets it as RAILMON_SESSION_ID (interpolated into docker-compose.yml, which
# repeats it only as a fallback default); the import step below passes the
# same value as --session-id. They must match, or the webhook and the file
# land in different sessions and every interaction is counted twice.
DEMO_SESSION_ID ?= railmon-raildash-stack
export DEMO_SESSION_ID

export RAILMON_TAG RAILDASH_TAG

# The base compose file requires both tags rather than defaulting them to
# `:latest`, so that a bare `docker compose up` cannot pull a moving tag into
# railmon's privileged, host-PID container (see docker-compose.yml). Compose
# interpolates that file for every subcommand though -- including `down` and
# `logs`, which resolve no image at all -- so the invocations that do not name
# a release still have to supply something. `local` is that something: it is
# the tag docker-compose.build.yml substitutes in anyway, and no teardown or
# log-tail command ever turns it into a registry pull.
PLACEHOLDER_TAGS := RAILMON_TAG=local RAILDASH_TAG=local

COMPOSE       := docker compose
COMPOSE_ANY   := $(PLACEHOLDER_TAGS) docker compose
COMPOSE_LOCAL := $(PLACEHOLDER_TAGS) docker compose -f docker-compose.yml -f docker-compose.build.yml

# Local-built mode needs a RailMon checkout, and one that honours the demo
# env vars this stack depends on (datrail/railmon#9) -- both of them: the URL
# alone would post under a session id the file import cannot match, which is
# the double-count this stack exists to avoid. Without the passthrough the
# webhook path never fires and the stack is silently half of what it claims,
# so this fails loudly instead.
railmon-src-check:
	@[ -f "$(RAILMON_SRC)/tools/local-demo/run_local_demo.sh" ] || { \
	  echo "no RailMon checkout at $(RAILMON_SRC) -- clone datrail/railmon there," >&2; \
	  echo "or point RAILMON_SRC at an existing checkout." >&2; exit 1; }
	@grep -q RAILMON_WEBHOOK_URL "$(RAILMON_SRC)/tools/local-demo/run_local_demo.sh" \
	  && grep -q RAILMON_SESSION_ID "$(RAILMON_SRC)/tools/local-demo/run_local_demo.sh" || { \
	  echo "the RailMon at $(RAILMON_SRC) does not honour RAILMON_WEBHOOK_URL /" >&2; \
	  echo "RAILMON_SESSION_ID (datrail/railmon#9), so only the file path would" >&2; \
	  echo "ingest. Update that checkout to a revision that includes it." >&2; exit 1; }

stack-local: railmon-src-check
	@$(MAKE) --no-print-directory _stack-up COMPOSE_CMD='$(COMPOSE_LOCAL)' UP_FLAGS=--build

# Registry mode. Tags may be git-style (v0.1.0-m2) or image-style (0.1.0-m2);
# the leading v is stripped to match what container-release.yml publishes. An
# image predating railmon#9 starts but never posts the webhook -- there is no
# way to check inside an image up front, so that case is caught at run time
# by stack-test's delivered-by-webhook assertion instead.
stack:
	@[ -n "$(RAILMON_TAG)" ] && [ -n "$(RAILDASH_TAG)" ] || { \
	  echo "registry mode needs both tags, e.g.:" >&2; \
	  echo "  make stack RAILMON_TAG=v0.1.1 RAILDASH_TAG=v0.1.0" >&2; \
	  echo "(or build from checkouts instead: make stack-local)" >&2; exit 1; }
	@$(MAKE) --no-print-directory _stack-up COMPOSE_CMD='$(COMPOSE)' UP_FLAGS= \
	  RAILMON_TAG='$(patsubst v%,%,$(RAILMON_TAG))' \
	  RAILDASH_TAG='$(patsubst v%,%,$(RAILDASH_TAG))'

# Internal: the run sequence both modes share -- one copy, so a fix to the
# readiness loop or the import cannot land in one mode and miss the other.
# COMPOSE_CMD is set by stack / stack-local; not for direct invocation.
#
# The import runs with the server stopped: a RailDash database is
# single-process by design (store.py takes PRAGMA locking_mode=EXCLUSIVE so an
# older process cannot write unredacted rows around a schema migration,
# DR-20), so a second opener gets "database is locked" wherever the file
# lives. If the import fails, the dashboard is started again before this
# target exits -- a failed import must not leave the stack down.
_stack-up:
	$(COMPOSE_CMD) up $(UP_FLAGS) -d
	@echo "waiting for the demo capture to finish..."
	@code=$$(docker wait "$$($(COMPOSE_CMD) ps -aq railmon)"); \
	  [ "$$code" = "0" ] || { \
	    echo "railmon's demo exited $$code -- capture is missing or truncated." >&2; \
	    echo "see: make stack-logs" >&2; exit 1; }
	@echo "importing the capture file (server paused)..."
	$(COMPOSE_CMD) stop raildash
	@if ! $(COMPOSE_CMD) run --rm --entrypoint python3 raildash \
	  -m raildash.cli --db /data/raildash.db load /captures/capture.jsonl \
	  --session-id "$(DEMO_SESSION_ID)"; then \
	  $(COMPOSE_CMD) start raildash; \
	  echo "the file import failed; the dashboard was restarted without it (see above)" >&2; \
	  exit 1; \
	fi
	$(COMPOSE_CMD) start raildash
	@ok=0; for i in $$(seq 1 30); do \
	  if curl -fsS http://127.0.0.1:8000/webhook/health >/dev/null 2>&1; then ok=1; break; fi; \
	  sleep 1; \
	done; \
	[ "$$ok" = "1" ] || { echo "raildash did not come back healthy" >&2; exit 1; }
	$(COMPOSE_CMD) ps
	@echo ""
	@echo "open http://127.0.0.1:8000 -- see README.md 'Running both together'"
	@echo "tail logs with: make stack-logs"

stack-logs:
	$(COMPOSE_ANY) logs -f --tail=50

stack-down:
	$(COMPOSE_ANY) down

# `down` alone keeps the named volumes, so capture.jsonl (RailMon appends) and
# the database survive and a second run shows the first run's rows too. This
# is the reset that makes the README's first-run numbers true again.
stack-clean:
	$(COMPOSE_ANY) down -v

# Compose-level smoke test, in local-built mode: raildash up, demo capture,
# file import, then check that what got stored equals what actually got
# parsed out of the capture -- not just "greater than zero". The count is
# scoped to this session id (/api/overview aggregates the whole database),
# the trap tears the volumes down even on the failure this exists to catch,
# and the delivered-by-webhook assertion fails when only the file path
# ingested -- the case where the dedup check would otherwise pass vacuously.
stack-test: railmon-src-check
	@set -e; \
	trap '$(COMPOSE_LOCAL) down -v' EXIT; \
	$(COMPOSE_LOCAL) up --build -d raildash; \
	$(COMPOSE_LOCAL) up --build --exit-code-from railmon railmon; \
	$(COMPOSE_LOCAL) stop raildash; \
	import_out=$$($(COMPOSE_LOCAL) run --rm --entrypoint python3 raildash \
	  -m raildash.cli --db /data/raildash.db load /captures/capture.jsonl \
	  --session-id "$(DEMO_SESSION_ID)"); \
	printf '%s\n' "$$import_out"; \
	$(COMPOSE_LOCAL) start raildash; \
	ok=0; for i in $$(seq 1 30); do \
	  if curl -fsS http://127.0.0.1:8000/webhook/health >/dev/null 2>&1; then ok=1; break; fi; \
	  sleep 1; \
	done; \
	[ "$$ok" = "1" ] || { echo "raildash did not come back healthy" >&2; exit 1; }; \
	capture=$$($(COMPOSE_LOCAL) exec -T raildash cat /captures/capture.jsonl) \
	  || { echo "stack-test: could not read /captures/capture.jsonl" >&2; exit 1; }; \
	file_lines=$$(printf '%s\n' "$$capture" | grep -c . || true); \
	[ "$$file_lines" -gt 0 ] || { echo "stack-test: capture.jsonl is empty -- RailMon captured nothing" >&2; exit 1; }; \
	inserted=$$(printf '%s\n' "$$import_out" | sed -n 's/^loaded \([0-9][0-9]*\) interaction.*/\1/p'); \
	duplicate=$$(printf '%s\n' "$$import_out" | sed -n 's/^ *\([0-9][0-9]*\) already present.*/\1/p'); \
	inserted=$${inserted:-0}; duplicate=$${duplicate:-0}; \
	total=$$((inserted + duplicate)); \
	[ "$$total" -gt 0 ] || { echo "stack-test: the import parsed no interactions out of $$file_lines line(s)" >&2; exit 1; }; \
	[ "$$total" -eq "$$file_lines" ] || echo "stack-test: note -- $$file_lines line(s) in capture.jsonl, $$total parsed (truncated or unparseable tail)" >&2; \
	stored=$$(curl -fsS "http://127.0.0.1:8000/api/overview?session_id=$(DEMO_SESSION_ID)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["totals"]["interactions"])'); \
	echo "capture parsed: $$total, interactions stored: $$stored"; \
	[ "$$stored" -gt 0 ] || { echo "stack-test: expected interactions > 0, got $$stored" >&2; exit 1; }; \
	[ "$$duplicate" -eq "$$total" ] || { echo "stack-test: the webhook path did not deliver -- the import found $$duplicate of $$total already present, so it ingested them itself. Both paths must be wired for this assertion to mean anything." >&2; exit 1; }; \
	[ "$$inserted" = "0" ] || { echo "stack-test: the import inserted $$inserted row(s) the webhook should already have delivered" >&2; exit 1; }; \
	[ "$$stored" -eq "$$total" ] || { echo "stack-test: both wirings double-counted -- $$stored stored vs $$total captured" >&2; exit 1; }
