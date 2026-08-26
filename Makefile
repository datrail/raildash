.PHONY: test lint serve demo clean stack stack-logs stack-down stack-test

VENV := .venv
PY   := $(VENV)/bin/python

RAILMON_REPO ?= https://github.com/datrail/railmon.git

# One source of truth for the session id both ingestion paths use. RailMon
# gets it as RAILMON_SESSION_ID (interpolated into docker-compose.yml, which
# repeats it only as a fallback default); the file-import step below passes
# the same value as --session-id. They must match or the webhook and the file
# land in different sessions and every interaction is counted twice.
DEMO_SESSION_ID ?= railmon-raildash-stack
export DEMO_SESSION_ID

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

clean:
	rm -rf $(VENV) .pytest_cache **/__pycache__ demo.db raildash.db *.db-wal *.db-shm

# DR-81 (BDL-F5) — RailMon + RailDash together, from one command. This repo
# has no RailMon source and no published RailMon image to build the other
# service from, so `make stack` clones it into ./railmon first (skipped if
# already present — delete the directory to force a re-clone). See
# docker-compose.yml's header and README.md's "Running both together" for
# why this lives here instead of a separate repo.
railmon:
	git clone --depth 1 $(RAILMON_REPO) railmon

# Only ONE process can hold this SQLite database: it lives on a named volume,
# where WAL's -shm file is not shareable, so a second opener gets "database is
# locked" even for a read-only PRAGMA (verified on WSL2 Docker, both from a
# second container and from a second process inside the raildash container).
# So the file import runs while the server is stopped, and is the sole opener
# for those few seconds. `docker wait` first, so the capture is complete
# before it is read. The dashboard is only down during setup, before anyone
# has opened it.
stack: railmon
	docker compose up --build -d
	@echo "waiting for the demo capture to finish..."
	@docker wait $$(docker compose ps -aq railmon) >/dev/null
	@echo "importing the capture file (server paused)..."
	docker compose stop raildash
	docker compose run --rm --entrypoint python3 raildash \
	  -m raildash.cli --db /data/raildash.db load /captures/capture.jsonl \
	  --session-id $(DEMO_SESSION_ID)
	docker compose start raildash
	@for i in $$(seq 1 30); do \
	  curl -fsS http://127.0.0.1:8000/webhook/health >/dev/null 2>&1 && break; \
	  sleep 1; \
	done
	docker compose ps
	@echo ""
	@echo "open http://127.0.0.1:8000 -- see README.md 'Running both together'"
	@echo "tail logs with: make stack-logs"

stack-logs:
	docker compose logs -f --tail=50

stack-down:
	docker compose down

# Compose-level smoke test: bring raildash up, run the demo capture, run the
# file-import, then check that what got stored equals what actually got
# captured -- not just "greater than zero". A dedup regression (the two
# wirings landing in different sessions -- see README.md) shows up as
# stored > file_lines, which "count > 0" alone would never catch.
# --exit-code-from makes `up` return once the named one-shot service exits,
# instead of hanging the way a bare `up` does for a non-long-running service.
stack-test: railmon
	docker compose up --build -d raildash
	docker compose up --build --exit-code-from railmon railmon
	docker compose stop raildash
	docker compose run --rm --entrypoint python3 raildash \
	  -m raildash.cli --db /data/raildash.db load /captures/capture.jsonl \
	  --session-id $(DEMO_SESSION_ID)
	docker compose start raildash
	@echo "waiting for the dashboard to come back..."
	@for i in $$(seq 1 30); do \
	  curl -fsS http://127.0.0.1:8000/webhook/health >/dev/null 2>&1 && break; \
	  sleep 1; \
	done
	file_lines=$$(docker compose exec -T raildash cat /captures/capture.jsonl | wc -l); \
	stored=$$(curl -fsS http://127.0.0.1:8000/api/overview | python3 -c 'import json,sys; print(json.load(sys.stdin)["totals"]["interactions"])'); \
	echo "capture.jsonl lines: $$file_lines, interactions stored: $$stored"; \
	ok=1; \
	[ "$$stored" -gt 0 ] || { echo "stack-test: expected interactions > 0, got $$stored" >&2; ok=0; }; \
	[ "$$stored" -eq "$$file_lines" ] || { echo "stack-test: webhook+file wirings double-counted -- $$stored stored vs $$file_lines captured" >&2; ok=0; }; \
	docker compose down; \
	[ "$$ok" -eq 1 ]
