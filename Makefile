.PHONY: test lint serve demo clean stack stack-logs stack-down stack-test

VENV := .venv
PY   := $(VENV)/bin/python

RAILMON_REPO ?= https://github.com/datrail/railmon.git

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

stack: railmon
	docker compose up --build -d
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
	docker compose up --build --exit-code-from raildash-loader raildash-loader
	file_lines=$$(docker compose exec -T raildash cat /captures/capture.jsonl | wc -l); \
	stored=$$(curl -fsS http://127.0.0.1:8000/api/overview | python3 -c 'import json,sys; print(json.load(sys.stdin)["interactions"])'); \
	echo "capture.jsonl lines: $$file_lines, interactions stored: $$stored"; \
	ok=1; \
	[ "$$stored" -gt 0 ] || { echo "stack-test: expected interactions > 0, got $$stored" >&2; ok=0; }; \
	[ "$$stored" -eq "$$file_lines" ] || { echo "stack-test: webhook+file wirings double-counted -- $$stored stored vs $$file_lines captured" >&2; ok=0; }; \
	docker compose down; \
	[ "$$ok" -eq 1 ]
