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

