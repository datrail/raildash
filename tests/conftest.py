"""Shared test setup.

Starlette's TestClient sends `Host: testserver`, a name RailDash refuses by
default (DR-317), so the suite allows it the way an operator would, before any
test imports `raildash.app`. Subprocesses the tests start inherit it.
"""

import os

os.environ.setdefault("RAILDASH_ALLOWED_HOSTS", "testserver")
