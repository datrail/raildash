"""The opt-in model step of the data-actions classifier (DR-205, design §4.2
step 5 and §4.5 Settings).

Off unless the user configures it:

- `RAILDASH_CLASSIFIER_MODEL_URL`: an OpenAI-compatible API base URL (a
  local model's, or a provider's), e.g. `http://127.0.0.1:11434/v1`;
- `RAILDASH_CLASSIFIER_MODEL`: the model name to ask;
- `RAILDASH_CLASSIFIER_API_KEY_FILE`: optional, a file holding the API key.
  The key is read from the file, never logged, and sent only to that URL.

Only a tool's schema is sent (its name, description and argument schema),
never a captured value (`data_actions.model_request_body`). The model is
asked only about tools the deterministic rules left unclassified, and its
answer counts only when every action is from the closed set; its `read` is
weak.

A network call never runs while RailDash holds its store lock: classifying
reads answers from a cache table only (`lookup`), and a miss is queued for
a background thread (`ModelClassifierWorker`) that asks the model and
stores the answer. Until it arrives the tool is `unclassified`, the safe
direction: the first call of a tool nothing else classifies is flagged as
unclassified, and later calls use the answer (an earlier row isn't
re-judged). A failed ask is cached too, and asked again after
`RETRY_AFTER`; an answer outside the closed set after `INVALID_RETRY_AFTER`.

The key goes only to the configured URL: a redirect is refused, not
followed (urllib would carry `Authorization` to wherever it points).
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import sys
import threading
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from . import data_actions as da

RETRY_AFTER = timedelta(hours=1)
# The same schema at temperature 0 likely gets the same answer again.
INVALID_RETRY_AFTER = timedelta(hours=24)
INVALID = {"_invalid": True}
REQUEST_TIMEOUT = 30
MAX_QUEUE = 1000


@dataclass(frozen=True)
class ModelSettings:
    url: str
    model: str
    api_key: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "ModelSettings | None":
        url = (environ.get("RAILDASH_CLASSIFIER_MODEL_URL") or "").strip()
        model = (environ.get("RAILDASH_CLASSIFIER_MODEL") or "").strip()
        if not url or not model:
            return None
        key_file = (environ.get("RAILDASH_CLASSIFIER_API_KEY_FILE") or "").strip()
        key = Path(key_file).read_text().strip() if key_file else None
        return cls(url=url.rstrip("/"), model=model, api_key=key or None)

    def __repr__(self) -> str:  # never show the key
        return f"ModelSettings(url={self.url!r}, model={self.model!r}, api_key={'set' if self.api_key else None})"


def schema_key(model: str, schema: Mapping[str, Any]) -> str:
    """One cached answer's key: the model, the classifier's version (the
    prompt is part of it) and what the model is shown."""
    shown = json.dumps(
        [model, da.CLASSIFIER_VERSION, schema.get("tool"), schema.get("description"),
         schema.get("input_schema")],
        sort_keys=True, default=str,
    )
    return hashlib.sha256(shown.encode("utf-8", "surrogatepass")).hexdigest()


class ModelClassifierWorker:
    """Asks the configured model about queued schemas, one at a time, and
    stores each answer through `store.record_model_answer`."""

    def __init__(self, store: Any, settings: ModelSettings,
                 post: Callable[[str, dict[str, str], bytes], dict[str, Any]] | None = None) -> None:
        self.store = store
        self.settings = settings
        self._post = post or _post_json
        self._queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(MAX_QUEUE)
        self._queued: set[str] = set()
        self._queued_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    # --- what the classifier calls, under the store lock: no network -----

    def lookup(self, schema: Mapping[str, Any]) -> dict[str, Any] | None:
        key = schema_key(self.settings.model, schema)
        answer = self.store._model_answer_locked(key)
        if answer is not None:
            asked_at, value = answer
            wait = INVALID_RETRY_AFTER if value == INVALID else RETRY_AFTER
            if value is not None and value != INVALID:
                return value
            if datetime.now(timezone.utc) - asked_at < wait:
                return None
        with self._queued_lock:
            if key in self._queued:
                return None
            # Marked before it is queued, and unmarked only once its answer
            # is stored, so a poll meanwhile doesn't queue it twice.
            self._queued.add(key)
        try:
            self._queue.put_nowait((key, {k: schema.get(k) for k in ("tool", "description", "input_schema")}))
        except queue.Full:
            with self._queued_lock:
                self._queued.discard(key)  # asked on a later classification
        return None

    # --- the background side ---------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="raildash-classifier-model", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            self.run_one()

    def run_one(self) -> None:
        """One blocking step of the worker: an exception (a busy or closed
        database, say) is logged by type and skipped, never ends it."""
        try:
            self.drain_once(block=True)
        except Exception as exc:  # noqa: BLE001 - the worker must outlive one bad item
            print(f"raildash: the classifier model worker skipped an item: {type(exc).__name__}",
                  file=sys.stderr)

    def drain_once(self, *, block: bool = False) -> int:
        """Ask about every queued schema (one when blocking). Returns how many
        were asked."""
        asked = 0
        while True:
            try:
                key, schema = self._queue.get(block=block and asked == 0)
            except queue.Empty:
                return asked
            try:
                if self.store.model_answer_fresh(key):
                    continue  # answered meanwhile
                self.store.record_model_answer(key, self.settings.model, self._ask(schema))
                asked += 1
            finally:
                with self._queued_lock:
                    self._queued.discard(key)
            if block:
                return asked

    def _ask(self, schema: Mapping[str, Any]) -> dict[str, Any] | None:
        body = json.dumps(da.model_request_body(self.settings.model, schema)).encode()
        headers = {"Content-Type": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        try:
            reply = self._post(f"{self.settings.url}/chat/completions", headers, body)
        except Exception as exc:  # noqa: BLE001 - a failed ask is retried later
            print(f"raildash: the classifier model couldn't be asked: {type(exc).__name__}", file=sys.stderr)
            return None
        return da.parse_model_reply(self.settings.model, reply) or dict(INVALID)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: following one would send the key elsewhere."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _post_json(url: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _OPENER.open(request, timeout=REQUEST_TIMEOUT) as response:  # noqa: S310 - the user's URL
        return json.loads(response.read(1_048_576))


def start_from_env(store: Any, environ: Mapping[str, str] = os.environ) -> ModelClassifierWorker | None:
    """Start the worker when the model is configured, and hand the store its
    cache-only lookup. Returns None (and changes nothing) when it isn't."""
    settings = ModelSettings.from_env(environ)
    if settings is None:
        return None
    worker = ModelClassifierWorker(store, settings)
    store.model_classifier = worker.lookup
    worker.start()
    return worker
