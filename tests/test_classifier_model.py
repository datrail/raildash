"""DR-205: the classifier's opt-in model step (raildash/classifier_model.py)."""

from __future__ import annotations

import json

from raildash import classifier_model as cm
from raildash.store import Store
from test_guardrail_data_actions import call, mcp

ENDPOINT = "docs.example.com/mcp"
FROB = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
    {"name": "frobnicate", "description": "Frobnicates.", "inputSchema": {"type": "object", "properties": {"x": {}}}}]}}


def test_settings_come_from_the_environment_and_never_show_the_key(tmp_path):
    assert cm.ModelSettings.from_env({}) is None
    assert cm.ModelSettings.from_env({"RAILDASH_CLASSIFIER_MODEL_URL": "http://x/v1"}) is None
    key = tmp_path / "key"
    key.write_text("sk-secret\n")
    settings = cm.ModelSettings.from_env({
        "RAILDASH_CLASSIFIER_MODEL_URL": "http://127.0.0.1:11434/v1/", "RAILDASH_CLASSIFIER_MODEL": "small",
        "RAILDASH_CLASSIFIER_API_KEY_FILE": str(key)})
    assert settings.url == "http://127.0.0.1:11434/v1" and settings.api_key == "sk-secret"
    assert "sk-secret" not in repr(settings)


def _store(tmp_path):
    store = Store(tmp_path / "m.db")
    store.upsert_session("s1")
    store.add_interactions("s1", [
        mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, FROB),
        call("frobnicate", {"x": "the captured value"}),
    ], authenticated=True)
    return store


def test_an_unclassified_tool_is_asked_about_off_the_lock_and_the_answer_is_used(tmp_path):
    store = _store(tmp_path)
    sent = []

    def post(url, headers, body):
        sent.append((url, headers, json.loads(body)))
        return {"choices": [{"message": {"content": json.dumps({"actions": ["read"], "reason": "fetches"})}}]}

    worker = cm.ModelClassifierWorker(store, cm.ModelSettings("http://m/v1", "small", "k"), post=post)
    store.model_classifier = worker.lookup
    [row] = store.data_action_rows(["session:s1"])
    assert row["actions"] == [] and row["unclassified"]  # not asked yet: unclassified
    assert sent == []
    assert worker.drain_once() == 1
    url, headers, body = sent[0]
    assert url == "http://m/v1/chat/completions" and headers["Authorization"] == "Bearer k"
    shown = json.loads(body["messages"][1]["content"])
    # The schema only, never a captured value.
    assert shown["name"] == f"mcp@{ENDPOINT}__frobnicate"
    assert "the captured value" not in json.dumps(body)
    [row] = store.data_action_rows(["session:s1"])
    assert row["actions"] == ["read"] and row["classification"]["weak_read"]
    assert row["classification"]["reasons"] == ["model small: fetches"]
    store.close()


def test_a_failed_ask_is_not_repeated_at_once(tmp_path):
    store = _store(tmp_path)
    calls = []

    def post(url, headers, body):
        calls.append(1)
        raise OSError("down")

    worker = cm.ModelClassifierWorker(store, cm.ModelSettings("http://m/v1", "small"), post=post)
    store.model_classifier = worker.lookup
    store.data_action_rows(["session:s1"])
    worker.drain_once()
    store.data_action_rows(["session:s1"])
    assert worker.drain_once() == 0  # cached failure, retried only later
    assert len(calls) == 1
    [row] = store.data_action_rows(["session:s1"])
    assert row["unclassified"]
    store.close()


def test_nothing_starts_unless_configured(tmp_path):
    store = Store(tmp_path / "n.db")
    assert cm.start_from_env(store, {}) is None
    assert store.model_classifier is None
    store.close()


def test_a_redirect_is_refused_so_the_key_never_follows_it(tmp_path):
    import http.server
    import threading
    import urllib.error

    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):  # noqa: N802
            seen.append((self.path, self.headers.get("Authorization")))
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()

        do_GET = do_POST  # noqa: N815

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        try:
            cm._post_json(f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                          {"Authorization": "Bearer k"}, b"{}")
        except urllib.error.HTTPError as error:
            assert error.code == 302
        assert seen == [("/v1/chat/completions", "Bearer k")]  # never /elsewhere
    finally:
        server.shutdown()


def test_the_worker_survives_a_bad_item_and_an_invalid_answer_waits_a_day(tmp_path):
    store = _store(tmp_path)
    answers = iter([{"choices": [{"message": {"content": json.dumps({"actions": ["steal"]})}}]}])
    worker = cm.ModelClassifierWorker(store, cm.ModelSettings("http://m/v1", "small"),
                                      post=lambda url, headers, body: next(answers))
    store.model_classifier = worker.lookup
    store.data_action_rows(["session:s1"])
    assert worker.drain_once() == 1
    store.data_action_rows(["session:s1"])
    assert worker.drain_once() == 0  # outside the closed set: not asked again soon
    store.close()


def test_the_worker_outlives_a_failing_write(tmp_path, monkeypatch):
    store = _store(tmp_path)
    reply = {"choices": [{"message": {"content": json.dumps({"actions": ["read"], "reason": "r"})}}]}
    worker = cm.ModelClassifierWorker(store, cm.ModelSettings("http://m/v1", "small"),
                                      post=lambda url, headers, body: reply)
    store.model_classifier = worker.lookup
    original = type(store).record_model_answer
    failures = iter([True])

    def flaky(self, *args):
        if next(failures, False):
            raise RuntimeError("database is locked")
        return original(self, *args)

    monkeypatch.setattr(type(store), "record_model_answer", flaky)
    store.data_action_rows(["session:s1"])
    worker.run_one()  # the write fails; the worker carries on
    store.data_action_rows(["session:s1"])  # queued again: the key was unmarked
    worker.run_one()
    [row] = store.data_action_rows(["session:s1"])
    assert row["actions"] == ["read"]
    store.close()
