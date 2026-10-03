"""Real-browser regression coverage for the ASP alignment dashboard."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from urllib.request import urlopen

from playwright.sync_api import sync_playwright

from raildash.acceptance import run_acceptance


ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "evidence-bundle-v1.json"


def _free_port() -> int:
    with closing(socket.socket()) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _wait_until_ready(url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"RailDash exited before startup ({process.returncode})\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        try:
            with urlopen(f"{url}/webhook/health", timeout=0.2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("RailDash did not become ready within 10 seconds")


def test_asp_alignment_survives_refresh_focus_and_theme_switch(tmp_path):
    database = tmp_path / "raildash.db"
    run_acceptance(database, FIXTURE)
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "raildash.cli",
            "--db",
            str(database),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on(
                "console",
                lambda message: errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: errors.append(str(error)))

            page.goto(url, wait_until="networkidle")
            assert page.title() == "RailDash"
            assert page.locator("#conn-text").inner_text().lower() == "live"

            cards = page.locator(".asp-state-card")
            assert cards.count() == 1
            card = cards.first
            assert "comparison unavailable" in card.inner_text().lower()
            assert "CONTRACT_MISMATCH" in card.inner_text()

            command = card.locator(".asp-command").first
            command.focus()
            assert command.evaluate("element => element === document.activeElement")
            page.wait_for_timeout(5_500)
            assert command.evaluate("element => element === document.activeElement")

            with page.expect_response(
                lambda response: "/api/asps?" in response.url
                and response.status == 200
            ):
                page.locator("#refresh").click()
            assert "CONTRACT_MISMATCH" in page.locator(".asp-state-card").inner_text()

            theme = page.locator("#theme")
            before = page.locator("html").get_attribute("data-theme")
            theme.click()
            after = page.locator("html").get_attribute("data-theme")
            assert after in {"light", "dark"}
            assert after != before
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


KEYED_FIXTURE = ROOT / "tests" / "fixtures" / "keyed-capture.jsonl"


def test_keyed_capture_gets_an_agent_filter_and_a_separate_unattributed_queue(tmp_path):
    # Rows the built RailMon binary emitted in railmon's
    # tests/ticket_claim_acceptance.py: planner's ticket agreed, executor's
    # named planner (conflict), critic sent none.
    database = tmp_path / "raildash.db"
    subprocess.run(
        [sys.executable, "-m", "raildash.cli", "--db", str(database), "load", str(KEYED_FIXTURE)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database), "serve",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "console",
                lambda message: errors.append(message.text) if message.type == "error" else None,
            )
            page.goto(url, wait_until="networkidle")

            # The default lane still lists every row.
            assert page.locator("#log tr").count() == 3
            assert "example.test" in page.locator("#log").inner_text()

            queue = page.locator("#unattributed-panel")
            assert queue.is_visible()
            rows = page.locator("#unattributed tr")
            assert rows.count() == 1
            text = rows.first.inner_text()
            assert "conflict" in text
            assert "TICKET_CLAIM_CONFLICT" in text
            assert "executor" in text

            agent = page.locator("#f-agent")
            assert page.locator("#f-agent-field").is_visible()
            options = agent.locator("option").all_inner_texts()
            assert options == ["any agent", "critic", "planner"]
            with page.expect_response(lambda r: "agent_key=planner" in r.url and "/api/profile" in r.url):
                agent.select_option("planner")
            page.wait_for_function("document.querySelectorAll('#log tr').length === 1")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_capture_drift_shows_an_image_upload_burst(tmp_path):
    """DR-132: same host, method and model, but one capture uploads images."""
    from raildash.ingest import normalise
    from raildash.store import Store

    def call(interaction_id: str, content) -> dict:
        return {
            "interaction_id": interaction_id,
            "request": {
                "method": "POST",
                "path": "/v1/messages",
                "headers": {"host": "api.anthropic.com", "content-type": "application/json"},
                "body": {"model": "claude-sonnet-5", "messages": [{"role": "user", "content": content}]},
            },
            "response": {"status_code": 200},
        }

    image = [{"type": "image", "source": {"type": "base64", "data": "iVBORw0KGgo"}}]
    database = tmp_path / "raildash.db"
    store = Store(database)
    for session_id, rows in (
        ("text-only", [call(f"t{i}", "hello") for i in range(3)]),
        ("with-uploads", [call(f"u{i}", image) for i in range(2)] + [call("u-text", "hi")]),
    ):
        store.upsert_session(session_id, agent="agent", source="test")
        store.add_interactions(session_id, [normalise(row) for row in rows])
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database), "serve",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "console",
                lambda message: errors.append(message.text) if message.type == "error" else None,
            )
            page.goto(url, wait_until="networkidle")

            page.locator("#drift-left").select_option("text-only")
            page.locator("#drift-right").select_option("with-uploads")
            group = page.locator(".drift-group", has_text="Uploaded content")
            group.wait_for()
            added = group.locator(".drift-change", has_text="Added")
            assert added.locator(".drift-label").all_inner_texts() == ["image"]
            # Nothing else drifted: the host is the same on both sides.
            hosts = page.locator(".drift-group", has_text="Hosts")
            assert hosts.locator(".drift-label").count() == 0
            assert "iVBORw0KGgo" not in page.content()
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_capture_drift_shows_a_much_larger_upload_to_a_known_host(tmp_path):
    """Lebin's payload-size dimension: same host, method and model, but one
    capture sends that host a request thousands of times the usual size."""
    from raildash.ingest import normalise
    from raildash.store import Store

    def call(interaction_id: str, request_size: int) -> dict:
        return {
            "interaction_id": interaction_id,
            "request": {
                "method": "POST",
                "path": "/v1/messages",
                "headers": {"host": "api.anthropic.com", "content-type": "application/json"},
                "body": {"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]},
            },
            "response": {"status_code": 200},
            "request_size": request_size,
        }

    database = tmp_path / "raildash.db"
    store = Store(database)
    for session_id, rows in (
        ("usual", [call("a", 900), call("b", 1_200)]),
        # Slightly longer prompts stay under the 2x threshold...
        ("longer-prompts", [call("c", 1_000), call("d", 2_000)]),
        # ...a 4 MB request does not.
        ("big-upload", [call("e", 1_000), call("f", 4 * 1024 * 1024)]),
    ):
        store.upsert_session(session_id, agent="agent", source="test")
        store.add_interactions(session_id, [normalise(row) for row in rows])
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database), "serve",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "console",
                lambda message: errors.append(message.text) if message.type == "error" else None,
            )
            page.goto(url, wait_until="networkidle")

            page.locator("#drift-left").select_option("usual")
            page.locator("#drift-right").select_option("longer-prompts")
            group = page.locator(".drift-group", has_text="Bytes sent per host")
            group.wait_for()
            page.wait_for_function(
                "() => [...document.querySelectorAll('.drift-group')]"
                ".some((g) => g.textContent.includes('Within 2× of before'))"
            )
            assert group.locator(".drift-label").count() == 0

            page.locator("#drift-right").select_option("big-upload")
            label = group.locator(".drift-label")
            label.wait_for()
            assert label.all_inner_texts() == ["api.anthropic.com 1.2 KB → 4.0 MB"]
            hosts = page.locator(".drift-group", has_text="Hosts")
            assert hosts.locator(".drift-label").count() == 0

            # The selected capture's observed profile lists the same fact.
            chip = page.locator(".profile-group", has_text="Bytes sent per host").locator(".profile-chip")
            chip.first.wait_for()
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_capture_drift_shows_a_file_the_agent_never_wrote_before(tmp_path):
    """Lebin's file and artifact-write dimensions: same host, model and tool
    names, but one capture reads a key and writes an archive to a share."""
    from raildash.ingest import normalise
    from raildash.store import Store

    def call(interaction_id: str, blocks: list[dict]) -> dict:
        return {
            "interaction_id": interaction_id,
            "request": {
                "method": "POST",
                "path": "/v1/messages",
                "headers": {"host": "api.anthropic.com", "content-type": "application/json"},
                "body": {"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "tidy up"}]},
            },
            "response": {"status_code": 200, "body": {"content": blocks}},
        }

    def tool(call_id: str, name: str, path: str) -> dict:
        return {"type": "tool_use", "id": call_id, "name": name, "input": {"file_path": path}}

    database = tmp_path / "raildash.db"
    store = Store(database)
    for session_id, rows in (
        ("usual", [call("a", [
            tool("a1", "Read", "/app/config.yaml"),
            tool("a2", "Write", "/app/out.log"),
        ])]),
        ("exfil", [call("b", [
            tool("b1", "Read", "/app/config.yaml"),
            tool("b2", "Read", "/home/me/.ssh/id_rsa"),
            tool("b3", "Write", "/srv/share/dump.tar"),
        ])]),
    ):
        store.upsert_session(session_id, agent="agent", source="test")
        store.add_interactions(session_id, [normalise(row) for row in rows])
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database), "serve",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "console",
                lambda message: errors.append(message.text) if message.type == "error" else None,
            )
            page.goto(url, wait_until="networkidle")

            def drift(title: str):
                return page.locator(".drift-group").filter(
                    has=page.get_by_role("heading", name=title, exact=True)
                )

            def changes(title: str) -> dict[str, list[str]]:
                rows = {}
                for row in drift(title).locator(".drift-change").all():
                    kind = row.locator(".drift-kind").inner_text()
                    rows[kind] = row.locator(".drift-label").all_inner_texts()
                return rows

            page.locator("#drift-left").select_option("usual")
            page.locator("#drift-right").select_option("exfil")
            drift("Files asked to write").locator(".drift-label").first.wait_for()
            assert changes("Files asked to write") == {
                "Added": ["/srv/share/dump.tar"], "Removed": ["/app/out.log"],
            }
            assert changes("Files asked to read") == {"Added": ["/home/me/.ssh/id_rsa"], "Removed": []}
            assert changes("File types asked to write") == {"Added": [".tar"], "Removed": [".log"]}
            # Nothing else about the traffic moved.
            assert changes("Hosts") == {"Added": [], "Removed": []}
            assert changes("Tools") == {"Added": [], "Removed": []}

            # The selected capture's observed profile lists the files it touched.
            files = page.locator(".profile-group").filter(
                has=page.get_by_role("heading", name="Files", exact=True)
            )
            files.locator(".profile-chip").first.wait_for()
            assert "not a filesystem trace" in files.locator(".note").inner_text()
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
