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
