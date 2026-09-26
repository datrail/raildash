"""Real-browser coverage for DR-120's ASP write-action UI.

Same launch pattern as tests/test_browser.py: a throwaway database, a
subprocess `raildash serve`, and headless Chromium driving the actual page --
so this proves the write routes and the UI wired to them work together, not
just that each layer works in isolation.
"""

from __future__ import annotations

import copy
import json
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from urllib.request import urlopen

from playwright.sync_api import sync_playwright

from raildash.asp import parse_bundle
from raildash.store import Store


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


def _drifted_bundle_bytes(*, bundle_id: str, destination: str) -> bytes:
    value = copy.deepcopy(parse_bundle(FIXTURE.read_bytes()))
    value["bundle_id"] = bundle_id
    value["collected_at"] = "2026-09-24T02:00:00Z"
    value["attributes"]["declared_destinations"]["value"] = [destination]
    return json.dumps(value, sort_keys=True).encode()


def test_asp_write_actions_drive_the_full_custody_flow_from_the_ui(tmp_path):
    database = tmp_path / "raildash.db"
    drifted_path = tmp_path / "drifted-bundle.json"
    drifted_path.write_bytes(
        _drifted_bundle_bytes(bundle_id="bnd-browser-drift", destination="browser.example")
    )

    # Only the very first ASP for this identity is pre-loaded, and
    # deliberately never locked -- so the UI's first-ASP auto-offer banner is
    # what greets the page, exactly the scenario DR-120 asks for.
    store = Store(database)
    store.load_asp(FIXTURE.read_bytes())
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            sys.executable, "-m", "raildash.cli",
            "--db", str(database),
            "serve", "--host", "127.0.0.1", "--port", str(port),
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
                lambda message: errors.append(message.text) if message.type == "error" else None,
            )
            page.on("pageerror", lambda error: errors.append(str(error)))

            page.goto(url, wait_until="networkidle")
            assert page.title() == "RailDash"

            # The page injects its own local write token; the UI's own fetch
            # calls must be able to read it back out of the DOM.
            token = page.locator('meta[name="raildash-token"]').get_attribute("content")
            assert token

            # --- 1. First-ASP auto-offer: lock and activate in one click ---
            card = page.locator(".asp-state-card").first
            assert "lock this as your alignment baseline" in card.inner_text().lower()

            with page.expect_response(
                lambda response: response.url.endswith("/lock") and response.status == 201
            ):
                card.get_by_role("button", name="Lock this as your alignment baseline").click()
            # Locking and switching to it immediately self-compares the ASP
            # against the version that is now its own baseline -> aligned.
            page.wait_for_selector(".asp-state-card:has-text('Aligned')")

            # --- 2. Drag-and-drop / file-upload ingest of a drifted bundle ---
            page.locator("#asp-upload-input").set_input_files(str(drifted_path))
            page.wait_for_selector("#asp-upload-status:has-text('Loaded as asp-')")
            page.wait_for_selector(".asp-state-card:has-text('Drift detected')")

            # --- 3. Drift explained: the per-attribute old/new detail ---
            drifted_card = page.locator(".asp-state-card", has_text="Drift detected").first
            diff_text = drifted_card.locator(".asp-diff-table").inner_text()
            assert "declared_destinations" in diff_text
            assert "browser.example" in diff_text

            # --- 4. Accept the drifted state as a new baseline ---
            accept_button = drifted_card.get_by_role(
                "button", name="Accept new state as new baseline"
            )
            with page.expect_response(
                lambda response: "/accept-drift" in response.url and response.status == 201
            ):
                accept_button.click()
            page.wait_for_selector(".asp-state-card:has-text('Aligned')")

            # --- 5. Switch back to the first locked version -> drift returns ---
            aligned_card = page.locator(".asp-state-card", has_text="Aligned").first
            aligned_card.locator("select").select_option(label="v1.0")
            with page.expect_response(
                lambda response: "/switch" in response.url and response.status == 200
            ):
                aligned_card.get_by_role("button", name="Switch").click()
            page.wait_for_selector(".asp-state-card:has-text('Drift detected')")

            # --- 6. Inspect evidence toggles the parsed bundle inline ---
            some_card = page.locator(".asp-state-card").first
            some_card.get_by_role("button", name="Inspect evidence").click()
            page.wait_for_selector(".asp-bundle-view")
            assert "bundle_id" in some_card.locator(".asp-bundle-view").inner_text()
            some_card.get_by_role("button", name="Hide evidence").click()
            assert page.locator(".asp-bundle-view").count() == 0

            # --- 7. Retention settings: view, save, and prune ---
            page.locator("#asp-retention summary").click()
            assert page.locator("#asp-retention-keep").input_value() != ""
            page.locator("#asp-retention-keep").fill("5")
            page.locator("#asp-retention-days").fill("14")
            with page.expect_response(
                lambda response: "/api/settings/asp-retention" in response.url
                and response.request.method == "POST"
            ):
                page.locator("#asp-retention-save").click()
            page.wait_for_selector("#asp-retention-status:has-text('Saved')")

            with page.expect_response(
                lambda response: "/api/asps/prune" in response.url and response.status == 200
            ):
                page.locator("#asp-retention-prune").click()
            page.wait_for_selector("#asp-retention-status:has-text('Pruned')")

            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_write_routes_reject_a_forged_token_from_outside_the_page(tmp_path):
    """The token is a same-origin CSRF defense: it must reject a wrong value,
    not merely accept whatever a script sends."""
    database = tmp_path / "raildash.db"
    store = Store(database)
    loaded = store.load_asp(FIXTURE.read_bytes())
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            sys.executable, "-m", "raildash.cli",
            "--db", str(database),
            "serve", "--host", "127.0.0.1", "--port", str(port),
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
            page.goto(url, wait_until="networkidle")

            status = page.evaluate(
                """async ({ aspId }) => {
                    const res = await fetch(`/api/asps/${aspId}/lock`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-RailDash-Token": "not-the-real-token",
                        },
                        body: JSON.stringify({ version: "v1.0" }),
                    });
                    return res.status;
                }""",
                {"aspId": loaded["asp_id"]},
            )
            assert status == 403
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
