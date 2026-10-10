"""Real-browser coverage for DR-184 M3: the Guardrail panel.

Same launch pattern as `test_browser_asp_write_routes.py`: a throwaway
database, a subprocess `raildash serve`, and headless Chromium driving the
page. The ASPs, heartbeats and captures arrive over the same HTTP routes
RailMon uses, with the local token read from `<db>.token`, so this proves
the store's hooks, the routes and the panel work together.

It walks the design's §6 step 3 list: each of the four states, propose →
adopt, Allow this, Acknowledge followed by a re-opening hit, a *declared
since gN* offer then Dismiss and no second offer after a switch, Turn off,
and the token on every write the panel makes.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from playwright.sync_api import expect, sync_playwright

from raildash.store import Store
from test_browser_asp_write_routes import _free_port, _wait_until_ready
from test_guardrail import DEMO_LISTENER, capture, declared
from test_guardrail_custody import _now, asp

ROOT = Path(__file__).parent.parent
TIMEOUT = 20_000  # the page polls every 5 s


def _post(url: str, path: str, token: str, body: bytes) -> None:
    request = Request(f"{url}{path}", data=body, method="POST", headers={
        "Content-Type": "application/json", "X-RailDash-Token": token,
    })
    with urlopen(request, timeout=5) as response:
        assert response.status in (200, 202), response.status


def _capture(url: str, token: str, host: str, name: str) -> None:
    item = copy.deepcopy(capture()[0])
    item["timestamp"] = _now()
    item["interaction_id"] = name
    item["request"]["headers"]["host"] = host
    _post(url, "/webhook/http-interactions", token,
          json.dumps({"session_id": "browser", "interactions": [item]}).encode())


def _heartbeat(url: str, token: str) -> None:
    _post(url, "/webhook/heartbeat", token,
          json.dumps({"collector_id": "browser", "taps_attached": 1, "sent_at": _now()}).encode())


def test_the_guardrail_panel_drives_every_action(tmp_path):
    database = tmp_path / "raildash.db"
    store = Store(database)
    asp_id = store.load_asp(json.dumps(asp(listeners=[DEMO_LISTENER])).encode())["asp_id"]
    store.make_baseline(asp_id, "v1.0")
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    writes: list[tuple[str, str | None]] = []
    try:
        _wait_until_ready(url, process)
        token = Path(f"{database}.token").read_text().strip()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("request", lambda req: writes.append(
                (req.url, req.headers.get("x-raildash-token"))
            ) if req.method == "POST" else None)
            page.goto(url)
            panel = page.locator("#guardrail-body")
            card = panel.locator(".guardrail-card")
            state = card.locator(".asp-state")

            # No guardrail: the proposal, with the baseline's own listener
            # listed as what would be a violation.
            expect(state).to_have_text("No guardrail", timeout=TIMEOUT)
            proposal = card.locator(".guardrail-proposal")
            expect(proposal).to_contain_text("Adopt a guardrail for this agent?")
            expect(proposal.locator(".guardrail-would-be")).to_contain_text("tcp/127.0.0.1/8443")

            # Adopt → Violated by that listener.
            proposal.get_by_role("button", name="Adopt", exact=True).click()
            expect(state).to_have_text("Violated", timeout=TIMEOUT)
            listener_row = card.locator("tr", has_text="tcp/127.0.0.1/8443")
            expect(listener_row).to_contain_text("counts")

            # Allow this → allowed by g2; no heartbeat yet, so Unverified. An
            # editor left open on g1 closes, since saving it would undo this.
            card.locator(".guardrail-editor > summary", has_text="Edit").click()
            listener_row.get_by_role("button", name="Allow this").click()
            expect(card.locator(".guardrail-editor[open]")).to_have_count(0, timeout=TIMEOUT)
            expect(listener_row).to_contain_text("allowed by g2", timeout=TIMEOUT)
            expect(state).to_have_text("Unverified")
            expect(card.locator(".guardrail-rules")).to_contain_text("no collector heartbeat")

            # The collector's heartbeat → Held.
            _heartbeat(url, token)
            expect(state).to_have_text("Held", timeout=TIMEOUT)

            # A capture without the token changes nothing; the collector's does.
            item = copy.deepcopy(capture()[0])
            item["timestamp"] = _now()
            item["request"]["headers"]["host"] = "forged.example"
            with urlopen(Request(f"{url}/webhook/http-interactions", method="POST",
                                 data=json.dumps([item]).encode(),
                                 headers={"Content-Type": "application/json"}), timeout=5):
                pass
            _capture(url, token, "exfil.example", "browser-1")
            expect(state).to_have_text("Violated", timeout=TIMEOUT)
            expect(panel).not_to_contain_text("forged.example")
            rows = card.locator("tr", has_text="exfil.example")
            expect(rows).to_have_count(2)  # an upload and an out-of-spec call

            # Acknowledge both → Held; the same upload again re-opens its row.
            for _ in range(2):
                rows.get_by_role("button", name="Acknowledge").first.click()
                page.wait_for_timeout(300)
            expect(rows.first).to_contain_text("acknowledged", timeout=TIMEOUT)
            _heartbeat(url, token)
            expect(state).to_have_text("Held", timeout=TIMEOUT)
            _capture(url, token, "exfil.example", "browser-2")
            expect(state).to_have_text("Violated", timeout=TIMEOUT)
            expect(rows.first).to_contain_text("counts")

            # A newly declared host is offered; Dismiss records it and it isn't
            # offered again, even after a switch back to g1.
            _post(url, "/v1/evidence-bundles", token,
                  json.dumps(asp(declared_destinations=declared(["docs.example"]))).encode())
            offers = card.locator(".guardrail-offers")
            expect(offers).to_contain_text("docs.example", timeout=TIMEOUT)
            offers.get_by_role("button", name="Dismiss").click()
            expect(offers).to_have_count(0, timeout=TIMEOUT)
            picker = card.get_by_label("Guardrail version")
            picker.select_option(label="g1 (adopt)")
            # A poll that redraws the panel (a new row arrives) keeps the
            # choice: Switch must not post the active version.
            _capture(url, token, "third.example", "browser-3")
            expect(card.locator("tr", has_text="third.example").first).to_be_visible(timeout=TIMEOUT)
            expect(picker.locator("option:checked")).to_have_text("g1 (adopt)")
            card.locator(".asp-version-picker").get_by_role("button", name="Switch").click()
            expect(card.locator(".asp-subject")).to_have_text("version g1", timeout=TIMEOUT)
            expect(listener_row).to_contain_text("counts")
            expect(offers).to_have_count(0)

            # Edit with rules the contract refuses says why, and changes nothing.
            card.locator(".guardrail-editor > summary", has_text="Edit").click()
            card.locator(".guardrail-editor textarea").fill('{"uploads": {}}')
            card.get_by_role("button", name="Save as a new version").click()
            expect(card.locator(".guardrail-editor .asp-status-msg")).to_have_attribute(
                "data-tone", "err", timeout=TIMEOUT)

            # Turn off → No guardrail, with the proposal offered again.
            card.get_by_role("button", name="Turn off").click()
            expect(state).to_have_text("No guardrail", timeout=TIMEOUT)
            expect(card.locator(".guardrail-proposal")).to_be_visible()
            # With no guardrail no row counts, and none can be allowed.
            expect(card.locator(".guardrail-row-status", has_text="counts")).to_have_count(0)
            expect(card.locator(".guardrail-rows").get_by_role("button", name="Allow this")).to_have_count(0)
            expect(card.locator(".guardrail-row-status", has_text="not counting").first).to_be_visible()
            history = card.locator(".guardrail-history")
            history.locator("summary").click()
            expect(history).to_contain_text("turn off")
            expect(history).to_contain_text("declared dismiss")
            browser.close()
    finally:
        process.terminate()
        process.communicate(timeout=10)

    panel_writes = [(target, sent) for target, sent in writes if "/api/" in target]
    assert panel_writes, "the panel made no writes"
    assert all(sent == token for _, sent in panel_writes), panel_writes
