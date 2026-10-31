"""Real-browser coverage for DR-184 M3: the Guardrail panel.

Same launch pattern as `test_browser_asp_write_routes.py`: a throwaway
database, a subprocess `raildash serve`, and headless Chromium driving the
page. The ASPs, heartbeats and captures arrive over the same HTTP routes
RailMon uses, with the local token read from `<db>.token`, so this proves
the store's hooks, the routes and the panel work together.

It walks the design's §6 step 3 list: each of the four states, propose →
adopt, Allow this, Acknowledge followed by a re-opening hit, a *declared
since gN* offer then Dismiss and no second offer after a switch, Turn off,
and the token on every write the panel makes. A second test clicks Allow
all (DR-202): one rule's rows allowed in one version.
"""

from __future__ import annotations

import copy
import json
import os
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


def _post(url: str, path: str, token: str, body: bytes, ok: tuple[int, ...] = (200, 202)) -> None:
    request = Request(f"{url}{path}", data=body, method="POST", headers={
        "Content-Type": "application/json", "X-RailDash-Token": token,
    })
    with urlopen(request, timeout=5) as response:
        assert response.status in ok, response.status


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
            # The one seeded glob says what it is for (DR-201).
            expect(proposal).to_contain_text("**/__pycache__/*.pyc (Python bytecode caches)")

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
            # Each rule's line agrees with its rows (DR-200): the two request
            # rules with a counting row read violated, the others held.
            rule_line = card.locator(".guardrail-rules")
            for rule in ("uploads", "out_of_spec_calls"):
                expect(rule_line.locator(f".guardrail-rule-violated[data-rule={rule}]")).to_have_count(1)
            for rule in ("service_ports", "saved_files"):
                expect(rule_line.locator(f".guardrail-rule-held[data-rule={rule}]")).to_have_count(1)

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


def test_allow_all_allows_a_rules_rows_in_one_version(tmp_path):
    database = tmp_path / "raildash.db"
    store = Store(database)
    asp_id = store.load_asp(json.dumps(asp(listeners=[DEMO_LISTENER])).encode())["asp_id"]
    made = store.make_baseline(asp_id, "v1.0")
    store.adopt_guardrail(made["alignment_version"]["alignment_version_id"])
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
        hosts = ("a.example", "b.example", "c.example")
        for n, host in enumerate((*hosts, "*.com")):
            _capture(url, token, host, f"allow-all-{n}")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("request", lambda req: writes.append(
                (req.url, req.headers.get("x-raildash-token"))
            ) if req.method == "POST" else None)
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            expect(card.locator(".asp-state")).to_have_text("Violated", timeout=TIMEOUT)

            # The uploads rule: three hosts one click can allow, and a
            # wildcard Host header it can't, which is left and said so.
            group = card.locator(".guardrail-allow-all").filter(
                has=page.locator('button[data-key="allow-all:uploads"]'))
            button = group.get_by_role("button")
            expect(button).to_have_text("Allow all 3", timeout=TIMEOUT)
            expect(group).to_contain_text("1 counting row can't be allowed with one click")
            button.click()

            uploads = card.locator("table").nth(1)  # service ports, then uploads
            for host in hosts:
                expect(uploads.locator("tr", has_text=host)).to_contain_text(
                    "allowed by g2", timeout=TIMEOUT)
            expect(uploads.locator("tr", has_text="*.com")).to_contain_text("counts")
            expect(page.locator('button[data-key="allow-all:uploads"]')).to_have_count(0)
            # The same hosts' out-of-spec rows are another rule's and still count.
            expect(page.locator('button[data-key="allow-all:out_of_spec_calls"]')).to_have_text(
                "Allow all 3")
            picker = card.get_by_label("Guardrail version")
            expect(picker.locator("option")).to_have_count(2)
            history = card.locator(".guardrail-history")
            history.locator("summary").click()
            # In the order the page listed them: newest first.
            expect(history).to_contain_text("allow rows g2 (3 items: c.example, b.example, a.example)")
            browser.close()
    finally:
        process.terminate()
        process.communicate(timeout=10)

    panel_writes = [(target, sent) for target, sent in writes if "/api/" in target]
    assert [target.rsplit("/", 1)[1] for target, _ in panel_writes] == ["allow-rows"]
    assert all(sent == token for _, sent in panel_writes), panel_writes


def test_the_panel_shows_data_actions_in_the_proposal_and_offers_them_to_a_v1_agent(tmp_path):
    """DR-205 M2: the proposal's data_actions lines and its blocked-until-
    allowed list are shown before Adopt; an agent on a v1 version is offered
    Add data actions, the proposal fetched when opened."""
    from test_guardrail_data_actions import call, listed

    database = tmp_path / "raildash.db"
    store = Store(database)
    store.upsert_session("s1")
    store.add_interactions("s1", [listed(), call("read_doc", {"doc_id": "d"})], authenticated=True)
    asp_id = store.load_asp(json.dumps(asp(listeners=[DEMO_LISTENER])).encode())["asp_id"]
    alignment = store.make_baseline(asp_id, "v1.0")["alignment_version"]
    proposal = store.propose_guardrail(alignment["alignment_version_id"])
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        token = Path(f"{database}.token").read_text().strip()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            shown = card.locator(".guardrail-proposal")
            expect(shown).to_contain_text("Data actions allowed", timeout=TIMEOUT)
            expect(shown).to_contain_text("mcp@docs.example.com/mcp__read_doc: read")
            expect(shown.locator(".guardrail-blocked")).to_contain_text("mcp@docs.example.com/mcp__upload_file")
            expect(shown.locator(".guardrail-blocked")).to_contain_text("upload")

            # Adopt it as a v1 (an edit without the rule): the offer appears.
            rules = {k: v for k, v in proposal["guardrail"]["rules"].items() if k != "data_actions"}
            adopt = Request(f"{url}/api/alignments/{alignment['alignment_version_id']}/guardrail",
                            data=json.dumps({"rules": rules}).encode(), method="POST",
                            headers={"Content-Type": "application/json", "X-RailDash-Token": token})
            with urlopen(adopt, timeout=5) as response:
                assert response.status == 201
            offer = card.locator(".guardrail-data-actions-offer")
            expect(offer).to_contain_text("Add data actions", timeout=TIMEOUT)
            offer.locator("summary", has_text="Show the proposal").click()
            expect(offer).to_contain_text("mcp@docs.example.com/mcp__read_doc: read", timeout=TIMEOUT)
            offer.get_by_role("button", name="Add data actions").click()
            expect(card.locator(".guardrail-data-actions-offer")).to_have_count(0, timeout=TIMEOUT)
            card.locator(".guardrail-active-policy > summary").click()
            expect(card.locator(".guardrail-active-policy")).to_contain_text("Data actions allowed")
            expect(card.locator('.guardrail-rules [data-rule="data_actions"]')).to_have_count(1)
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_a_data_action_row_says_why_and_an_override_saves_a_version(tmp_path):
    """DR-205 M3: Why shows the classification's reasons and schemas, and
    Override saves the actions the user says the tool has as a new version."""
    from test_guardrail_data_actions import PNG, call, listed

    database = tmp_path / "raildash.db"
    store = Store(database)
    store.upsert_session("s1")
    store.add_interactions("s1", [listed(), call("read_doc", {"doc_id": "d"})], authenticated=True)
    asp_id = store.load_asp(json.dumps(asp(listeners=[DEMO_LISTENER])).encode())["asp_id"]
    alignment = store.make_baseline(asp_id, "v1.0")["alignment_version"]
    store.adopt_guardrail(alignment["alignment_version_id"])
    store.record_heartbeat("browser", taps_attached=1, sent_at=_now())
    store.add_interactions("s1", [call("upload_file", {"content": PNG})], authenticated=True)
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            row = card.locator("tr", has_text="mcp__upload_file · upload")
            expect(row).to_contain_text("counts", timeout=TIMEOUT)
            row.locator(".guardrail-why > summary").click()
            why = row.locator(".guardrail-why")
            expect(why).to_contain_text("Classified upload", timeout=TIMEOUT)
            expect(why).to_contain_text('argument "content" is base64')
            # Nothing ticked isn't "harmless": Save asks for an action.
            why.get_by_role("button", name="Save as a new version").click()
            expect(why).to_contain_text("Tick at least one action.", timeout=TIMEOUT)
            # Say the tool only reads: a new version, and the row stops counting.
            why.locator('input[value="read"]').check()
            why.get_by_role("button", name="Save as a new version").click()
            expect(row).to_contain_text("allowed by", timeout=TIMEOUT)
            card.locator(".guardrail-active-policy > summary").click()
            expect(card.locator(".guardrail-active-policy")).to_contain_text("mcp@docs.example.com/mcp__upload_file: read")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_the_egress_line_and_require_containment(tmp_path):
    """DR-207 M2: the Egress line in words with the declared proxy beside it,
    and Require containment on an open agent warning first, then making a
    version whose rule is violated."""
    from test_guardrail_egress import PROXY, egress

    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER], egress_containment=egress("open"), egress_proxy_declared=PROXY)
    asp_id = store.load_asp(json.dumps(value).encode())["asp_id"]
    alignment = store.make_baseline(asp_id, "v1.0")["alignment_version"]
    store.adopt_guardrail(alignment["alignment_version_id"])
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            line = card.locator(".guardrail-egress")
            expect(line).to_contain_text("Open: this agent can reach any host", timeout=TIMEOUT)
            expect(line).to_contain_text("declares a proxy (HTTPS_PROXY=http://proxy.corp:3128)")
            expect(line).to_contain_text("doesn't force traffic through it")
            expect(card.locator('.guardrail-rules [data-rule="egress_containment"]')).to_have_count(0)
            require = card.locator(".guardrail-require-egress")
            expect(require).to_contain_text("starts Violated")
            require.get_by_role("button", name="Require containment").click()
            expect(card.locator('.guardrail-rules [data-rule="egress_containment"]')).to_contain_text(
                "violated", timeout=TIMEOUT)
            expect(card.locator(".asp-state")).to_have_text("Violated")
            expect(card.locator("tr", has_text="open")).to_contain_text("counts")
            expect(card.locator(".guardrail-require-egress")).to_have_count(0)
            card.locator(".guardrail-active-policy > summary").click()
            expect(card.locator(".guardrail-active-policy")).to_contain_text("must be contained")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_the_proposal_labels_openshells_dns(tmp_path):
    """DR-247: the two listeners a proposal allows for an agent in an
    OpenShell sandbox say what they are."""
    from test_guardrail_egress import OPENSHELL_DNS, egress

    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER, *OPENSHELL_DNS], egress_containment=egress("allow_list_enforced"))
    store.make_baseline(store.load_asp(json.dumps(value).encode())["asp_id"], "v1.0")
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            proposal = page.locator("#guardrail-body .guardrail-card .guardrail-proposal")
            expect(proposal).to_contain_text("tcp/127.0.0.53/53 (OpenShell's DNS)", timeout=TIMEOUT)
            expect(proposal).to_contain_text("udp/127.0.0.53/53 (OpenShell's DNS)")
            expect(proposal.locator(".guardrail-would-be")).to_contain_text("tcp/127.0.0.1/8443")
            expect(proposal.locator(".guardrail-would-be")).not_to_contain_text("127.0.0.53")
            # Adopted, the version in force says the same.
            card = page.locator("#guardrail-body .guardrail-card")
            proposal.get_by_role("button", name="Adopt", exact=True).click()
            card.locator(".guardrail-active-policy > summary").click(timeout=TIMEOUT)
            expect(card.locator(".guardrail-active-policy")).to_contain_text(
                "udp/127.0.0.53/53 (OpenShell's DNS)")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_an_allow_list_railmon_read_is_counted_on_the_egress_line(tmp_path):
    """DR-266: when RailMon's ASP carries the sandbox's allow-list (read from
    OpenShell by `railmon openshell`), the Egress line says how many
    endpoints it holds instead of that its contents aren't visible."""
    from test_guardrail_egress import egress

    attribute = egress("allow_list_enforced")
    attribute["value"]["allow_list"] = [
        {"host": host, "allowed_ips": [], "port": 443, "path": None, "protocol": "rest", "enforcement": "enforce",
         "access": "read-only", "rules": [], "deny_rules": 0, "binaries": ["/usr/bin/python3"]}
        for host in ("api.github.com", "pypi.org")]
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER], egress_containment=attribute)
    store.make_baseline(store.load_asp(json.dumps(value).encode())["asp_id"], "v1.0")
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            line = page.locator("#guardrail-body .guardrail-card .guardrail-egress")
            expect(line).to_contain_text("OpenShell enforces an allow-list of 2 endpoints, in the ASP",
                                         timeout=TIMEOUT)
            expect(line).not_to_contain_text("aren't visible")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_an_imported_openshell_policy_shows_on_the_egress_line_and_seeds_the_proposal(tmp_path):
    """DR-248: the import control on an agent OpenShell contains; a file
    that isn't a policy is refused with what was wrong; OpenShell 0.1.3's
    own `--policy-only` output then shows one row per endpoint and marks the
    hosts it seeds into the proposal."""
    from test_guardrail_egress import egress

    fixtures = Path(__file__).parent / "fixtures" / "openshell-0.1.3"
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER], egress_containment=egress("allow_list_enforced"))
    store.make_baseline(store.load_asp(json.dumps(value).encode())["asp_id"], "v1.0")
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            expect(card.locator(".guardrail-egress")).to_contain_text(
                "its contents aren't visible to datRail", timeout=TIMEOUT)
            section = card.locator(".guardrail-openshell")
            chooser = section.locator("input[type=file]")
            chooser.set_input_files(str(fixtures / "missing-sandbox.stderr.txt"))
            expect(section).to_contain_text("Not imported: not an OpenShell policy but OpenShell's error output",
                                            timeout=TIMEOUT)
            expect(section.locator(".guardrail-openshell-endpoints")).to_have_count(0)
            chooser.set_input_files(str(fixtures / "provider-pypi.policy-only.yaml"))
            rows = card.locator(".guardrail-openshell-endpoints li")
            expect(rows.first).to_be_visible(timeout=TIMEOUT)
            expect(card.locator(".guardrail-egress")).to_contain_text("the imported policy is below")
            expect(section).to_contain_text("OpenShell's policy, imported")
            expect(section).to_contain_text("declared by the operator")
            expect(rows.filter(has_text="api.github.com:443 · /usr/local")).to_contain_text(
                "api.github.com:443 · /usr/local/bin/python3.13 · read-only · enforce")
            expect(rows.filter(has_text="*.example.com")).to_contain_text("*.example.com:443,8443 · ")
            expect(rows.filter(has_text="*.example.com")).to_contain_text("read-write · audit")
            expect(rows.filter(has_text="uploads.github.com")).to_contain_text("2 rules · enforce")
            expect(rows.filter(has_text="raw.githubusercontent.com")).to_contain_text("any traffic (L4)")
            expect(rows.filter(has_text="pypi.org:443").first).to_contain_text("(provider fx_pypi)")
            seed = card.locator(".guardrail-openshell-seed")
            expect(seed).to_contain_text("Hosts it may call from OpenShell's policy (imported", timeout=TIMEOUT)
            expect(seed).to_contain_text("api.github.com (_provider_fx_pypi, github_api)")
            expect(card.locator(".guardrail-proposal .guardrail-policy")).to_contain_text("*.example.com")
            expect(section.get_by_role("button", name="Import a newer policy")).to_be_visible()
            # DR-257: the proposal seeds every host the policy names, so
            # nothing it allows is beyond it; a hostless endpoint is listed
            # as not comparable, never as covered.
            beyond = section.locator(".guardrail-openshell-beyond")
            expect(beyond).to_contain_text("OpenShell allows no host beyond the guardrail's allowed hosts.")
            chooser.set_input_files(str(fixtures / "allowed-ips.policy-only.yaml"))
            beyond_rows = beyond.locator(".guardrail-openshell-beyond-list li")
            expect(beyond_rows).to_have_count(1, timeout=TIMEOUT)
            expect(beyond_rows.first).to_contain_text(
                "any host in 10.30.0.0/24, 10.31.0.0/24:8080 · rule lab_subnet · "
                "can't be compared: allowed_ips only, no host")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_the_guardrail_downloads_as_an_openshell_policy(tmp_path):
    """DR-258 (DR-194 M4): with a version in force, the OpenShell section
    offers the download, which carries the base policy's static sections,
    audit endpoints and the apply/rollback steps; the panel says the same."""
    from test_guardrail_custody import baseline
    from test_guardrail_egress import egress

    fixtures = Path(__file__).parent / "fixtures" / "openshell-0.1.3"
    database = tmp_path / "raildash.db"
    store = Store(database)
    alignment, ref = baseline(store, asp(listeners=[DEMO_LISTENER], egress_containment=egress("allow_list_enforced")))
    store.import_openshell_policy(ref, (fixtures / "base.policy-only.yaml").read_bytes())
    store.adopt_guardrail(alignment["alignment_version_id"])
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(accept_downloads=True)
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            section = card.locator(".guardrail-openshell-export")
            button = section.get_by_role("button", name="Download as OpenShell policy")
            expect(button).to_be_visible(timeout=TIMEOUT)
            with page.expect_download() as download_info:
                button.click()
            download = download_info.value
            assert download.suggested_filename.startswith("openshell-policy-")
            text = Path(download.path()).read_text()
            assert text.startswith("# OpenShell policy exported by RailDash")
            assert "filesystem_policy:" in text and "network_policies:" in text
            assert "enforcement: enforce" not in text
            expect(section.locator(".asp-status-msg")).to_contain_text("Downloaded openshell-policy-")
            section.get_by_text("How to apply it, and roll it back").click()
            expect(section).to_contain_text("openshell policy set <sandbox> --policy")
            expect(section).to_contain_text("--rev <N> --base --output json | jq -e .policy")
            expect(section).not_to_contain_text("--dry-run")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_a_held_403_says_it_waits_for_openshells_log(tmp_path):
    """DR-261: a request answered 403 while the collector reports on the
    agent's sandbox isn't judged until OpenShell's log says whether it
    blocked it, and the section says so even before any denial."""
    from test_guardrail_custody import request, send
    from test_guardrail_egress import egress

    fixtures = Path(__file__).parent / "fixtures" / "openshell-0.1.3"
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER], egress_containment=egress("allow_list_enforced"))
    made = store.make_baseline(store.load_asp(json.dumps(value).encode())["asp_id"], "v1.0")
    store.adopt_guardrail(made["alignment_version"]["alignment_version_id"])
    store.record_openshell_policy("fixture-agent", (fixtures / "collector-policy.json").read_bytes())
    row = request("api.github.com")
    row["path"], row["status_code"] = "/markdown", 403
    send(store, row)
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            denials = card.locator(".guardrail-openshell-denials")
            expect(denials).to_contain_text("Blocked by OpenShell (last 24 h)", timeout=TIMEOUT)
            expect(denials).to_contain_text("1 request answered 403 since")
            expect(denials).to_contain_text("waits for OpenShell's log: one it blocked isn't judged")
            expect(denials.locator(".guardrail-openshell-denial-list")).to_have_count(0)
            expect(card).not_to_contain_text("api.github.com · uploads")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

def test_blocked_by_openshell_shows_the_collectors_denials(tmp_path):
    """DR-249: what `railmon openshell` posts (the policy and the first
    poll's denials of the recorded sandbox) shows under the Egress line."""
    from test_guardrail_egress import egress

    fixtures = Path(__file__).parent / "fixtures" / "openshell-0.1.3"
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER], egress_containment=egress("allow_list_enforced"))
    store.make_baseline(store.load_asp(json.dumps(value).encode())["asp_id"], "v1.0")
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        token = Path(f"{database}.token").read_text().strip()
        _post(url, "/v1/openshell/sandboxes/fixture-agent/policy", token,
              (fixtures / "collector-policy.json").read_bytes(), ok=(201,))
        body = json.loads((fixtures / "collector-denials.json").read_text())
        for denial in body["denials"]:
            denial["at"] = _now()
        body["partial"]["to"] = _now()
        _post(url, "/v1/openshell/sandboxes/fixture-agent/denials", token, json.dumps(body).encode(), ok=(201,))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            expect(card.locator(".guardrail-openshell")).to_contain_text(
                "OpenShell's policy revision 1, read by the collector", timeout=TIMEOUT)
            denials = card.locator(".guardrail-openshell-denials")
            expect(denials).to_contain_text("Blocked by OpenShell (last 24 h)")
            expect(denials).to_contain_text("Denials may be missing between the collector's start and")
            expect(denials).to_contain_text("(the collector started)")
            rows = denials.locator(".guardrail-openshell-denial-list li")
            expect(rows).to_have_count(3)
            expect(rows.filter(has_text="api.github.com:443")).to_contain_text("binary not logged · 1 time")
            expect(rows.filter(has_text="api.github.com:443")).to_contain_text("POST /markdown")
            expect(rows.filter(has_text="example.org:443")).to_contain_text(
                "/usr/local/bin/python3.13 · 1 time")
            expect(rows.filter(has_text="example.org:443")).to_contain_text(
                "tried an out-of-spec host; OpenShell blocked it")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_a_v4_versions_body_kind_members_read_in_words(tmp_path):
    """REST uploads M2: the active version's policy names the hosts the
    agent only queried, the body kinds the user set and a raised budget."""
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER])
    asp_id = store.load_asp(json.dumps(value).encode())["asp_id"]
    alignment = store.make_baseline(asp_id, "v1.0")["alignment_version"]
    rules = store.propose_guardrail(alignment["alignment_version_id"])["guardrail"]["rules"]
    rules["uploads"].update(
        parameters_only_hosts=["api.search.example"],
        body_kind_overrides=[{"host": "api.search.example", "method": "POST", "path": "/v1/query/*",
                              "kind": "parameters"}],
        parameters_budget={"agent": 2 * 1024 * 1024},
    )
    store.adopt_guardrail(alignment["alignment_version_id"], rules)
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            card.locator(".guardrail-active-policy > summary").click(timeout=TIMEOUT)
            policy = card.locator(".guardrail-active-policy")
            expect(policy).to_contain_text("Hosts it only queriedapi.search.example")
            expect(policy).to_contain_text("POST api.search.example/v1/query/*: parameters")
            expect(policy).to_contain_text("the agent 2.0 MB")
            if os.environ.get("RAILDASH_SHOT_DIR"):
                policy.screenshot(path=os.path.join(os.environ["RAILDASH_SHOT_DIR"], "v4-policy.png"))
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_an_upload_rows_bodies_say_why_and_this_is_parameters_clears_it(tmp_path):
    """REST uploads M2c: an `uploads` row lists each body's kind, method,
    path template and reasons, and **This is parameters** on an unknown body
    saves a version whose answer clears the row; a hard upload offers none."""
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER])
    asp_id = store.load_asp(json.dumps(value).encode())["asp_id"]
    alignment = store.make_baseline(asp_id, "v1.0")["alignment_version"]
    store.adopt_guardrail(alignment["alignment_version_id"])
    store.close()

    def rest_capture(url, token, host, path, body, content_type="application/json"):
        item = copy.deepcopy(capture()[0])
        item["timestamp"] = _now()
        item["interaction_id"] = f"{host}{path}"
        text = body if isinstance(body, str) else json.dumps(body)
        item["request"]["method"] = "POST"
        item["request"]["path"] = path
        item["request"]["body"] = body
        item["request"]["headers"].update({"host": host, "content-type": content_type,
                                           "content-length": str(len(text))})
        if host is None:
            del item["request"]["headers"]["host"]
            item["interaction_id"] = f"nohost{path}"
        _post(url, "/webhook/http-interactions", token,
              json.dumps({"session_id": "browser", "interactions": [item]}).encode())

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        token = (tmp_path / "raildash.db.token").read_text().strip()
        _heartbeat(url, token)
        rest_capture(url, token, "api.search.example", "/v1/search/12345",
                     {"filter": {"a": {"b": {"c": {"d": 1}}}}})
        rest_capture(url, token, "files.example", "/v1/files", "x" * 20000, "application/octet-stream")
        rest_capture(url, token, None, "/v1/deep", {"filter": {"a": {"b": {"c": {"d": 1}}}}})
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            search = card.locator("tr", has=page.locator("code", has_text="api.search.example")).filter(
                has=page.locator(".guardrail-bodies"))
            expect(search).to_contain_text("unknown · POST /v1/search/*", timeout=TIMEOUT)
            expect(search).to_contain_text("counts")
            files = card.locator("tr", has=page.locator("code", has_text="files.example")).filter(
                has=page.locator(".guardrail-bodies"))
            expect(files).to_contain_text("application/octet-stream body")
            expect(files.get_by_role("button", name="This is parameters")).to_have_count(0)
            # No host: nothing can key an answer, so none is offered.
            nohost = card.locator("tr", has=page.locator("code", has_text="(unknown host)")).filter(
                has=page.locator(".guardrail-bodies"))
            expect(nohost).to_contain_text("unknown · POST /v1/deep")
            expect(nohost.get_by_role("button", name="This is parameters")).to_have_count(0)
            if os.environ.get("RAILDASH_SHOT_DIR"):
                card.locator(".guardrail-rows").screenshot(
                    path=os.path.join(os.environ["RAILDASH_SHOT_DIR"], "body-kinds-rows.png"))
            search.get_by_role("button", name="This is parameters").click()
            expect(search).to_contain_text("you marked it parameters", timeout=TIMEOUT)
            expect(search).to_contain_text("allowed by g2", timeout=TIMEOUT)
            card.locator(".guardrail-active-policy > summary").click()
            expect(card.locator(".guardrail-active-policy")).to_contain_text(
                "POST api.search.example/v1/search/*: parameters")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_narrow_uploads_moves_a_host_only_sent_queries(tmp_path):
    """REST uploads M2c: an upload host the last 24 hours only sent
    parameters is offered as *Narrow uploads*; accepting it saves a version
    that lists the host as only queried, and the offer goes."""
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER])
    asp_id = store.load_asp(json.dumps(value).encode())["asp_id"]
    alignment = store.make_baseline(asp_id, "v1.0")["alignment_version"]
    rules = store.propose_guardrail(alignment["alignment_version_id"])["guardrail"]["rules"]
    rules["uploads"]["allowed_hosts"] = sorted({*rules["uploads"]["allowed_hosts"], "api.search.example"})
    rules["out_of_spec_calls"]["allowed_hosts"] = sorted(
        {*rules["out_of_spec_calls"]["allowed_hosts"], "api.search.example"})
    store.adopt_guardrail(alignment["alignment_version_id"], rules)
    store.close()

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        token = (tmp_path / "raildash.db.token").read_text().strip()
        _heartbeat(url, token)
        from datetime import datetime
        item = copy.deepcopy(capture()[0])
        item["timestamp"] = _now()
        # RailMon's timestamp_ns is wall-clock (epoch ms x 1e6).
        item["timestamp_ns"] = int(datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")).timestamp() * 1e9)
        item["interaction_id"] = "narrow-query"
        text = json.dumps({"q": "invoices 2026", "limit": 20})
        item["request"].update(method="POST", path="/v1/query", body=json.loads(text))
        item["request"]["headers"].update({"host": "api.search.example", "content-type": "application/json",
                                           "content-length": str(len(text))})
        _post(url, "/webhook/http-interactions", token,
              json.dumps({"session_id": "browser", "interactions": [item]}).encode())
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            card = page.locator("#guardrail-body .guardrail-card")
            offer = card.locator(".guardrail-narrow-uploads-offer")
            expect(offer).to_contain_text("api.search.example · 1 parameters body", timeout=TIMEOUT)
            if os.environ.get("RAILDASH_SHOT_DIR"):
                offer.screenshot(path=os.path.join(os.environ["RAILDASH_SHOT_DIR"], "narrow-uploads-offer.png"))
            offer.get_by_role("button", name="Narrow uploads").click()
            expect(card.locator(".guardrail-narrow-uploads-offer")).to_have_count(0, timeout=TIMEOUT)
            card.locator(".guardrail-active-policy > summary").click()
            policy = card.locator(".guardrail-active-policy")
            expect(policy).to_contain_text("g2")
            expect(policy).to_contain_text("Hosts it only queriedapi.search.example")
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_an_api_spec_is_imported_for_a_host_and_listed(tmp_path):
    """REST uploads M3: **Import an API spec** takes a host and a file; the
    panel lists the spec with how many operations take files or content,
    refuses a file that isn't a spec with why, and Remove drops it."""
    database = tmp_path / "raildash.db"
    store = Store(database)
    value = asp(listeners=[DEMO_LISTENER])
    asp_id = store.load_asp(json.dumps(value).encode())["asp_id"]
    alignment = store.make_baseline(asp_id, "v1.0")["alignment_version"]
    store.adopt_guardrail(alignment["alignment_version_id"])
    store.close()
    spec_file = Path(__file__).parent / "fixtures" / "openapi" / "github-excerpt.json"
    bad_file = tmp_path / "swagger.json"
    bad_file.write_text('{"swagger": "2.0", "paths": {}}')

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "raildash.cli", "--db", str(database),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_until_ready(url, process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            section = page.locator("#guardrail-body .guardrail-api-specs")
            expect(section).to_contain_text("API specs", timeout=TIMEOUT)
            section.get_by_label("Host the spec is for").fill("api.github.com")
            with page.expect_file_chooser() as chooser:
                section.get_by_role("button", name="Import an API spec").click()
            chooser.value.set_files(str(bad_file))
            expect(section).to_contain_text("Not imported: a Swagger 2.0 spec", timeout=TIMEOUT)
            with page.expect_file_chooser() as chooser:
                section.get_by_role("button", name="Import an API spec").click()
            chooser.value.set_files(str(spec_file))
            expect(section.locator(".guardrail-api-spec-list")).to_contain_text(
                "api.github.com GitHub v3 REST API 1.1.4 · 7 operations, 2 take files or content", timeout=TIMEOUT)
            if os.environ.get("RAILDASH_SHOT_DIR"):
                section.screenshot(path=os.path.join(os.environ["RAILDASH_SHOT_DIR"], "api-specs.png"))
            section.get_by_role("button", name="Remove").click()
            expect(section.locator(".guardrail-api-spec-list")).to_have_count(0, timeout=TIMEOUT)
            assert errors == []
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
