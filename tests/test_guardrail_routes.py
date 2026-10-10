"""HTTP routes for the Data Guardrail (DR-184 M2).

The custody itself is tested in `test_guardrail_custody.py`; this is the
HTTP contract on top: the local-token gate on every write and on the detail
that names hosts and paths, the status codes, and the whole path end to end
through the same routes RailMon and the dashboard use -- an ASP posted to
`/v1/evidence-bundles`, captures posted to `/webhook/http-interactions`
with and without the token, and a heartbeat.
"""

from __future__ import annotations

import copy
import json

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.store import Store
from test_guardrail import DEMO_LISTENER, PORT_9000, capture, declared
from test_guardrail_custody import _now, asp

@pytest.fixture()
def client(tmp_path, monkeypatch):
    store = Store(tmp_path / "routes.db")
    monkeypatch.setattr(app_module, "store", store)
    yield TestClient(app_module.app)
    store.close()


def auth():
    return {"X-RailDash-Token": app_module.LOCAL_TOKEN}


def post_asp(client, value: dict) -> str:
    res = client.post("/v1/evidence-bundles", content=json.dumps(value).encode(), headers=auth())
    assert res.status_code == 202, res.text
    return res.json()["asp_id"]


def post_capture(client, host: str, *, token: bool = True) -> None:
    item = copy.deepcopy(capture()[0])
    item["timestamp"] = _now()
    item["interaction_id"] = f"route-{host}-{token}"
    item["request"]["headers"]["host"] = host
    res = client.post(
        "/webhook/http-interactions",
        json={"session_id": "s1", "interactions": [item]},
        headers=auth() if token else {},
    )
    assert res.status_code == 200, res.text


def heartbeat(client) -> None:
    res = client.post("/webhook/heartbeat", headers=auth(),
                      json={"collector_id": "c1", "taps_attached": 1, "sent_at": _now()})
    assert res.status_code == 200


def adopted(client) -> tuple[str, dict]:
    asp_id = post_asp(client, asp())
    res = client.post(f"/api/asps/{asp_id}/baseline", json={"version": "v1.0"}, headers=auth())
    alignment_id = res.json()["alignment_version"]["alignment_version_id"]
    [agent] = client.get("/api/guardrails").json()
    assert agent["state"] == "no_guardrail"
    res = client.post(f"/api/alignments/{alignment_id}/guardrail", json={}, headers=auth())
    assert res.status_code == 201, res.text
    return agent["agent_ref"], res.json()


def detail(client, ref: str) -> dict:
    res = client.get(f"/api/guardrails/{ref}", headers=auth())
    assert res.status_code == 200, res.text
    return res.json()


def by_item(body: dict) -> dict:
    return {(row["rule"], row["item"]): row for row in body["rows"]}


# --------------------------------------------------------------- the gate


WRITES = [
    ("/api/alignments/aspver-x/guardrail", {}),
    ("/api/guardrail-versions/grd-x/edit", {"rules": {}}),
    ("/api/guardrail-versions/grd-x/switch", None),
    ("/api/guardrails/agt-x/turn-off", None),
    ("/api/guardrail-rows/1/acknowledge", None),
    ("/api/guardrail-rows/1/allow", None),
    ("/api/guardrails/agt-x/offers/allow", {"kind": "host", "value": "a.example"}),
    ("/api/guardrails/agt-x/offers/dismiss", {"kind": "host", "value": "a.example"}),
]


@pytest.mark.parametrize(("path", "body"), WRITES)
def test_every_guardrail_write_needs_the_local_token(client, path, body):
    assert client.post(path, json=body).status_code == 403
    assert client.post(path, json=body, headers={"X-RailDash-Token": "wrong"}).status_code == 403


@pytest.mark.parametrize(("path", "body"), WRITES)
def test_an_unknown_id_is_404(client, path, body):
    assert client.post(path, json=body, headers=auth()).status_code == 404


def test_the_detail_needs_the_token_and_the_list_names_no_items(client):
    ref, _ = adopted(client)
    assert client.get(f"/api/guardrails/{ref}").status_code == 403
    [agent] = client.get("/api/guardrails").json()
    assert agent["state"] == "violated" and agent["counting_rows"] == 1
    assert "8443" not in json.dumps(agent)
    assert client.get("/api/guardrails/agt-nobody", headers=auth()).status_code == 404


# -------------------------------------------------------------- end to end


def test_the_guardrail_end_to_end_over_http(client):
    ref, g1 = adopted(client)
    body = detail(client, ref)
    assert body["state"] == "violated"
    listener = by_item(body)[("service_ports", "tcp/127.0.0.1/8443")]

    res = client.post(f"/api/guardrail-rows/{listener['row_id']}/allow", headers=auth())
    assert res.status_code == 201 and res.json()["guardrail"]["version"] == "g2"
    heartbeat(client)
    assert detail(client, ref)["state"] == "held"

    # A forged capture without the token changes nothing; the collector's does.
    post_capture(client, "exfil.attacker.net", token=False)
    assert detail(client, ref)["state"] == "held"
    post_capture(client, "exfil.attacker.net")
    body = detail(client, ref)
    assert body["state"] == "violated"
    upload = by_item(body)[("uploads", "exfil.attacker.net")]
    assert upload["evidence_class"] == "observed" and upload["counts"]

    res = client.post(f"/api/guardrail-rows/{upload['row_id']}/acknowledge", headers=auth())
    assert res.status_code == 200 and res.json()["acknowledged"]
    out_of_spec = by_item(detail(client, ref))[("out_of_spec_calls", "exfil.attacker.net")]
    client.post(f"/api/guardrail-rows/{out_of_spec['row_id']}/acknowledge", headers=auth())
    assert detail(client, ref)["state"] == "held"

    # A new listener on the next scan.
    post_asp(client, asp(listeners=[DEMO_LISTENER, PORT_9000]))
    assert detail(client, ref)["state"] == "violated"

    res = client.post(f"/api/guardrail-versions/{g1['guardrail']['guardrail_version_id']}/switch",
                      headers=auth())
    assert res.status_code == 200 and res.json()["guardrail"]["version"] == "g1"
    assert [e["action"] for e in detail(client, ref)["events"]][:2] == ["switch", "acknowledge"]

    assert client.post(f"/api/guardrails/{ref}/turn-off", headers=auth()).status_code == 200
    assert detail(client, ref)["state"] == "no_guardrail"
    assert client.post(f"/api/guardrails/{ref}/turn-off", headers=auth()).status_code == 409


def test_edit_rejects_rules_the_contract_refuses_and_only_edits_the_active_version(client):
    ref, g1 = adopted(client)
    version_id = g1["guardrail"]["guardrail_version_id"]
    rules = copy.deepcopy(g1["guardrail"]["rules"])
    rules["uploads"]["blocked"] = True
    res = client.post(f"/api/guardrail-versions/{version_id}/edit", json={"rules": rules},
                      headers=auth())
    assert res.status_code == 422
    assert client.post(f"/api/guardrail-versions/{version_id}/edit", json={},
                       headers=auth()).status_code == 422
    del rules["uploads"]["blocked"]
    rules["service_ports"]["allowed"] = [{"protocol": "tcp", "port": 8443}]
    res = client.post(f"/api/guardrail-versions/{version_id}/edit", json={"rules": rules},
                      headers=auth())
    assert res.status_code == 201 and res.json()["guardrail"]["version"] == "g2"
    assert client.post(f"/api/guardrail-versions/{version_id}/edit", json={"rules": rules},
                       headers=auth()).status_code == 409
    adopt_again = client.post(
        f"/api/alignments/{g1['guardrail']['derived_from']['alignment_version_id']}/guardrail",
        json={}, headers=auth(),
    )
    assert adopt_again.status_code == 409


def test_offers_over_http(client):
    ref, _ = adopted(client)
    post_asp(client, asp(declared_destinations=declared(["docs.example", "attacker.example"])))
    assert detail(client, ref)["offers"] == [{"kind": "host", "value": "attacker.example"},
                                             {"kind": "host", "value": "docs.example"}]
    res = client.post(f"/api/guardrails/{ref}/offers/dismiss", headers=auth(),
                      json={"kind": "host", "value": "attacker.example"})
    assert res.status_code == 201
    res = client.post(f"/api/guardrails/{ref}/offers/allow", headers=auth(),
                      json={"kind": "host", "value": "docs.example"})
    assert res.status_code == 201
    assert "docs.example" in res.json()["guardrail"]["rules"]["out_of_spec_calls"]["allowed_hosts"]
    assert detail(client, ref)["offers"] == []
    again = client.post(f"/api/guardrails/{ref}/offers/allow", headers=auth(),
                        json={"kind": "host", "value": "attacker.example"})
    assert again.status_code == 409
    assert client.post(f"/api/guardrails/{ref}/offers/allow", headers=auth(),
                       json={"kind": 1}).status_code == 422


def test_a_capture_sent_through_the_webhook_is_judged_by_the_request_hook(client):
    ref, _ = adopted(client)
    post_capture(client, "api.anthropic.com")
    found = set(by_item(detail(client, ref)))
    # This baseline declares no hosts and no inference endpoint, and nothing
    # was captured before the lock, so the proposal listed no host at all.
    assert {("out_of_spec_calls", "api.anthropic.com"), ("uploads", "api.anthropic.com")} <= found
