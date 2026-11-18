"""RailDash refuses a request whose Host names another site (DR-317).

A page on another site can rebind its own name to 127.0.0.1 and read the write
token from `/` as same-origin; the browser still sends that name as `Host`.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from raildash import app as app_module
from raildash.app import ALLOWED_HOSTS_ENV_VAR, host_allowed

client = TestClient(app_module.app)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.0.0.1:8000",
        "[::1]:8000",
        "::1",
        "10.0.0.5:8000",
        "localhost",
        "LOCALHOST:8000",
        "localhost.",
        "app.localhost:8000",
        "raildash:8000",
        None,
    ],
)
def test_this_machine_and_the_compose_service_are_allowed(host):
    assert host_allowed(host, environ={})


@pytest.mark.parametrize(
    "host",
    ["attacker.example", "attacker.example:8000", "raildash.attacker.example", "localhost.attacker.example", ""],
)
def test_other_names_are_refused(host):
    assert not host_allowed(host, environ={})


def test_the_operator_can_add_names_or_turn_the_check_off():
    assert host_allowed("dash.lan:8000", environ={ALLOWED_HOSTS_ENV_VAR: "box, Dash.LAN"})
    assert not host_allowed("other.lan", environ={ALLOWED_HOSTS_ENV_VAR: "box, dash.lan"})
    assert host_allowed("anything.example", environ={ALLOWED_HOSTS_ENV_VAR: "*"})


def test_a_rebound_page_cannot_read_the_token():
    response = client.get("/", headers={"Host": "attacker.example:8000"})
    assert response.status_code == 400
    assert app_module.LOCAL_TOKEN not in response.text
    assert ALLOWED_HOSTS_ENV_VAR in response.text


def test_a_rebound_page_cannot_call_a_gated_route_even_with_the_token():
    response = client.post(
        "/webhook/heartbeat",
        json={},
        headers={"Host": "attacker.example", "X-RailDash-Token": app_module.LOCAL_TOKEN},
    )
    assert response.status_code == 400


def test_two_host_headers_are_refused():
    response = client.get("/", headers=[("Host", "127.0.0.1"), ("Host", "attacker.example")])
    assert response.status_code == 400


def test_loopback_and_the_service_name_still_get_the_page():
    for host in ("127.0.0.1:8000", "localhost:8000", "raildash:8000"):
        response = client.get("/", headers={"Host": host})
        assert response.status_code == 200
        assert app_module.LOCAL_TOKEN in response.text
