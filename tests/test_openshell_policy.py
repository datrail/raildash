"""DR-248 (DR-194 M2): an OpenShell sandbox's policy, imported beside the ASP.

The fixtures under `fixtures/openshell-0.1.3/` are OpenShell 0.1.3's own
output (that directory's README says how they were recorded). The proposal
cases use `test_guardrail`'s real capture and `test_guardrail_egress`'s
OpenShell egress value.
"""

from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path

import pytest

from raildash import guardrail as g
from raildash import openshell_policy as osp
from raildash.store import Store
from test_guardrail import DECLARED, _lock, _propose, stored_requests, v1_bundle
from test_guardrail_custody import asp, baseline
from test_guardrail_egress import egress

FIXTURES = Path(__file__).parent / "fixtures" / "openshell-0.1.3"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def endpoints(name: str) -> dict[tuple[str, str | None], dict]:
    return {(e["rule"], e["host"]): e for e in osp.parse_policy(fixture(name))["endpoints"]}


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "openshell.db")
    yield db
    db.close()


# ------------------------------------------------------------------ parsing


def test_the_policy_only_yaml_reads_as_one_row_per_endpoint():
    record = osp.parse_policy(fixture("base.policy-only.yaml"))
    assert record["format"] == "yaml"
    # The YAML carries no revision and doesn't say where the policy came from.
    assert (record["revision"], record["policy_source"], record["sandbox"]) == (None, None, None)
    binary = ["/usr/local/bin/python3.13"]
    assert record["endpoints"] == [
        {"rule": "example_wildcard", "rule_name": "example-wildcard", "provider": None,
         "host": "*.example.com", "ports": [443, 8443], "path": None, "protocol": "rest",
         "enforcement": "audit", "access": "read-write", "rules": [], "deny_rules": 0,
         "allowed_ips": [], "binaries": binary, "body_allowed": True},
        {"rule": "github_api", "rule_name": "github-api-readonly", "provider": None,
         "host": "api.github.com", "ports": [443], "path": None, "protocol": "rest",
         "enforcement": "enforce", "access": "read-only", "rules": [], "deny_rules": 0,
         "allowed_ips": [], "binaries": binary, "body_allowed": False},
        {"rule": "github_uploads", "rule_name": "github-uploads", "provider": None,
         "host": "uploads.github.com", "ports": [443], "path": None, "protocol": "rest",
         "enforcement": "enforce", "access": None,
         "rules": ["GET /repos/**", "POST /repos/*/*/releases/*/assets"], "deny_rules": 0,
         "allowed_ips": [], "binaries": binary, "body_allowed": True},
        {"rule": "raw_content", "rule_name": "raw-content", "provider": None,
         "host": "raw.githubusercontent.com", "ports": [443], "path": None, "protocol": None,
         "enforcement": None, "access": None, "rules": [], "deny_rules": 0,
         "allowed_ips": [], "binaries": [*binary, "/usr/bin/curl"], "body_allowed": True},
    ]


def test_the_json_views_carry_the_revision_and_read_as_the_same_policy():
    yaml_record = osp.parse_policy(fixture("base.policy-only.yaml"))
    full = osp.parse_policy(fixture("base.policy-full.json"))
    sandbox = osp.parse_policy(fixture("base.sandbox-get.json"))
    assert (full["format"], full["revision"], full["policy_source"]) == ("json", 1, "sandbox")
    assert (sandbox["revision"], sandbox["policy_source"], sandbox["sandbox"]) == (1, "sandbox", "fx-base")
    assert full["endpoints"] == sandbox["endpoints"] == yaml_record["endpoints"]
    assert full["digest"] == sandbox["digest"] == yaml_record["digest"]
    newer = osp.parse_policy(fixture("base.policy-only-rev2.yaml"))
    assert newer["digest"] != yaml_record["digest"]
    assert [e["host"] for e in newer["endpoints"] if e["host"] not in
            {e["host"] for e in yaml_record["endpoints"]}] == ["api.openai.com"]


def test_a_global_policy_says_so_only_in_its_json_views():
    assert osp.parse_policy(fixture("global.policy-only.yaml"))["policy_source"] is None
    sandbox = osp.parse_policy(fixture("global.sandbox-get.json"))
    assert (sandbox["revision"], sandbox["policy_source"]) == (2, "global")
    stored = osp.parse_policy(fixture("global.policy-get-global.json"))
    assert (stored["revision"], stored["policy_source"]) == (1, "global")
    assert [e["host"] for e in stored["endpoints"]] == ["pypi.org", "files.pythonhosted.org"]
    assert stored["endpoints"][0]["binaries"] == ["/usr/local/bin/python3.13", "/usr/local/bin/pip*"]


def test_provider_rules_are_labelled_with_their_provider():
    pypi = endpoints("provider-pypi.policy-only.yaml")
    rule = pypi[("_provider_fx_pypi", "pypi.org")]
    assert rule["provider"] == "fx_pypi"
    # The pypi profile's endpoints are L4: no protocol, no enforcement.
    assert (rule["protocol"], rule["enforcement"], rule["body_allowed"]) == (None, None, True)
    assert pypi[("github_api", "api.github.com")]["provider"] is None
    github = osp.parse_policy(fixture("provider-github.policy-only.yaml"))["endpoints"]
    mine = [e for e in github if e["provider"] == "fx_github"]
    assert [(e["host"], e["path"], e["protocol"], e["access"], e["body_allowed"]) for e in mine] == [
        ("api.github.com", None, "rest", "read-only", False),
        # A read-only GraphQL query is still a POST with a body.
        ("api.github.com", "/graphql", "graphql", "read-only", True),
        # Its rules allow POST to git-upload-pack.
        ("github.com", None, "rest", None, True),
    ]
    assert mine[2]["rules"] == ["GET **", "HEAD **", "OPTIONS **", "POST /**/git-upload-pack"]


def test_an_mcp_endpoint_lists_its_rules_by_method_and_tool():
    [endpoint] = osp.parse_policy(fixture("mcp.policy-only.yaml"))["endpoints"]
    assert (endpoint["host"], endpoint["path"], endpoint["protocol"]) == ("mcp.example.com", "/mcp", "mcp")
    assert endpoint["rules"] == ["initialize", "notifications/initialized", "tools/list",
                                 "tools/call search_docs", "tools/call read_page"]
    assert endpoint["body_allowed"] is True
    assert osp.endpoint_label(endpoint) == "mcp.example.com:443"


def test_allowed_ips_with_and_without_a_host():
    found = endpoints("allowed-ips.policy-only.yaml")
    limited = found[("internal_api", "api.corp.example.com")]
    assert limited["allowed_ips"] == ["10.20.0.0/16"]
    assert osp.not_representable(limited) is None
    hostless = found[("lab_subnet", None)]
    assert hostless["allowed_ips"] == ["10.30.0.0/24", "10.31.0.0/24"]
    assert osp.endpoint_label(hostless) == "any host in 10.30.0.0/24, 10.31.0.0/24:8080"
    assert osp.not_representable(hostless) == osp.NOT_REPRESENTABLE_HOSTLESS


@pytest.mark.parametrize(("raw", "message"), [
    # `--policy-only` for a sandbox that doesn't exist prints nothing on stdout.
    (b"", "the file is empty"),
    (b"  \n", "the file is empty"),
    # ... and this on stderr, which a user saving with 2>&1 uploads.
    (fixture("missing-sandbox.stderr.txt"), "OpenShell's error output: .*sandbox not found"),
    (b"version: 1\nnetwork_policies:\n  a:\n    endpoints: [ {host: x", "not valid YAML"),
    (b'{"policy": ', "not valid JSON"),
    (b"\xff\xfe", "not UTF-8"),
    (b"- a\n- b\n", "not an OpenShell policy"),
    (b"name: something else\n", "no `version` or `network_policies`"),
    (b"version: 2\nnetwork_policies: {}\n", "policy version 2"),
    (b"version: 1\nnetwork_policies: [a, b]\n", "not a mapping of rules"),
    (b"version: 1\nnetwork_policies:\n  a: {endpoints: [{port: 443}]}\n", "neither a host nor allowed_ips"),
    (b"version: 1\nnetwork_policies:\n  a: {endpoints: [{host: x.example, port: '443'}]}\n", "not a TCP port"),
    (b"version: 1\nnetwork_policies:\n  a: {endpoints: [{host: x.example, port: 70000}]}\n", "not a TCP port"),
    (b"version: 1\nnetwork_policies:\n  a: {endpoints: {host: x.example}}\n", "not a list"),
    (b"version: 1\nnetwork_policies:\n  a: {binaries: [{name: x}]}\n", "no path"),
    (b"version: 1\nnetwork_policies:\n  a: {endpoints: [{host: x.example, rules: [{deny: {}}]}]}\n", "no allow"),
    (b"version: 1\nnetwork_policies:\n  a: {}\n  a: {}\n", "duplicate key"),
    (b"version: 1\nx: &a [1]\ny: *a\n", "aliases are not accepted"),
    (b"version: 1\n# " + b"x" * osp.MAX_POLICY_BYTES, "over 256 KiB"),
    # A JSON view without its policy body (`policy get` without --full)
    # carries a top-level `version` too, and is still no policy.
    (b'{"active_version": 1, "version": 1, "hash": "ab"}', "JSON view with no `policy`"),
    (b'{"version": 1, "policy": null}', "JSON view with no `policy`"),
    (b'{"version": 1, "network_policies": {}, "network_policies": {}}', "duplicate key"),
    (b"version: true\nnetwork_policies: {}\n", "policy version True"),
    (b"version: 1\n? [a, b]\n: c\n", "mapping key must be a scalar"),
    (b"version: 1\nx: " + b"[" * 50_000, "nested too deeply|not valid YAML"),
    (b'{"policy": ' + b"[" * 50_000, "nested too deeply|not valid JSON"),
])
def test_a_file_that_isnt_a_policy_is_an_error_never_an_empty_list(raw, message):
    with pytest.raises(osp.PolicyImportError, match=message):
        osp.parse_policy(raw)


def test_a_policy_with_no_network_rules_is_one_with_no_endpoints():
    # Not a failure: OpenShell's deny-by-default with nothing allowed.
    assert osp.parse_policy(b"version: 1\nfilesystem_policy: {read_only: [/usr]}\n")["endpoints"] == []


SECRET = "s3cr3t-must-not-be-stored"
WITH_CREDENTIALS = f"""
version: 1
network_policies:
  signed:
    name: signed
    endpoints:
      - host: bedrock.us-east-1.amazonaws.com
        port: 443
        protocol: rest
        access: read-write
        credential_signing: aws-sigv4
        signing_service: bedrock
        signing_region: us-east-1
        credential_binding: {{provider: {SECRET}}}
        password: {SECRET}
        rules:
          - allow: {{method: POST, path: /model/*, query: {{token: {SECRET}}}}}
    binaries: [{{path: /usr/bin/agent}}]
network_middlewares:
  audit_hook:
    name: audit-hook
    middleware: webhook
    config: {{url: https://hooks.example, token: {SECRET}}}
""".encode()


def test_credential_fields_never_reach_storage(store):
    """§5: only an allow-list of endpoint fields is kept. A middleware's
    config, signing settings, a credential binding, a rule's query values
    and any field this RailDash doesn't know are dropped before storage."""
    record = osp.parse_policy(WITH_CREDENTIALS)
    assert SECRET not in json.dumps(record)
    assert record["endpoints"][0]["rules"] == ["POST /model/*"]
    _, ref = baseline(store, asp(egress_containment=egress()))
    store.import_openshell_policy(ref, WITH_CREDENTIALS)
    dump = "\n".join(store._db.iterdump())  # noqa: SLF001
    assert "bedrock.us-east-1.amazonaws.com" in dump
    assert SECRET not in dump


# -------------------------------------------------------------------- store


def test_the_newest_import_is_the_agents_policy_and_shows_its_age(store):
    _, ref = baseline(store, asp(egress_containment=egress()))
    assert store.guardrail_detail(ref)["openshell_policy"] is None
    first = store.import_openshell_policy(ref, fixture("base.policy-only.yaml"))
    assert (first["agent_ref"], first["source"], first["stale"], first["revision"]) == (ref, "import", False, None)
    store.import_openshell_policy(ref, fixture("base.policy-full.json"))
    shown = store.guardrail_detail(ref)["openshell_policy"]
    assert shown["revision"] == 1 and shown["stale"] is False
    assert len(shown["endpoints"]) == 4
    # Past DR-184's longest stale window (two hours) the line dates it ("as of").
    store._db.execute(  # noqa: SLF001
        "UPDATE openshell_policies SET imported_at = '2020-01-01T00:00:00.000000Z'")
    assert store.guardrail_detail(ref)["openshell_policy"]["stale"] is True
    events = [e for e in store.guardrail_detail(ref)["events"] if e["action"] == "import_openshell_policy"]
    assert [e["detail"]["revision"] for e in events] == [1, None]


def test_a_failed_import_stores_nothing_and_keeps_the_policy_held(store):
    _, ref = baseline(store, asp(egress_containment=egress()))
    store.import_openshell_policy(ref, fixture("mcp.policy-only.yaml"))
    with pytest.raises(osp.PolicyImportError):
        store.import_openshell_policy(ref, fixture("missing-sandbox.stderr.txt"))
    assert store.guardrail_detail(ref)["openshell_policy"]["endpoints"][0]["host"] == "mcp.example.com"
    assert store._db.execute("SELECT count(*) FROM openshell_policies").fetchone()[0] == 1  # noqa: SLF001
    with pytest.raises(KeyError):
        store.import_openshell_policy("agt-nobody", fixture("mcp.policy-only.yaml"))


def test_an_import_changes_no_asp_baseline_or_guardrail_version(store):
    alignment, ref = baseline(store, asp(egress_containment=egress()))
    store.adopt_guardrail(alignment["alignment_version_id"])

    def snapshot():
        return [store._db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()  # noqa: SLF001
                for table in ("asps", "alignment_versions", "guardrail_versions", "guardrail_bindings")]

    before = [[tuple(row) for row in rows] for rows in snapshot()]
    store.import_openshell_policy(ref, fixture("provider-github.policy-only.yaml"))
    assert [[tuple(row) for row in rows] for rows in snapshot()] == before


def test_the_route_is_token_gated_and_refuses_a_file_that_isnt_a_policy(store, monkeypatch):
    from fastapi.testclient import TestClient

    from raildash import app as app_module

    _, ref = baseline(store, asp(egress_containment=egress()))
    monkeypatch.setattr(app_module, "store", store)
    client = TestClient(app_module.app)
    path = f"/api/guardrails/{ref}/openshell-policy"
    body = fixture("base.policy-only.yaml")
    assert client.post(path, content=body).status_code == 403
    headers = {"X-RailDash-Token": app_module.LOCAL_TOKEN}
    answer = client.post(path, content=body, headers=headers)
    assert answer.status_code == 201, answer.text
    assert [e["host"] for e in answer.json()["endpoints"]][:2] == ["*.example.com", "api.github.com"]
    refused = client.post(path, content=fixture("missing-sandbox.stderr.txt"), headers=headers)
    assert refused.status_code == 422
    assert "OpenShell's error output" in refused.json()["detail"]
    assert client.post(path, content=b"", headers=headers).status_code == 422
    assert client.post(path, content=b"#" * (osp.MAX_POLICY_BYTES + 1), headers=headers).status_code == 413
    assert client.post("/api/guardrails/agt-nobody/openshell-policy", content=body,
                       headers=headers).status_code == 404
    assert store._db.execute("SELECT count(*) FROM openshell_policies").fetchone()[0] == 1  # noqa: SLF001


# ----------------------------------------------------------------- proposal


SEED_POLICY = b"""
version: 1
network_policies:
  openai:
    endpoints: [{host: api.openai.com, port: 443, protocol: rest, access: read-write}]
  anthropic:
    endpoints: [{host: api.anthropic.com, port: 443, protocol: rest, enforcement: enforce, access: read-only}]
  registry:
    endpoints: [{host: registry.npmjs.org, port: 443}]
  content:
    endpoints:
      - {host: "*.githubusercontent.com", port: 443, protocol: rest, access: read-write}
      - {host: "*-api.example.com", port: 443}
  lab:
    endpoints: [{port: 8080, allowed_ips: [10.30.0.0/24]}]
"""


def _seeded(store, egress_value, policy=SEED_POLICY):
    alignment, bundle = _lock(store, v1_bundle(**DECLARED, egress_containment=egress_value))
    record = {**osp.parse_policy(policy), "imported_at": "2026-09-24T00:01:00Z", "source": "import"}
    return g.propose_guardrail(alignment, bundle, stored_requests(store), guardrail_version_id="grd-1",
                               version="g1", created_at="2026-09-24T00:02:00Z", openshell_policy=record)


def test_a_proposal_for_an_agent_openshell_contains_seeds_from_its_policy(store):
    """§4.4, golden: the policy's hosts join out_of_spec_calls.allowed_hosts
    (the wildcard kept, the forms DR-184 can't write listed instead), and
    api.anthropic.com, which the agent sent a body to but the policy allows
    only reads to, stays out of uploads and is a would-be violation."""
    proposal = _seeded(store, egress())
    rules = proposal["guardrail"]["rules"]
    assert g.guardrail_problems(proposal["guardrail"]) == []
    assert rules["out_of_spec_calls"]["allowed_hosts"] == [
        "*.githubusercontent.com", "api.anthropic.com", "api.openai.com", "mcp.example.com",
        "registry.npmjs.org"]
    # The declared seed is still only what the agent declared.
    assert rules["out_of_spec_calls"]["seeded_from_declared"]["hosts"] == ["api.openai.com", "mcp.example.com"]
    assert rules["uploads"]["allowed_hosts"] == ["api.openai.com", "host.openshell.internal"]
    assert proposal["openshell"] == {
        "revision": None,
        "digest": osp.parse_policy(SEED_POLICY)["digest"],
        "imported_at": "2026-09-24T00:01:00Z",
        "policy_source": None,
        "hosts": [{"host": "*.githubusercontent.com", "rules": ["content"]},
                  {"host": "api.anthropic.com", "rules": ["anthropic"]},
                  {"host": "api.openai.com", "rules": ["openai"]},
                  {"host": "registry.npmjs.org", "rules": ["registry"]}],
        "upload_hosts": ["api.openai.com"],
        "withheld_upload_hosts": ["api.anthropic.com"],
        "not_representable": [
            {"rule": "content", "endpoint": "*-api.example.com:443", "reason": osp.NOT_REPRESENTABLE_WILDCARD},
            {"rule": "lab", "endpoint": "any host in 10.30.0.0/24:8080", "reason": osp.NOT_REPRESENTABLE_HOSTLESS},
        ],
    }
    assert [(v["rule"], v["item"]) for v in proposal["would_be_violations"]] == [
        ("service_ports", "tcp/127.0.0.1/8443"),
        ("uploads", "api.anthropic.com"),
        ("out_of_spec_calls", "host.openshell.internal"),
        ("out_of_spec_calls", "exfil.attacker.net"),
        ("out_of_spec_calls", "(unknown host)"),
    ]
    assert proposal["empty_because"] == {}


def test_only_an_agent_openshell_contains_is_seeded(tmp_path):
    # For an agent nothing contains, or one contained otherwise, the
    # proposal with a policy held is exactly the one DR-184 makes without.
    record = {**osp.parse_policy(SEED_POLICY), "imported_at": "2026-09-24T00:01:00Z", "source": "import"}
    for level in ("open", "no_network"):
        with closing(Store(tmp_path / f"{level}.db")) as db:
            alignment, bundle = _lock(db, v1_bundle(**DECLARED, egress_containment=egress(level)))
            requests = stored_requests(db)
            plain = _propose(alignment, bundle, requests)
            seeded = g.propose_guardrail(alignment, bundle, requests, guardrail_version_id="grd-1", version="g1",
                                         created_at="2026-09-24T00:02:00Z", openshell_policy=record)
        assert seeded == plain, level
        assert "openshell" not in seeded


def test_the_stored_policy_seeds_the_panels_proposal(store):
    _, ref = baseline(store, asp(egress_containment=egress()))
    assert "openshell" not in store.guardrail_detail(ref)["proposal"]
    store.import_openshell_policy(ref, fixture("base.sandbox-get.json"))
    proposal = store.guardrail_detail(ref)["proposal"]
    assert proposal["openshell"]["revision"] == 1
    assert proposal["openshell"]["policy_source"] == "sandbox"
    assert {"*.example.com", "api.github.com", "raw.githubusercontent.com", "uploads.github.com"} <= set(
        proposal["guardrail"]["rules"]["out_of_spec_calls"]["allowed_hosts"])
    assert g.guardrail_problems(proposal["guardrail"]) == []


def test_an_inference_host_the_policy_allows_no_body_is_withheld_too(store):
    # The base URL's host is seeded into uploads like a body the agent sent;
    # the policy's refusal applies to it alike, so it is never both.
    policy = SEED_POLICY.replace(b"access: read-write}]\n  anthropic", b"access: read-only}]\n  anthropic")
    proposal = _seeded(store, egress(), policy)
    assert "api.openai.com" not in proposal["guardrail"]["rules"]["uploads"]["allowed_hosts"]
    assert proposal["openshell"]["withheld_upload_hosts"] == ["api.anthropic.com", "api.openai.com"]
    assert proposal["openshell"]["upload_hosts"] == []


# ------------------------------------------ beyond the guardrail (DR-257)


@pytest.mark.parametrize(("pattern", "allowed", "covered"), [
    ("api.github.com", ["api.github.com"], True),
    ("api.github.com", ["*.github.com"], True),
    ("github.com", ["*.github.com"], False),  # a wildcard never matches its own base
    ("*.github.com", ["api.github.com"], False),
    ("*.github.com", ["*.github.com"], True),
    ("*.api.github.com", ["*.github.com"], True),
    ("*.github.com", ["*.api.github.com"], False),
    ("*.xgithub.com", ["*.github.com"], False),
    ("api.github.com", [], False),
])
def test_a_policy_host_is_covered_only_by_a_pattern_at_or_above_it(pattern, allowed, covered):
    assert osp.pattern_covered(pattern, allowed) is covered


def test_beyond_the_guardrail_lists_what_the_policy_allows_and_the_hosts_dont(store):
    """Design §4.5's comparison, golden: one row per uncovered endpoint, as
    host:port with its rule; the endpoints that can't be compared are
    listed with why, never read as covered."""
    record = osp.parse_policy(SEED_POLICY)
    assert osp.beyond_guardrail(record, ["api.openai.com", "*.example.com", "*.githubusercontent.com"]) == [
        {"endpoint": "api.anthropic.com:443", "rule": "anthropic", "provider": None, "reason": None},
        {"endpoint": "*-api.example.com:443", "rule": "content", "provider": None,
         "reason": osp.NOT_REPRESENTABLE_WILDCARD},
        {"endpoint": "any host in 10.30.0.0/24:8080", "rule": "lab", "provider": None,
         "reason": osp.NOT_REPRESENTABLE_HOSTLESS},
        {"endpoint": "registry.npmjs.org:443", "rule": "registry", "provider": None, "reason": None},
    ]
    # A guardrail that names one subdomain doesn't cover the policy's wildcard.
    narrow = osp.beyond_guardrail(record, ["githubusercontent.com", "raw.githubusercontent.com"])
    assert "*.githubusercontent.com:443" in [row["endpoint"] for row in narrow]
    provider = osp.beyond_guardrail(osp.parse_policy(fixture("provider-github.policy-only.yaml")), [])
    assert {row["provider"] for row in provider if row["rule"].startswith("_provider_")} == {"fx_github"}


def test_the_panel_compares_the_policy_with_the_proposal_then_the_version_in_force(store):
    alignment, ref = baseline(store, asp(egress_containment=egress()))
    store.import_openshell_policy(ref, fixture("base.sandbox-get.json"))
    shown = store.guardrail_detail(ref)["openshell_policy"]
    # The proposal seeds every host the policy names (§4.4), so only what
    # DR-184 can't write is beyond it.
    assert all(row["reason"] is not None for row in shown["beyond_guardrail"])
    active = store.adopt_guardrail(alignment["alignment_version_id"])
    rules = json.loads(json.dumps(active["guardrail"]["rules"]))
    rules["out_of_spec_calls"]["allowed_hosts"] = [
        host for host in rules["out_of_spec_calls"]["allowed_hosts"] if host != "*.example.com"]
    store.edit_guardrail(active["guardrail"]["guardrail_version_id"], rules)
    detail = store.guardrail_detail(ref)
    beyond = [row for row in detail["openshell_policy"]["beyond_guardrail"] if row["reason"] is None]
    assert beyond == [{"endpoint": "*.example.com:443,8443", "rule": "example_wildcard", "provider": None,
                       "reason": None}]


# --------------------------------------------------- the collector (DR-249)

# What `railmon openshell` posts for the recorded sandbox: its policy as the
# collector strips it, and the first poll of its log (railmon's parser over
# the recorded `openshell logs` output, tests/fixtures there).
COLLECTOR_POLICY = fixture("collector-policy.json")
COLLECTOR_DENIALS = json.loads(fixture("collector-denials.json"))
SANDBOX = "fixture-agent"  # test_guardrail's v1 fixture's sandbox_name


def test_the_collectors_policy_shows_for_the_agent_its_sandbox_holds(store):
    _, ref = baseline(store, asp(egress_containment=egress()))
    answer = store.record_openshell_policy(SANDBOX, COLLECTOR_POLICY)
    assert (answer["revision"], answer["endpoints"]) == (1, 4)
    shown = store.guardrail_detail(ref)["openshell_policy"]
    assert (shown["source"], shown["revision"], shown["policy_source"]) == ("collector", 1, "sandbox")
    assert shown["digest"] == osp.parse_policy(fixture("base.policy-full.json"))["digest"]
    # The newest wins, whichever way it came.
    store.import_openshell_policy(ref, fixture("mcp.policy-only.yaml"))
    assert store.guardrail_detail(ref)["openshell_policy"]["source"] == "import"
    store.record_openshell_policy(SANDBOX, COLLECTOR_POLICY)
    assert store.guardrail_detail(ref)["openshell_policy"]["source"] == "collector"
    # Another sandbox's policy is not this agent's.
    store.record_openshell_policy("someone-else", fixture("global.policy-get-global.json"))
    assert store.guardrail_detail(ref)["openshell_policy"]["sandbox"] == "fx-base"
    with pytest.raises(osp.PolicyImportError, match="sandbox name"):
        store.record_openshell_policy("bad name", COLLECTOR_POLICY)
    with pytest.raises(osp.PolicyImportError):
        store.record_openshell_policy(SANDBOX, b'{"active_version": 2}')


def test_blocked_by_openshell_groups_the_denials_and_shows_the_partial_span(store):
    _, ref = baseline(store, asp(egress_containment=egress()))
    assert store.guardrail_detail(ref)["openshell_denials"] is None
    # Stamped now, so they fall inside the 24 h shown.
    body = json.loads(json.dumps(COLLECTOR_DENIALS))
    now = store._receive_time()  # noqa: SLF001
    for denial in body["denials"]:
        denial["at"] = now
    body["partial"]["to"] = now
    answer = store.record_openshell_denials(SANDBOX, body)
    assert (answer["stored"], answer["duplicates"], answer["partial"]) == (3, 0, True)
    # The overlapping next poll posts the same lines again: stored once.
    again = store.record_openshell_denials(SANDBOX, {"denials": body["denials"], "partial": None})
    assert (again["stored"], again["duplicates"]) == (0, 3)
    shown = store.guardrail_detail(ref)["openshell_denials"]
    assert shown["partial"] == [{"from": None, "to": now, "reasons": ["first_poll"]}]
    groups = {(grp["host"], grp["port"], grp["binary"]): grp for grp in shown["groups"]}
    assert set(groups) == {("api.github.com", 443, None), ("example.org", 443, "/usr/local/bin/python3.13"),
                           ("169.254.169.254", 80, "/usr/local/bin/python3.13")}
    l7 = groups[("api.github.com", 443, None)]
    assert l7["requests"] == ["POST /markdown"] and l7["count"] == 1
    assert l7["reasons"] == ["L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy"]
    # Against the proposal's hosts (the fixture declares none), all three
    # are outside the guardrail.
    assert all(grp["outside_guardrail"] is True for grp in shown["groups"])


def test_a_denial_changes_no_guardrail_state(store):
    alignment, ref = baseline(store, asp(egress_containment=egress()))
    store.adopt_guardrail(alignment["alignment_version_id"])
    before = store.guardrail_detail(ref)
    body = json.loads(json.dumps(COLLECTOR_DENIALS))
    now = store._receive_time()  # noqa: SLF001
    for denial in body["denials"]:
        denial["at"] = now
    store.record_openshell_denials(SANDBOX, body)
    after = store.guardrail_detail(ref)
    assert (after["state"], after["rules"], after["rows"]) == (before["state"], before["rules"], before["rows"])
    assert after["openshell_denials"]["groups"]


def test_old_denials_leave_the_view_and_then_the_database(store):
    _, ref = baseline(store, asp(egress_containment=egress()))
    store.record_openshell_denials(SANDBOX, {"denials": [
        {"at": "2020-01-01T00:00:00Z", "hash": "a" * 32, "kind": "net", "host": "old.example.com"}], "partial": None})
    # Older than the retention week: pruned in the same post.
    assert store._db.execute("SELECT count(*) FROM openshell_denials").fetchone()[0] == 0  # noqa: SLF001
    assert store.guardrail_detail(ref)["openshell_denials"] is None


@pytest.mark.parametrize(("body", "message"), [
    ([], "the body must be"),
    ({"denials": [], "extra": 1}, "the body must be"),
    ({"denials": [{"at": "2026-10-24T00:00:00Z", "hash": "a" * 32, "kind": "dns"}]}, "kind"),
    ({"denials": [{"at": "2026-10-24T00:00:00Z", "hash": "XYZ", "kind": "net"}]}, "hash"),
    ({"denials": [{"at": "yesterday", "hash": "a" * 32, "kind": "net"}]}, "date-time"),
    ({"denials": [{"at": "2026-10-24T00:00:00", "hash": "a" * 32, "kind": "net"}]}, "time zone"),
    ({"denials": [{"at": "2026-10-24T00:00:00Z", "hash": "a" * 32, "kind": "net", "port": 0}]}, "TCP port"),
    ({"denials": [{"at": "2026-10-24T00:00:00Z", "hash": "a" * 32, "kind": "net", "host": "x" * 254}]}, "at most 253"),
    ({"denials": [{"at": "2026-10-24T00:00:00Z", "hash": "a" * 32, "kind": "net", "token": "x"}]}, "unknown fields"),
    ({"denials": [], "partial": {"to": "2026-10-24T00:00:00Z", "reasons": ["bored"]}}, "partial.reasons"),
    ({"denials": [], "partial": {"to": "2026-10-24T00:00:00Z", "reasons": []}}, "partial.reasons"),
])
def test_a_denials_post_that_isnt_one_is_refused(body, message):
    with pytest.raises(osp.PolicyImportError, match=message):
        osp.parse_denials(body)


def test_the_collector_routes_are_token_gated(store, monkeypatch):
    from fastapi.testclient import TestClient

    from raildash import app as app_module

    baseline(store, asp(egress_containment=egress()))
    monkeypatch.setattr(app_module, "store", store)
    client = TestClient(app_module.app)
    headers = {"X-RailDash-Token": app_module.LOCAL_TOKEN}
    policy = f"/v1/openshell/sandboxes/{SANDBOX}/policy"
    denials = f"/v1/openshell/sandboxes/{SANDBOX}/denials"
    assert client.post(policy, content=COLLECTOR_POLICY).status_code == 403
    assert client.post(denials, json=COLLECTOR_DENIALS).status_code == 403
    assert client.post(policy, content=COLLECTOR_POLICY, headers=headers).status_code == 201
    answer = client.post(denials, json=COLLECTOR_DENIALS, headers=headers)
    assert answer.status_code == 201 and answer.json()["stored"] == 3
    assert client.post(denials, content=json.dumps(COLLECTOR_DENIALS), headers=headers).status_code == 415
    assert client.post(denials, json={"denials": "x"}, headers=headers).status_code == 422
    assert client.post("/v1/openshell/sandboxes/bad%20name/policy", content=COLLECTOR_POLICY,
                       headers=headers).status_code == 422
    assert client.post(policy, content=b'{"version": 1}', headers=headers).status_code == 422


def test_only_the_newest_collector_policies_are_kept(store):
    from raildash import guardrail_store

    for _ in range(guardrail_store.OPENSHELL_POLICIES_KEPT + 5):
        store.record_openshell_policy(SANDBOX, COLLECTOR_POLICY)
    count = store._db.execute("SELECT count(*) FROM openshell_sandbox_policies").fetchone()[0]  # noqa: SLF001
    assert count == guardrail_store.OPENSHELL_POLICIES_KEPT
