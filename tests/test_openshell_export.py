"""DR-258 (DR-194 M4, design §4.5): the guardrail in force as an OpenShell policy.

Golden tests over OpenShell 0.1.3's own output (`fixtures/openshell-0.1.3/`),
with `test_openshell_policy`'s store helpers. Lebin's §7 Q2 (2026-10-27): a
user-applied policy generated from the ASP baseline is the first step towards
enforcement, so the export writes a file and sends nothing.
"""

from __future__ import annotations

import json

import pytest
import yaml

from raildash import openshell_policy as osp
from test_guardrail_custody import asp, baseline
from test_guardrail_egress import egress
from test_openshell_policy import COLLECTOR_POLICY, SANDBOX, fixture, store  # noqa: F401 -- a fixture

BINARY = [{"path": "/usr/local/bin/python3.13"}]


def rules(hosts, uploads=(), denied=()):
    return {
        "out_of_spec_calls": {"allowed_hosts": list(hosts), "allowed_mcp_servers": [],
                              "seeded_from_declared": {"hosts": [], "mcp_servers": []}},
        "uploads": {"allowed_hosts": list(uploads), "max_request_bytes": {},
                    "denied_tool_calls": list(denied)},
        "saved_files": {"allowed": []},
        "service_ports": {"allowed": []},
    }


def imported(name, at="2026-10-28T01:00:00.000000Z"):
    return {**osp.parse_policy(fixture(name)), "imported_at": at}


def export(guardrail, record, base=None):
    return osp.export_policy(guardrail, record, base, agent="agt-x", version="g1 (gv-1)",
                             exported_at="2026-10-28T02:00:00.000000Z")


# ------------------------------------------------------------- the import


def test_the_import_keeps_the_static_sections_an_export_starts_from():
    base = osp.parse_policy(fixture("base.policy-only.yaml"))["base"]
    assert base == {
        "sections": {
            "filesystem_policy": {
                "include_workdir": True,
                "read_only": ["/bin", "/usr", "/lib", "/proc", "/dev/urandom", "/etc", "/var/log", "/opt"],
                "read_write": ["/sandbox", "/tmp", "/dev/null"],
            },
            "landlock": {"compatibility": "best_effort"},
        },
        "dropped": [],
    }
    # The full JSON view carries them inside `policy`; the collector's post
    # (railmon's strip_policy) carries none.
    assert osp.parse_policy(fixture("base.policy-full.json"))["base"] == base
    assert osp.parse_policy(COLLECTOR_POLICY)["base"] is None


def test_a_base_field_outside_the_allow_list_is_dropped_and_named_never_stored():
    raw = b"""
version: 1
filesystem_policy:
  read_only: [/usr]
  read_write: 12
  secret_mount: {token: hunter2}
landlock: {compatibility: hard_requirement}
process: {run_as_user: sandbox, run_as_group: sandbox, env: {API_KEY: sk-live-1}}
inference: {api_key: sk-live-2}
network_policies: {}
"""
    record = osp.parse_policy(raw)
    assert record["base"] == {
        "sections": {
            "filesystem_policy": {"read_only": ["/usr"]},
            "landlock": {"compatibility": "hard_requirement"},
            "process": {"run_as_group": "sandbox", "run_as_user": "sandbox"},
        },
        "dropped": ["filesystem_policy.read_write", "filesystem_policy.secret_mount", "process.env", "inference"],
    }
    assert "hunter2" not in json.dumps(record) and "sk-live" not in json.dumps(record)


# ------------------------------------------------------------- the export


def test_each_allowed_host_is_an_audit_endpoint_on_the_policys_ports():
    """Golden, over the base fixture: read-only, or read-write where the
    guardrail allows uploads; the policy's ports, else 443; its binaries."""
    record = imported("base.policy-only.yaml")
    out = export(rules(["*.example.com", "api.github.com", "api.anthropic.com"],
                       uploads=["api.anthropic.com"]), record, record)
    assert out["policy"]["network_policies"] == {
        "raildash_any_example_com": {
            "name": "raildash-any-example-com",
            "endpoints": [{"host": "*.example.com", "ports": [443, 8443], "protocol": "rest",
                           "enforcement": "audit", "access": "read-only"}],
            "binaries": BINARY,
        },
        "raildash_api_anthropic_com": {
            "name": "raildash-api-anthropic-com",
            # Not in the policy: 443, and every binary the policy names.
            "endpoints": [{"host": "api.anthropic.com", "port": 443, "protocol": "rest",
                           "enforcement": "audit", "access": "read-write"}],
            "binaries": [{"path": "/usr/bin/curl"}, {"path": "/usr/local/bin/python3.13"}],
        },
        "raildash_api_github_com": {
            "name": "raildash-api-github-com",
            "endpoints": [{"host": "api.github.com", "port": 443, "protocol": "rest",
                           "enforcement": "audit", "access": "read-only"}],
            "binaries": BINARY,
        },
    }
    # Only network_policies is replaced: the static sections are the base's.
    assert {k: v for k, v in out["policy"].items() if k != "network_policies"} == {
        "version": 1, **record["base"]["sections"]}


def test_the_file_reads_back_as_a_policy_with_its_gaps_in_the_header():
    record = imported("base.policy-only.yaml")
    out = export(rules(["api.github.com"], uploads=["uploads.github.com"]), record, record)
    text = out["text"]
    header = [line for line in text.splitlines() if line.startswith("#")]
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    assert yaml.safe_load(text) == yaml.safe_load(body) == out["policy"]
    back = osp.parse_policy(text.encode())
    assert [(e["host"], e["enforcement"], e["access"]) for e in back["endpoints"]] == [
        ("api.github.com", "audit", "read-only")]
    assert back["base"] == record["base"]
    joined = "\n".join(header)
    assert "openshell policy set <sandbox> --policy <this file> --wait" in joined
    assert "--rev <N> --base" in joined and "--dry-run" not in text
    assert "enforcement: audit" in joined
    assert "uploads.github.com" in joined  # an upload host calls aren't allowed to
    assert all(f"# - {gap}" in joined for gap in out["gaps"])


def test_without_a_base_policy_the_file_is_version_1_and_says_what_is_missing():
    out = export(rules(["api.github.com"]), None, None)
    assert out["policy"] == {
        "version": 1,
        "network_policies": {"raildash_api_github_com": {
            "name": "raildash-api-github-com",
            "endpoints": [{"host": "api.github.com", "port": 443, "protocol": "rest",
                           "enforcement": "audit", "access": "read-only"}],
        }},
    }
    gaps = "\n".join(out["gaps"])
    assert "No base policy is held" in gaps
    assert "No binary is known for api.github.com" in gaps


def test_an_mcp_endpoint_keeps_its_tool_rules_minus_a_denied_tool():
    record = imported("mcp.policy-only.yaml")
    out = export(rules(["mcp.example.com"], denied=["mcp__docs__read_page", "Bash"]), record, record)
    assert out["policy"]["network_policies"] == {
        "raildash_mcp_example_com_mcp": {
            "name": "raildash-mcp-example-com-mcp",
            "endpoints": [{
                "host": "mcp.example.com", "path": "/mcp", "port": 443, "protocol": "mcp",
                "enforcement": "audit",
                "rules": [{"allow": {"method": "initialize"}},
                          {"allow": {"method": "notifications/initialized"}},
                          {"allow": {"method": "tools/list"}},
                          {"allow": {"method": "tools/call", "tool": "search_docs"}}],
            }],
            "binaries": BINARY,
        },
    }
    assert any("no tools/call for read_page" in gap for gap in out["gaps"])
    # A host the guardrail doesn't allow isn't exported at all.
    assert export(rules(["api.github.com"]), record, record)["policy"]["network_policies"].keys() == {
        "raildash_api_github_com"}


@pytest.mark.parametrize("text, rules_out, dropped, still", [
    ("tools/call read_page", [], ["read_page"], []),
    ("tools/call {search_docs, read_page}",
     [{"allow": {"method": "tools/call", "tool": {"any": ["search_docs"]}}}], ["read_page"], []),
    ("tools/call {read_page}", [], ["read_page"], []),
    ("tools/call search_*", [{"allow": {"method": "tools/call", "tool": "search_*"}}], [], []),
    ("tools/call read_*", [{"allow": {"method": "tools/call", "tool": "read_*"}}], [], ["read_page"]),
    ("tools/call", [{"allow": {"method": "tools/call"}}], [], ["read_page"]),
    ("tools/list", [{"allow": {"method": "tools/list"}}], [], []),
])
def test_mcp_rules_are_never_wider_than_the_policys(text, rules_out, dropped, still):
    """A denied tool is taken out where an allow rule can express it; a rule
    that allows it some other way is kept, and the tool is named."""
    assert osp._mcp_rules({"rules": [text]}, {"read_page"}) == (rules_out, dropped, still)  # noqa: SLF001


def test_a_bare_tools_call_rule_is_named_as_still_allowing_a_denied_tool():
    raw = fixture("mcp.policy-only.yaml").replace(
        b"          - allow:\n              method: tools/list\n",
        b"          - allow:\n              method: tools/list\n          - allow:\n              method: tools/call\n")
    record = {**osp.parse_policy(raw), "imported_at": "2026-10-28T01:00:00.000000Z"}
    gaps = "\n".join(export(rules(["mcp.example.com"], denied=["mcp__docs__read_page"]), record, record)["gaps"])
    assert "still allows read_page" in gaps


def test_a_host_keeps_its_l4_form_and_its_allowed_ips_pin():
    raw = b"""
version: 1
network_policies:
  db:
    endpoints: [{host: db.internal, port: 5432}]
    binaries: [{path: /usr/bin/psql}]
  corp:
    endpoints: [{host: api.corp.example.com, port: 443, protocol: rest, access: read-only,
                 allowed_ips: [10.20.0.0/16]}]
    binaries: [{path: /usr/bin/curl}]
"""
    record = {**osp.parse_policy(raw), "imported_at": "2026-10-28T01:00:00.000000Z"}
    network = export(rules(["db.internal", "api.corp.example.com", "api.github.com"]), record, None)
    assert network["policy"]["network_policies"]["raildash_db_internal"]["endpoints"] == [
        {"host": "db.internal", "port": 5432}]
    assert network["policy"]["network_policies"]["raildash_api_corp_example_com"]["endpoints"] == [
        {"host": "api.corp.example.com", "port": 443, "allowed_ips": ["10.20.0.0/16"],
         "protocol": "rest", "enforcement": "audit", "access": "read-only"}]
    gaps = "\n".join(network["gaps"])
    assert "db.internal stays L4" in gaps
    # api.github.com has no rule of its own: every binary, and said so.
    assert network["policy"]["network_policies"]["raildash_api_github_com"]["binaries"] == [
        {"path": "/usr/bin/curl"}, {"path": "/usr/bin/psql"}]
    assert "No policy rule names the binaries for api.github.com" in gaps


def test_an_imported_value_cant_break_out_of_the_header_comment():
    raw = b"""{"version": 1, "x\\nprocess:\\n  run_as_user: root\\n#": 1,
 "network_policies": {"r\\nlandlock: {compatibility: hard_requirement}\\n#": {
   "endpoints": [{"host": "*.*.example.com", "port": 443}]}}}"""
    record = {**osp.parse_policy(raw), "imported_at": "2026-10-28T01:00:00.000000Z"}
    assert record["base"] is None  # no static section: nothing kept, so nothing named
    text = export(rules(["api.github.com"]), record, record)["text"]
    assert [line for line in text.splitlines() if line.startswith("process") or line.startswith("landlock")] == []
    assert set(yaml.safe_load(text)) == {"version", "network_policies"}
    with_base = osp.parse_policy(b"""{"version": 1, "landlock": {"compatibility": "best_effort"},
 "x\\nprocess:\\n  run_as_user: root\\n#": 1, "network_policies": {}}""")
    assert with_base["base"]["dropped"] == ["x\nprocess:\n  run_as_user: root\n#"]
    text = export(rules(["api.github.com"]), None, {**with_base, "imported_at": "t"})["text"]
    assert set(yaml.safe_load(text)) == {"version", "landlock", "network_policies"}
    assert yaml.safe_load(text)["landlock"] == {"compatibility": "best_effort"}


def test_an_endpoint_that_cant_be_carried_over_is_named():
    record = imported("allowed-ips.policy-only.yaml")
    gaps = "\n".join(export(rules([]), record, record)["gaps"])
    assert osp.NOT_REPRESENTABLE_HOSTLESS in gaps


# --------------------------------------------------------- store and route


def test_the_export_is_of_the_version_in_force_on_the_newest_base(store):  # noqa: F811
    alignment, ref = baseline(store, asp(egress_containment=egress()))
    with pytest.raises(ValueError, match="no guardrail version is in force"):
        store.export_openshell_policy(ref)
    store.import_openshell_policy(ref, fixture("base.policy-only.yaml"))
    store.adopt_guardrail(alignment["alignment_version_id"])
    # The collector's newer post (no static sections) is the policy shown;
    # the base still comes from the import.
    store.record_openshell_policy(SANDBOX, COLLECTOR_POLICY)
    assert store.guardrail_detail(ref)["openshell_policy"]["source"] == "collector"
    out = store.export_openshell_policy(ref)
    assert out["policy"]["filesystem_policy"]["read_write"] == ["/sandbox", "/tmp", "/dev/null"]
    endpoints = [e for rule in out["policy"]["network_policies"].values() for e in rule["endpoints"]]
    # Every L7 endpoint is audit; the policy's plain L4 host stays L4.
    assert {e.get("enforcement") for e in endpoints} == {"audit", None}
    assert [e["host"] for e in endpoints if "protocol" not in e] == ["raw.githubusercontent.com"]
    # Read-only: nothing new is stored.
    assert store._db.execute("SELECT count(*) FROM openshell_policies").fetchone()[0] == 1  # noqa: SLF001


def test_the_route_is_token_gated_and_answers_a_yaml_download(store, monkeypatch):  # noqa: F811
    from fastapi.testclient import TestClient

    from raildash import app as app_module

    alignment, ref = baseline(store, asp(egress_containment=egress()))
    monkeypatch.setattr(app_module, "store", store)
    client = TestClient(app_module.app)
    path = f"/api/guardrails/{ref}/openshell-policy/export"
    headers = {"X-RailDash-Token": app_module.LOCAL_TOKEN}
    assert client.get(path).status_code == 403
    assert client.get(path, headers=headers).status_code == 409
    store.adopt_guardrail(alignment["alignment_version_id"])
    answer = client.get(path, headers=headers)
    assert answer.status_code == 200, answer.text
    assert answer.headers["content-type"].startswith("application/yaml")
    assert answer.headers["content-disposition"].startswith('attachment; filename="openshell-policy-')
    assert answer.text.startswith("# OpenShell policy exported by RailDash")
    # This ASP's guardrail allows no outside host: a policy with no rules.
    assert yaml.safe_load(answer.text) == {"version": 1, "network_policies": {}}
    assert client.get("/api/guardrails/agt-nobody/openshell-policy/export", headers=headers).status_code == 404
