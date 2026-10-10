"""DR-184 M1: the guardrail contract and its pure evaluator, golden cases.

The ASPs are RailMon's real v1 fixture with the attributes each case needs
set the way RailMon's scanner writes them, stored and read back through
RailDash's own `Store.load_asp`/`asp_bundle`, and locked with
`Store.lock_alignment` where a proposal needs a baseline. The single-agent
v2 ASP is split from the same fixture the way RailMon's v2 composer splits
it (as `test_asp.py` does). The two-agent v2 ASP is RailMon's own
`tests/fixtures/evidence-bundle-v2.valid.json`, copied byte for byte as
`fixtures/evidence-bundle-v2-two-agents.json`. Captured requests are
`fixtures/capture.jsonl` and `fixtures/keyed-capture.jsonl` through
`read_jsonl`, `normalise` and `Store.add_interactions`/`interaction`.
"""

from __future__ import annotations

import copy
import itertools
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from raildash import guardrail as g
from raildash.asp import parse_bundle
from raildash.ingest import normalise, read_jsonl
from raildash.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMAS = Path(__file__).parents[1] / "raildash" / "schemas"
V1_FIXTURE = FIXTURES / "evidence-bundle-v1.json"
TWO_AGENTS_FIXTURE = FIXTURES / "evidence-bundle-v2-two-agents.json"
COLLECTED_AT = "2026-09-24T00:00:00Z"  # the v1 fixture's
NOW = "2026-09-24T00:01:00Z"
PREVIOUS = "2026-09-23T23:59:00Z"
_BUNDLE_IDS = itertools.count(1)

# The demo agent's own listener and an extra one, as listensnoop reports them.
DEMO_LISTENER = {"protocol": "tcp", "addr": "127.0.0.1", "port": 8443, "process": "node"}
PORT_9000 = {"protocol": "tcp", "addr": "0.0.0.0", "port": 9000, "process": "python3"}
LISTEN_METHOD = (
    "listensnoop events: protocol, bound address, port (a kernel-chosen "
    "port is 'ephemeral'), process name"
)
FILE_METHOD = "filesnoop events: each regular file a process in the sandbox opened"


def _file(path: str, *, write: bool = True, layer: bool = False) -> dict:
    return {"path": path, "read": not write, "write": write, "exec": False, "layer": layer}


def observed(value, status: str = "ANSWERED", method: str = LISTEN_METHOD) -> dict:
    """An observed attribute in each status, as RailMon's scanner writes it."""
    if status == "ABSENT":
        return {"value": None, "status": "ABSENT", "tier": "observed", "method": method}
    if status in ("BLIND", "FAILED"):
        reason = "NOT_COLLECTED_BY_PACK" if status == "BLIND" else "PARSE_FAILED"
        return {"value": None, "status": status, "reason": reason, "tier": "observed"}
    field = {"value": value, "status": status, "tier": "observed", "authored_by": "none",
             "method": method}
    if status == "PARTIAL":
        field.update(reason="NO_SOURCE_ACCESS",
                     note="listensnoop restarted: listeners may be missing from this list")
    return field


def declared(value, status: str = "ANSWERED", *, reason: str | None = None) -> dict:
    if status == "ANSWERED":
        return {"value": value, "status": "ANSWERED", "tier": "declared",
                "authored_by": "subject", "method": "MCP config parsed for mcpServers"}
    if status == "ABSENT":
        return {"value": None, "status": "ABSENT", "tier": "declared",
                "method": "scanned no MCP config roots"}
    return {"value": None, "status": status, "reason": reason, "tier": "declared",
            "method": "MCP config holds one gateway URL only"}


def v1_bundle(**attributes) -> dict:
    """The real v1 fixture with some attributes set (None removes one)."""
    value = json.loads(V1_FIXTURE.read_bytes())
    value["rule_pack_version"] = 4
    for name, attribute in attributes.items():
        if attribute is None:
            value["attributes"].pop(name, None)
        else:
            value["attributes"][name] = attribute
    return value


def raw(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True).encode()


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "guardrail.db")
    yield db
    db.close()


def stored(store: Store, value: dict) -> tuple[str, dict]:
    """Store exact bytes as an ASP and read the parsed bundle back. Each
    gets its own bundle id, as each RailMon scan does."""
    value = dict(value, bundle_id=f"bnd-guardrail-{next(_BUNDLE_IDS)}")
    summary = store.load_asp(raw(value))
    return summary["asp_id"], store.asp_bundle(summary["asp_id"])


def capture() -> list[dict]:
    items, skipped = read_jsonl(str(FIXTURES / "capture.jsonl"))
    assert skipped == 0
    return items


def stored_requests(store: Store, path: str = "capture.jsonl") -> list[dict]:
    items, _ = read_jsonl(str(FIXTURES / path))
    store.upsert_session("s1")
    store.add_interactions("s1", [normalise(item) for item in items])
    ids = [row[0] for row in store._db.execute("SELECT id FROM interactions ORDER BY id")]
    return [store.interaction(row_id) for row_id in ids]


def guardrail(**rules) -> dict:
    """The design's §4.2 example, with any rule replaced."""
    value = {
        "guardrail_contract_version": 1,
        "guardrail_version_id": "grd-fixture-1",
        "version": "g1",
        "created_at": "2026-10-07T00:00:00Z",
        "agent_identity": {"kind": "local_agent_key", "value": "my-agent"},
        "derived_from": {"alignment_version_id": "aspver-fixture"},
        "rules": {
            "uploads": {
                "allowed_hosts": ["api.openai.com", "*.anthropic.com"],
                "max_request_bytes": {"api.openai.com": 2097152},
                "denied_tool_calls": ["mcp__fs__upload_file"],
            },
            "saved_files": {
                "allowed": [
                    {"path": "/app/workdir/**", "kinds": [".json", ".md"]},
                    {"path": "/app/agent.log"},
                    {"path": "/tmp/tmp*", "literal": True},
                ]
            },
            "service_ports": {
                "allowed": [{"protocol": "tcp", "addr": "127.0.0.1", "port": "ephemeral"}]
            },
            "out_of_spec_calls": {
                "allowed_hosts": ["api.openai.com", "mcp.example.com", "api.github.com"],
                "allowed_mcp_servers": ["example"],
                "seeded_from_declared": {
                    "hosts": ["api.openai.com", "mcp.example.com"],
                    "mcp_servers": ["example"],
                },
            },
        },
    }
    for name, rule in rules.items():
        value["rules"][name] = rule
    return value


# ------------------------------------------------------------------ contract


def test_the_designs_example_is_a_valid_version_under_the_schema_and_the_code():
    value = guardrail()
    schema = json.loads((SCHEMAS / "guardrail-version-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    assert g.guardrail_problems(value) == []
    assert g.validate_guardrail(value) is value
    assert set(g.RULES) == set(schema["properties"]["rules"]["required"])


def _mutated(mutate):
    value = guardrail()
    mutate(value)
    return value


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda v: v.update(extra=1), id="unknown top-level field"),
        pytest.param(lambda v: v["rules"].update(downloads={}), id="unknown rule name"),
        pytest.param(lambda v: v["rules"].pop("uploads"), id="missing rule"),
        pytest.param(lambda v: v["rules"]["uploads"].update(blocked=True), id="unknown rule field"),
        pytest.param(lambda v: v["derived_from"].update(asp_id="x"), id="unknown provenance field"),
        pytest.param(lambda v: v.update(guardrail_contract_version=2), id="contract version"),
        pytest.param(lambda v: v["rules"]["saved_files"]["allowed"].append({"path": "/x", "mode": "w"}),
                     id="unknown saved-file field"),
        pytest.param(lambda v: v["rules"]["saved_files"]["allowed"][0].update(kinds=["(other)"]),
                     id="(other) in kinds"),
        pytest.param(lambda v: v["rules"]["saved_files"]["allowed"][0].update(kinds=[".JSON"]),
                     id="upper-case kind"),
        pytest.param(lambda v: v["rules"]["saved_files"]["allowed"][0].update(kinds=["json"]),
                     id="kind without dot"),
        pytest.param(lambda v: v["rules"]["saved_files"]["allowed"][0].update(kinds=["." + "a" * 16]),
                     id="over-long kind"),
        pytest.param(lambda v: v["rules"]["saved_files"]["allowed"][0].update(kinds=[]),
                     id="empty kinds"),
        pytest.param(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "sctp", "port": 1}),
                     id="protocol"),
        pytest.param(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "tcp", "port": 0}),
                     id="port 0"),
        pytest.param(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "tcp", "port": 65536}),
                     id="port too high"),
        pytest.param(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "tcp", "port": "any"}),
                     id="port word"),
        pytest.param(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "tcp", "port": 80.0}),
                     id="float port"),
        pytest.param(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "tcp", "port": True}),
                     id="bool port"),
        pytest.param(lambda v: v["rules"]["uploads"]["max_request_bytes"].update({"a.example": 1024.0}),
                     id="float cap"),
        pytest.param(lambda v: v["rules"]["uploads"]["max_request_bytes"].update({"a.example": False}),
                     id="bool cap"),
        pytest.param(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "tcp", "port": 1, "peer": "x"}),
                     id="unknown port field"),
        pytest.param(lambda v: v["rules"]["uploads"]["allowed_hosts"].append("API.openai.com"),
                     id="host not lower-case"),
        pytest.param(lambda v: v["rules"]["uploads"]["allowed_hosts"].append("api.openai.com:443"),
                     id="host with port"),
        pytest.param(lambda v: v["rules"]["uploads"]["allowed_hosts"].append("api.*.com"),
                     id="wildcard not leading"),
        pytest.param(lambda v: v["rules"]["uploads"]["allowed_hosts"].append("10.0.0.0/8"),
                     id="ip range"),
        pytest.param(lambda v: v["rules"]["uploads"]["max_request_bytes"].update({"Big.example": 1}),
                     id="cap host not normalized"),
        pytest.param(lambda v: v["rules"]["uploads"]["max_request_bytes"].update({"a.example": -1}),
                     id="negative cap"),
        pytest.param(lambda v: v["rules"]["out_of_spec_calls"]["allowed_mcp_servers"].append("my.server"),
                     id="mcp name not normalized"),
        pytest.param(lambda v: v["rules"]["out_of_spec_calls"].pop("seeded_from_declared"),
                     id="missing seeded_from_declared"),
        pytest.param(lambda v: v.update(created_at="2026-10-07T09:00:00+09:00"), id="created_at not UTC"),
        pytest.param(lambda v: v.update(agent_identity={"kind": "local_agent_keys", "value": ["planner", "executor"]}),
                     id="unsorted key list"),
        pytest.param(lambda v: v.update(agent_identity={"kind": "sandbox", "value": "x"}),
                     id="unknown identity kind"),
    ],
)
def test_the_contract_is_closed(mutate):
    value = _mutated(mutate)
    assert g.guardrail_problems(value)
    with pytest.raises(g.GuardrailValidationError):
        g.validate_guardrail(value)


@pytest.mark.parametrize(
    "identity",
    [
        {"kind": "deployment_environment", "value": {"deployment": "payments-agent", "namespace": "production"}},
        {"kind": "deployment_compose", "value": {"host_id": "h", "project": "p", "service": "s"}},
        {"kind": "local_agent_key", "value": "my-agent"},
        {"kind": "local_agent_keys", "value": ["executor"]},
    ],
)
def test_a_guardrail_binds_to_every_identity_kind_an_alignment_version_does(identity):
    alignment_schema = json.loads((SCHEMAS / "alignment-version-v1.schema.json").read_text())
    guardrail_schema = json.loads((SCHEMAS / "guardrail-version-v1.schema.json").read_text())
    assert guardrail_schema["$defs"]["identity"] == alignment_schema["$defs"]["identity"]
    assert g.guardrail_problems(_mutated(lambda v: v.update(agent_identity=identity))) == []


def test_a_non_object_is_reported_not_a_crash():
    assert g.guardrail_problems(["not", "a", "version"]) == ["guardrail version must be an object"]


# ------------------------------------------------------------------ matchers


@pytest.mark.parametrize(
    ("host", "normalized"),
    [
        ("API.Example.com", "api.example.com"),
        ("api.example.com:443", "api.example.com"),
        ("api.example.com.", "api.example.com"),
        ("[::1]:8443", "::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("host.openshell.internal:8091", "host.openshell.internal"),
        ("", None),
        ("   ", None),
        (None, None),
        ("[::1", None),
    ],
)
def test_hosts_are_normalized_before_matching(host, normalized):
    assert g.normalize_host(host) == normalized


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        ("a.example.com", True),
        ("a.b.example.com", True),
        ("A.Example.com:443", True),
        ("example.com", False),
        ("badexample.com", False),
        ("example.com.evil", False),
        (None, False),
    ],
)
def test_a_wildcard_host_matches_subdomains_only(host, allowed):
    assert g.host_allowed(host, ["*.example.com"]) is allowed


@pytest.mark.parametrize(
    ("pattern", "path", "matches"),
    [
        ("/app/*", "/app/out.json", True),
        ("/app/*", "/app/sub/out.json", False),
        ("/app/**", "/app/sub/deeper/out.json", True),
        ("/app/**", "/app", False),
        ("/app/**/x.md", "/app/a/b/x.md", True),
        ("/app/**/x.md", "/app/x.md", False),
        ("/app/*.json", "/app/.json", True),
        ("/app/file?.txt", "/app/file1.txt", False),
        ("/app/file?.txt", "/app/file?.txt", True),
        ("/app/[ab].txt", "/app/a.txt", False),
        ("/app/{a,b}", "/app/a", False),
        ("/tmp/tmp*", "/tmp/tmp*", True),
        ("/tmp/tmp*", "/tmp/tmpq9x2", True),
    ],
)
def test_the_glob_dialect_has_only_star_and_double_star(pattern, path, matches):
    assert g.glob_matches(pattern, path) is matches


@pytest.mark.parametrize(
    "path", ["/app/Main.PY", "/home/me/.bashrc", "/app/Makefile", "archive.tar.gz", "x." + "a" * 16]
)
def test_a_kind_is_exactly_what_the_observed_profile_reports(path):
    assert g.file_kind(path) == Store._file_type(path)


@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        ("/app/workdir/notes/a.md", True),
        ("/app/workdir/a.JSON", True),
        ("/app/workdir/report.zip", False),  # right place, wrong kind
        ("/app/workdir/Makefile", False),
        ("/app/other/a.json", False),  # right kind, wrong place
        ("/app/agent.log", True),
        ("/tmp/tmp*", True),  # the folded template, exactly
        ("/tmp/tmpq9x2", False),  # a literal entry is never a glob
        ("/tmp/tmp*.json", False),
        ("/proc/self/oom_score_adj", True),
        ("/sys/fs/cgroup/x", True),
        ("/dev/null", True),
        ("/dev/shm/x", False),  # a tmpfs is storage, not a kernel interface
        ("/devices/x", False),
    ],
)
def test_saved_file_entries_need_path_and_kind_from_the_same_entry(path, allowed):
    entries = guardrail()["rules"]["saved_files"]["allowed"]
    assert g.saved_file_allowed(path, entries) is allowed


def test_a_none_kind_and_an_empty_list():
    assert g.saved_file_allowed("/out/Makefile", [{"path": "/out/*", "kinds": ["(none)"]}])
    assert not g.saved_file_allowed("/out/a.txt", [{"path": "/out/*", "kinds": ["(none)"]}])
    assert not g.saved_file_allowed("/out/a.txt", [])


@pytest.mark.parametrize(
    ("listener", "entry", "allowed"),
    [
        ({"protocol": "tcp", "addr": "127.0.0.1", "port": "ephemeral"},
         {"protocol": "tcp", "port": "ephemeral"}, True),
        ({"protocol": "tcp", "addr": "127.0.0.1", "port": 41234},
         {"protocol": "tcp", "port": "ephemeral"}, False),
        ({"protocol": "tcp", "addr": "127.0.0.1", "port": "ephemeral"},
         {"protocol": "tcp", "port": 8443}, False),
        ({"protocol": "tcp", "addr": "10.0.0.5", "port": 8443},
         {"protocol": "tcp", "port": 8443}, True),
        ({"protocol": "udp", "addr": "127.0.0.1", "port": 8443},
         {"protocol": "tcp", "port": 8443}, False),
        ({"protocol": "tcp", "addr": "127.0.0.1", "port": 8443},
         {"protocol": "tcp", "addr": "127.0.0.1", "port": 8443}, True),
        ({"protocol": "tcp", "addr": "0.0.0.0", "port": 8443},
         {"protocol": "tcp", "addr": "127.0.0.1", "port": 8443}, False),
        ({"protocol": "tcp", "addr": "::", "port": 8443},
         {"protocol": "tcp", "addr": "0.0.0.0", "port": 8443}, True),
        ({"protocol": "tcp", "addr": "0.0.0.0", "port": 8443},
         {"protocol": "tcp", "addr": "::", "port": 8443}, True),
        ({"protocol": "tcp", "addr": "::1", "port": 8443},
         {"protocol": "tcp", "addr": "::", "port": 8443}, False),
        ({"protocol": "tcp", "addr": "127.0.0.1", "port": 8443}, None, False),
    ],
)
def test_port_and_address_matching(listener, entry, allowed):
    assert g.listener_allowed(listener, [entry] if entry else []) is allowed


@pytest.mark.parametrize(
    ("name", "server", "item"),
    [
        ("mcp__github__create_issue", "github", "mcp__github"),
        ("mcp__github__x__create_issue", "github__x", "mcp__github__x"),
        ("mcp__my-server_1__t", "my-server_1", "mcp__my-server_1"),
        ("mcp__github", None, "mcp__github"),
        ("Read", None, "Read"),
    ],
)
def test_a_tool_calls_server_is_the_text_before_its_last_double_underscore(name, server, item):
    assert g.tool_call_server(name) == server
    assert g.mcp_item(name) == item


def test_mcp_server_names_are_normalized_as_agents_build_tool_names():
    assert g.normalize_mcp_server("my.server") == "my_server"
    assert g.normalize_mcp_server("ctx 7/€") == "ctx_7__"
    assert g.normalize_mcp_server("github-x_1") == "github-x_1"


# ----------------------------------------------------------------- ASP rules

LISTENER_ITEMS = {"violating": [DEMO_LISTENER, PORT_9000], "clean": []}
FILE_ITEMS = {
    "violating": [_file("/app/workdir/a.json"), _file("/data/report.zip"), _file("/etc/hosts", write=False)],
    "clean": [_file("/app/workdir/a.json"), _file("/etc/hosts", write=False)],
}
SERVICE_PORTS_ALLOWED = {"allowed": [{"protocol": "tcp", "addr": "127.0.0.1", "port": 8443}]}


def _asp_case(store, rule: str, status: str, items: str | None, *, previous=PREVIOUS, now=NOW):
    attribute_name = g.LISTENERS_ATTRIBUTE if rule == "service_ports" else "observed_file_access"
    values = LISTENER_ITEMS if rule == "service_ports" else FILE_ITEMS
    if rule == "service_ports":
        listeners = values[items] if items else None
        attribute = observed(
            listeners if status != "ANSWERED" or listeners else [DEMO_LISTENER], status
        )
    else:
        attribute = observed(values[items] if items else None, status, FILE_METHOD)
    asp_id, bundle = stored(store, v1_bundle(**{attribute_name: attribute}))
    result = g.evaluate_asp(
        guardrail(service_ports=SERVICE_PORTS_ALLOWED),
        bundle, asp_id=asp_id, previous_collected_at=previous, now=now,
    )
    assert result["multi_agent"] is False
    return asp_id, result["rules"][rule]


@pytest.mark.parametrize("rule", ["service_ports", "saved_files"])
@pytest.mark.parametrize(
    ("status", "items", "state", "reason", "count"),
    [
        ("ANSWERED", "clean", "held", None, 0),
        ("ANSWERED", "violating", "violated", None, 1),
        ("ABSENT", None, "held", None, 0),
        # A capped list keeps what it lists, but can't show nothing else broke.
        ("PARTIAL", "violating", "violated", "PARTIAL", 1),
        ("PARTIAL", "clean", "unverified", "PARTIAL", 0),
        ("BLIND", None, "unverified", "BLIND", 0),
        ("FAILED", None, "unverified", "FAILED", 0),
    ],
)
def test_each_asp_rule_against_each_evidence_status(store, rule, status, items, state, reason, count):
    asp_id, result = _asp_case(store, rule, status, items)
    assert (result["state"], result["reason"], len(result["violations"])) == (state, reason, count)
    for violation in result["violations"]:
        assert violation["rule"] == rule
        assert violation["evidence_class"] == "observed"
        assert violation["source"] == {"kind": "asp", "id": asp_id}
    if count and rule == "service_ports":
        assert result["violations"][0]["item"] == "tcp/0.0.0.0/9000"
        assert result["violations"][0]["detail"]["process"] == "python3"
    if count and rule == "saved_files":
        assert result["violations"][0]["item"] == "/data/report.zip"
        assert result["violations"][0]["detail"]["kind"] == ".zip"


@pytest.mark.parametrize("rule", ["service_ports", "saved_files"])
def test_a_stale_asp_is_unverified_but_its_violations_stay_real(store, rule):
    late = "2026-09-24T00:06:00Z"  # 6 min after a 1-min gap: bound is 5 min
    _, result = _asp_case(store, rule, "ANSWERED", "clean", now=late)
    assert (result["state"], result["reason"]) == ("unverified", "STALE")
    _, result = _asp_case(store, rule, "ANSWERED", "violating", now=late)
    assert result["state"] == "violated"


@pytest.mark.parametrize("rule", ["service_ports", "saved_files"])
def test_an_attribute_the_rule_pack_does_not_carry_is_unverified(store, rule):
    # The real v1 fixture carries neither attribute.
    asp_id, bundle = stored(store, v1_bundle())
    result = g.evaluate_asp(guardrail(), bundle, asp_id=asp_id, previous_collected_at=None, now=NOW)
    assert result["rules"][rule] == {"state": "unverified", "reason": "NOT_COLLECTED", "violations": []}


@pytest.mark.parametrize(
    ("previous", "now", "stale"),
    [
        (None, "2026-09-24T02:00:00Z", False),  # one ASP: 2 h
        (None, "2026-09-24T02:00:01Z", True),
        ("2026-09-23T23:59:00Z", "2026-09-24T00:05:00Z", False),  # 3 x 1 min < 5 min floor
        ("2026-09-23T23:59:00Z", "2026-09-24T00:05:01Z", True),
        ("2026-09-23T23:30:00Z", "2026-09-24T01:30:00Z", False),  # 3 x 30 min
        ("2026-09-23T23:30:00Z", "2026-09-24T01:30:01Z", True),
        ("2026-09-23T22:00:00Z", "2026-09-24T02:00:00Z", False),  # 3 x 2 h, capped at 2 h
        ("2026-09-23T22:00:00Z", "2026-09-24T02:00:01Z", True),
        ("2026-09-23T23:59:00Z", "2026-09-23T23:50:00Z", True),  # collected 10 min in the future
    ],
)
def test_the_stale_bound(previous, now, stale):
    assert g.asp_is_stale(COLLECTED_AT, previous, now) is stale


def test_a_layer_item_is_matched_by_its_own_path_and_folded_temp_names_literally(store):
    files = [
        _file("/tmp/tmp*"),  # RailMon's folded template
        _file("/tmp/tmp*.json"),
        _file("/var/lib/docker/overlay2/abc/diff/app/out.bin", layer=True),
        _file("/app/workdir/a.json", layer=True),
        _file("/app/workdir/a.json"),
        _file("/proc/self/attr/current"),
        _file("/dev/null"),
    ]
    asp_id, bundle = stored(store, v1_bundle(observed_file_access=observed(files, method=FILE_METHOD)))
    result = g.evaluate_asp(guardrail(), bundle, asp_id=asp_id, previous_collected_at=PREVIOUS, now=NOW)
    items = [v["item"] for v in result["rules"]["saved_files"]["violations"]]
    assert items == ["/tmp/tmp*.json", "/var/lib/docker/overlay2/abc/diff/app/out.bin"]
    assert result["rules"]["saved_files"]["violations"][1]["detail"]["layer"] is True

    globbed = guardrail(saved_files={"allowed": [{"path": "/tmp/tmp*"}, {"path": "/app/**"},
                                                 {"path": "/var/lib/docker/overlay2/**"}]})
    result = g.evaluate_asp(globbed, bundle, asp_id=asp_id, previous_collected_at=PREVIOUS, now=NOW)
    assert result["rules"]["saved_files"]["state"] == "held"


def test_an_unreadable_listener_is_unverified_unless_another_breaks_the_rule(store):
    odd = {"protocol": "tcp", "addr": "127.0.0.1", "port": "8443"}
    asp_id, bundle = stored(store, v1_bundle(observed_listeners=observed([odd])))
    result = g.evaluate_asp(guardrail(), bundle, asp_id=asp_id, previous_collected_at=PREVIOUS, now=NOW)
    assert result["rules"]["service_ports"]["reason"] == "MALFORMED_EVIDENCE"
    asp_id, bundle = stored(store, v1_bundle(observed_listeners=observed([odd, PORT_9000])))
    result = g.evaluate_asp(guardrail(), bundle, asp_id=asp_id, previous_collected_at=PREVIOUS, now=NOW)
    assert result["rules"]["service_ports"]["state"] == "violated"


def _single_agent_v2(listeners, files) -> dict:
    """RailMon's v2 split of the v1 fixture: one keyed agent, with listeners
    and file access in the sandbox scope (`SANDBOX_ATTRIBUTES`)."""
    value = v1_bundle()
    value["bundle_version"] = 2
    inputs = value.pop("inputs_attempted")
    attributes = value.pop("attributes")
    sandbox = {name: attributes.pop(name) for name in ("container_identity", "image_digest", "mounts", "deployment")}
    sandbox["observed_listeners"] = observed(listeners)
    sandbox["observed_file_access"] = observed(files, method=FILE_METHOD)
    value["sandbox"] = {"inputs_attempted": inputs, "attributes": sandbox}
    value["agents"] = [{"agent_key": "executor", "discovery_status": "available",
                        "inputs_attempted": inputs, "attributes": attributes}]
    return value


def test_a_single_agent_v2_asp_is_evaluated_on_its_sandbox_scope(store):
    asp_id, bundle = stored(store, _single_agent_v2([DEMO_LISTENER], [_file("/data/report.zip")]))
    assert bundle["bundle_version"] == 2
    result = g.evaluate_asp(
        guardrail(service_ports=SERVICE_PORTS_ALLOWED), bundle,
        asp_id=asp_id, previous_collected_at=PREVIOUS, now=NOW,
    )
    assert result["multi_agent"] is False
    assert result["rules"]["service_ports"]["state"] == "held"
    assert [v["item"] for v in result["rules"]["saved_files"]["violations"]] == ["/data/report.zip"]


def test_a_two_agent_sandbox_is_unverified_multi_agent_and_nothing_is_evaluated(store):
    asp_id, bundle = stored(store, json.loads(TWO_AGENTS_FIXTURE.read_bytes()))
    assert [agent["agent_key"] for agent in bundle["agents"]] == ["executor", "planner"]
    result = g.evaluate_asp(guardrail(), bundle, asp_id=asp_id, previous_collected_at=None, now=NOW)
    assert result["multi_agent"] is True
    states = g.rule_states(result, g.request_rules_status(
        now=NOW, last_heartbeat_at=NOW, last_unattributed_at=None, last_tool_calls_unreadable_at=None))
    assert {rule: (s["state"], s["reason"]) for rule, s in states.items()} == {
        rule: ("unverified", "MULTI_AGENT") for rule in g.RULES
    }
    assert g.agent_state(has_active_guardrail=True, rule_results=states, counting_rows=0) == "unverified"


# ------------------------------------------------------------- request rules


def _row(interaction: dict) -> dict:
    return normalise(interaction)


def _with_response_tools(interaction: dict, *names: str, openai: bool = False) -> dict:
    changed = copy.deepcopy(interaction)
    if openai:
        changed["response"]["body"] = {"choices": [{"message": {"tool_calls": [
            {"type": "function", "function": {"name": name, "arguments": "{}"}} for name in names
        ]}}]}
    else:
        changed["response"]["body"] = {"content": [
            {"type": "tool_use", "id": f"t{i}", "name": name, "input": {}} for i, name in enumerate(names)
        ]}
    return changed


def _items(result: dict) -> dict:
    return {rule: [(v["item"], v["evidence_class"]) for v in result[rule]] for rule in g.REQUEST_RULES}


def test_every_captured_fixture_request_against_the_request_rules(store):
    policy = guardrail(
        uploads={"allowed_hosts": ["api.anthropic.com"], "max_request_bytes": {}, "denied_tool_calls": []},
        out_of_spec_calls={"allowed_hosts": ["api.anthropic.com"], "allowed_mcp_servers": [],
                           "seeded_from_declared": {"hosts": ["api.anthropic.com"], "mcp_servers": []}},
    )
    rows = stored_requests(store)
    results = [g.evaluate_request(policy, row) for row in rows]
    assert all(r["tool_calls"] == {"readable": True, "reason": None} for r in results)
    found = [_items(r) for r in results]
    openshell = ("host.openshell.internal", "observed")
    assert found == [
        {"uploads": [], "out_of_spec_calls": []},  # built-in tool call: not judged
        {"uploads": [openshell], "out_of_spec_calls": [openshell]},
        {"uploads": [], "out_of_spec_calls": []},
        {"uploads": [], "out_of_spec_calls": [("registry.npmjs.org", "observed")]},  # GET, no body
        {"uploads": [], "out_of_spec_calls": []},
        {"uploads": [], "out_of_spec_calls": [("exfil.attacker.net", "observed")]},
        {"uploads": [openshell], "out_of_spec_calls": [openshell]},
        # `request: null`: a call to nobody known, but nothing says it had a body.
        {"uploads": [], "out_of_spec_calls": [("(unknown host)", "observed")]},
    ]
    violation = g.evaluate_request(policy, rows[1])["uploads"][0]
    assert violation["source"] == {"kind": "interaction", "id": rows[1]["id"]}
    assert violation["detail"]["reasons"] == ["body_to_unlisted_host"]


def test_a_body_with_no_host_is_an_upload_to_unknown_host():
    http2 = {"request": {"method": "POST", "headers": {}, "body": {"file": "x"}},
             "response": {"status_code": 200}, "request_size": 900}
    found = g.evaluate_request(guardrail(), _row(http2))
    assert [(v["rule"], v["item"]) for v in found["uploads"] + found["out_of_spec_calls"]] == [
        ("uploads", "(unknown host)"), ("out_of_spec_calls", "(unknown host)"),
    ]


@pytest.mark.parametrize(
    ("body", "headers", "carries"),
    [
        (None, {}, False),
        ("", {}, False),
        ({}, {}, True),  # an empty JSON object still came from bytes on the wire
        ("a=1", {}, True),
        (None, {"Content-Length": "12"}, True),
        (None, {"content-length": "0"}, False),
        (None, {"content-length": "lots"}, True),
    ],
)
def test_what_carries_a_body(body, headers, carries):
    interaction = {"request": {"method": "POST", "headers": {"host": "x.example", **headers}, "body": body},
                   "response": {"status_code": 200}}
    assert g.carries_body(_row(interaction)) is carries


def test_an_unreadable_stored_raw_counts_as_a_body():
    assert g.carries_body({"host": "x.example", "raw": "{not json"}) is True


def test_the_size_cap_reads_request_size_and_the_smallest_matching_cap():
    base = capture()[0]  # POST to api.anthropic.com, request_size 296
    caps = {"*.anthropic.com": 1000, "api.anthropic.com": 296}
    policy = guardrail(uploads={"allowed_hosts": ["api.anthropic.com"], "max_request_bytes": caps,
                                "denied_tool_calls": []})
    assert g.evaluate_request(policy, _row(base))["uploads"] == []
    bigger = dict(base, request_size=297)
    [violation] = g.evaluate_request(policy, _row(bigger))["uploads"]
    assert (violation["item"], violation["detail"]["reasons"]) == ("api.anthropic.com", ["request_size_over_cap"])
    assert violation["detail"]["max_request_bytes"] == 296
    unknown = dict(base, request_size=None)
    [violation] = g.evaluate_request(policy, _row(unknown))["uploads"]
    assert violation["detail"]["reasons"] == ["request_size_unknown"]


def test_denied_and_out_of_spec_tool_calls_are_requested_violations():
    base = capture()[0]
    answer = _with_response_tools(
        base, "mcp__fs__upload_file", "mcp__example__search", "mcp__example__fetch",
        "mcp__github__x__create_issue", "mcp__github__list", "Bash",
    )
    policy = guardrail(
        uploads={"allowed_hosts": ["api.anthropic.com"], "max_request_bytes": {},
                 "denied_tool_calls": ["mcp__fs__upload_file", "Bash"]},
        out_of_spec_calls={"allowed_hosts": ["api.anthropic.com"], "allowed_mcp_servers": ["example", "github"],
                           "seeded_from_declared": {"hosts": [], "mcp_servers": []}},
    )
    found = g.evaluate_request(policy, _row(answer))
    assert _items(found) == {
        "uploads": [("mcp__fs__upload_file", "requested"), ("Bash", "requested")],
        # `github__x` is not `github`; two tools of one server share a row.
        "out_of_spec_calls": [("mcp__fs", "requested"), ("mcp__github__x", "requested")],
    }
    assert found["out_of_spec_calls"][1]["detail"] == {
        "kind": "mcp_server", "server": "github__x", "tool": "mcp__github__x__create_issue",
    }


def test_openai_tool_calls_count_and_a_request_that_only_echoes_a_call_does_not():
    rows = capture()
    policy = guardrail(uploads={"allowed_hosts": ["api.anthropic.com"], "max_request_bytes": {},
                                "denied_tool_calls": ["delivery_track_package"]})
    assert [v["item"] for v in g.evaluate_request(policy, _row(rows[0]))["uploads"]] == ["delivery_track_package"]
    # rows[2] replays that tool_use in its request messages: the model did not ask again.
    assert rows[2]["request"]["body"]["messages"][1]["content"][0]["name"] == "delivery_track_package"
    assert g.evaluate_request(policy, _row(rows[2]))["uploads"] == []
    openai = _with_response_tools(rows[2], "delivery_track_package", openai=True)
    assert [v["item"] for v in g.evaluate_request(policy, _row(openai))["uploads"]] == ["delivery_track_package"]


def test_a_server_less_mcp_name_fails_closed():
    answer = _with_response_tools(capture()[0], "mcp__example")
    [violation] = g.evaluate_request(guardrail(), _row(answer))["out_of_spec_calls"][1:]
    assert (violation["item"], violation["detail"]["server"]) == ("mcp__example", None)
    assert not g.item_allowed(guardrail(), violation)


# --------------------------------------------------- liveness and attribution


@pytest.mark.parametrize(
    ("heartbeat", "unattributed", "unreadable", "reason"),
    [
        ("2026-09-24T00:00:30Z", None, None, None),
        ("2026-09-24T00:00:30Z", "2026-09-23T23:50:00Z", None, None),  # 11 min ago
        ("2026-09-24T00:00:30Z", "2026-09-23T23:52:00Z", None, "UNATTRIBUTED_TRAFFIC"),
        ("2026-09-24T00:00:30Z", None, "2026-09-23T23:52:00Z", "TOOL_CALLS_UNREADABLE"),
        ("2026-09-24T00:00:30Z", None, "2026-09-23T23:50:00Z", None),
        (None, None, None, "NO_HEARTBEAT"),
        ("2026-09-23T23:58:00Z", None, None, None),  # exactly 3 min ago is still "the last 3 minutes"
        ("2026-09-23T23:57:59Z", None, None, "NO_HEARTBEAT"),
        ("2026-09-24T00:05:00Z", None, None, "NO_HEARTBEAT"),  # ahead of now by more than the window
    ],
)
def test_request_rules_need_a_heartbeat_and_no_recent_unattributed_or_unreadable_traffic(
    heartbeat, unattributed, unreadable, reason
):
    status = g.request_rules_status(now=NOW, last_heartbeat_at=heartbeat, last_unattributed_at=unattributed,
                                    last_tool_calls_unreadable_at=unreadable)
    for rule in g.REQUEST_RULES:
        assert status[rule]["state"] == ("unverified" if reason else "held")
        assert status[rule]["reason"] == reason


PLANNER = {"identity": {"kind": "local_agent_keys", "value": ["planner"]}, "sandboxes": []}
CRITIC = {"identity": {"kind": "deployment_compose", "value": {"host_id": "acceptance-host",
                                                              "project": "p", "service": "critic"}},
          "sandboxes": [("acceptance-host", "critic-box")]}
SHARED = {"identity": {"kind": "deployment_environment", "value": {"deployment": "d", "namespace": "n"}},
          "sandboxes": [("acceptance-host", "shared-container")]}


def _keyed(store) -> dict[str, dict]:
    rows = stored_requests(store, "keyed-capture.jsonl")
    return {
        row["attribution_state"] if row["attribution_state"] != "attributed" else row["agent_key"]: row
        for row in rows
    }


def test_attributed_requests_go_to_the_guardrail_naming_their_agent_or_sandbox(store):
    rows = _keyed(store)
    assert set(rows) == {"conflict", "planner", "critic"}
    planner = rows["planner"]
    assert g.request_owner(planner, [PLANNER, CRITIC], authenticated=True) == {
        "decision": "guardrail", "identity": PLANNER["identity"]}
    # The critic row names no guardrail key, and its sandbox is not CRITIC's.
    assert g.request_owner(rows["critic"], [PLANNER, CRITIC], authenticated=True) == {"decision": "no_guardrail"}
    assert g.request_owner(rows["critic"], [PLANNER, SHARED], authenticated=True) == {
        "decision": "guardrail", "identity": SHARED["identity"]}
    # Two guardrails claiming one request is a conflict, never a guess.
    assert g.request_owner(planner, [PLANNER, SHARED], authenticated=True) == {"decision": "unattributed"}


@pytest.mark.parametrize("state", ["conflict", "ambiguous", "unknown", None])
def test_unattributed_requests_belong_only_to_a_sole_active_guardrail(store, state):
    row = dict(_keyed(store)["conflict"], attribution_state=state)
    assert g.request_owner(row, [PLANNER], authenticated=True) == {
        "decision": "guardrail", "identity": PLANNER["identity"]}
    assert g.request_owner(row, [PLANNER, CRITIC], authenticated=True) == {"decision": "unattributed"}
    assert g.request_owner(row, [], authenticated=True) == {"decision": "no_guardrail"}


def test_a_single_agent_capture_has_no_attribution_and_goes_to_the_sole_guardrail(store):
    row = stored_requests(store)[0]
    assert row["attribution_state"] is None
    assert g.request_owner(row, [PLANNER], authenticated=True)["decision"] == "guardrail"


def test_an_unauthenticated_capture_never_counts(store):
    for row in _keyed(store).values():
        assert g.request_owner(row, [PLANNER], authenticated=False) == {"decision": "ignored"}


# ------------------------------------------------------------------ proposal


DECLARED = dict(
    inference_endpoint={"value": "https://API.openai.com/v1", "status": "ANSWERED", "tier": "observed",
                        "authored_by": "subject", "method": "the base URL the scanned environment declares"},
    declared_destinations=declared(["api.openai.com", "mcp.example.com"]),
    mcp_servers_declared=declared([{"name": "example", "url": "https://mcp.example.com/mcp", "transport": "http"},
                                   {"name": "ex.ample", "command": "mcp-server"},
                                   {"name": "ex_ample", "command": "mcp-server"}]),
    observed_listeners=observed([DEMO_LISTENER]),
    observed_file_access=observed(
        [_file("/app/agent.log"), _file("/tmp/tmp*"), _file("/app/agent.log", layer=True),
         _file("/proc/self/attr/current"), _file("/etc/hosts", write=False)],
        method=FILE_METHOD),
)


def _lock(store, value: dict) -> tuple[dict, dict]:
    asp_id, bundle = stored(store, value)
    return store.lock_alignment(asp_id, "v1.0"), bundle


def _propose(alignment, bundle, requests):
    return g.propose_guardrail(alignment, bundle, requests, guardrail_version_id="grd-1",
                               version="g1", created_at="2026-09-24T00:02:00Z")


def test_a_proposal_from_answered_declarations(store):
    alignment, bundle = _lock(store, v1_bundle(**DECLARED))
    requests = stored_requests(store)
    answer = _with_response_tools(capture()[0], "mcp__example__search", "mcp__notion__search")
    store.add_interactions("s1", [normalise(dict(answer, timestamp="2026-08-15T17:05:00Z"))])
    requests.append(store.interaction(len(requests) + 1))
    proposal = _propose(alignment, bundle, requests)
    rules = proposal["guardrail"]["rules"]
    assert g.guardrail_problems(proposal["guardrail"]) == []
    assert proposal["guardrail"]["agent_identity"] == alignment["agent_identity"]
    assert proposal["guardrail"]["derived_from"] == {"alignment_version_id": alignment["alignment_version_id"]}
    assert rules["uploads"] == {
        # the base URL's host, plus every host a body went to before the lock
        "allowed_hosts": ["api.anthropic.com", "api.openai.com", "host.openshell.internal"],
        "max_request_bytes": {}, "denied_tool_calls": [],
    }
    assert rules["saved_files"] == {"allowed": [{"path": "/app/agent.log", "literal": True},
                                                {"path": "/tmp/tmp*", "literal": True}]}
    assert rules["service_ports"] == {"allowed": []}
    assert rules["out_of_spec_calls"] == {
        "allowed_hosts": ["api.openai.com", "mcp.example.com"],
        "allowed_mcp_servers": ["ex_ample", "example"],
        "seeded_from_declared": {"hosts": ["api.openai.com", "mcp.example.com"],
                                 "mcp_servers": ["ex_ample", "example"]},
    }
    assert [(v["rule"], v["item"], v["evidence_class"]) for v in proposal["would_be_violations"]] == [
        ("service_ports", "tcp/127.0.0.1/8443", "observed"),
        ("out_of_spec_calls", "api.anthropic.com", "observed"),
        ("out_of_spec_calls", "host.openshell.internal", "observed"),
        ("out_of_spec_calls", "registry.npmjs.org", "observed"),
        ("out_of_spec_calls", "exfil.attacker.net", "observed"),
        ("out_of_spec_calls", "(unknown host)", "observed"),
        ("out_of_spec_calls", "mcp__notion", "requested"),
    ]
    assert proposal["empty_because"] == {}

    # Adopted unedited, the baseline itself breaks exactly what was listed.
    result = g.evaluate_asp(proposal["guardrail"], bundle, asp_id=alignment["asp"]["asp_id"],
                            previous_collected_at=None, now=NOW)
    assert result["rules"]["saved_files"]["state"] == "held"
    assert [v["item"] for v in result["rules"]["service_ports"]["violations"]] == ["tcp/127.0.0.1/8443"]


def test_a_proposal_from_absent_declarations_says_why_its_lists_are_empty(store):
    # The real fixture as RailMon wrote it: no MCP config, no base URL.
    alignment, bundle = _lock(store, v1_bundle())
    proposal = _propose(alignment, bundle, [])
    rules = proposal["guardrail"]["rules"]
    assert rules["uploads"]["allowed_hosts"] == []
    assert rules["out_of_spec_calls"]["allowed_hosts"] == []
    assert rules["out_of_spec_calls"]["allowed_mcp_servers"] == []
    assert rules["saved_files"]["allowed"] == []
    assert {where: (why["status"], why["reason"]) for where, why in proposal["empty_because"].items()} == {
        "saved_files.allowed": (None, "NOT_COLLECTED"),
        "out_of_spec_calls.allowed_hosts": ("ABSENT", None),
        "out_of_spec_calls.allowed_mcp_servers": ("ABSENT", None),
    }
    assert proposal["empty_because"]["out_of_spec_calls.allowed_mcp_servers"]["note"] == (
        bundle["attributes"]["mcp_servers_declared"]["note"]
    )


def test_a_proposal_behind_a_gateway_lists_mcp_servers_as_rows_to_allow(store):
    gateway = dict(
        DECLARED,
        declared_destinations=declared(["gateway.example.com"]),
        mcp_servers_declared=declared(None, "BLIND", reason="GATEWAY_MANAGED"),
    )
    alignment, bundle = _lock(store, v1_bundle(**gateway))
    answer = _with_response_tools(dict(capture()[0], request=dict(capture()[0]["request"], headers={
        "host": "gateway.example.com"})), "mcp__example__search")
    proposal = _propose(alignment, bundle, [_row(answer)])
    rules = proposal["guardrail"]["rules"]
    assert rules["out_of_spec_calls"]["allowed_hosts"] == ["gateway.example.com"]
    assert rules["out_of_spec_calls"]["allowed_mcp_servers"] == []
    assert proposal["empty_because"]["out_of_spec_calls.allowed_mcp_servers"]["reason"] == "GATEWAY_MANAGED"
    assert [(v["rule"], v["item"]) for v in proposal["would_be_violations"]] == [
        ("service_ports", "tcp/127.0.0.1/8443"),
        ("out_of_spec_calls", "mcp__example"),
    ]


def test_a_proposal_from_a_single_agent_v2_baseline_reads_both_scopes(store):
    value = _single_agent_v2([DEMO_LISTENER], [_file("/app/agent.log")])
    value["agents"][0]["attributes"]["declared_destinations"] = declared(["api.openai.com"])
    alignment, bundle = _lock(store, value)
    proposal = _propose(alignment, bundle, [])
    rules = proposal["guardrail"]["rules"]
    assert rules["out_of_spec_calls"]["allowed_hosts"] == ["api.openai.com"]
    assert rules["saved_files"]["allowed"] == [{"path": "/app/agent.log", "literal": True}]
    assert [v["item"] for v in proposal["would_be_violations"]] == ["tcp/127.0.0.1/8443"]


def test_no_proposal_for_a_two_agent_baseline(store):
    alignment, bundle = _lock(store, json.loads(TWO_AGENTS_FIXTURE.read_bytes()))
    assert _propose(alignment, bundle, [])["guardrail"] is None
    assert _propose(alignment, bundle, [])["reason"] == "MULTI_AGENT"


# ------------------------------------------------------------------- roll-up


def _states(**overrides):
    states = {rule: {"state": "held", "reason": None, "violations": []} for rule in g.RULES}
    for rule, state in overrides.items():
        states[rule] = {"state": state, "reason": None, "violations": []}
    return states


@pytest.mark.parametrize(
    ("active", "states", "rows", "expected"),
    [
        (False, _states(), 0, "no_guardrail"),
        (False, _states(), 3, "no_guardrail"),
        (True, _states(), 0, "held"),
        (True, _states(uploads="violated"), 0, "held"),  # acknowledged: verified, nothing counts
        (True, _states(uploads="unverified"), 0, "unverified"),
        (True, _states(uploads="unverified"), 1, "violated"),
        (True, {rule: s for rule, s in _states().items() if rule != "saved_files"}, 0, "unverified"),
    ],
)
def test_the_state_roll_up(active, states, rows, expected):
    assert g.agent_state(has_active_guardrail=active, rule_results=states, counting_rows=rows) == expected


def test_no_asp_yet_leaves_the_asp_rules_unverified():
    request = g.request_rules_status(now=NOW, last_heartbeat_at=NOW, last_unattributed_at=None,
                                     last_tool_calls_unreadable_at=None)
    states = g.rule_states(None, request)
    assert states["service_ports"]["reason"] == "NOT_COLLECTED"
    assert g.agent_state(has_active_guardrail=True, rule_results=states, counting_rows=0) == "unverified"


def test_a_row_counts_only_while_unacknowledged_and_disallowed_by_the_version_in_force(store):
    rows = stored_requests(store)
    tight = guardrail()
    [host_row, *_] = g.evaluate_request(tight, rows[5])["out_of_spec_calls"]
    assert host_row["item"] == "exfil.attacker.net"
    assert g.row_counts(tight, host_row)
    assert not g.row_counts(tight, dict(host_row, acknowledged=True))
    looser = guardrail(out_of_spec_calls=dict(tight["rules"]["out_of_spec_calls"],
                                              allowed_hosts=["exfil.attacker.net"]))
    assert not g.row_counts(looser, host_row)  # allowed by g2: listed, not counted
    assert g.row_counts(tight, host_row)  # switching back makes it count again
    assert not g.row_counts(None, host_row)
    assert g.row_counts(looser, {"rule": "uploads", "item": "N more items", "overflow": True})

    over = dict(capture()[0], request_size=5000)
    policy = guardrail(uploads={"allowed_hosts": ["api.anthropic.com"],
                                "max_request_bytes": {"api.anthropic.com": 1000}, "denied_tool_calls": []})
    [size_row] = g.evaluate_request(policy, _row(over))["uploads"]
    assert g.row_counts(policy, size_row)
    raised = guardrail(uploads=dict(policy["rules"]["uploads"], max_request_bytes={"api.anthropic.com": 8000}))
    assert not g.row_counts(raised, size_row)

    port_row = {"rule": "service_ports", "item": "tcp/0.0.0.0/9000",
                "detail": {"protocol": "tcp", "addr": "0.0.0.0", "port": 9000}}
    assert g.row_counts(tight, port_row)
    assert not g.row_counts(guardrail(service_ports={"allowed": [{"protocol": "tcp", "addr": "::", "port": 9000}]}),
                            port_row)
    file_row = {"rule": "saved_files", "item": "/data/report.zip", "detail": {}}
    assert g.row_counts(tight, file_row)
    assert not g.row_counts(guardrail(saved_files={"allowed": [{"path": "/data/*", "kinds": [".zip"]}]}), file_row)
    unknown = {"rule": "out_of_spec_calls", "item": "(unknown host)", "detail": {"kind": "host"}}
    assert g.row_counts(guardrail(), unknown)


def test_a_float_port_passes_json_schema_alone_but_not_the_contract():
    # JSON Schema's `integer` accepts 80.0; the code-side check is what refuses it.
    value = _mutated(lambda v: v["rules"]["service_ports"]["allowed"].append({"protocol": "tcp", "port": 80.0}))
    schema = json.loads((SCHEMAS / "guardrail-version-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    assert g.guardrail_problems(value) == ["rules.service_ports.allowed.1.port: must be an integer"]


# ---------------------------------------- violated on evidence that isn't verified


@pytest.mark.parametrize(
    ("status", "now", "reason"),
    [
        ("ANSWERED", "2026-09-24T00:06:00Z", "STALE"),
        ("PARTIAL", NOW, "PARTIAL"),
    ],
)
def test_violations_on_unverified_evidence_leave_the_agent_unverified_once_acknowledged(
    store, status, now, reason
):
    asp_id, bundle = stored(store, v1_bundle(observed_listeners=observed([DEMO_LISTENER, PORT_9000], status)))
    result = g.evaluate_asp(guardrail(service_ports=SERVICE_PORTS_ALLOWED), bundle,
                            asp_id=asp_id, previous_collected_at=PREVIOUS, now=now)
    ports = result["rules"]["service_ports"]
    assert (ports["state"], ports["reason"]) == ("violated", reason)
    assert [v["item"] for v in ports["violations"]] == ["tcp/0.0.0.0/9000"]
    states = dict(_states(), service_ports=ports)
    # Rows still unacknowledged: Violated. Acknowledged: the evidence still
    # never showed the rule held, so Unverified, never Held.
    assert g.agent_state(has_active_guardrail=True, rule_results=states, counting_rows=1) == "violated"
    assert g.agent_state(has_active_guardrail=True, rule_results=states, counting_rows=0) == "unverified"


# ------------------------------------------------------- streamed tool calls


def _sse_row(text: str | None = None, **response_headers) -> dict:
    """RailMon's own streamed capture (copied from its
    `tests/fixtures/runtime-interactions.jsonl`), with the event-stream text
    it stored as `{"raw": text}` replaced when a case needs other events."""
    [line] = (FIXTURES / "sse-capture.jsonl").read_text().splitlines()
    interaction = json.loads(line)
    response = interaction["raw"]["response"]
    if text is not None:
        response["body"] = {"raw": text}
    response["headers"].update(response_headers)
    return _row(interaction)


def _stream(*events, done: bool = True) -> str:
    lines = []
    for event in events:
        if isinstance(event, dict) and "type" in event:
            lines.append(f"event: {event['type']}")
        lines.append("data: " + (event if isinstance(event, str) else json.dumps(event)))
        lines.append("")
    if done:
        lines.extend(["data: [DONE]", ""])
    return "\r\n".join(lines) + "\r\n"


ANTHROPIC_STREAM = [
    {"type": "message_start", "message": {"id": "msg_1", "content": []}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_start", "index": 1,
     "content_block": {"type": "tool_use", "id": "toolu_1", "name": "mcp__fs__upload_file", "input": {}}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{}"}},
    {"type": "content_block_start", "index": 2,
     "content_block": {"type": "tool_use", "id": "toolu_2", "name": "mcp__notion__search", "input": {}}},
    {"type": "message_stop"},
]
OPENAI_CHAT_STREAM = [
    {"choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
        {"index": 0, "id": "call_1", "type": "function",
         "function": {"name": "mcp__fs__upload_file", "arguments": ""}}]}}]},
    {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{}"}}]}}]},
    {"choices": [{"index": 0, "delta": {"tool_calls": [
        {"index": 1, "id": "call_2", "type": "function",
         "function": {"name": "mcp__notion__search", "arguments": ""}}]}}]},
    {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
]
OPENAI_RESPONSES_STREAM = [
    {"type": "response.created", "response": {"id": "resp_1", "output": []}},
    {"type": "response.output_item.added", "output_index": 0,
     "item": {"type": "function_call", "id": "fc_1", "name": "mcp__fs__upload_file", "arguments": ""}},
    {"type": "response.function_call_arguments.delta", "output_index": 0, "delta": "{}"},
    {"type": "response.output_item.done", "output_index": 1,
     "item": {"type": "function_call", "id": "fc_2", "name": "mcp__notion__search", "arguments": "{}"}},
    {"type": "response.completed", "response": {"id": "resp_1"}},
]


@pytest.mark.parametrize(
    "events", [ANTHROPIC_STREAM, OPENAI_CHAT_STREAM, OPENAI_RESPONSES_STREAM],
    ids=["anthropic", "openai-chat", "openai-responses"],
)
def test_tool_calls_are_read_from_a_streamed_response(events):
    row = _sse_row(_stream(*events))
    assert g.requested_tool_calls(row) == {
        "names": ["mcp__fs__upload_file", "mcp__notion__search"], "readable": True, "reason": None,
    }
    found = g.evaluate_request(guardrail(), row)
    assert [(v["item"], v["evidence_class"]) for v in found["uploads"]] == [("mcp__fs__upload_file", "requested")]
    assert [v["item"] for v in found["out_of_spec_calls"]] == ["api.anthropic.com", "mcp__fs", "mcp__notion"]
    assert found["tool_calls"] == {"readable": True, "reason": None}


@pytest.mark.parametrize(
    "events", [ANTHROPIC_STREAM, OPENAI_CHAT_STREAM, OPENAI_RESPONSES_STREAM],
    ids=["anthropic", "openai-chat", "openai-responses"],
)
def test_a_truncated_stream_keeps_the_names_it_reached_but_fails_closed(events):
    text = _stream(*events, done=False)
    cut = text.index("mcp__notion__search") - 20  # mid-way through the second call's event
    assert g.requested_tool_calls(_sse_row(text[:cut])) == {
        "names": ["mcp__fs__upload_file"], "readable": False, "reason": "RESPONSE_TRUNCATED_EVENT",
    }


def test_a_stream_cut_after_a_whole_event_still_reads():
    # The last event's JSON is complete; only its blank line is missing.
    text = _stream(*ANTHROPIC_STREAM[:3], done=False).rstrip("\r\n")
    assert g.requested_tool_calls(_sse_row(text)) == {
        "names": ["mcp__fs__upload_file"], "readable": True, "reason": None,
    }


EVIL_CHUNK = {"choices": [{"delta": {"tool_calls": [
    {"function": {"name": "mcp__evil__y", "arguments": "a\u2028b"}}]}}]}


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\u0085"])
def test_a_raw_unicode_line_separator_inside_json_does_not_split_the_event(separator):
    data = json.dumps(EVIL_CHUNK, ensure_ascii=False).replace("\u2028", separator)
    assert separator in data  # raw, as JSON allows inside a string
    row = _sse_row(f"data: {data}\n\ndata: [DONE]\n\n")
    assert g.requested_tool_calls(row) == {"names": ["mcp__evil__y"], "readable": True, "reason": None}
    assert [v["item"] for v in g.evaluate_request(guardrail(), row)["out_of_spec_calls"]][1:] == ["mcp__evil"]


def test_an_events_data_lines_join_before_parsing():
    data = json.dumps(EVIL_CHUNK)
    half = len(data) // 2
    for ending in ("\n", "\r\n", "\r"):
        text = ending.join([f"data: {data[:half]}", f"data:{data[half:]}", "", "data: [DONE]", "", ""])
        assert g.requested_tool_calls(_sse_row(text)) == {
            "names": ["mcp__evil__y"], "readable": True, "reason": None,
        }


def test_event_data_that_is_not_json_makes_the_response_unreadable():
    text = _stream(ANTHROPIC_STREAM[2], '{"type": "content_block_start", "content_block": {"type": "tool_')
    assert g.requested_tool_calls(_sse_row(text)) == {
        "names": ["mcp__fs__upload_file"], "readable": False, "reason": "RESPONSE_UNPARSABLE_EVENT",
    }


def test_an_html_error_page_is_readable_and_asks_for_nothing():
    page = "<!DOCTYPE html>\r\n<html><body><h1>502 Bad Gateway</h1>\r\ndata loss: none</body></html>\r\n"
    assert g.requested_tool_calls(_sse_row(page, **{"content-type": "text/html"})) == {
        "names": [], "readable": True, "reason": None,
    }


def test_railmons_own_streamed_capture_reads_as_asking_for_nothing():
    # The fixture as RailMon stored it: a stream cut after its first line.
    row = _sse_row()
    assert json.loads(row["raw"])["raw"]["response"]["body"] == {"raw": "event: message_start"}
    assert g.requested_tool_calls(row) == {"names": [], "readable": True, "reason": None}


def test_a_non_streamed_responses_api_output_is_read():
    row = _with_response_tools(capture()[0])
    row["response"]["body"] = {"output": [
        {"type": "message", "content": [{"type": "output_text", "text": "hi"}]},
        {"type": "function_call", "name": "mcp__fs__upload_file", "arguments": "{}"},
    ]}
    assert g.requested_tool_calls(_row(row))["names"] == ["mcp__fs__upload_file"]


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        pytest.param(lambda: _sse_row("data: " + "x" * g.MAX_SCANNED_RESPONSE_BYTES),
                     "RESPONSE_TOO_LARGE", id="too large to scan"),
        pytest.param(lambda: _sse_row(_stream({"type": "ping", "deep": "[" * 200 + "]" * 200}, "[" * 200 + "]" * 200)),
                     "RESPONSE_UNSCANNABLE", id="an event past the depth bound"),
        pytest.param(lambda: _sse_row(_stream(*ANTHROPIC_STREAM), **{"content-encoding": "gzip"}),
                     "RESPONSE_ENCODED", id="compressed"),
        pytest.param(lambda: {"host": "api.anthropic.com", "raw": "{not json"},
                     "UNREADABLE_CAPTURE", id="row unreadable"),
    ],
)
def test_a_response_that_cannot_be_scanned_is_flagged_not_held(row, reason):
    found = g.evaluate_request(guardrail(), row())
    assert found["tool_calls"] == {"readable": False, "reason": reason}
    status = g.request_rules_status(now=NOW, last_heartbeat_at=NOW, last_unattributed_at=None,
                                    last_tool_calls_unreadable_at=NOW)
    states = g.rule_states({"multi_agent": False, "rules": {r: _states()[r] for r in g.ASP_RULES}}, status)
    assert {r: states[r]["reason"] for r in g.REQUEST_RULES} == {r: "TOOL_CALLS_UNREADABLE" for r in g.REQUEST_RULES}
    assert g.agent_state(has_active_guardrail=True, rule_results=states, counting_rows=0) == "unverified"


def _nested(depth: int) -> dict:
    value: dict = {"leaf": True}
    for _ in range(depth - 1):
        value = {"n": value}
    return value


def test_a_deeply_nested_request_body_cannot_hide_the_responses_tool_calls():
    deep = _with_response_tools(capture()[0], "mcp__fs__upload_file")
    deep["request"]["body"] = _nested(130)
    row = _row(deep)
    # Shown as a row, the whole capture is past the 128-level bound...
    assert Store._safe_raw(row["raw"]) == g.UNSAFE_LEGACY_CAPTURE
    # ...but its response is judged on its own, and the body still counts.
    assert g.requested_tool_calls(row) == {"names": ["mcp__fs__upload_file"], "readable": True, "reason": None}
    assert g.carries_body(row) is True
    found = g.evaluate_request(guardrail(), row)
    assert [v["item"] for v in found["uploads"]] == ["mcp__fs__upload_file"]


def test_a_row_too_deep_to_parse_at_all_is_unreadable_not_empty():
    deeper = _with_response_tools(capture()[0], "mcp__fs__upload_file")
    deeper["request"]["body"] = _nested(g.MAX_STORED_ROW_DEPTH + 10)
    assert g.requested_tool_calls(_row(deeper)) == {
        "names": [], "readable": False, "reason": "UNREADABLE_CAPTURE",
    }
