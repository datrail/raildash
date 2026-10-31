"""REST uploads M1: body kinds (REST uploads design §3 and §6).

Every expected kind is written down here, first over the captures in
`fixtures/` (model and MCP traffic, the keyed capture's empty POSTs, a
trimmed SSE request and OpenClaw's start-up calls and model requests), then over bodies shaped as public APIs document them, then
over each bound.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from raildash import body_kinds as bk
from raildash.ingest import legacy_exchange

FIXTURES = Path(__file__).parent / "fixtures"
JSON = {"content-type": "application/json"}
FORM = {"content-type": "application/x-www-form-urlencoded"}


def kind(body, headers=JSON, path="/v1/x", **kwargs):
    return bk.classify(method="POST", host="api.example", path=path, headers=headers,
                       body=body, **kwargs)


def exchanges(name):
    for line in (FIXTURES / name).read_text().splitlines():
        if line.strip():
            yield legacy_exchange(json.loads(line))


# (fixture, the kind of each request that carries a body, in file order)
REAL_CAPTURES = [
    # Claude-shaped model requests and the delivery/context7 MCP calls.
    ("capture.jsonl", ["upload/traffic"] * 5),
    # The railmon demo's MCP calls; the fourth body was kept as text that
    # isn't JSON, so it is unknown, which the rule reads as an upload.
    ("mcp-demo-captures.jsonl", ["upload/traffic"] * 3 + ["unknown/shape", "upload/traffic"]),
    # Trimmed to `model` and `max_tokens`, with no `messages`: not DR-205's
    # model shape, so its two short values are parameters.
    ("sse-capture.jsonl", ["parameters/shape"]),
    ("codex-responses-captures.jsonl", ["upload/traffic"] * 3),
    # Keyed multi-agent capture: three POSTs of `{}`.
    ("keyed-capture.jsonl", ["parameters/shape"] * 3),
    # OpenClaw 2026.10.8, as datrail-project's openclaw jobs run it: the
    # gateway's three start-up GETs carry no body; one exec turn's two
    # chat-completions POSTs, each about 37 KB (over the 16 KiB bound), are
    # model traffic by their shape.
    ("openclaw/captures.jsonl", ["upload/traffic"] * 2),
]


@pytest.mark.parametrize("name,expected", REAL_CAPTURES)
def test_real_captures(name, expected):
    got = []
    for exchange in exchanges(name):
        request = exchange.get("request") or {}
        if request.get("body") in (None, ""):
            continue
        result = bk.classify_exchange(exchange, host="h")
        got.append(f"{result['kind']}/{result['source']}")
    assert got == expected


def test_openclaws_start_up_calls_carry_no_body():
    # Its update check, model catalog and plugin feed: nothing for the
    # classifier, so none of them can count against the uploads rule.
    starts = [e["request"] for e in exchanges("openclaw/captures.jsonl")
              if e["request"]["method"] == "GET"]
    assert [(r["headers"]["host"], r["path"]) for r in starts] == [
        ("telemetry.openclaw.ai", "/api/latest-version"),
        ("catalog.openclaw.ai", "/models/v2/catalog.json"),
        ("clawhub.ai", "/v1/feeds/plugins"),
    ]
    assert not any(bk.request_carries_body(r) for r in starts)
    assert {bk.stored_kind(e) for e in exchanges("openclaw/captures.jsonl")} == {"", "traffic"}


def test_claude_codes_request_is_model_traffic_whatever_its_size():
    request = json.loads((FIXTURES / "claude-code-messages-request.json").read_text())
    result = bk.classify_exchange(legacy_exchange(request), host="api.anthropic.com")
    assert (result["kind"], result["step"], result["reasons"]) == (
        bk.UPLOAD, bk.STEP_NOT_REST, ["model request"])


def test_the_stacks_exfil_post_reads_as_parameters():
    # datrail-project's stack acceptance sends this to an unlisted host as
    # its "upload". By shape it only passes a parameter, so M4 changes it.
    assert kind({"report": "quarterly numbers"})["kind"] == bk.PARAMETERS


# Shaped as each API's public documentation shows its requests.
PUBLIC_SHAPES = [
    ("GitHub GraphQL: a viewer query",
     {"query": "query($n: Int!) { viewer { login repositories(first: $n) { nodes { name } } } }",
      "variables": {"n": 10}}, JSON, bk.PARAMETERS),
    ("GitHub GraphQL: createCommitOnBranch",
     {"query": "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input)"
               " { commit { oid } } }",
      "variables": {"input": {"branch": {"branchName": "main"}, "message": {"headline": "x"}}}},
     JSON, bk.UNKNOWN),
    ("GitHub GraphQL: a fragment and a query",
     {"query": "fragment f on Repository { name }\nquery { viewer { repositories(first: 1)"
               " { nodes { ...f } } } }", "operationName": None}, JSON, bk.PARAMETERS),
    ("a search API's query string member", {"query": "invoices 2026", "limit": 20}, JSON,
     bk.PARAMETERS),
    ("Algolia search", {"params": "query=invoices&hitsPerPage=20"}, JSON, bk.PARAMETERS),
    ("Slack chat.postMessage as a form", {"raw": "channel=C123&text=hello"}, FORM, bk.PARAMETERS),
    # Four containers deep, the query DSL's leaf is the fifth: unknown. A
    # first-cut bound the plan checks against captures (§7).
    ("Elasticsearch bool query",
     {"query": {"bool": {"must": [{"match": {"title": "invoice"}}]}}}, JSON, bk.UNKNOWN),
    ("S3 PutObject", {"raw": "PK\x03\x04..."}, {"content-type": "application/octet-stream"},
     bk.UPLOAD),
    ("a Drive multipart upload", {"raw": "--b\r\n..."},
     {"content-type": "multipart/related; boundary=b"}, bk.UPLOAD),
    ("an image", {"raw": "�PNG"}, {"content-type": "image/png"}, bk.UPLOAD),
]


@pytest.mark.parametrize("what,body,headers,expected", PUBLIC_SHAPES, ids=[p[0] for p in PUBLIC_SHAPES])
def test_public_api_shapes(what, body, headers, expected):
    assert kind(body, headers)["kind"] == expected


# ------------------------------------------------------------- the bounds


def test_strings_up_to_256_characters_are_parameters_and_up_to_1_kib_unknown():
    assert kind({"q": "a" * 256})["kind"] == bk.PARAMETERS
    result = kind({"q": "a" * 257})
    assert (result["kind"], result["step"]) == (bk.UNKNOWN, bk.STEP_OTHER)
    assert kind({"q": "a" * 1024})["kind"] == bk.UNKNOWN


def test_a_string_over_1_kib_is_a_hard_upload_anywhere_even_a_key():
    for body in ({"q": "a" * 1025}, {"a": {"b": ["x", "a" * 1025]}}, {"a" * 1025: 1}):
        result = kind(body)
        assert (result["kind"], result["step"], result["source"]) == (
            bk.UPLOAD, bk.STEP_HARD, bk.SOURCE_HARD)


def test_a_body_over_16_kib_is_a_hard_upload_even_framed_only():
    assert kind({"a": [1] * 9000})["reasons"][0] == "body over 16 KiB"
    # The capture kept two bytes, but the request said it was 20000.
    result = kind({"raw": "{}"}, {**JSON, "content-length": "20000"})
    assert (result["kind"], result["step"], result["bytes"]) == (bk.UPLOAD, bk.STEP_HARD, 20000)
    assert kind({}, framed=20000)["kind"] == bk.UPLOAD


def test_json_parameters_bounds_size_values_and_depth():
    assert kind({"k": ["x" * 50] * 64})["kind"] == bk.PARAMETERS  # 64 values, under 4 KiB
    assert kind({"k": [1] * 65})["reasons"] == ["JSON with over 64 values"]
    assert kind({"k": ["x" * 200] * 21})["reasons"] == ["JSON over 4 KiB"]
    assert kind({"a": {"b": {"c": {"d": 1}}}})["kind"] == bk.PARAMETERS
    assert kind({"a": {"b": {"c": {"d": {}}}}})["reasons"] == ["JSON with nested over 4 deep"]
    assert kind({})["kind"] == bk.PARAMETERS
    assert kind({"k": None, "b": True, "n": 1.5})["kind"] == bk.PARAMETERS


def test_what_isnt_a_json_object_or_form_is_unknown():
    assert kind({"raw": "[1, 2]"})["reasons"] == ["JSON, not an object"]
    assert kind({"raw": "hello"}, {"content-type": "text/plain"})["reasons"] == ["text/plain body"]
    assert kind({"raw": "not json"})["reasons"] == ["not JSON"]
    assert kind(None, {"content-length": "12"})["reasons"] == ["body not kept by the capture"]
    # Text over 1 KiB is one long string: a hard upload.
    assert kind({"raw": "x" * 1100}, {"content-type": "text/plain"})["step"] == bk.STEP_HARD


def test_a_kept_text_that_parses_as_a_json_object_is_read_as_one():
    assert kind({"raw": '{"q": "x"}'})["kind"] == bk.PARAMETERS


def test_forms():
    assert kind({"raw": "a=1&b="}, FORM)["reasons"] == ["form, 2 short values"]
    assert kind({"raw": "a=" + "x" * 257}, FORM)["kind"] == bk.UNKNOWN
    assert kind({"raw": "a=" + "x" * 1025}, FORM)["step"] == bk.STEP_HARD
    assert kind({"raw": "&".join(f"k{i}=1" for i in range(65))}, FORM)["kind"] == bk.UNKNOWN
    assert kind({"raw": "no-equals-sign"}, FORM)["reasons"] == ["not a urlencoded form"]
    assert kind({"raw": "&".join(f"k{i}={'x' * 200}" for i in range(21))}, FORM)["kind"] == bk.UNKNOWN
    # A form whose text is over 1 KiB but whose values are short isn't one long string.
    many = "&".join(f"key{i}=value-{i:010d}" for i in range(50))
    assert len(many) > 1024 and kind({"raw": many}, FORM)["kind"] == bk.PARAMETERS


def test_media_types_are_hard_uploads():
    for mtype in ("multipart/form-data; boundary=x", "application/octet-stream", "image/jpeg",
                  "audio/wav", "video/mp4", "application/pdf", "application/zip",
                  "Application/PDF"):
        assert kind({"q": "x"}, {"content-type": mtype})["step"] == bk.STEP_HARD, mtype


def test_a_coalesced_content_type_with_a_file_type_is_a_hard_upload():
    result = kind({"q": "x"}, {"content-type": "application/json, multipart/form-data; boundary=b"})
    assert (result["kind"], result["step"]) == (bk.UPLOAD, bk.STEP_HARD)
    assert kind({"q": "x"}, {"content-type": "application/json, text/plain"})["reasons"] == [
        "two content types"]


def test_an_encoded_body_is_unknown():
    assert kind({"q": "x"}, {**JSON, "content-encoding": "gzip"})["reasons"] == ["gzip-encoded body"]
    assert kind({"q": "x"}, {**JSON, "content-encoding": "identity"})["kind"] == bk.PARAMETERS


def exchange(body, headers=JSON, **extra):
    return {"request": {"method": "POST", "path": "/v1/q", "headers": headers, "body": body,
                        **extra.pop("request", {})}, **extra}


def test_the_exchanges_own_size_counts_when_the_kept_body_is_smaller():
    # `{"q": "<100 KB>", "q": "x"}` sent chunked: the parser kept the last key.
    sent = exchange({"q": "x"}, request={"first_line": "POST /v1/q HTTP/1.1"}, request_size=100_200)
    result = bk.classify_exchange(sent, host="h")
    assert (result["kind"], result["step"]) == (bk.UPLOAD, bk.STEP_HARD)
    # The parser's own content_length counts too.
    assert bk.classify_exchange(exchange({"q": "x"}, request={"content_length": 20_000}),
                                host="h")["step"] == bk.STEP_HARD
    # A small request's head is not counted as body.
    small = exchange({"q": "x"}, request={"first_line": "POST /v1/q HTTP/1.1"}, request_size=80)
    assert bk.classify_exchange(small, host="h")["kind"] == bk.PARAMETERS
    # With content_length kept, stripped credential headers don't count as body.
    authed = exchange({"q": "invoices", "limit": 10},
                      request={"first_line": "POST /v1/q HTTP/1.1", "content_length": 27},
                      request_size=27 + 4000)
    result = bk.classify_exchange(authed, host="h")
    assert (result["kind"], result["bytes"]) == (bk.PARAMETERS, 27)
    assert bk.body_bytes({"a": 1}, {}, 20000.0) == 20000
    assert bk.body_bytes({"a": 1}, {"Content-Length": 99999}) == 99999


def test_a_repeated_key_hides_nothing():
    # `{"note": "<900 x A>", "note": "ok"}`: kept as text, it doesn't parse.
    text = '{"note": "' + "A" * 900 + '", "note": "ok"}'
    assert kind({"raw": text})["reasons"] == ["a repeated JSON key"]
    assert kind({"raw": text}, {"content-type": "text/plain"})["kind"] == bk.UNKNOWN
    # Kept parsed (RailMon's parser kept the last), the exact length shows it.
    assert kind({"note": "ok"}, exact=len(text))["reasons"] == ["more sent than was kept"]
    assert kind({"note": "ok"}, {**JSON, "content-length": str(len(text))})["kind"] == bk.UNKNOWN
    # The estimate from request_size, which stripped headers inflate, doesn't.
    assert kind({"note": "ok"}, framed=len(text))["kind"] == bk.PARAMETERS
    # Pretty-printed or ASCII-escaped bodies are not mistaken for it.
    body = {"query": "naïve café", "filters": {"year": 2026, "tags": ["a", "b"]}, "limit": 10}
    for sent in (json.dumps(body, indent=4), json.dumps(body)):
        assert kind(body, exact=len(sent.encode()))["kind"] == bk.PARAMETERS


def test_hostile_texts_are_read_in_linear_time():
    import time
    start = time.monotonic()
    assert kind({"query": "#\n" * 1_000_000})["step"] == bk.STEP_HARD
    assert bk.path_template("/" + "a1" * 50_000 + "!") .startswith("/a1")
    assert time.monotonic() - start < 2


def test_with_no_recorded_size_a_body_isnt_parameters():
    assert bk.classify_exchange(exchange({"q": "x"}), host="h")["reasons"] == [
        "body size not recorded"]
    assert bk.classify_exchange(exchange({"q": "x"}, {**JSON, "content-length": "9"}),
                                host="h")["kind"] == bk.PARAMETERS


def test_the_exchanges_path_is_read_as_ingest_reads_it():
    for request in ({"path": None, ":path": "/v1/files/7"},
                    {"path": None, "uri": "/v1/files/7"},
                    {"path": "https://api.example/v1/files/7?x=1"}):
        result = bk.classify_exchange(exchange({"q": "x"}, {**JSON, "content-length": "9"},
                                               request=request), host="h")
        assert result["path_template"] == "/v1/files/*"


# ---------------------------------------------------------------- GraphQL


def gql(query, **extra):
    return kind({"query": query, **extra})


def test_graphql_query_text_is_exempt_from_the_1_kib_string_up_to_4_kib():
    fields = " ".join(f"field{i}" for i in range(150))  # about 1.4 KiB
    assert gql("{ viewer { " + fields + " } }")["kind"] == bk.PARAMETERS
    # Past 4 KiB, or not a query-only document, the text is one more long
    # string: a hard upload that no override can clear.
    big = " ".join(f"field{i}" for i in range(500))
    assert gql("{ viewer { " + big + " } }")["step"] == bk.STEP_HARD
    overrides = [{"host": "api.example", "method": "POST", "path": "/v1/x", "kind": "parameters"}]
    for query in ("{ a }#" + "Z" * 1500, 'mutation { a(s: "' + "Z" * 1500 + '") }'):
        result = kind({"query": query}, overrides=overrides)
        assert (result["kind"], result["step"]) == (bk.UPLOAD, bk.STEP_HARD)


def test_comments_before_a_graphql_document_are_read_in_linear_time():
    import time
    start = time.monotonic()
    for text in ("#" * 5000, "# \n" * 2000 + "x", "#    \n" * 2000 + "x"):
        assert gql(text)["kind"] != bk.PARAMETERS
    assert time.monotonic() - start < 1
    assert bk.looks_like_graphql({"query": "# c\r\n  # d\n query { a }"})


def test_graphql_operations_other_than_queries_are_unknown():
    assert gql("subscription { s }")["reasons"] == ["a GraphQL subscription"]
    assert gql("query a { x } mutation b { y }")["reasons"] == ["a GraphQL mutation"]
    assert gql("{ a } { b }")["kind"] == bk.PARAMETERS  # two anonymous queries
    assert gql("# leading comment\nquery { a(s: \"}\") }")["kind"] == bk.PARAMETERS


@pytest.mark.parametrize("query", [
    "{ a ", "{ a ) }", "query ( { a }", "query", "{ a } extra", "{ a } type T { x: Int }",
    "{ a ^ }",
])
def test_a_document_that_doesnt_parse_is_unknown(query):
    assert gql(query)["kind"] == bk.UNKNOWN


def test_graphql_variables_are_held_to_the_parameters_bounds():
    assert gql("{ a }", variables={"x": "y" * 257})["reasons"] == [
        "GraphQL variables: a string over 256 characters"]
    assert gql("{ a }", variables=[1])["kind"] == bk.UNKNOWN
    # A long string in the variables is still a hard upload.
    assert gql("{ a }", variables={"x": "y" * 1025})["step"] == bk.STEP_HARD
    assert gql("{ a }", operationName="A" * 300)["kind"] == bk.UNKNOWN


def test_a_query_member_that_isnt_graphql_is_an_ordinary_json_member():
    assert kind({"query": "x" * 1025})["step"] == bk.STEP_HARD
    assert kind({"query": "{ a }", "other": 1})["kind"] == bk.PARAMETERS  # not GraphQL's members


# ------------------------------------------------------- traffic, overrides


def test_model_and_mcp_bodies_are_never_classified():
    for body in ({"model": "m", "messages": []}, {"model": "m", "input": "hi"},
                 {"jsonrpc": "2.0", "method": "tools/call"},
                 {"raw": '[{"jsonrpc": "2.0", "method": "ping"}]'}):
        result = kind(body)
        assert (result["kind"], result["source"]) == (bk.UPLOAD, bk.SOURCE_TRAFFIC)


def test_a_large_mcp_batch_is_still_mcp_traffic_and_large_text_isnt_parsed():
    batch = json.dumps([{"jsonrpc": "2.0", "id": i, "method": "tools/call",
                         "params": {"name": "t", "arguments": {"x": "y" * 100}}} for i in range(200)])
    result = kind({"raw": batch})
    assert (result["kind"], result["source"], result["reasons"]) == (
        bk.UPLOAD, bk.SOURCE_TRAFFIC, ["MCP message"])
    result = kind({"raw": "--b\r\n" + "x" * 20_000}, {"content-type": "multipart/form-data; boundary=b"})
    assert result["reasons"] == ["multipart/form-data body", "body over 16 KiB"]


@pytest.mark.parametrize("path,template", [
    ("/v1/files/123", "/v1/files/*"),
    ("/v1/files/123?x=1", "/v1/files/*"),
    ("/v1/items/0b4f6e2e-1f0a-4c55-9d1b-6a8c3d2e1f00/tags", "/v1/items/*/tags"),
    ("/v1/doc/AbCdEfGh1jKlMnOpQrStUv", "/v1/doc/*"),
    # A long name with no digit is a name: an override on one isn't on the other.
    ("/api/searchDocumentsQuickly", "/api/searchDocumentsQuickly"),
    ("/api/uploadDocumentContents", "/api/uploadDocumentContents"),
    ("/v1/doc/a1b2c3d4e5f6a7b8c9d0e1", "/v1/doc/*"),
    ("/v1/conversations-and-messages-search", "/v1/conversations-and-messages-search"),
    ("/v1/search", "/v1/search"),
    ("", "/"),
    (None, "/"),
])
def test_path_templates(path, template):
    assert bk.path_template(path) == template


def test_an_override_decides_after_the_hard_signals_and_before_the_shape():
    overrides = [{"host": "api.example", "method": "post", "path": "/v1/files/*", "kind": "upload"},
                 {"host": "api.example", "method": "POST", "path": "/v1/q", "kind": "parameters"}]
    result = kind({"q": "x"}, path="/v1/files/42", overrides=overrides)
    assert (result["kind"], result["source"], result["step"]) == (bk.UPLOAD, bk.SOURCE_USER,
                                                                  bk.STEP_OVERRIDE)
    assert kind({"raw": "not json"}, path="/v1/q", overrides=overrides)["kind"] == bk.PARAMETERS
    # Nothing overrules a hard signal.
    assert kind({"q": "x" * 2000}, path="/v1/q", overrides=overrides)["step"] == bk.STEP_HARD
    # An unknown host matches no override.
    assert bk.classify(method="POST", host=None, path="/v1/q", headers=JSON, body={"raw": "x"},
                       overrides=[{"method": "POST", "path": "/v1/q", "kind": "parameters"}]
                       )["kind"] == bk.UNKNOWN
    # Another host, method or path isn't the override's.
    assert kind({"raw": "not json"}, path="/v1/q2", overrides=overrides)["kind"] == bk.UNKNOWN
    other = bk.classify(method="PUT", host="api.example", path="/v1/q", headers=JSON,
                        body={"raw": "x"}, overrides=overrides)
    assert other["kind"] == bk.UNKNOWN


# ------------------------------------------------------------ drip check


def params(size):
    return {"kind": bk.PARAMETERS, "source": bk.SOURCE_SHAPE, "step": bk.STEP_SHAPE,
            "reasons": ["JSON object"], "bytes": size}


def test_drip_past_an_entrys_day_budget_turns_parameters_into_uploads():
    budget = bk.ParametersBudget(entry_budget=1000, agent_budget=10_000)
    assert budget.observe(params(600), ["*.workers.dev"], 0)["kind"] == bk.PARAMETERS
    over = budget.observe(params(600), ["*.workers.dev"], 10)
    assert (over["kind"], over["step"]) == (bk.UPLOAD, bk.STEP_DRIP)
    assert over["reasons"] == ["parameters volume over 1000 bytes a day to *.workers.dev",
                               "JSON object"]
    assert over["drip"] == {"entries": {"*.workers.dev": 600}, "agent": 600, "bytes": 600}
    # Another entry has its own budget.
    assert budget.observe(params(600), ["api.example"], 20)["kind"] == bk.PARAMETERS
    # A day after the first, its bytes have left the sum.
    assert budget.observe(params(600), ["*.workers.dev"], bk.DAY_SECONDS)["kind"] == bk.PARAMETERS


def test_drip_default_budgets_and_reasons():
    budget = bk.ParametersBudget()
    for i in range(64):
        assert budget.observe(params(4096), ["a.example"], i)["kind"] == bk.PARAMETERS
    over = budget.observe(params(4096), ["a.example"], 64)
    assert over["reasons"][0] == "parameters volume over 256 KiB a day to a.example"
    for i, host in enumerate(f"h{n}.example" for n in range(3 * 64)):
        budget.observe(params(4096), [host], 100 + i)
    over = budget.observe(params(4096), ["fresh.example"], 1000)
    assert over["reasons"] == ["parameters volume over 1 MiB a day for the agent", "JSON object"]


def test_drip_a_raised_entry_budget_and_other_kinds_pass_through():
    budget = bk.ParametersBudget(entry_budgets={"big.example": 5000}, entry_budget=1000)
    assert budget.observe(params(4000), ["big.example"], 0)["kind"] == bk.PARAMETERS
    upload = {**params(9999), "kind": bk.UPLOAD}
    assert budget.observe(upload, ["small.example"], 1) == upload
    assert budget.observe(params(900), ["small.example"], 2)["kind"] == bk.PARAMETERS


def test_drip_counts_once_per_entry_the_host_matches():
    budget = bk.ParametersBudget(entry_budget=1000, agent_budget=10_000)
    budget.observe(params(800), ["*.example", "api.example"], 0)
    assert budget.observe(params(300), ["*.example"], 1)["kind"] == bk.UPLOAD
    assert budget.observe(params(300), ["api.example"], 2)["kind"] == bk.UPLOAD
    assert budget.observe(params(300), ["other.test"], 3)["kind"] == bk.PARAMETERS
