"""REST uploads M3: an OpenAPI spec imported per host (design §3 step 3,
§4 "Specs", §6 "Specs").

The specs are public: an excerpt of GitHub's REST API description and the
Swagger Petstore (tests/fixtures/openapi/README.md says where from). Each
data-carrying operation must make its requests uploads, however small, and
every other operation must leave the body's shape to decide.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raildash import api_specs as a
from raildash import app as app_module
from raildash import body_kinds as bk
from raildash import guardrail as g
from raildash.store import Store
from test_guardrail import store  # noqa: F401
from test_guardrail_body_kinds import rest
from test_guardrail_custody import baseline, live, rows, send
from test_guardrail_narrow_uploads import now

FIXTURES = Path(__file__).parent / "fixtures" / "openapi"
GITHUB = (FIXTURES / "github-excerpt.json").read_bytes()
PETSTORE = (FIXTURES / "petstore3.json").read_bytes()
GH = "api.github.com"
PET = "petstore3.swagger.io"
FILE_PUT = {"message": "add notes", "content": "bm90ZXM="}  # a tiny file, base64


@pytest.fixture(autouse=True)
def body_kinds_on(monkeypatch):
    monkeypatch.setenv(g.BODY_KINDS_ENV, "on")


@pytest.fixture(scope="module")
def github() -> dict:
    return a.parse_spec(GITHUB)


@pytest.fixture(scope="module")
def petstore() -> dict:
    return a.parse_spec(PETSTORE)


def spec(paths: dict, **extra) -> bytes:
    return json.dumps({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": paths,
                       **extra}).encode()


def body_op(content: dict, method: str = "post") -> dict:
    return {method: {"operationId": "op", "requestBody": {"content": content}, "responses": {}}}


# ------------------------------------------------------------------ parse


def test_the_public_specs_index_their_operations_and_upload_marks(github, petstore):
    assert a.summary(github)["operations"] == 7 and a.summary(github)["title"] == "GitHub v3 REST API"
    marked = {op["operation_id"] for op in github["operations"] if any(op["media"].values())}
    # A file's base64 `content`, and an issue's `body` text: content sent.
    assert marked == {"repos/create-or-update-file-contents", "issues/create"}
    assert petstore["base_paths"] == ["/api/v3"]
    assert {op["operation_id"] for op in petstore["operations"] if any(op["media"].values())} == {"uploadFile"}
    assert github["sha256"] == __import__("hashlib").sha256(GITHUB).hexdigest()


@pytest.mark.parametrize("raw, problem", [
    (b"", "empty"),
    (b"\xff\xfe", "not UTF-8"),
    (b"{not json", "not valid JSON"),
    (b"- a\n- b\n", "isn't a mapping"),
    (b'{"swagger": "2.0", "paths": {}}', "Swagger 2.0"),
    (b'{"openapi": "2.0", "paths": {}}', "no `openapi: 3.x`"),
    (b'{"openapi": "3.1.0"}', "no `paths`"),
    (b"openapi: 3.0.0\npaths: &p {}\nother: *p\n", "aliases are not accepted"),
    (b"openapi: 3.0.0\nopenapi: 3.1.0\npaths: {}\n", "duplicate key"),
])
def test_a_file_that_isnt_an_openapi_3_spec_is_refused_with_why(raw, problem):
    with pytest.raises(a.SpecImportError, match=problem):
        a.parse_spec(raw)


def test_size_and_operation_bounds(monkeypatch):
    monkeypatch.setattr(a, "MAX_SPEC_BYTES", 10)
    with pytest.raises(a.SpecImportError, match="over"):
        a.parse_spec(b'{"openapi": "3.0.0", "paths": {}}')
    monkeypatch.setattr(a, "MAX_SPEC_BYTES", 1024 * 1024)
    monkeypatch.setattr(a, "MAX_OPERATIONS", 2)
    with pytest.raises(a.SpecImportError, match="more than 2 operations"):
        a.parse_spec(spec({"/a": {"get": {}, "post": {}}, "/b": {"get": {}}}))


def test_yaml_specs_read_as_json_does():
    raw = b"""openapi: 3.0.3
info: {title: files, version: '2'}
paths:
  /v1/files:
    post:
      operationId: uploadFile
      requestBody:
        content:
          multipart/form-data:
            schema: {type: object, properties: {file: {type: string, format: binary}}}
"""
    [op] = a.parse_spec(raw)["operations"]
    assert op["media"]["multipart/form-data"] == ["takes multipart/form-data"]


def test_schema_marks_follow_refs_and_combinators_and_stop_on_cycles():
    components = {"schemas": {
        "Node": {"type": "object", "properties": {"name": {"type": "string"},
                                                  "children": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}}}},
        "Blob": {"type": "string", "format": "byte"},
        "Wrapped": {"allOf": [{"$ref": "#/components/schemas/Node"},
                              {"type": "object", "properties": {"payload": {"$ref": "#/components/schemas/Blob"}}}]},
    }}
    raw = spec({
        "/tree": body_op({"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}),
        "/wrapped": body_op({"application/json": {"schema": {"$ref": "#/components/schemas/Wrapped"}}}),
        "/remote": body_op({"application/json": {"schema": {"$ref": "other.yaml#/Thing"}}}),
    }, components=components)
    ops = {op["path"]: op["media"]["application/json"] for op in a.parse_spec(raw)["operations"]}
    assert ops["/tree"] == []  # recursive, nothing carried: terminates, shape decides
    assert ops["/wrapped"] == ['property "payload" is format byte']
    # What a remote reference holds can't be read: fail closed.
    assert ops["/remote"] == ["request schema too large or not readable to the end"]


def test_a_schema_past_the_walk_bound_is_marked(monkeypatch):
    monkeypatch.setattr(a, "MAX_SCHEMA_NODES", 3)
    props = {f"k{i}": {"type": "string"} for i in range(10)}
    [op] = a.parse_spec(spec({"/q": body_op({"application/json": {"schema": {"properties": props}}})}))["operations"]
    assert op["media"]["application/json"] == ["request schema too large or not readable to the end"]


# ------------------------------------------------------------------ match


@pytest.mark.parametrize("method, path, operation", [
    ("PUT", "/repos/o/r/contents/notes.md", "repos/create-or-update-file-contents"),
    # GitHub's `{path}` takes slashes, so the last parameter takes the rest.
    ("PUT", "/repos/o/r/contents/docs/a/notes.md", "repos/create-or-update-file-contents"),
    ("POST", "/repos/o/r/issues", "issues/create"),
    ("POST", "/repos/o/r/issues/12/labels", "issues/add-labels"),
    ("post", "/markdown?x=1", "markdown/render"),
    ("GET", "/search/issues", "search/issues-and-pull-requests"),
    ("DELETE", "/repos/o/r/issues", None),
    ("POST", "/nowhere", None),
    ("POST", "/repos/o/r/issues/", "issues/create"),
])
def test_requests_match_operations(github, method, path, operation):
    found = a.match(github, method, path)
    assert (found and found["operation_id"]) == operation


def test_the_servers_base_path_is_stripped_and_literals_beat_parameters(petstore):
    assert a.match(petstore, "POST", "/api/v3/pet/7/uploadImage")["operation_id"] == "uploadFile"
    assert a.match(petstore, "POST", "/api/v3/pet")["operation_id"] == "addPet"
    assert a.match(petstore, "GET", "/api/v3/pet/findByStatus")["operation_id"] == "findPetsByStatus"
    assert a.match(petstore, "GET", "/api/v3/pet/12")["operation_id"] == "getPetById"


def test_the_requests_media_type_picks_the_entry():
    [op] = a.parse_spec(spec({"/v1/notes": body_op({
        "application/json": {"schema": {"properties": {"title": {"type": "string"}}}},
        "multipart/form-data": {"schema": {"properties": {"title": {"type": "string"}}}},
    })}))["operations"]
    assert a.upload_reasons(op, ["application/json"]) == []
    assert a.upload_reasons(op, ["multipart/form-data"]) == ["spec op: takes multipart/form-data"]
    # No media type sent, or one the spec doesn't list: every entry counts.
    assert a.upload_reasons(op, []) == ["spec op: takes multipart/form-data"]
    assert a.upload_reasons(op, ["text/csv"]) == ["spec op: takes multipart/form-data"]


# ------------------------------------------------------------ classifier


def classify(index, method, path, body, content_type="application/json", overrides=()):
    text = body if isinstance(body, str) else json.dumps(body)
    return bk.classify(method=method, host=GH, path=path,
                       headers={"content-type": content_type, "content-length": str(len(text))},
                       body=body, overrides=overrides, spec=index)


def test_a_data_carrying_operation_makes_a_small_body_an_upload(github, petstore):
    without = classify(None, "PUT", "/repos/o/r/contents/notes.md", FILE_PUT)
    assert without["kind"] == bk.PARAMETERS
    found = classify(github, "PUT", "/repos/o/r/contents/notes.md", FILE_PUT)
    assert (found["kind"], found["source"], found["step"]) == (bk.UPLOAD, bk.SOURCE_SPEC, bk.STEP_SPEC)
    assert found["reasons"] == ['spec repos/create-or-update-file-contents: property "content"']
    issue = classify(github, "POST", "/repos/o/r/issues", {"title": "t", "body": "patient list"})
    assert issue["kind"] == bk.UPLOAD
    image = classify(petstore, "POST", "/api/v3/pet/7/uploadImage", "PNG", "application/octet-stream")
    assert image["kind"] == bk.UPLOAD and image["step"] == bk.STEP_HARD  # the media type alone says so


def test_any_other_operation_leaves_the_shape_to_decide_and_is_named(github, petstore):
    found = classify(github, "POST", "/markdown", {"text": "Hello **world**", "mode": "gfm"})
    assert found["kind"] == bk.PARAMETERS and found["step"] == bk.STEP_SHAPE
    assert found["reasons"][-1] == "spec operation markdown/render"
    pet = classify(petstore, "POST", "/api/v3/pet", {"name": "doggie", "photoUrls": ["u"]})
    assert pet["kind"] == bk.PARAMETERS


def test_a_spec_never_makes_a_body_parameters(github):
    deep = {"text": {"a": {"b": {"c": {"d": 1}}}}}
    assert classify(github, "POST", "/markdown", deep)["kind"] == bk.UNKNOWN
    assert classify(github, "POST", "/markdown", "x" * 20000, "text/plain")["kind"] == bk.UPLOAD


def test_the_users_answer_comes_before_the_spec(github):
    answer = [{"host": GH, "method": "PUT", "path": "/repos/o/r/contents/notes.md", "kind": "parameters"}]
    found = classify(github, "PUT", "/repos/o/r/contents/notes.md", FILE_PUT, overrides=answer)
    assert found["kind"] == bk.PARAMETERS and found["step"] == bk.STEP_OVERRIDE


def test_the_proposals_window_reads_specs(github):
    requests = [rest(GH, FILE_PUT, path="/repos/o/r/contents/notes.md", method="PUT")]
    budget = lambda: bk.ParametersBudget()  # noqa: E731
    [plain] = g.window_body_kinds(requests, call_hosts=[], budget=budget())
    [spec_read] = g.window_body_kinds(requests, call_hosts=[], budget=budget(), specs={GH: github})
    assert plain["kind"] == bk.PARAMETERS and spec_read["kind"] == bk.UPLOAD


# ------------------------------------------------------------- store


def _agent(store):  # noqa: F811
    alignment, ref = baseline(store)
    live(store)
    rules = store.propose_guardrail(alignment["alignment_version_id"])["guardrail"]["rules"]
    rules["out_of_spec_calls"]["allowed_hosts"] = sorted({*rules["out_of_spec_calls"]["allowed_hosts"], GH})
    store.adopt_guardrail(alignment["alignment_version_id"], rules)
    return ref


def test_an_imported_spec_judges_later_requests_to_its_host(store):  # noqa: F811
    ref = _agent(store)
    send(store, now(GH, FILE_PUT, path="/repos/o/r/contents/a.md", method="PUT"))
    assert ("uploads", GH) not in rows(store, ref)
    made = store.import_api_spec(GH, GITHUB)
    assert made["host"] == GH and made["operations"] == 7 and made["upload_operations"] == 2
    send(store, now(GH, FILE_PUT, path="/repos/o/r/contents/b.md", method="PUT"))
    row = rows(store, ref)[("uploads", GH)]
    assert row["counts"]
    [body] = row["detail"]["bodies"]
    assert body["step"] == bk.STEP_SPEC and "content" in body["reasons"][0]
    # A query to an operation without a mark still isn't an upload.
    send(store, now(GH, {"text": "hi"}, path="/markdown"))
    assert len(rows(store, ref)[("uploads", GH)]["detail"]["bodies"]) == 1
    [listed] = store.api_spec_list()
    assert listed["host"] == GH and listed["current"] is True
    store.remove_api_spec(GH)
    assert store.api_spec_list() == []
    with pytest.raises(KeyError):
        store.remove_api_spec(GH)


@pytest.mark.parametrize("host", ["API.github.com", "*.github.com", "https://api.github.com", "", "a b"])
def test_a_spec_is_for_one_normalized_host(store, host):  # noqa: F811
    with pytest.raises(a.SpecImportError, match="one normalized host"):
        store.import_api_spec(host, GITHUB)


def test_a_new_import_replaces_the_hosts_spec(store):  # noqa: F811
    store.import_api_spec(PET, GITHUB)
    store.import_api_spec(PET, PETSTORE)
    [listed] = store.api_spec_list()
    assert listed["title"].startswith("Swagger Petstore")


# ------------------------------------------------------------ routes


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = Store(tmp_path / "routes.db")
    monkeypatch.setattr(app_module, "store", db)
    yield TestClient(app_module.app)
    db.close()


def auth():
    return {"X-RailDash-Token": app_module.LOCAL_TOKEN}


def test_routes_import_list_and_remove_behind_the_token(client):
    assert client.post(f"/api/api-specs?host={GH}", content=GITHUB).status_code in (401, 403)
    assert client.get("/api/api-specs").status_code in (401, 403)
    res = client.post(f"/api/api-specs?host={GH}", content=GITHUB, headers=auth())
    assert res.status_code == 201, res.text
    assert res.json()["upload_operations"] == 2
    assert [s["host"] for s in client.get("/api/api-specs", headers=auth()).json()["specs"]] == [GH]
    assert client.delete(f"/api/api-specs/{GH}").status_code in (401, 403)
    assert client.delete(f"/api/api-specs/{GH}", headers=auth()).status_code == 200
    assert client.delete(f"/api/api-specs/{GH}", headers=auth()).status_code == 404


def test_routes_refuse_a_bad_file_or_host_with_422(client):
    bad = client.post(f"/api/api-specs?host={GH}", content=b'{"swagger": "2.0"}', headers=auth())
    assert bad.status_code == 422 and "Swagger 2.0" in bad.json()["detail"]
    assert client.post("/api/api-specs?host=*.github.com", content=GITHUB, headers=auth()).status_code == 422
    assert client.post("/api/api-specs", content=GITHUB, headers=auth()).status_code == 422
