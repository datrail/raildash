"""DR-205 M1: classifying tools into data actions (data-actions design §4.2)."""

from __future__ import annotations

import json

import pytest

from raildash import data_actions as da

OBJ = {"type": "object"}


def schema(description=None, properties=None, annotations=None, **extra):
    input_schema = {"type": "object", "properties": properties or {}, **extra}
    return {"description": description, "input_schema": input_schema, "annotations": annotations}


def actions(tool, *schemas, **kwargs):
    return da.classify(tool, list(schemas) or [schema()], **kwargs)["actions"]


# What each tool of a few public MCP servers should be, written down once
# (design §6 step 1). Names are the servers' own; arguments are the ones
# that decide the answer.
PUBLIC_SERVERS = [
    # GitHub
    ("create_or_update_file", schema("Create or update a single file in a GitHub repository",
                                     {"content": {"type": "string"}, "repo": {"type": "string"}}),
     ["upload", "update"]),
    ("push_files", schema("Push multiple files to a GitHub repository in a single commit",
                          {"files": {"type": "array"}, "repo": {"type": "string"}}),
     ["upload", "update"]),
    ("search_repositories", schema("Search for GitHub repositories", {"query": {"type": "string"}}),
     ["read"]),
    ("get_file_contents", schema("Get the contents of a file or directory",
                                 {"path": {"type": "string"}}), ["read"]),
    ("create_issue", schema("Create a new issue in a GitHub repository",
                            {"title": {"type": "string"}, "body": {"type": "string"}}), ["upload"]),
    ("list_issues", schema("List issues in a GitHub repository", {"state": {"type": "string"}}),
     ["read"]),
    ("fork_repository", schema("Fork a GitHub repository to your account",
                               {"owner": {"type": "string"}}), ["upload"]),
    ("delete_branch", schema("Delete a branch", {"branch": {"type": "string"}}), ["delete"]),
    # Filesystem
    ("read_file", schema("Read the complete contents of a file", {"path": {"type": "string"}}),
     ["read"]),
    ("write_file", schema("Create a new file or completely overwrite an existing file",
                          {"path": {"type": "string"}, "content": {"type": "string"}}),
     ["upload", "update"]),
    ("edit_file", schema("Make line-based edits to a text file", {"edits": {"type": "array"}}),
     ["update"]),
    ("move_file", schema("Move or rename files and directories",
                         {"source": {"type": "string"}, "destination": {"type": "string"}}),
     ["update"]),
    ("list_allowed_directories", schema("Returns the list of directories this server can access"),
     ["read"]),
    # Google Drive
    ("gdrive_search", schema("Search for files in Google Drive", {"query": {"type": "string"}}),
     ["read"]),
    ("gdrive_read_file", schema("Read contents of a file from Google Drive",
                                {"fileId": {"type": "string"}}), ["read"]),
    # Slack
    ("slack_post_message", schema("Post a new message to a Slack channel",
                                  {"channel_id": {"type": "string"}, "text": {"type": "string"}}),
     ["upload"]),
    ("slack_get_channel_history", schema("Get recent messages from a channel",
                                         {"channel_id": {"type": "string"}}), ["read"]),
    ("slack_add_reaction", schema("Add a reaction emoji to a message",
                                  {"reaction": {"type": "string"}}), ["upload"]),
]


@pytest.mark.parametrize("tool,tool_schema,expected", PUBLIC_SERVERS, ids=[p[0] for p in PUBLIC_SERVERS])
def test_public_mcp_server_tools(tool, tool_schema, expected):
    result = da.classify(tool, [tool_schema])
    assert result["actions"] == expected
    assert result["unclassified"] is (expected == [])
    assert result["reasons"] or expected == []


def test_mcp_prefixes_are_not_read_as_words():
    assert da.tool_part("mcp__github__create_issue") == "create_issue"
    assert da.tool_part("provider-mcp__Docs_Hub__read_doc") == "read_doc"
    assert da.tool_part("mcp@docs.example.com/mcp__upload_file") == "upload_file"
    # A server named after a verb doesn't classify its tools.
    assert actions("mcp__delete__frobnicate_repository") == []
    assert da.words("createIssue") == ["create", "issue"]


def test_the_description_is_read_only_when_the_name_has_no_verb():
    assert actions("notes", schema("Upload the notes. Then list them.")) == ["upload"]
    # The name's verb wins; the description's isn't added.
    assert actions("get_notes", schema("Upload nothing; this reads.")) == ["read"]


def test_a_data_carrying_argument_makes_an_upload_whatever_the_name_says():
    for spec in ({"type": "string", "format": "binary"}, {"type": "string", "contentEncoding": "base64"},
                 {"type": "string", "contentMediaType": "image/png"}):
        result = da.classify("get_status", [schema(properties={"blob_x": spec})])
        assert result["actions"] == ["read", "upload"]
    assert actions("sync_notes", schema(properties={"content": {"type": "string"}})) == ["upload"]


def test_only_an_explicitly_loose_schema_is_an_upload():
    assert actions("get_me", {"description": None, "input_schema": OBJ, "annotations": None}) == ["read"]
    assert actions("get_me", schema()) == ["read"]
    assert actions("get_me", schema(additionalProperties=False)) == ["read"]
    assert actions("get_me", schema(additionalProperties=True)) == ["read", "upload"]
    assert actions("get_me", schema(additionalProperties={"type": "string"})) == ["read", "upload"]
    assert actions("get_me", schema(patternProperties={"^x": {}})) == ["read", "upload"]


def test_hints_only_add_and_a_hinted_read_is_weak():
    hinted = da.classify("sync_notes", [schema(annotations={"readOnlyHint": True})])
    assert hinted["actions"] == ["read"] and hinted["weak_read"] and not hinted["unclassified"]
    assert hinted["sources"] == {"read": ["annotation"]}
    # A readOnly hint can't hide an upload argument.
    lying = da.classify("sync_notes", [schema(properties={"content": {}}, annotations={"readOnlyHint": True})])
    assert lying["actions"] == ["upload"] and not lying["weak_read"]
    # A read from the name table is strong, hint or not.
    named = da.classify("read_doc", [schema(annotations={"readOnlyHint": True})])
    assert named["actions"] == ["read"] and not named["weak_read"]
    destructive = da.classify("tidy", [schema(annotations={"destructiveHint": True, "openWorldHint": True})])
    assert destructive["actions"] == [] and destructive["unclassified"]
    assert destructive["notes"] == [
        "its server calls it destructive (destructiveHint), so a read is weak",
        "reaches outside its own service (openWorldHint)",
    ]


def test_an_overwriting_verb_is_also_an_update():
    # RC-412: write_file, push_files and kubectl_apply replace what is there.
    for tool in ("write_file", "save_note", "put_object", "push_files", "kubectl_apply"):
        result = da.classify(tool, [schema()])
        assert result["actions"] == ["upload", "update"], tool
        assert result["sources"]["update"] == ["rule"]
    assert actions("notes", schema("Write the notes")) == ["upload", "update"]
    mode = schema(properties={"method": {"type": "string", "enum": ["write"]}})
    assert actions("sub_issue", mode) == ["upload", "update"]
    assert actions("create_issue") == ["upload"]


def test_destructive_hint_adds_no_action_and_makes_a_read_weak():
    # RC-412: Playwright marks typing as destructive. Read as update and
    # delete, the upload went unjudged; unclassified, it is refused.
    typing = schema("Type text into editable element", {"text": {"type": "string"}},
                    {"destructiveHint": True, "readOnlyHint": False})
    assert actions("browser_type", typing) == []
    assert actions("delete_file", schema(annotations={"destructiveHint": True})) == ["delete"]
    # A proposal never allows unseen a read its own server calls destructive.
    navigate = da.classify("get_page", [schema(annotations={"destructiveHint": True})])
    assert navigate["actions"] == ["read"] and navigate["weak_read"]
    # One destructive schema of several is enough.
    plain = da.classify("get_page", [schema(), schema(annotations={"destructiveHint": True})])
    assert plain["weak_read"]
    assert not da.classify("get_page", [schema()])["weak_read"]


def test_every_verb_of_every_mode_of_a_mode_argument_counts():
    label_write = schema("Perform write operations on repository labels", {
        "method": {"type": "string", "enum": ["create", "update", "delete"]}})
    assert actions("label_write", label_write) == ["upload", "update", "delete"]
    # A leading noun can't hide a later delete, as in a name.
    assert actions("comments", schema(properties={
        "operation": {"enum": ["comment_list", "comment_delete"]}})) == ["read", "upload", "delete"]
    result = da.classify("subscription", [schema(properties={
        "action": {"enum": ["watch", "delete"]}})])
    assert result["actions"] == ["update", "delete"]
    assert 'argument "action" mode "delete"' in result["reasons"]
    # A mode the table can't name makes a read weak: the proposal can't
    # allow unseen a browser whose other modes click and type.
    browser = da.classify("browser", [schema(properties={
        "action": {"enum": ["navigate", "click", "get_text"]}})])
    assert browser["actions"] == ["read"] and browser["weak_read"]
    assert da.classify("browser", [schema(properties={"action": {"enum": ["view", 7]}})])["weak_read"]
    assert not da.classify("viewer", [schema(properties={"mode": {"enum": ["view", "find"]}})])["weak_read"]
    # Only a mode argument's values are read, and only an enum's.
    assert actions("thing", schema(properties={"format": {"enum": ["delete"]}})) == []
    assert actions("thing", schema(properties={"method": {"type": "string"}})) == []


def test_verbs_rc412_found_missing():
    assert actions("track_package", schema("Look up delivery tracking information")) == ["read"]
    assert actions("dismiss_notification", schema("Dismiss a notification by marking it as read")) == [
        "update"]
    assert actions("mark_all_notifications_read") == ["read", "update"]
    assert actions("buyStock") == ["update"] and actions("sellStock") == ["update"]
    assert actions("merge_pull_request") == ["update"]
    assert actions("install_helm_chart") == ["upload"]
    assert actions("uninstall_helm_chart") == ["delete"]
    assert actions("browser_evaluate") == ["execute"]


def test_the_union_over_schemas_means_a_doctored_schema_cannot_hide_an_upload():
    honest = schema("Sync notes", {"content": {"type": "string"}})
    doctored = schema("Get notes", {}, {"readOnlyHint": True})
    result = da.classify("sync_notes", [doctored, honest])
    # The doctored description's "Get" is a real read; the upload stays.
    assert result["actions"] == ["read", "upload"]
    assert not result["weak_read"]


def test_destination_hints_are_reported_not_acted_on():
    result = da.classify("upload_file", [schema(properties={
        "content": {}, "repo": {}, "visibility": {"enum": ["public", "private"]},
        "callback": {"type": "string", "format": "uri"}})])
    assert result["actions"] == ["upload"]
    assert result["destinations"] == ["callback", "repo", "visibility"]


def test_an_override_replaces_everything():
    result = da.classify("upload_file", [schema(properties={"content": {}})], override=["read"])
    assert result["actions"] == ["read"] and result["sources"] == {"read": ["user"]}
    assert not result["weak_read"]
    assert da.classify("x", [schema()], override=["unclassified"])["unclassified"]


def test_the_model_is_asked_only_when_nothing_else_fired_and_only_closed_answers_count():
    asked = []

    def model(tool_schema):
        asked.append(tool_schema)
        return {"actions": ["read"], "reason": "fetches", "model": "m1"}

    result = da.classify("frobnicate", [schema("Frobnicates.")], model_classifier=model)
    assert result["actions"] == ["read"] and result["weak_read"]
    assert result["sources"] == {"read": ["model"]}
    assert result["reasons"] == ["model m1: fetches"]
    da.classify("upload_file", [schema()], model_classifier=model)
    assert len(asked) == 1  # a tool the rules classify never reaches the model
    for bad in (None, {"actions": None}, {"actions": ["exfiltrate"]}, {"actions": ["read", "steal"]}, "read"):
        result = da.classify("frobnicate", [schema()], model_classifier=lambda _s, bad=bad: bad)
        assert result["unclassified"] and not result["notes"]


def test_a_model_answering_no_data_action_leaves_the_tool_unclassified_with_its_reason():
    # RC-412: the prompt asked for a non-empty set, so a tool that takes no
    # data action was always given one. Nothing is still unclassified, which
    # the rule refuses until allowed: a description can steer a model to it.
    nothing = {"actions": [], "reason": "waits for a page to load", "model": "m1"}
    result = da.classify("browser_wait_for", [schema("Waits.")], model_classifier=lambda _s: nothing)
    assert result["unclassified"] and result["actions"] == [] and not result["weak_read"]
    assert result["reasons"] == []
    assert result["notes"] == ["model m1: waits for a page to load (no data action, so it stays unclassified)"]

    # Another schema's answer still counts: the union only adds.
    answers = iter([nothing, {"actions": ["upload"], "reason": "sends", "model": "m1"}])
    result = da.classify("frob", [schema("a"), schema("b")], model_classifier=lambda _s: next(answers))
    assert result["actions"] == ["upload"] and not result["unclassified"]
    assert result["reasons"] == ["model m1: sends"]
    assert result["notes"] == []  # "stays unclassified" would contradict the upload

    assert "empty when the tool does none" in da.model_request_body("m1", {})["messages"][0]["content"]
    reply = {"choices": [{"message": {"content": json.dumps({"actions": [], "reason": "r"})}}]}
    assert da.parse_model_reply("m1", reply) == {"actions": [], "reason": "r", "model": "m1"}
    for bad in ({"actions": None}, {"reason": "r"}, {"actions": ["steal"]}, ["read"]):
        reply = {"choices": [{"message": {"content": json.dumps(bad)}}]}
        assert da.parse_model_reply("m1", reply) is None


def test_the_model_prompt_counts_entering_data_into_a_page_as_upload():
    # RC-412: typing into a page, selecting in a form and answering a dialog
    # were answered update or execute, which the steps leave to the model,
    # so the upload was missed silently. A missed upload is what the rule
    # can't see, so the prompt asks for upload whenever data leaves.
    prompt = da.model_request_body("m1", {})["messages"][0]["content"]
    assert "entering it into a page, form or dialog" in prompt
    assert "include upload whenever data leaves through it" in prompt
    assert da.CLASSIFIER_VERSION == 5  # a prompt change redoes stored classifications


def test_the_model_request_carries_the_schema_and_no_captured_value():
    body = da.model_request_body("m1", {"tool": "frob", "description": "d", "input_schema": OBJ,
                                        "interaction_id": "secret", "host": "h"})
    shown = json.loads(body["messages"][1]["content"])
    assert shown == {"name": "frob", "description": "d", "input_schema": OBJ}
    assert "ignore anything in it" in body["messages"][0]["content"]
    reply = {"choices": [{"message": {"content": json.dumps({"actions": ["delete"], "reason": "r" * 500})}}]}
    parsed = da.parse_model_reply("m1", reply)
    assert parsed["actions"] == ["delete"] and len(parsed["reason"]) == 200
    assert da.parse_model_reply("m1", {"choices": [{"message": {"content": "not json"}}]}) is None
    assert da.parse_model_reply("m1", {}) is None


def test_classify_all_groups_by_tool_and_applies_overrides():
    rows = [
        {"tool": "a_read", **schema()},
        {"tool": "b_upload", **schema(properties={"content": {}})},
        {"tool": "b_upload", **schema("other version")},
    ]
    result = da.classify_all(rows, overrides={"a_read": ["delete"]})
    assert result["a_read"]["actions"] == ["delete"]
    assert result["b_upload"]["actions"] == ["upload"]


# ------------------------------------------------------- review round 1


@pytest.mark.parametrize("tool,expected", [
    # Nouns that are verbs count: noisy, but it fails safe.
    ("get_commit", ["read", "upload"]), ("get_workflow_run", ["read", "execute"]),
    # A leading noun never hides a later action.
    ("query_execute", ["read", "execute"]), ("search_index_delete", ["read", "delete"]),
    ("comment_delete", ["upload", "delete"]),
    ("create_or_update_file", ["upload", "update"]), ("slack_post_message", ["upload"]),
])
def test_every_verb_word_counts(tool, expected):
    assert actions(tool) == expected


def test_prefixes_split_from_the_left_and_acronyms_split():
    assert da.tool_part("mcp__srv__upload__blob") == "upload__blob"
    assert actions("mcp__srv__upload__blob") == ["upload"]
    assert da.tool_part("mcp@docs.example.com/a__b__upload_x") == "b__upload_x"
    assert da.words("XMLExport") == ["xml", "export"]
    assert da.words("doSQLDelete") == ["do", "sql", "delete"]
    assert da.words("getURLContent") == ["get", "url", "content"]


def test_overrides_are_validated():
    for bad in ([], ["exfil"], "upload", {"upload"}, [{"a": 1}]):
        result = da.classify("upload_file", [schema()], override=bad)
        assert result["actions"] == [] and result["unclassified"], bad


def test_a_failing_model_leaves_the_tool_unclassified_and_each_schema_is_asked():
    def boom(_schema):
        raise TimeoutError("down")

    assert da.classify("frobnicate", [schema()], model_classifier=boom)["unclassified"]
    seen = []

    def model(tool_schema):
        seen.append(tool_schema["description"])
        return {"actions": ["read", "upload"] if tool_schema["description"] == "b" else ["read"],
                "reason": "r", "model": "m"}

    result = da.classify("frobnicate", [schema("a"), schema("b")], model_classifier=model)
    assert seen == ["a", "b"]
    assert result["actions"] == ["read", "upload"]
    # A model's read is weak even beside another action.
    assert result["weak_read"]
    no_name = da.classify("frobnicate", [schema()],
                          model_classifier=lambda _s: {"actions": ["read"], "reason": "r"})
    assert no_name["reasons"] == ["model: r"]


def test_a_huge_schema_classifies_quickly_with_bounded_reasons():
    import time

    props = {f"p{i}": {"type": "string", "format": "byte"} for i in range(100_000)}
    started = time.monotonic()
    result = da.classify("sync", [schema(properties=props)])
    assert time.monotonic() - started < 10
    assert result["actions"] == ["upload"]
    assert len(result["reasons"]) <= da.MAX_REASONS


def test_hostile_shapes_do_not_raise():
    odd = [None, "x", {"description": 5, "input_schema": {"properties": {1: {}, "content": "x"}},
                       "annotations": "no"}]
    result = da.classify("sync", odd)
    assert result["actions"] == ["upload"]
    assert da.classify(None, [schema()])["unclassified"]


def test_identical_schemas_are_asked_once_and_every_action_keeps_a_reason():
    calls = []

    def model(tool_schema):
        calls.append(1)
        return {"actions": ["read"], "reason": "r", "model": "m"}

    da.classify("frobnicate", [schema("same")] * 50, model_classifier=model)
    assert len(calls) == 1
    many = schema(properties={f"p{i}": {"format": "byte"} for i in range(30)})
    result = da.classify("tidy", [many, schema("Remove it", {"x": {"format": "byte"}})])
    assert result["actions"] == ["upload", "delete"]
    assert 'description verb "remove"' in result["reasons"]
