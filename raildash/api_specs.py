"""REST uploads step 3: an OpenAPI spec the user imported for a host.

The REST uploads design (railxia/docs `design/2026-10-30-rest-uploads`,
§3 step 3 and §4 "Specs") lets a user import an OpenAPI 3.x spec (JSON or
YAML) for one host. RailDash keeps a compact index of its operations, not
the spec: each operation's method, path template, `operationId`, summary,
and, per request media type, why its body carries files or content:

- a file media type (`multipart/*`, `application/octet-stream`, images,
  ...), or
- a data-carrying property in the request schema, by DR-205's rules
  (`format: binary`/`byte`, `contentEncoding`, `contentMediaType`, or a
  name such as `content`, `file` or `data`).

A spec can only tighten: a matched operation with such a mark makes the
body an upload however small it is, and one without leaves the body's own
shape to decide (a schema says what the server accepts, not what the agent
sent). The vendor writes `operationId` and the summary, so they are shown
as reasons only (DR-205's weak-read rule).

Pure: no I/O and no store. `parse_spec` reads the file into the index,
`match` finds a request's operation in it, and `upload_reasons` says what
the operation's mark is for the request's media type.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .body_kinds import FILE_MEDIA_FAMILIES, FILE_MEDIA_TYPES
from .data_actions import data_carrying

# Bounds on what an import may cost. GitHub's REST description is about
# 14 MB of JSON with ~1,100 operations.
MAX_SPEC_BYTES = 16 * 1024 * 1024
MAX_OPERATIONS = 5000
# A request schema is walked at most this deep and over at most this many
# schema nodes per operation and media type; past either, the walk stops
# and says so, which makes the operation's bodies uploads (fail closed:
# a mark could have been past it).
MAX_SCHEMA_DEPTH = 10
MAX_SCHEMA_NODES = 2000
MAX_REASONS = 4
MAX_TEXT = 160
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
# Bumped when what the index holds or how it is read changes; an index of
# another version is refused, and the spec must be imported again.
INDEX_VERSION = 1


class SpecImportError(Exception):
    """An upload that isn't a readable OpenAPI 3.x spec. The message says
    what was wrong, for the import's error line (422, as a policy import)."""


def _text(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = " ".join(value.split())
    return value if len(value) <= MAX_TEXT else value[: MAX_TEXT - 1] + "…"


def _load(raw: bytes) -> Any:
    if not raw.strip():
        raise SpecImportError("the file is empty")
    if len(raw) > MAX_SPEC_BYTES:
        raise SpecImportError(f"the file is over {MAX_SPEC_BYTES // (1024 * 1024)} MiB")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SpecImportError("the file is not UTF-8 text") from exc
    try:
        if text.lstrip().startswith("{"):
            try:
                return json.loads(text)
            except ValueError as exc:
                raise SpecImportError(f"not valid JSON: {exc}") from exc
        import yaml

        # The OpenShell import's safe loader: no aliases (the cheap way to
        # blow up memory), no duplicate or non-scalar keys.
        from .openshell_policy import _Loader

        try:
            return yaml.load(text, Loader=_Loader)  # noqa: S506 -- a SafeLoader subclass
        except yaml.YAMLError as exc:
            first = str(exc).strip().splitlines()[0] if str(exc).strip() else "unreadable"
            raise SpecImportError(f"not valid YAML: {first[:200]}") from exc
    except RecursionError as exc:
        raise SpecImportError("nested too deeply to be a spec") from exc


def _file_media_type(media_type: str) -> bool:
    return media_type in FILE_MEDIA_TYPES or media_type.startswith(FILE_MEDIA_FAMILIES)


class _Walk:
    """Data-carrying marks in one request schema, `$ref`s within the spec
    resolved, each followed once per path through the schema (a recursive
    schema stops where it repeats)."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        self.document = document
        self.nodes = 0
        self.reasons: list[str] = []
        self.cut = False

    def _resolve(self, ref: Any) -> Any:
        if not isinstance(ref, str) or not ref.startswith("#/"):
            # A remote or relative reference isn't followed: what it points
            # to can't be read, so it could carry anything.
            self.cut = True
            return None
        node: Any = self.document
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, Mapping) or part not in node:
                self.cut = True
                return None
            node = node[part]
        return node

    def _add(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)

    def walk(self, schema: Any, depth: int = 0, refs: tuple[str, ...] = (), via: str = "body") -> None:
        """`via` is how the walk reached this schema: the request body
        itself, a property (whose name check already reported its own
        format), or an array's items."""
        if not isinstance(schema, Mapping) or self.cut:
            return
        self.nodes += 1
        if depth > MAX_SCHEMA_DEPTH or self.nodes > MAX_SCHEMA_NODES:
            self.cut = True
            return
        ref = schema.get("$ref")
        if ref is not None:
            if ref in refs:
                return
            self.walk(self._resolve(ref), depth + 1, (*refs, ref), via)
            return
        if via != "property":
            what = "body" if via == "body" else "an array item"
            if schema.get("format") in ("binary", "byte"):
                self._add(f"{what} is format {schema['format']}")
            if schema.get("contentEncoding") or schema.get("contentMediaType"):
                self._add(f"{what} has a content encoding or media type")
        properties = schema.get("properties")
        if isinstance(properties, Mapping):
            for name, spec in properties.items():
                resolved = spec
                if isinstance(spec, Mapping) and isinstance(spec.get("$ref"), str) and spec["$ref"] not in refs:
                    resolved = self._resolve(spec["$ref"])
                why = data_carrying(str(name), resolved if isinstance(resolved, Mapping) else {})
                if why is not None:
                    self._add(why.replace("argument", "property"))
                self.walk(spec, depth + 1, refs, "property")
        if isinstance(schema.get("items"), Mapping):
            self.walk(schema["items"], depth + 1, refs, "items")
        if isinstance(schema.get("additionalProperties"), Mapping):
            self.walk(schema["additionalProperties"], depth + 1, refs, "items")
        for key in ("allOf", "anyOf", "oneOf"):
            if isinstance(schema.get(key), list):
                for part in schema[key]:
                    self.walk(part, depth + 1, refs, via)


def _media_reasons(document: Mapping[str, Any], media_type: str, entry: Any) -> list[str]:
    """Why bodies of one media type carry files or content, or `[]`."""
    if _file_media_type(media_type):
        return [f"takes {media_type}"]
    schema = entry.get("schema") if isinstance(entry, Mapping) else None
    walk = _Walk(document)
    walk.walk(schema)
    if walk.cut:
        return ["request schema too large or not readable to the end"]
    return walk.reasons[:MAX_REASONS]


def _request_body(document: Mapping[str, Any], operation: Mapping[str, Any]) -> Mapping[str, Any] | None:
    body = operation.get("requestBody")
    for _ in range(MAX_SCHEMA_DEPTH):
        if not (isinstance(body, Mapping) and isinstance(body.get("$ref"), str)):
            break
        body = _Walk(document)._resolve(body["$ref"])  # noqa: SLF001
    return body if isinstance(body, Mapping) else None


def _segments(template: str) -> list[str]:
    return [part for part in template.split("/") if part != ""]


@functools.lru_cache(maxsize=16384)
def _segment_pattern(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _segment_regex(segment: str) -> str | None:
    """A template segment as a regex, or None for a plain literal."""
    if "{" not in segment:
        return None
    out, pos = [], 0
    for found in re.finditer(r"\{[^{}/]*\}", segment):
        out.append(re.escape(segment[pos:found.start()]))
        out.append("[^/]+")
        pos = found.end()
    out.append(re.escape(segment[pos:]))
    return "".join(out)


def _base_paths(document: Mapping[str, Any]) -> list[str]:
    bases: list[str] = []
    servers = document.get("servers")
    for server in servers if isinstance(servers, list) else []:
        url = server.get("url") if isinstance(server, Mapping) else None
        if not isinstance(url, str):
            continue
        # A server variable in the path ({version}) can't be stripped as a
        # literal; such a base is skipped and the spec's paths are tried as
        # they are.
        path = (urlsplit(url).path if "://" in url else url.split("?", 1)[0]).rstrip("/")
        if path and "{" not in path and path.startswith("/") and path not in bases:
            bases.append(path)
    return bases


def parse_spec(raw: bytes) -> dict[str, Any]:
    """The index of an OpenAPI 3.x spec file (JSON or YAML), or
    `SpecImportError` saying why it isn't one."""
    document = _load(raw)
    if not isinstance(document, Mapping):
        raise SpecImportError("not an OpenAPI spec: the file isn't a mapping")
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        if "swagger" in document:
            raise SpecImportError("a Swagger 2.0 spec; RailDash reads OpenAPI 3.x")
        raise SpecImportError("not an OpenAPI 3.x spec: no `openapi: 3.x` field")
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        raise SpecImportError("not an OpenAPI spec: no `paths` mapping")
    operations: list[dict[str, Any]] = []
    for template, item in paths.items():
        if not isinstance(template, str) or not template.startswith("/") or not isinstance(item, Mapping):
            continue
        for method in METHODS:
            operation = item.get(method)
            if not isinstance(operation, Mapping):
                continue
            if len(operations) >= MAX_OPERATIONS:
                raise SpecImportError(f"more than {MAX_OPERATIONS} operations")
            media: dict[str, list[str]] = {}
            body = _request_body(document, operation)
            content = body.get("content") if body is not None else None
            if isinstance(content, Mapping):
                for media_type, entry in content.items():
                    if isinstance(media_type, str):
                        media[media_type.strip().lower()] = _media_reasons(document, media_type.strip().lower(), entry)
            operations.append({
                "method": method.upper(),
                "path": template,
                "operation_id": _text(operation.get("operationId")),
                "summary": _text(operation.get("summary")),
                "media": media,
            })
    info = document.get("info") if isinstance(document.get("info"), Mapping) else {}
    return {
        "index_version": INDEX_VERSION,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "openapi": version,
        "title": _text(info.get("title")),
        "version": _text(str(info["version"])) if info.get("version") is not None else None,
        "base_paths": _base_paths(document),
        "operations": operations,
    }


def summary(index: Mapping[str, Any]) -> dict[str, Any]:
    """What the panel lists for an imported spec."""
    operations = index.get("operations") or []
    marked = [op for op in operations if any(op.get("media", {}).values())]
    return {
        "title": index.get("title"), "version": index.get("version"), "openapi": index.get("openapi"),
        "sha256": index.get("sha256"), "operations": len(operations), "upload_operations": len(marked),
    }


def _template_match(template: str, segments: list[str]) -> tuple[int, int, int] | None:
    """How well a path template matches a request's segments: (exact or
    not, literal segments before the first parameter, literal segments in
    all), or None.
    A template whose last segment is only a parameter (`{path}`) may take
    the rest of the path, slashes included (GitHub's contents API), ranked
    after every exact match."""
    parts = _segments(template)
    greedy = False
    if len(parts) != len(segments):
        if not parts or len(segments) <= len(parts) or not re.fullmatch(r"\{[^{}/]+\}", parts[-1]):
            return None
        segments = [*segments[: len(parts) - 1], "/".join(segments[len(parts) - 1:])]
        greedy = True
    prefix, literal, in_prefix = 0, 0, True
    last = len(parts) - 1
    for position, (part, value) in enumerate(zip(parts, segments)):
        pattern = _segment_regex(part)
        if pattern is None:
            if part != value:
                return None
            literal += 1
            prefix += 1 if in_prefix else 0
        else:
            if not _segment_pattern(".+" if greedy and position == last else pattern).fullmatch(value):
                return None
            in_prefix = False
    return (0 if greedy else 1, prefix, literal)


def match(index: Mapping[str, Any] | None, method: Any, path: Any) -> dict[str, Any] | None:
    """The operation a request's method and path name in an index, longest
    literal prefix first; None when none does. The path is the request's
    origin-form path; the spec's server base paths are stripped first."""
    if not index or not isinstance(path, str) or not isinstance(method, str):
        return None
    path = path.split("?", 1)[0].split("#", 1)[0]
    method = method.upper()
    candidates = [path]
    for base in index.get("base_paths") or ():
        if path == base or path.startswith(base + "/"):
            candidates.insert(0, path[len(base):] or "/")
    best: tuple[Any, dict[str, Any]] | None = None
    for candidate in candidates:
        segments = _segments(candidate)
        for operation in index.get("operations") or ():
            if operation.get("method") != method:
                continue
            score = _template_match(str(operation.get("path")), segments)
            if score is not None and (best is None or score > best[0]):
                best = (score, operation)
        if best is not None:
            return best[1]
    return None


def operation_name(operation: Mapping[str, Any]) -> str:
    return operation.get("operation_id") or f"{operation.get('method')} {operation.get('path')}"


def upload_reasons(operation: Mapping[str, Any], media_types: Iterable[str]) -> list[str]:
    """Why a matched operation makes a body of these media types an upload,
    or `[]` when it leaves the body's shape to decide. The request's own
    media type picks the entry; a wildcard entry (`*/*`, `text/*`) stands
    in for it; with none that fits, or no media type sent, every entry
    counts (a spec can only tighten)."""
    media = operation.get("media") or {}
    if not media:
        return []
    types = [t for t in media_types if isinstance(t, str)]
    chosen: list[list[str]] = []
    for media_type in types:
        if media_type in media:
            chosen.append(media[media_type])
        else:
            family = media_type.split("/", 1)[0] + "/*"
            for key in (family, "*/*"):
                if key in media:
                    chosen.append(media[key])
                    break
    if not chosen:
        chosen = list(media.values())
    name = operation_name(operation)
    reasons: list[str] = []
    for found in chosen:
        for reason in found:
            text = f"spec {name}: {reason}"
            if text not in reasons:
                reasons.append(text)
    return reasons[:MAX_REASONS]
