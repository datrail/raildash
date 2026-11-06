"""One spelling for each ASP value that can be written more than one way.

`root` and `0` are one user, `HTTPS://API.example.com:443/v1` and
`https://api.example.com/v1` are one endpoint, and a list's order is not state.
RailDash and Rail Center both read an Agent Security Profile's values through
this module, so the two agree on when two values are one value.

Three functions are the whole surface:

- `respelled(name, value)`: attribute `name`'s value in its one spelling
  (`SPELLINGS`), or as it came for an attribute `SPELLINGS` does not name;
- `sorted_lists(value)`: the value with every list in it, at any depth, in one
  fixed order;
- `canonical(value)`: the JSON two values are compared and ordered by.

Each takes one attribute's value and knows nothing of a bundle's structure,
an attribute's status or a schema. Which values a caller respells is the
caller's rule: both consumers respell an `ANSWERED` or `PARTIAL` value, sort
every value, and compare by `canonical`. A value of a shape a spelling does
not know is kept as it came, so no spelling turns a usable value into an
unusable one or back.

The attribute names `SPELLINGS` keys on are RailMon's (`schemas/`), which is
why the module lives here. It uses only the standard library. RailMon's own
bundle never goes through it: a bundle keeps every value as it was observed,
which is the evidence a respelled value was made from.

**Versioning.** `SPELLING_VERSION` moves whenever a spelling is added,
dropped or changed, since the same evidence then reads differently. A
consumer that records how it read a value records this version with it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

__all__ = ["SPELLINGS", "SPELLING_VERSION", "canonical", "respelled", "sorted_lists"]

#: Moves with every change to `SPELLINGS` or to a function it holds. Version 1
#: is Rail Center's RC-386 table as it stood when it moved here.
SPELLING_VERSION = 1

def _members(**spellings: Callable[[object], object]) -> Callable[[object], object]:
    """An object with each member `spellings` names in its one spelling, and every other member, and
    a value that is not an object, as it came."""

    def respell(value: object) -> object:
        if not isinstance(value, dict):
            return value
        return {key: spellings[key](item) if key in spellings else item for key, item in value.items()}

    return respell


def _each(spelling: Callable[[object], object]) -> Callable[[object], object]:
    """A list with each entry in its one spelling, and a value that is not a list as it came."""

    def respell(value: object) -> object:
        return [spelling(entry) for entry in value] if isinstance(value, list) else value

    return respell


_NUMBER = re.compile(r"(?P<sign>[+-]?)(?P<digits>[0-9]+)")


def _account(account: str) -> str:
    """One side of a `user`, the account or its group: `root` for 0, and any other number in decimal.

    A uid is a number however it is written, so `00`, `+0` and `0` are one uid. It is respelled as
    text rather than through `int`, which refuses a run of digits past 4300 and would make one such
    value refuse the whole bundle. Uid 0 is the account Linux images name `root`, and gid 0 the group
    they name `root`. Those names are the image's `/etc/passwd` and `/etc/group`, which no bundle
    carries, so this is the one spelling here that rests on a convention rather than a definition: an
    image that gave the name `root` to another uid would still read as root, as Rail Center's
    ceiling rules have always read it. No other name has a number an ASP can know.
    """
    if number := _NUMBER.fullmatch(account):
        digits = number["digits"].lstrip("0") or "0"
        account = f"-{digits}" if number["sign"] == "-" and digits != "0" else digits
    return "root" if account == "0" else account


def _user(value: object) -> object:
    """`user`'s account and group, each as `_account` writes it, a blank account as `root` and a blank
    group as none.

    A blank account is the runtime's default user, which is root: moby's `GetExecUser` reads an empty
    account, and an empty group, as none given. So an empty user and one naming only a group
    (`:1000`) run as root, and RailMon writes `root` itself where Docker's user is unset; and `0:`
    is `0`, since a blank group leaves the user's own. A JSON number is the uid it names, which is
    how a Kubernetes pod spec reports `runAsUser`, and is written as the string a Dockerfile's
    `USER` is. A group that is named is kept, so `0` and `0:0` stay two values:
    only the second names its group.

    A user name is not folded to one case. Linux reads `ROOT` as an account of its own.
    """
    if isinstance(value, bool) or not isinstance(value, str | int):
        return value
    account, _, group = str(value).partition(":")
    return ("root" if not account else _account(account)) + (f":{_account(group)}" if group else "")


_SLASHES = re.compile(r"/{2,}")

# What a URI starts with, its scheme and the colon after it, and a drive letter does too.
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def _path(value: object) -> object:
    """A filesystem path with each run of slashes as one, and no slash at its end but `/` itself.

    Linux resolves a run of slashes as one, a leading pair included (`//` is the root
    `/`), and a trailing slash names the directory the path without it names: on
    anything but a directory the path does not resolve at all, so one read off a running agent that
    ends in a slash is a directory. Nothing else is resolved. `..` is not the parent of the path
    before it where that path is a symlink, so `/a/../b` is kept as it came.

    Only a path is. A value that starts with a scheme is a URI, whose slashes are its own syntax's:
    `file:///srv` is a local directory and `file://srv` a host, and `s3://b/a//k` and `s3://b/a/k`
    are two objects. An MCP root may be either a path or a `file:` URI, so a URI is kept as it came.
    """
    if not isinstance(value, str) or _SCHEME.match(value):
        return value
    collapsed = _SLASHES.sub("/", value)
    return collapsed.rstrip("/") or collapsed


# A host, and the port after it where there is one: a registered name (RFC 3986's `reg-name`, which
# an IPv4 address also is) or an IP literal in brackets.
_ADDRESS = re.compile(r"(?P<host>[A-Za-z0-9._~%!$&'()*+,;=-]*|\[[0-9A-Fa-f:.]+\])(?::(?P<port>[0-9]*))?")


def _host(value: object) -> object:
    """A host, or `host:port`, in lower case.

    DNS compares names without regard to case (RFC 4343), and an IP literal's hex digits name the
    same address in either case. Only ASCII letters are folded, as RFC 4343 folds them: a name
    holding anything else is an internationalised one, whose case is IDNA's to settle rather than
    `str.lower`'s, and it is kept as it came, as is a value that is not a host at all.
    """
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        return value
    return value.lower()


_named_host = _members(host=_host)


def _destination(value: object) -> object:
    """A destination: a host, as RailMon sends `declared_destinations`, or an object naming one in
    `host`, as it sends `observed_destinations`."""
    return _host(value) if isinstance(value, str) else _named_host(value)


# A backslash ends the authority too, so a URL holding one there is not matched and is kept as it came:
# RFC 3986 refuses it, and a WHATWG parser, Node's and every browser's, reads it as a slash, so in
# `http://u\@Host:80/A` the host is `u` and `Host:80` is a path no rule may respell.
_URL = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/\\?#]*)(?P<rest>[/?#].*)?", re.DOTALL)

# The ports `http` and `https` mean where a URL names none, as `_url` compares them: as text, without
# leading zeros, since `int` refuses a run of digits past 4300.
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _url(value: object) -> object:
    """An `http` or `https` URL with its scheme and host in lower case, and no port where it names
    the scheme's own.

    RFC 3986 makes the scheme and the host case-insensitive (§3.1, §3.2.2), and has a URL that names
    its scheme's default port, or an empty one, written without it (§6.2.3): so
    `HTTPS://API.example.com:443/v1` is `https://api.example.com/v1`. The rest is kept as it came,
    since a path's case and its trailing slash can each name another resource, and so are the
    `user@` before the host and a URL of any other scheme, whose default port this does not know.
    """
    if not isinstance(value, str) or not (url := _URL.fullmatch(value)):
        return value
    scheme = url["scheme"].lower()
    address = _ADDRESS.fullmatch(url["authority"].rpartition("@")[2])
    if scheme not in _DEFAULT_PORTS or address is None:
        return value
    userinfo = url["authority"][: len(url["authority"]) - len(address[0])]
    port = address["port"]
    named = bool(port) and port.lstrip("0") != _DEFAULT_PORTS[scheme]
    return f"{scheme}://{userinfo}{address['host'].lower()}{f':{port}' if named else ''}{url['rest'] or ''}"


def _endpoint(value: object) -> object:
    """An MCP server's endpoint: a URL as `_url` writes one, or a `host:port` as `_host` does."""
    return _url(value) if isinstance(value, str) and "://" in value else _host(value)


# An access mode spelled out, and the abbreviation Docker writes in a bind mount, where RailMon reads it.
_MODES = {"read-only": "ro", "read-write": "rw"}


def _mode(value: object) -> object:
    """An access mode as `ro` or `rw`. A mode carrying options beside it, Docker's `ro,Z`, is kept
    as it came."""
    return _MODES.get(value, value) if isinstance(value, str) else value


_CAPABILITY = re.compile(r"[A-Za-z0-9_]+")


def _capability(value: object) -> object:
    """A Linux capability in upper case with its `CAP_` prefix, and `ALL` as itself.

    The kernel names each capability that way (capabilities(7)). Docker takes one in either case and
    with or without the prefix, and its client writes every one it sends in this form (moby's
    `normalizeCap`), while a Kubernetes pod spec writes `NET_ADMIN` bare. `ALL` is Docker's word for
    every capability, and is never prefixed.
    """
    if not isinstance(value, str) or not _CAPABILITY.fullmatch(value):
        return value
    name = value.upper()
    return name if name == "ALL" or name.startswith("CAP_") else f"CAP_{name}"


_VERSION_PREFIX = re.compile(r"v(?=[0-9]+\.[0-9])")


def _version(value: object) -> object:
    """A dotted version without a `v` before its first digit.

    PEP 440 has that `v` ignored for every purpose and left out of a version's normal form, and npm's
    semver parses past it, so the Python and the JavaScript packages an agent runs on both read the
    two as one version. They meet in practice: Node reports its own version as `v24.20.0`, and
    RailMon sends it so in `framework_identity`. A `v` before an undotted number is kept, since
    `org/v2` is as often a repository, or Go's `/v2` module suffix, as a version.
    """
    if isinstance(value, str) and _VERSION_PREFIX.match(value):
        return value[1:]
    return value


def _identity(value: object) -> object:
    """`name/version`, or a map of names to versions as RailMon sends `framework_identity`, with each
    version as `_version` writes it. A string with any other number of slashes is not a name and a
    version, so it is kept as it came: in `https://host/v1.2` the `v` is part of a path."""
    if isinstance(value, dict):
        return {name: _version(version) for name, version in value.items()}
    if not isinstance(value, str) or value.count("/") != 1:
        return value
    name, slash, version = value.partition("/")
    return name + slash + _version(version)


_capabilities = _each(_capability)

#: Each attribute whose value can be written more than one way, and the one way an ASP writes it.
#: A caller applies it to an `ANSWERED` or `PARTIAL` value, before `sorted_lists`, so a list is
#: ordered by its respelled items.
#:
#: **Exact, never alike.** Each spelling makes two values one only where they name the same thing
#: by a rule that says so -- Linux, DNS, RFC 3986, the kernel's capability names, PEP 440 -- and its
#: function names the rule. That is what keeps alignment's recall: a merge of what is merely alike
#: would read a lookalike host as the one it imitates, and an ASP keeps no trace of the spelling it
#: replaced. The evidence it was made from does: the bundle keeps every value as it was observed.
#:
#: **By what a value means, not by how it looks.** A trailing slash is dropped from a path and kept
#: on a URL, where it can name another resource, and a host is folded to one case while a user name
#: is not. So a spelling belongs to an attribute, or to a member of its value, and a value or an
#: entry of a shape it does not know is kept as it came. None of them turns a shape a rule can read
#: into one it cannot, or back, so whether a value is usable does not depend on its spelling. A
#: value no rule can use is respelled as any other is, in the entries a spelling can read, so two
#: collections that sent one unusable value in two spellings still make one ASP.
#:
#: **No model chooses a spelling.** An ASP's spelling has to be the same on every run and under
#: every model version, or `canonical` stops meaning one thing; a model here would read text
#: the agent wrote with no fence round it, upstream of every profiler; and what a model merges is
#: what looks alike, which the first rule refuses. A model may propose an equivalence for a person to
#: add, as a new version (below).
#:
#: **A spelling added, dropped or changed is a new `SPELLING_VERSION`**, since the same evidence then
#: reads differently, and `tests/test_asp_spelling.py` holds every name here to a case.
SPELLINGS: dict[str, Callable[[object], object]] = {
    "user": _user,
    "workdir": _path,
    "mounts": _each(_members(source=_path, target=_path, mode=_mode)),
    "mcp_servers_declared": _each(_members(root=_path, mode=_mode, url=_url)),
    "mcp_servers_observed": _each(_members(endpoint=_endpoint)),
    "inference_endpoint": _url,
    "declared_destinations": _each(_destination),
    "observed_destinations": _each(_destination),
    "undeclared_destinations": _each(_destination),
    # `cap_add` and `cap_drop` are RailMon's, read from Docker's `HostConfig`; `caps` is the
    # prototype corpus's.
    "permissions": _members(caps=_capabilities, cap_add=_capabilities, cap_drop=_capabilities),
    "harness_identity": _identity,
    "framework_identity": _identity,
}


def respelled(name: str, value: object) -> object:
    """`value` in the one spelling `SPELLINGS` gives `name`'s values: as it came, for an attribute
    `SPELLINGS` does not name."""
    spelling = SPELLINGS.get(name)
    return value if spelling is None else spelling(value)


def sorted_lists(value: Any) -> Any:
    """`value` with the items of every list in it, at any depth, in one fixed order.

    **Why.** RailMon lists items in the order of wherever it read them: the environment for
    credentials, `docker inspect` for mounts, a config file for MCP servers and skills. That is
    not something the agent decided, and the same items in another order are the same state.

    **Why that loses nothing.** No rule that reads an ASP may depend on an item's place in a list:
    what matters is whether an item is there. A reader that is a model can be told to read past
    order but not held to it, which is a reason to give it one order: the same state then always
    reads the same to it. Where an order does carry something, the items carry it too:
      - `in_layer_deleted_secrets` names each item's `layer`;
      - RailMon ranks `observed_destinations` by traffic, and each destination holds its own `count`;
      - Docker mounts by destination, whatever order a spec lists the mounts in.
    An order that means something has to live in the items, because this is where order stops.

    **How.** Each item's own lists are sorted first, and the items are then ordered by their
    canonical JSON. So two lists holding the same items in any order, at any depth, come out the
    same. Duplicates are kept: whether a repeated item says anything is for a reader to judge, and
    with attribute names an open set, this module cannot know.
    """
    if isinstance(value, list):
        return sorted((sorted_lists(item) for item in value), key=canonical)
    if isinstance(value, dict):
        return {key: sorted_lists(item) for key, item in value.items()}
    return value


def canonical(value: Any) -> str:
    """`value` as canonical JSON (keys sorted, no spaces): what two values are compared and
    ordered by, so that `1` and `true`, equal in Python, are not the same reading."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
