"""One normalization from an evidence bundle to the attributes of each agent it describes.

RailDash and Rail Center both profile an agent from what this module makes of a bundle, so the
two read the same normalized data. It works on a bundle as decoded JSON (a `dict`), the way
RailMon's schemas (`schemas/evidence-bundle-v{1,2}.schema.json`) describe it, and uses only the
standard library and `asp_spelling`.

**What it makes.** `normalized(bundle, shapes)` gives one attribute map per agent: a v1 bundle
describes one agent, with no key; a v2 bundle describes one per agent scope, with the sandbox
scope's attributes merged into each. In every map:

  - a value read (`ANSWERED` or `PARTIAL`) is in its one spelling (`asp_spelling.respelled`);
  - every list in a value, at any depth, is in one fixed order (`asp_spelling.sorted_lists`);
  - a `window`'s keys are sorted, since they are a set the schema spells as a list;
  - a read value of a shape the caller's rules cannot use is marked unusable (`readable`).

Everything else about an attribute is kept as the bundle gave it, and a member the bundle left
out stays out. The bundle itself is not changed.

**What the caller keeps.** Which shapes its rules can use (`shapes`), what it builds around the
maps (a typed ASP, a version of its own, an identity for an unkeyed agent), and what it leaves
out of a profile. Rail Center passes its `SHAPES`. A caller that passes none marks nothing: the
bundle schemas leave `value` untyped, so a `user` of `0.0` arrives `ANSWERED`. Two callers passing
different shapes get the same values and differ only in which attributes are marked.

**Two scopes may not disagree.** RailMon gives each attribute to exactly one scope, so a v2
bundle whose sandbox and agent scopes both carry an attribute with different readings is not
RailMon's, or not working, and no rule for picking one is safe: taking either would let one
scope clear what the other found. `normalized` raises `ScopeConflict` naming every such pair.
Two readings that say the same thing, decided on the canonical JSON after respelling and
sorting, are kept as one.

**Versions.** `RULES_VERSION` names the rules `normalized` applies, and `steps` says what each
version changed, so a map made under older rules can be read under newer ones (`lifted`)
without the evidence it came from. Version 1 carried every value as the bundle sent it, lists
sorted; version 2 marked a read value of an unusable shape `FAILED`, its value kept; version 3
respelled every read value (`asp_spelling`, `SPELLING_VERSION` 1). These are Rail Center's
`ASP_VERSION` steps 1 to 3 as they stood when they moved here (RC-357, RC-382, RC-386, RC-468).

**A step is frozen once a later version exists, and so is everything its lift reaches.** Lifting
a version 2 map to 3 has to make what version 3 made, whatever a version 4 does. Step 2 reaches
only the `shapes` it is given, so a changed shape is a new step given its own map. Step 3 reaches
`asp_spelling`'s `respelled` and `SPELLINGS` as they are today, so a spelling version that changes
them first binds step 3 to version 1's table and functions, and only then changes the table
(`test_each_step_changes_what_its_rules_name` fails until it does). A function changed in place
changes every step that reaches it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Optional

try:  # vendored beside asp_spelling.py inside a package, as RailDash does
    from .asp_spelling import canonical, respelled, sorted_lists
except ImportError:  # installed, or loaded as a top-level module
    from asp_spelling import canonical, respelled, sorted_lists

__all__ = [
    "READ",
    "RULES_VERSION",
    "NoChainOfSteps",
    "ScopeConflict",
    "Shapes",
    "Step",
    "chain",
    "lifted",
    "normalized",
    "normalized_attribute",
    "readable",
    "steps",
    "unliftable",
    "unusable",
]

#: The rules `normalized` applies, and the last version `steps` reaches.
RULES_VERSION = 3

#: The statuses whose value a rule reads, and so the only ones respelled and checked for shape.
#: A `TEMPLATED` value is a template deferred to deployment, which may rightly be a string where a
#: list will be; `ABSENT` says nothing is there; a collector's `BLIND` and `FAILED` carry no value.
READ = frozenset({"ANSWERED", "PARTIAL"})

#: What a caller's rules can use of each attribute: a predicate per attribute name, true where the
#: value is a shape its rules can read. An attribute not named is usable whatever its shape.
Shapes = Mapping[str, Callable[[object], bool]]

_NO_SHAPES: Shapes = MappingProxyType({})


class ScopeConflict(ValueError):
    """A v2 bundle whose sandbox scope and an agent scope give different readings of one attribute.

    `conflicts` names each one as `(agent_key, attribute)`, every conflict in the bundle rather than
    the first, so a producer sees the whole of what it got wrong at once.
    """

    def __init__(self, conflicts: Iterable[tuple[str, str]]) -> None:
        self.conflicts = tuple(conflicts)
        named = ", ".join(f"{agent_key}: {attribute}" for agent_key, attribute in self.conflicts)
        super().__init__(f"the sandbox scope and an agent scope give different readings of {named}")


class NoChainOfSteps(ValueError):
    """A map asked to be lifted to a version no chain of steps leads to from its own (`chain`)."""

    def __init__(self, version: int, to: int) -> None:
        self.version = version
        self.to = to
        super().__init__(f"no chain of steps lifts a map of version {version} to version {to}")


# ── One attribute ───────────────────────────────────────────────────────────────────────────────


def normalized_attribute(name: str, attribute: Mapping[str, Any]) -> dict[str, Any]:
    """`attribute` with its value in its one spelling where it is read, every list in its value
    sorted, and its `window`'s keys sorted. A copy: the bundle's attribute is not changed.

    A v1 attribute is already in its v2 form as JSON: the two differ only in which reasons the
    schema admits, and a v1 reason is spelled the same in v2.
    """
    value = attribute.get("value")
    if attribute.get("status") in READ:
        value = respelled(name, value)
    out = dict(attribute)
    out["value"] = sorted_lists(value)
    window = attribute.get("window")
    if isinstance(window, Mapping):
        out["window"] = {key: keys if keys is None else sorted(keys) for key, keys in window.items()}
    return out


def unusable(attribute: Mapping[str, Any]) -> bool:
    """Whether `readable` marked `attribute` `FAILED` because no rule can use its value, which it
    kept. A collector's own `FAILED` names no author, so it never is."""
    return attribute.get("status") == "FAILED" and attribute.get("authored_by") is not None


def readable(attributes: Mapping[str, Mapping[str, Any]], shapes: Optional[Shapes] = None) -> dict[str, dict[str, Any]]:
    """`attributes`, with each read value of a shape `shapes` says its rules cannot use marked
    `FAILED` with the reason `PARSE_FAILED`.

    **Marking changes only the status and the reason.** The value is kept, and so is who could
    have written it: a collector that sent something unusable and one that sent nothing are
    different facts, and the author is what keeps agent-written text fenced. A `PARTIAL`
    attribute's own reason is the one thing lost. The whole attribute is marked, not the entry,
    because the entry skipped could be the one that bounds a rule.
    """
    shapes = _NO_SHAPES if shapes is None else shapes
    out: dict[str, dict[str, Any]] = {}
    for name, attribute in attributes.items():
        shape = shapes.get(name)
        if attribute.get("status") in READ and shape is not None and not shape(attribute.get("value")):
            out[name] = {**attribute, "status": "FAILED", "reason": "PARSE_FAILED"}
        else:
            out[name] = dict(attribute)
    return out


# ── A bundle ────────────────────────────────────────────────────────────────────────────────────


def normalized(
    bundle: Mapping[str, Any], shapes: Optional[Shapes] = None
) -> list[tuple[Optional[str], dict[str, dict[str, Any]]]]:
    """Every agent `bundle` describes, as `(agent_key, attributes)`, in the bundle's order.

    One entry for a v1 bundle, keyed `None`, since a v1 bundle names no agent. One per agent
    scope for a v2 bundle, its attributes the sandbox scope's merged with its own.

    `ScopeConflict` where a v2 bundle's sandbox scope and an agent scope give different readings
    of one attribute.
    """
    if int(bundle.get("bundle_version", 1)) < 2:
        return [(None, readable(_normalized_map(bundle.get("attributes", {})), shapes))]

    sandbox = _normalized_map(bundle.get("sandbox", {}).get("attributes", {}))
    agents: list[tuple[Optional[str], dict[str, dict[str, Any]]]] = []
    conflicts: list[tuple[str, str]] = []
    for scope in bundle.get("agents", []):
        key = scope["agent_key"]
        own = _normalized_map(scope.get("attributes", {}))
        conflicts += [
            (key, name)
            for name in sorted(sandbox.keys() & own.keys())
            if canonical(sandbox[name]) != canonical(own[name])
        ]
        agents.append((key, readable({**sandbox, **own}, shapes)))
    if conflicts:
        raise ScopeConflict(conflicts)
    return agents


def _normalized_map(attributes: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {name: normalized_attribute(name, attribute) for name, attribute in attributes.items()}


# ── Versions ────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Step:
    """What one version changed, as `lifted` applies it to a map the version before made.

    `changes` names every attribute the version normalizes differently from the one before it, and
    `lift` makes one of them, as the version before made it, what this version makes of the same
    evidence. An attribute `changes` does not name is carried as it is.

    `cannot_lift` names those of `changes` that `lift` cannot make, where a map of the version
    before holds too little to tell. `lift` is never handed one, nor is any later step's.
    """

    changes: frozenset
    lift: Callable[[str, Mapping[str, Any]], dict[str, Any]]
    cannot_lift: frozenset = frozenset()

    def __post_init__(self) -> None:
        if stray := sorted(self.cannot_lift - self.changes):
            raise ValueError(f"a step cannot fail to lift what it does not change: {', '.join(stray)}")


#: The attributes version 3 respells: `asp_spelling`'s `SPELLINGS` at `SPELLING_VERSION` 1. Written
#: out rather than read off the table, so a later spelling version can't move this step; the tests
#: hold it to the table while `SPELLING_VERSION` is 1.
_RESPELLED_IN_3 = frozenset(
    {
        "user",
        "workdir",
        "mounts",
        "mcp_servers_declared",
        "mcp_servers_observed",
        "inference_endpoint",
        "declared_destinations",
        "observed_destinations",
        "undeclared_destinations",
        "permissions",
        "harness_identity",
        "framework_identity",
    }
)


def _respelled_where_read(name: str, attribute: Mapping[str, Any]) -> dict[str, Any]:
    """Version 3's change: the value in its one spelling, its lists sorted again by their respelled
    items, where its status is one a rule reads or where version 2 marked it unusable. Such a value
    arrived read, and version 3 respells it before marking it. A spelling never changes whether a
    value is usable, so none is marked again."""
    if attribute.get("status") not in READ and not unusable(attribute):
        return dict(attribute)
    return {**attribute, "value": sorted_lists(respelled(name, attribute.get("value")))}


def steps(shapes: Optional[Shapes] = None) -> Mapping[int, Step]:
    """Each version's `Step`, keyed by the version it reaches, for a caller whose rules use `shapes`.

    Version 2's step marks what `shapes` names, and changes exactly those names, so its lift and its
    change set come from one map. Pass the map version 2 was made with: a caller whose shapes later
    change adds a step of its own for the new map (the module docstring says why).
    """
    shapes = MappingProxyType(dict(_NO_SHAPES if shapes is None else shapes))

    def marked_where_unusable(name: str, attribute: Mapping[str, Any]) -> dict[str, Any]:
        return readable({name: attribute}, shapes)[name]

    return MappingProxyType(
        {
            2: Step(changes=frozenset(shapes), lift=marked_where_unusable),
            3: Step(changes=_RESPELLED_IN_3, lift=_respelled_where_read),
        }
    )


def chain(older: int, newer: int, steps: Mapping[int, Step]) -> Optional[list[tuple[int, Step]]]:
    """Every step of `steps` from version `older` up to `newer`, each with the version it reaches, in
    order; or None where no chain connects them: `newer` below `older`, or a version between with no
    step. Empty between two of one version."""
    if newer < older:
        return None
    found: list[tuple[int, Step]] = []
    for version in range(older + 1, newer + 1):
        step = steps.get(version)
        if step is None:
            return None
        found.append((version, step))
    return found


def unliftable(older: int, newer: int, steps: Mapping[int, Step]) -> frozenset:
    """The attributes some step from `older` up to `newer` cannot lift: none where no chain exists."""
    return frozenset().union(*(step.cannot_lift for _, step in chain(older, newer, steps) or ()))


def lifted(
    attributes: Mapping[str, Mapping[str, Any]], older: int, newer: int, steps: Mapping[int, Step]
) -> dict[str, dict[str, Any]]:
    """`attributes`, made under version `older`, as version `newer` makes the same evidence: each step
    between applied in turn. An attribute some step cannot lift is carried as it was made, through
    every step. `NoChainOfSteps` where no chain leads there."""
    found = chain(older, newer, steps)
    if found is None:
        raise NoChainOfSteps(older, newer)
    stuck = unliftable(older, newer, steps)
    out = {name: dict(attribute) for name, attribute in attributes.items()}
    for _, step in found:
        out = {
            name: step.lift(name, attribute) if name in step.changes - stuck else attribute
            for name, attribute in out.items()
        }
    return out
