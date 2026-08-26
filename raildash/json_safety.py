"""Cheap structural limits for JSON before a full Python object is built.

The stdlib decoder has no node or nesting limit.  A small wire payload such as
an array of empty objects can therefore allocate many times its input size.
This scanner is deliberately not a second JSON parser: it only tracks JSON's
ASCII structural characters outside strings, which is enough to put a hard
ceiling on the number of containers/members and on nesting depth before
``json.loads`` materialises the tree.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_JSON_STRUCTURE_TOKENS = 2_200_000
MAX_JSON_DEPTH = 128
MAX_JSON_SCALAR_CHARS = 8 * 1024 * 1024
MAX_SAFE_JSON_BYTES = 16 * 1024 * 1024


class JSONStructureTooComplex(ValueError):
    """The input would create an object tree outside RailDash's safety bound."""


@dataclass
class JSONStructureGuard:
    """Stateful scanner so request chunks can be rejected as they arrive."""

    max_tokens: int = MAX_JSON_STRUCTURE_TOKENS
    max_depth: int = MAX_JSON_DEPTH
    tokens: int = 0
    depth: int = 0
    _in_string: bool = False
    _escaped: bool = False
    _scalar_chars: int = 0

    def feed(self, chunk: bytes | bytearray | memoryview | str) -> None:
        for unit in chunk:
            code = unit if isinstance(unit, int) else ord(unit)
            if self._in_string:
                self._scalar_chars += 1
                if self._scalar_chars > MAX_JSON_SCALAR_CHARS:
                    raise JSONStructureTooComplex(
                        f"JSON scalar exceeds {MAX_JSON_SCALAR_CHARS} characters"
                    )
                if self._escaped:
                    self._escaped = False
                elif code == ord("\\"):
                    self._escaped = True
                elif code == ord('"'):
                    self._in_string = False
                continue

            if code == ord('"'):
                self._in_string = True
                self._scalar_chars = 0
                continue
            if code in (ord("{"), ord("[")):
                self._scalar_chars = 0
                self.depth += 1
                if self.depth > self.max_depth:
                    raise JSONStructureTooComplex(
                        f"JSON nesting exceeds {self.max_depth} levels"
                    )
            elif code in (ord("}"), ord("]")):
                self._scalar_chars = 0
                self.depth -= 1
            elif code in (ord(","), ord(":")):
                self._scalar_chars = 0
            else:
                self._scalar_chars += 1
                if self._scalar_chars > MAX_JSON_SCALAR_CHARS:
                    raise JSONStructureTooComplex(
                        f"JSON scalar exceeds {MAX_JSON_SCALAR_CHARS} characters"
                    )

            if code in (
                ord("{"),
                ord("}"),
                ord("["),
                ord("]"),
                ord(","),
                ord(":"),
            ):
                self.tokens += 1
                if self.tokens > self.max_tokens:
                    raise JSONStructureTooComplex(
                        f"JSON structure exceeds {self.max_tokens} tokens"
                    )


def check_json_structure(data: bytes | bytearray | memoryview | str) -> None:
    """Apply the default bounds to an already-buffered JSON document."""
    JSONStructureGuard().feed(data)
