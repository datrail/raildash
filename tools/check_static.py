#!/usr/bin/env python3
"""Check the three static files hold together.

There is no build step, which is deliberate for a tool people run locally —
but it means nothing catches a stylesheet referencing a token that was
renamed, or `$("thing")` reaching for an id that no longer exists. Both fail
silently at runtime: the first paints the wrong colour, the second returns
null and the handler never fires.

Exits non-zero and says which file and which name, so a failure is actionable
rather than "the dashboard looks odd".
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "raildash" / "static"


def main() -> int:
    css = (STATIC / "app.css").read_text()
    js = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()

    problems: list[str] = []

    if css.count("{") != css.count("}"):
        problems.append(
            f"app.css: {css.count('{')} opening braces, {css.count('}')} closing"
        )

    used = set(re.findall(r"var\((--[a-z0-9-]+)", css))
    defined = set(re.findall(r"^\s*(--[a-z0-9-]+)\s*:", css, re.M))
    for name in sorted(used - defined):
        problems.append(f"app.css: var({name}) is used but never defined")

    ids_in_js = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', js))
    ids_in_html = set(re.findall(r'id="([A-Za-z0-9_-]+)"', html))
    for name in sorted(ids_in_js - ids_in_html):
        problems.append(f'app.js: $("{name}") has no matching id in index.html')

    # Captured traffic is untrusted; the front end must never assign markup.
    for sink in ("innerHTML =", "outerHTML =", "insertAdjacentHTML", "document.write"):
        if sink in js:
            problems.append(f"app.js: {sink} would render captured traffic as markup")

    # Every colour must come from a token, so both themes stay complete. A
    # literal in a component rule is the classic one-theme-only bug: it looks
    # right in whichever theme it was written against and wrong in the other.
    body_css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    token_block_literals = len(re.findall(r"--[a-z0-9-]+:\s*#", body_css))
    all_literals = len(re.findall(r":\s*#[0-9A-Fa-f]{3,8}", body_css))
    if all_literals != token_block_literals:
        problems.append(
            f"app.css: {all_literals - token_block_literals} colour literal(s) "
            "outside a token definition — both themes must come from tokens"
        )

    if problems:
        print("static check failed:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(
        f"static check ok — {len(defined)} tokens, {len(ids_in_js)} ids, "
        "no markup sinks"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
