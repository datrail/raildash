#!/usr/bin/env python3
"""Black-box smoke test against a running RailDash, e.g. the built image (DR-109 M4).

    python3 tests/image_smoke.py <base-url> <local-token>

Standard library only, so it runs on the CI runner against the container
rather than inside it. It exercises the two inputs RailMon actually delivers:
keyed RuntimeInteraction rows the built RailMon binary emitted
(`tests/fixtures/keyed-capture.jsonl`: attributed `critic` and `planner`, and a
`conflict` row for `executor`) and an evidence bundle over the token-guarded
ingest route. A unit test cannot show that the image ships what these paths
read at runtime; this does.
"""

import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def call(base: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(base + path, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def main() -> None:
    base, token = sys.argv[1].rstrip("/"), sys.argv[2]

    deadline = time.monotonic() + 30
    while True:
        try:
            if call(base, "/webhook/health")[0] == 200:
                break
        except OSError:
            pass
        require(time.monotonic() < deadline, "RailDash did not become healthy within 30s")
        time.sleep(0.5)

    rows = [json.loads(line) for line in (FIXTURES / "keyed-capture.jsonl").read_text().splitlines()]
    status, body = call(
        base,
        "/webhook/http-interactions",
        json.dumps(rows).encode(),
        {"content-type": "application/json"},
    )
    require(status == 200 and body.get("stored") == len(rows), f"interaction ingest: {status} {body}")
    status, body = call(base, "/api/interactions")
    require(status == 200 and body.get("total") == len(rows), f"interaction list: {status} {body}")
    status, body = call(base, "/api/filters")
    # The conflict row names no agent, so only the two attributed keys index.
    require(body.get("agent_keys") == ["critic", "planner"], f"agent index: {body}")

    bundle = (FIXTURES / "evidence-bundle-v1.json").read_bytes()
    status, _ = call(base, "/v1/evidence-bundles?agent_key=smoke", bundle)
    require(status == 403, f"bundle ingest without the local token answered {status}, not 403")
    status, body = call(base, "/v1/evidence-bundles?agent_key=smoke", bundle, {"X-RailDash-Token": token})
    require(status == 202 and body.get("accepted") is True, f"bundle ingest: {status} {body}")
    status, body = call(base, "/api/asps")
    require(status == 200 and body.get("total") == 1, f"ASP list: {status} {body}")

    print(json.dumps({"result": "PASS", "interactions": len(rows), "asps": 1}))


if __name__ == "__main__":
    main()
