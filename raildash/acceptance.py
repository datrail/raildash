#!/usr/bin/env python3
"""Run the deterministic OSS ASP v1 acceptance flow without a control plane."""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

from .asp import parse_bundle
from .store import Store


DEFAULT_FIXTURE = (
    Path(sys.prefix) / "share" / "raildash" / "evidence-bundle-v1.json"
)


def encoded(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode()


def run_acceptance(database: Path, fixture: Path) -> dict:
    baseline_raw = fixture.read_bytes()
    baseline_bundle = parse_bundle(baseline_raw)
    store = Store(database)
    try:
        baseline = store.load_asp(baseline_raw)
        replay = store.load_asp(baseline_raw)
        version_one = store.lock_alignment(baseline["asp_id"], "v1.0")
        store.switch_alignment(version_one["alignment_version_id"])
        replay_state = store.asp_state(replay["asp_id"])

        changed_bundle = copy.deepcopy(baseline_bundle)
        changed_bundle["bundle_id"] = "bnd-asp-v1-acceptance-drift"
        changed_bundle["collected_at"] = "2026-09-24T04:00:00Z"
        changed_bundle["attributes"]["declared_destinations"]["value"] = [
            "acceptance-change.example"
        ]
        changed = store.load_asp(encoded(changed_bundle))
        drift_state = store.asp_state(changed["asp_id"])

        version_two = store.lock_alignment(changed["asp_id"], "v2.0")
        store.switch_alignment(version_two["alignment_version_id"])
        switched_state = store.asp_state(changed["asp_id"])
        store.switch_alignment(version_one["alignment_version_id"])
        restored_state = store.asp_state(changed["asp_id"])

        incompatible_bundle = copy.deepcopy(changed_bundle)
        incompatible_bundle["bundle_id"] = "bnd-asp-v1-acceptance-incompatible"
        incompatible_bundle["collected_at"] = "2026-09-24T05:00:00Z"
        incompatible_bundle["rule_pack_version"] += 1
        incompatible = store.load_asp(encoded(incompatible_bundle))
        incompatible_state = store.asp_state(incompatible["asp_id"])

        checks = {
            "exact_replay_idempotent": replay["replayed"] is True
            and replay["asp_id"] == baseline["asp_id"],
            "replay_aligned": replay_state["state"] == "ALIGNED",
            "controlled_change_alerts": drift_state["state"] == "DRIFT_DETECTED",
            "switch_to_new_version_aligns": switched_state["state"] == "ALIGNED",
            "switch_back_restores_drift": restored_state["state"] == "DRIFT_DETECTED",
            "rule_pack_mismatch_is_non_comparable": (
                incompatible_state["state"] == "COMPARISON_UNAVAILABLE"
                and incompatible_state["drift"]["reason"] == "CONTRACT_MISMATCH"
            ),
        }
        if not all(checks.values()):
            raise RuntimeError(
                "ASP v1 acceptance failed: "
                + ", ".join(name for name, passed in checks.items() if not passed)
            )
        return {
            "acceptance": "passed",
            "checks": checks,
            "artifacts": {
                "baseline_asp_id": baseline["asp_id"],
                "drift_asp_id": changed["asp_id"],
                "incompatible_asp_id": incompatible["asp_id"],
                "alignment_versions": [
                    version_one["alignment_version_id"],
                    version_two["alignment_version_id"],
                ],
            },
        }
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument(
        "--database",
        type=Path,
        help="private database path to retain; default uses a temporary directory",
    )
    args = parser.parse_args()

    if args.database is not None:
        if args.database.exists():
            parser.error(
                "--database must name a new dedicated acceptance database; "
                "refusing to mutate an existing database"
            )
        result = run_acceptance(args.database, args.fixture)
    else:
        with tempfile.TemporaryDirectory(prefix="raildash-asp-v1-") as directory:
            result = run_acceptance(Path(directory) / "raildash.db", args.fixture)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
