#!/usr/bin/env python3
"""Deterministic diff of two Tier 0 health scan snapshots (M04, D-034, D-037, D-038).

Outputs counts only (by class and by check, sorted), with no paths, unit names,
hostnames, or messages, so its output is safe to copy into the vault.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect import CHECK_IDS, SCHEMA_VERSION, validate_snapshot  # noqa: E402

CHANGE_CLASSES: tuple[str, ...] = ("new", "resolved", "changed", "tool-failure")


def diff_snapshots(snap_a: dict[str, Any], snap_b: dict[str, Any]) -> dict[str, Any]:
    """Validate and compare two snapshots, returning sorted counts by class and check."""
    validate_snapshot(snap_a)
    validate_snapshot(snap_b)

    if snap_a["schema_version"] != snap_b["schema_version"]:
        raise ValueError(
            f"schema_version mismatch: {snap_a['schema_version']} vs {snap_b['schema_version']}"
        )
    if snap_a["simulation"] != snap_b["simulation"]:
        raise ValueError(
            f"simulation flag mismatch: {snap_a['simulation']} vs {snap_b['simulation']}"
        )

    status_a = {c["check"]: c["status"] for c in snap_a["checks"]}
    status_b = {c["check"]: c["status"] for c in snap_b["checks"]}

    findings_a: dict[str, dict[tuple[str, str, str], dict[str, Any]]] = {cid: {} for cid in CHECK_IDS}
    findings_b: dict[str, dict[tuple[str, str, str], dict[str, Any]]] = {cid: {} for cid in CHECK_IDS}

    for f in snap_a["findings"]:
        key = (f["check"], f["kind"], f["subject"])
        findings_a[f["check"]][key] = f
    for f in snap_b["findings"]:
        key = (f["check"], f["kind"], f["subject"])
        findings_b[f["check"]][key] = f

    totals = {cls: 0 for cls in sorted(CHANGE_CLASSES)}
    by_check: dict[str, dict[str, int]] = {}

    for cid in sorted(CHECK_IDS):
        counts = {cls: 0 for cls in sorted(CHANGE_CLASSES)}
        if status_a[cid] != "ok" or status_b[cid] != "ok":
            counts["tool-failure"] = 1
        else:
            fa = findings_a[cid]
            fb = findings_b[cid]
            for key in fb.keys() - fa.keys():
                counts["new"] += 1
            if cid != "paclog":
                for key in fa.keys() - fb.keys():
                    counts["resolved"] += 1
            for key in fa.keys() & fb.keys():
                if fa[key]["state"] != fb[key]["state"] or fa[key]["attributes"] != fb[key]["attributes"]:
                    counts["changed"] += 1

        by_check[cid] = dict(sorted(counts.items()))
        for cls, val in counts.items():
            totals[cls] += val

    return {
        "schema_version": SCHEMA_VERSION,
        "simulation": snap_a["simulation"],
        "totals": dict(sorted(totals.items())),
        "by_check": dict(sorted(by_check.items())),
    }


def format_diff(result: dict[str, Any]) -> str:
    """Serialize `result` deterministically with sorted keys and trailing newline."""
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Diff two Tier 0 system health scan snapshots into counts")
    ap.add_argument("snapshot_a", help="Path to baseline/first snapshot JSON")
    ap.add_argument("snapshot_b", help="Path to second snapshot JSON")
    args = ap.parse_args(argv)

    try:
        path_a = Path(args.snapshot_a).expanduser()
        path_b = Path(args.snapshot_b).expanduser()
        snap_a = json.loads(path_a.read_text(encoding="utf-8"))
        snap_b = json.loads(path_b.read_text(encoding="utf-8"))
        result = diff_snapshots(snap_a, snap_b)
    except Exception as exc:
        print(f"diff.py error: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(format_diff(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
