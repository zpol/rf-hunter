#!/usr/bin/env python3
"""List logical duplicate groups from recent-capture-manifest.json (dry; no deletes)."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "results" / "recent-capture-manifest.json",
    )
    ap.add_argument("--dry-run", action="store_true", default=True)
    args = ap.parse_args()
    rows = json.loads(args.manifest.read_text())
    by = defaultdict(list)
    for r in rows:
        h = r.get("source_sha256")
        if h:
            by[h].append(r["source_file"])
    groups = {h: ps for h, ps in by.items() if len(ps) > 1}
    print(f"duplicate_groups={len(groups)}")
    for h, ps in list(groups.items())[:30]:
        print(h[:24] + "…", len(ps))
        for p in ps:
            print(" ", p)
    print("# dry-run: originals not deleted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
