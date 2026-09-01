#!/usr/bin/env python3
"""Find capture files in a time window."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_research_report import DEFAULT_CAPTURES, parse_since, parse_until
from datetime import datetime


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--captures", type=Path, default=DEFAULT_CAPTURES)
    ap.add_argument("--since", default="12 hours ago")
    ap.add_argument("--until", default=None)
    args = ap.parse_args()
    now = datetime.now().astimezone()
    t0, t1 = parse_since(args.since, now), parse_until(args.until, now)
    n = 0
    for p in sorted(args.captures.rglob("*")):
        if not p.is_file():
            continue
        mt = datetime.fromtimestamp(p.stat().st_mtime, tz=now.tzinfo)
        if t0 <= mt <= t1:
            print(p)
            n += 1
    print(f"# {n} files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
