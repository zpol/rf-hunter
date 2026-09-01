#!/usr/bin/env python3
"""Print research target ranking CSV."""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--csv",
        type=Path,
        default=ROOT / "results" / "research-target-ranking.csv",
    )
    args = ap.parse_args()
    print(args.csv.read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
