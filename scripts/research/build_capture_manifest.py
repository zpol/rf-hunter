#!/usr/bin/env python3
"""Build capture manifest (delegates to generate_research_report)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_research_report import main

if __name__ == "__main__":
    # alias entry
    raise SystemExit(main(sys.argv[1:]))
