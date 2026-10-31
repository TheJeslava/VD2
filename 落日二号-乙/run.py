#!/usr/bin/env python3
"""便捷入口：python run.py <zip> [--llm off] [-o out]"""

from __future__ import annotations

from sunset.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
