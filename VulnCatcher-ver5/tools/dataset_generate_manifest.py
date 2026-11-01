"""Generate the checked-in AWVS-compatible 20-category manifest."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sunset.baofeng import build_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=Path, default=Path("runtime/dataset-targets.json"))
    parser.add_argument("--base-url", default="http://127.0.0.1:18081")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_manifest(args.base_url), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(build_manifest(args.base_url)['targets'])} targets / 20 categories -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
