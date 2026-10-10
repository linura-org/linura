#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "visual/baselines/manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Linura visual regression helper")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    compare = sub.add_parser("compare")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("actual", type=Path)
    compare.add_argument("diff", type=Path)
    args = parser.parse_args()
    if args.command == "list":
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for item in data["baselines"]:
            print(f"{item['id']}: {item['surface']} {item['width']}x{item['height']} scale={item['scale']} baseline={item['baseline']}")
        return 0
    compare_bin = shutil.which("compare")
    if compare_bin is None:
        print("ImageMagick compare is required for visual comparison", file=sys.stderr)
        return 2
    args.diff.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run([compare_bin, "-metric", "AE", str(args.baseline), str(args.actual), str(args.diff)], check=False)
    return 0 if completed.returncode == 0 else completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
