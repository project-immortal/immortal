#!/usr/bin/env python3
# Capture game window or desktop screenshot
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)

import argparse
from datetime import datetime
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import REPO_ROOT, get_window_info


def main():
    parser = argparse.ArgumentParser(
        prog="agyis screenshot",
        description="Capture game window or desktop screenshot",
    )
    parser.add_argument("--output", "-o", help="Target output image path")
    parser.add_argument("--window", action="store_true", help="Capture Paladins game window only")
    args = parser.parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = REPO_ROOT / "scratch" / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.output or str(out_dir / f"screen_{ts}.png")
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    captured = False
    if args.window:
        win = get_window_info("Paladins")
        if win and subprocess.run(["which", "import"], stdout=subprocess.DEVNULL).returncode == 0:
            res = subprocess.run(["import", "-window", str(win["window_id"]), out_path], check=False)
            if res.returncode == 0:
                captured = True

    if not captured:
        # Fallback to grim (Wayland) or spectacle or maim
        for tool_cmd in [
            ["grim", out_path],
            ["spectacle", "-b", "-n", "-o", out_path],
            ["import", "-window", "root", out_path],
        ]:
            if subprocess.run(["which", tool_cmd[0]], stdout=subprocess.DEVNULL).returncode == 0:
                res = subprocess.run(tool_cmd, check=False)
                if res.returncode == 0:
                    captured = True
                    break

    if captured and os.path.exists(out_path):
        size_kb = round(os.path.getsize(out_path) / 1024, 2)
        print(f"[+] Screenshot captured: {out_path} ({size_kb} KB)")
        return 0
    else:
        print("[!] Failed to capture screenshot (ensure grim/spectacle/imagemagick is installed).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
