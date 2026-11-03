#!/usr/bin/env python3
# Hardware-accelerated screen recording and clipping via gpu-screen-recorder
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import (
    RECORD_PID_FILE,
    REPO_ROOT,
    check_dependencies,
    pid_is_running,
    start_recording,
    stop_recording,
)


def cmd_record_status(args):
    if not os.path.exists(RECORD_PID_FILE):
        if getattr(args, "json", False):
            print(json.dumps({"active": False}))
        else:
            print("[*] No active screen recording.")
        return 0

    try:
        with open(RECORD_PID_FILE, "r") as f:
            state = json.load(f)
    except Exception:
        state = {}

    pid = state.get("pid")
    out_file = state.get("output_file")
    is_active = pid and pid_is_running(pid)

    if not is_active:
        if os.path.exists(RECORD_PID_FILE):
            os.remove(RECORD_PID_FILE)
        if getattr(args, "json", False):
            print(json.dumps({"active": False, "stale_cleaned": True}))
        else:
            print(f"[*] No active recording (cleared stale state for PID {pid}).")
        return 0

    elapsed = time.time() - state.get("start_time", time.time())
    size_bytes = os.path.getsize(out_file) if out_file and os.path.exists(out_file) else 0
    size_kb = round(size_bytes / 1024, 2)

    res = {
        "active": True,
        "pid": pid,
        "output_file": out_file,
        "elapsed_seconds": round(elapsed, 1),
        "size_bytes": size_bytes,
        "size_kb": size_kb,
        "preset": state.get("preset"),
        "resolution": state.get("resolution"),
        "fps": state.get("fps"),
        "window": state.get("window"),
    }

    if getattr(args, "json", False):
        print(json.dumps(res, indent=2))
        return 0

    print("=== Active Screen Recording ===")
    print(f"  PID:        {pid}")
    print(f"  Output:     {out_file}")
    print(f"  Duration:   {elapsed:.1f}s")
    print(f"  File Size:  {size_kb} KB ({size_bytes} bytes)")
    print(f"  Preset:     {state.get('preset')} ({state.get('resolution')} @ {state.get('fps')}fps)")
    print(f"  Target:     {state.get('window')}")
    return 0


def cmd_record_clip(args):
    check_dependencies(["gpu-screen-recorder"])
    recordings_dir = REPO_ROOT / "scratch" / "recordings"
    recordings_dir.mkdir(parents=True, exist_ok=True)

    duration = float(args.duration or 5.0)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = args.output or str(recordings_dir / f"clip_{ts}.mp4")
    out_file = os.path.abspath(out_file)
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    preset = "agent" if (getattr(args, "agent", False) or getattr(args, "fast", False)) else "standard"
    res = args.resolution or ("1720x720" if preset == "agent" else "1920x1080")
    fps = str(args.fps or (3 if preset == "agent" else 30))
    window = args.window or "screen"

    cmd = ["gpu-screen-recorder", "-w", window, "-s", res, "-f", fps, "-c", "mp4", "-o", out_file]

    print(f"[*] Recording {duration}s clip ({preset} {res}@{fps}fps) to {out_file}...")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(duration)
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)
    except Exception as e:
        proc.kill()
        print(f"[!] Recording interrupted or timed out: {e}", file=sys.stderr)
        return 1

    if not os.path.exists(out_file):
        print(f"[!] Output file was not created: {out_file}", file=sys.stderr)
        return 1

    size_bytes = os.path.getsize(out_file)
    size_kb = round(size_bytes / 1024, 2)
    print(f"[+] Clip recorded successfully: {out_file} ({size_kb} KB, {size_bytes} bytes)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="agyis record",
        description="Hardware-accelerated screen recording and clipping via gpu-screen-recorder",
    )
    sub = parser.add_subparsers(dest="record_cmd", help="Recorder subcommand")

    # start
    p_start = sub.add_parser("start", help="Start background screen recording")
    p_start.add_argument("--output", "-o", help="Target output MP4 file path")
    p_start.add_argument("--agent", action="store_true", default=True, help="Use agent preset (1720x720 @ 3fps)")
    p_start.add_argument("--resolution", "-s", help="Custom resolution (e.g. 1920x1080)")
    p_start.add_argument("--fps", "-f", type=int, help="Frames per second")
    p_start.add_argument("--window", "-w", default="screen", help="Window or 'screen'")

    # stop
    sub.add_parser("stop", help="Stop active screen recording")

    # status
    p_stat = sub.add_parser("status", help="Inspect recording status")
    p_stat.add_argument("--json", action="store_true", help="Output JSON")

    # clip
    p_clip = sub.add_parser("clip", help="Record a short fixed-duration clip")
    p_clip.add_argument("--duration", "-d", type=float, default=5.0, help="Clip duration in seconds")
    p_clip.add_argument("--output", "-o", help="Target output MP4 file path")
    p_clip.add_argument("--agent", action="store_true", default=True, help="Use agent preset")
    p_clip.add_argument("--resolution", "-s", help="Custom resolution")
    p_clip.add_argument("--fps", "-f", type=int, help="Frames per second")
    p_clip.add_argument("--window", "-w", default="screen", help="Window or 'screen'")

    args = parser.parse_args()
    if not args.record_cmd or args.record_cmd == "status":
        return cmd_record_status(args)
    if args.record_cmd == "start":
        return start_recording(
            output_file=args.output,
            agent_preset=args.agent,
            resolution=args.resolution,
            fps=args.fps,
            window=args.window,
        )
    if args.record_cmd == "stop":
        return stop_recording()
    if args.record_cmd == "clip":
        return cmd_record_clip(args)


if __name__ == "__main__":
    sys.exit(main())
