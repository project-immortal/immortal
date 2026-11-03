# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Shared routines for Immortal bespoke extension commands (ADR-034).
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

DIRTYROOM_ROOT = Path(
    os.environ.get("IMMORTAL_DIRTYROOM")
    or (REPO_ROOT / ".dirtyroom")
    or "/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0"
)
if (REPO_ROOT / ".dirtyroom").exists():
    DIRTYROOM_ROOT = (REPO_ROOT / ".dirtyroom").resolve()
elif not DIRTYROOM_ROOT.exists():
    DIRTYROOM_ROOT = Path("/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0")

DB_PATH = DIRTYROOM_ROOT / "symbols" / "paladins_symbols.sqlite"
RECORD_PID_FILE = "/tmp/immortal_recorder.json"


def get_db() -> Optional[sqlite3.Connection]:
    """Returns an open connection to the dirtyroom symbol database."""
    if not DB_PATH.is_file():
        # Fallback to any sqlite in dirtyroom
        cands = [
            DIRTYROOM_ROOT / "symbols" / "dirtyroom.db",
            DIRTYROOM_ROOT / "paladins_symbols.sqlite",
            DIRTYROOM_ROOT / "dirtyroom.db",
        ]
        for c in cands:
            if c.is_file():
                return sqlite3.connect(str(c))
        return None
    return sqlite3.connect(str(DB_PATH))


def get_launch_log_path() -> str:
    """Discovers client Launch.log in Steam Proton compatdata."""
    primary = os.path.expanduser(
        "/mnt/fast_data/games/SteamLibrary/steamapps/compatdata/444090/pfx/drive_c/users/steamuser/Documents/My Games/Paladins/ChaosGame/Logs/Launch.log"
    )
    if os.path.exists(primary):
        return primary
    for root_dir in [
        "/mnt/fast_data/games/SteamLibrary/steamapps/compatdata/444090",
        os.path.expanduser("~/.local/share/Steam/steamapps/compatdata/444090"),
    ]:
        cand = os.path.join(
            root_dir,
            "pfx/drive_c/users/steamuser/Documents/My Games/Paladins/ChaosGame/Logs/Launch.log",
        )
        if os.path.exists(cand):
            return cand
    return primary


def check_dependencies(bins: List[str]) -> None:
    """Asserts required system CLI tools are present."""
    missing = [b for b in bins if shutil.which(b) is None]
    if missing:
        print(
            f"[!] Error: Missing required system dependencies: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)


def pid_is_running(pid: int) -> bool:
    """Checks if a PID is actively executing."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def kill_game_and_server() -> None:
    """Terminates lingering Paladins and Immortal server processes."""
    subprocess.run(["pkill", "-9", "-f", "ShippingPC-ChaosGame.exe"], stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "immortal-server"], stderr=subprocess.DEVNULL)
    time.sleep(0.3)


def ensure_immortal_server_built() -> Optional[str]:
    """Ensures target/release/immortal-server is compiled and available."""
    server_bin = REPO_ROOT / "target" / "release" / "immortal-server"
    if not server_bin.is_file():
        print("[*] [FLIGHT] Building target/release/immortal-server...")
        res = subprocess.run(["cargo", "build", "--release", "-p", "immortal-server"], cwd=REPO_ROOT)
        if res.returncode != 0:
            print("[!] Warning: cargo build --release -p immortal-server failed.", file=sys.stderr)
            return None
    return str(server_bin)


# --- Hardware Screen Recording Helpers (gpu-screen-recorder) ---

def start_recording(
    output_file: Optional[str] = None,
    agent_preset: bool = True,
    resolution: Optional[str] = None,
    fps: Optional[int] = None,
    window: str = "screen",
) -> int:
    """Starts screen recording via gpu-screen-recorder in background."""
    check_dependencies(["gpu-screen-recorder"])
    recordings_dir = REPO_ROOT / "scratch" / "recordings"
    recordings_dir.mkdir(parents=True, exist_ok=True)

    if os.path.exists(RECORD_PID_FILE):
        try:
            with open(RECORD_PID_FILE, "r") as f:
                state = json.load(f)
            pid = state.get("pid")
            if pid and pid_is_running(pid):
                print(
                    f"[!] Error: Recorder already running (PID: {pid}, output: {state.get('output_file')})",
                    file=sys.stderr,
                )
                return 1
        except Exception:
            pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = output_file or str(recordings_dir / f"rec_{ts}.mp4")
    out_file = os.path.abspath(out_file)
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    preset = "agent" if agent_preset else "standard"
    res = resolution or ("1720x720" if preset == "agent" else "1920x1080")
    fps_val = str(fps or (3 if preset == "agent" else 30))

    cmd = ["gpu-screen-recorder", "-w", window, "-s", res, "-f", fps_val, "-c", "mp4", "-o", out_file]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    state = {
        "pid": proc.pid,
        "output_file": out_file,
        "start_time": time.time(),
        "preset": preset,
        "resolution": res,
        "fps": fps_val,
        "window": window,
    }
    with open(RECORD_PID_FILE, "w") as f:
        json.dump(state, f, indent=2)

    print(f"[*] Screen recording started (PID: {proc.pid})")
    print(f"    Output:     {out_file}")
    print(f"    Preset:     {preset} ({res} @ {fps_val}fps)")
    print(f"    Target:     {window}")
    return 0


def stop_recording() -> int:
    """Stops active screen recording cleanly via SIGINT."""
    if not os.path.exists(RECORD_PID_FILE):
        print("[!] No active recording found.", file=sys.stderr)
        return 1

    try:
        with open(RECORD_PID_FILE, "r") as f:
            state = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read recorder state: {e}", file=sys.stderr)
        return 1

    pid = state.get("pid")
    out_file = state.get("output_file")
    if pid and pid_is_running(pid):
        try:
            os.kill(pid, signal.SIGINT)
        except ProcessLookupError:
            pass

        start_wait = time.time()
        while time.time() - start_wait < 5.0:
            if not pid_is_running(pid):
                break
            time.sleep(0.1)

        if pid_is_running(pid):
            print(f"[!] Process {pid} did not exit after SIGINT, forcing termination...", file=sys.stderr)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    if os.path.exists(RECORD_PID_FILE):
        try:
            os.remove(RECORD_PID_FILE)
        except OSError:
            pass

    size_bytes = os.path.getsize(out_file) if out_file and os.path.exists(out_file) else 0
    size_kb = round(size_bytes / 1024, 2)
    print(f"[*] Screen recording stopped (PID: {pid}).")
    print(f"    Output: {out_file} ({size_kb} KB, {size_bytes} bytes)")
    return 0


# --- Window & Input Automation Helpers (xdotool & ydotool) ---

def get_window_info(name_substring: str = "Paladins") -> Optional[Dict[str, Any]]:
    """Gets window geometry and ID matching name substring."""
    try:
        proc = subprocess.run(["xdotool", "search", "--name", name_substring], stdout=subprocess.PIPE, text=True)
        wids = [w.strip() for w in proc.stdout.splitlines() if w.strip()]
        if not wids:
            return None

        # Inspect geometry of top matching window
        for wid in wids:
            gproc = subprocess.run(["xdotool", "getwindowgeometry", wid], stdout=subprocess.PIPE, text=True)
            out = gproc.stdout
            if "Position:" in out and "Geometry:" in out:
                pos_line = [l for l in out.splitlines() if "Position:" in l][0]
                geom_line = [l for l in out.splitlines() if "Geometry:" in l][0]
                pos_str = pos_line.split("Position:")[1].split("(")[0].strip()
                x, y = [int(p) for p in pos_str.split(",")]
                w, h = [int(g) for g in geom_line.split("Geometry:")[1].strip().split("x")]
                if w > 100 and h > 100:  # Ignore off-screen helper windows
                    return {
                        "window_id": int(wid),
                        "window_id_hex": hex(int(wid)),
                        "name": name_substring,
                        "x": x,
                        "y": y,
                        "width": w,
                        "height": h,
                    }
    except Exception:
        pass
    return None


def button_to_hex(button: int, state: str = "click") -> str:
    """Converts mouse button number (1, 2, 3) to ydotool hex code."""
    btn_idx = button - 1
    if state == "click":
        return hex(0xC0 | btn_idx)
    elif state == "down":
        return hex(0x40 | btn_idx)
    elif state == "up":
        return hex(0x80 | btn_idx)
    return hex(0xC0 | btn_idx)


def run_ydotool(*args: str) -> subprocess.CompletedProcess:
    """Executes a command via ydotool with safe error handling."""
    cmd = ["ydotool"] + list(args)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def send_key(key_name: str) -> subprocess.CompletedProcess:
    """Sends a key press and release via ydotool."""
    KEY_MAP = {
        "Return": "28:1 28:0",
        "Enter": "28:1 28:0",
        "Escape": "1:1 1:0",
        "Space": "57:1 57:0",
        "Tab": "15:1 15:0",
        "F10": "68:1 68:0",
        "F11": "87:1 87:0",
        "F12": "88:1 88:0",
    }
    key_seq = KEY_MAP.get(key_name)
    if key_seq:
        return run_ydotool("key", *key_seq.split())
    else:
        return run_ydotool("key", key_name)
