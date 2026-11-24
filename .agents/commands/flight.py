#!/usr/bin/env python3
# Vector 4 automated flight test runner and watchdog
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.capture_core import inspect_sdd_status
from lib.common import (
    DIRTYROOM_ROOT,
    RECORD_PID_FILE,
    REPO_ROOT,
    button_to_hex,
    ensure_immortal_server_built,
    find_game_and_server_processes,
    get_launch_log_path,
    get_window_info,
    is_ydotoold_running,
    kill_game_and_server,
    run_ydotool,
    send_key,
    start_recording,
    stop_recording,
)

MILESTONE_ORDER = [
    "LOBBY_MENU",
    "MATCH_INVITE",
    "GAZEBO",
    "MAP_CHANGE",
    "BROWSE_RANGE",
    "WELCOMED",
    "WORLD_READY",
    "MAP_LOADED",
    "ACTORS_REPLICATED",
]

MILESTONE_SOURCES = {
    "LOBBY_MENU": "client",
    "MATCH_INVITE": "client",
    "GAZEBO": "client",
    "MAP_CHANGE": "client",
    "BROWSE_RANGE": "client",
    "WELCOMED": "client",
    "WORLD_READY": "client",
    "MAP_LOADED": "server",
    "ACTORS_REPLICATED": "server",
}

FLIGHT_TARGET_MAP = {
    "menu": "LOBBY_MENU",
    "invite": "MATCH_INVITE",
    "gazebo": "GAZEBO",
    "map": "MAP_CHANGE",
    "range": "BROWSE_RANGE",
    "welcome": "WELCOMED",
    "world": "WORLD_READY",
    "actors": "ACTORS_REPLICATED",
    "spawn": "ACTORS_REPLICATED",
}

FLIGHT_PATTERNS = {
    "LOBBY_MENU": ["Changing lobby state from 1 to 2."],
    "MATCH_INVITE": [
        "Sending event 0x3af4",
        "MATCH READY",
        "PopMatchInviteDialog",
    ],
    "GAZEBO": ["Changing lobby state from 2 to 3"],
    "MAP_CHANGE": ["ReceiveChangeMap: mapGameId 1615"],
    "BROWSE_RANGE": [
        "Browse: Shootingrange_P",
        "LoadMap: 0.0.0.0:7777/Shootingrange_P",
        "LoadMap: 127.0.0.1:7777/Shootingrange_P",
    ],
    "WELCOMED": ["DevNet: Welcomed by server"],
    "WORLD_READY": [
        "Bringing World shootingrange_p.TheWorld up for play",
        "Bringing World Shootingrange_P.TheWorld up for play",
    ],
    "MAP_LOADED": ["NMT_MapLoaded 0x2A"],
    "ACTORS_REPLICATED": ["emitting UActorChannel opens"],
}

DIAGNOSTIC_PATTERNS = (
    "Bunch",
    "Overflow",
    "Validation failed",
    "NMT_Failure",
    "Error processing datagram",
)
MAX_DIAGNOSTICS = 50


def perform_flight_auto_accept():
    print("[*] [FLIGHT] MATCH_INVITE detected. Waiting 500ms before auto-accept...")
    time.sleep(0.5)
    win = get_window_info("Paladins")
    if win:
        subprocess.run(["xdotool", "windowactivate", "--sync", str(win["window_id"])], check=False)
        time.sleep(0.05)
        target_x = int(win["x"] + 0.5 * win["width"])
        target_y = int(win["y"] + 0.75 * win["height"])
        btn_hex = button_to_hex(1, state="click")
        run_ydotool("mousemove", "--absolute", str(target_x), str(target_y))
        time.sleep(0.02)
        run_ydotool("click", btn_hex)
        time.sleep(0.05)
        send_key("Return")
        print(f"[*] [FLIGHT] Auto-accepted match invite via click at ({target_x}, {target_y}) and Return.")
    else:
        send_key("Return")
        print("[*] [FLIGHT] Paladins window not found for xdotool; dispatched Return key via ydotool.")


def launch_client():
    client_path = "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64/ShippingPC-ChaosGame.exe"
    proton_bin = os.path.expanduser("~/.local/share/Steam/compatibilitytools.d/GE-Proton9-15/proton")
    env = os.environ.copy()
    env["STEAM_COMPAT_CLIENT_INSTALL_PATH"] = os.path.expanduser("~/.local/share/Steam")
    env["STEAM_COMPAT_DATA_PATH"] = "/mnt/fast_data/games/SteamLibrary/steamapps/compatdata/444090"
    env["STEAM_COMPAT_APP_ID"] = "444090"
    env["SteamAppId"] = "444090"
    env["SteamGameId"] = "444090"
    cmd_args = [
        proton_bin,
        "run",
        client_path,
        "-steam",
        "-NoEAC",
        "-nomovie",
        "-hostx=127.0.0.1:9000",
        "-tcp=1",
        "-dumpmar",
        "-dumpallmar",
        "-seekfreeloadingPCConsole",
    ]
    log_path = DIRTYROOM_ROOT / "logs" / "client.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(cmd_args, env=env, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
    print(f"[*] Paladins client process dispatched (PID: {proc.pid}, logging to {log_path}).")
    return proc


def extract_keyframe(rec_file, timestamp_offset, output_img):
    if not rec_file or not os.path.exists(rec_file):
        return None
    offset_s = max(0.0, float(timestamp_offset))
    os.makedirs(os.path.dirname(output_img), exist_ok=True)
    cmd = [
        "ffmpeg",
        "-y",
        "-ss",
        f"{offset_s:.2f}",
        "-i",
        rec_file,
        "-vframes",
        "1",
        "-q:v",
        "2",
        output_img,
    ]
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return output_img if res.returncode == 0 and os.path.exists(output_img) else None


class LogTailer:
    """Non-blocking file tailer handling log creation, truncation, and rotation."""

    def __init__(self, path: Any, source: str):
        self.path = str(path)
        self.source = source
        self.handle = None
        self.ino: Optional[int] = None
        self.pos: int = 0
        self.warned: bool = False

    def read_new_lines(self) -> List[str]:
        """Reads newly appended lines since the last poll."""
        if not os.path.exists(self.path):
            return []
        try:
            st = os.stat(self.path)
            if self.handle is None or st.st_ino != self.ino or st.st_size < self.pos:
                self.close()
                self.handle = open(self.path, "r", encoding="utf-8", errors="replace")
                self.ino = st.st_ino
                self.pos = 0
            lines = self.handle.readlines()
            if lines:
                self.pos = self.handle.tell()
            return lines
        except OSError as exc:
            if not self.warned:
                print(f"[!] Warning: Error reading {self.path}: {exc}", file=sys.stderr)
                self.warned = True
            return []

    def close(self) -> None:
        """Closes the open file handle if present."""
        if self.handle is not None:
            try:
                self.handle.close()
            except OSError:
                pass
            self.handle = None


def create_milestones() -> Dict[str, Dict[str, Any]]:
    """Creates a fresh milestone tracking dictionary in canonical progression order."""
    return {
        m: {"detected": False, "timestamp": None, "elapsed": None, "line": None, "keyframe": None}
        for m in MILESTONE_ORDER
    }


def compute_post_hold(target_key: str, post_hold_arg: Optional[float]) -> float:
    """Returns post-target hold duration, defaulting to 5.0s for late-stage targets."""
    if post_hold_arg is not None:
        return max(0.0, float(post_hold_arg))
    return 5.0 if target_key in ("WORLD_READY", "ACTORS_REPLICATED") else 0.5


def process_log_lines(
    lines: List[str],
    source: str,
    milestones: Dict[str, Dict[str, Any]],
    diagnostics: List[str],
    flight_start_time: float,
    now_fn: Callable[[], float] = time.time,
    on_milestone: Optional[Callable[[str], None]] = None,
) -> None:
    """Matches source-specific milestone patterns and captures bounded error diagnostics."""
    for raw_line in lines:
        clean_line = raw_line.strip()
        if not clean_line:
            continue

        for m_name in MILESTONE_ORDER:
            if MILESTONE_SOURCES.get(m_name) != source or milestones[m_name]["detected"]:
                continue
            for pat in FLIGHT_PATTERNS[m_name]:
                if pat in clean_line:
                    now = now_fn()
                    elapsed = now - flight_start_time
                    milestones[m_name]["detected"] = True
                    milestones[m_name]["timestamp"] = now
                    milestones[m_name]["elapsed"] = round(elapsed, 2)
                    milestones[m_name]["line"] = clean_line
                    print(f"[+] [FLIGHT] Milestone REACHED: {m_name} (+{elapsed:.2f}s)")
                    if on_milestone is not None:
                        on_milestone(m_name)
                    break

        if len(diagnostics) < MAX_DIAGNOSTICS and any(pat in clean_line for pat in DIAGNOSTIC_PATTERNS):
            diagnostics.append(f"[{source}] {clean_line}")


def build_summary_markdown(
    ts_tag: str,
    target_key: str,
    passed: bool,
    total_flight_duration: float,
    timeout_sec: int,
    rec_file: Optional[str],
    rec_size_bytes: int,
    milestones: Dict[str, Dict[str, Any]],
    diagnostics: List[str],
) -> str:
    """Renders the markdown telemetry summary including milestones and bounded diagnostics."""
    summary_lines = [
        f"# Immortal Automated Flight Telemetry: {ts_tag}",
        f"- **Target Milestone**: `{target_key}`",
        f"- **Overall Result**: **{'PASS' if passed else 'FAIL / TIMEOUT'}**",
        f"- **Total Duration**: {total_flight_duration}s (timeout: {timeout_sec}s)",
        f"- **Video Recording**: `{rec_file or 'None'}` ({round(rec_size_bytes / 1024, 2)} KB)",
        "",
        "## Milestone Progression",
        "| Milestone | Detected | Elapsed (s) | Keyframe | Sample Log Line |",
        "| :--- | :---: | :---: | :--- | :--- |",
    ]
    for m_name in MILESTONE_ORDER:
        m_data = milestones[m_name]
        det = "✅ PASS" if m_data["detected"] else "❌"
        el = f"+{m_data['elapsed']}s" if m_data["detected"] else "-"
        kf = f"`{m_data['keyframe']}`" if m_data["keyframe"] else "-"
        ln = f"`{m_data['line'][:60]}...`" if m_data["line"] else "-"
        summary_lines.append(f"| **{m_name}** | {det} | {el} | {kf} | {ln} |")

    summary_lines.extend(["", f"## Diagnostics ({len(diagnostics)}/{MAX_DIAGNOSTICS} max)"])
    if diagnostics:
        summary_lines.extend(f"- `{diag}`" for diag in diagnostics)
    else:
        summary_lines.append("- None")
    return "\n".join(summary_lines)


def print_flight_report(
    args: argparse.Namespace,
    target_key: str,
    passed: bool,
    total_flight_duration: float,
    timeout_sec: int,
    rec_file: Optional[str],
    rec_size_bytes: int,
    summary_path: Path,
    milestones: Dict[str, Dict[str, Any]],
    extracted_keyframes: Dict[str, str],
    diagnostics: List[str],
) -> None:
    """Prints the human-readable post-flight telemetry summary."""
    print("\n============================================================")
    print("              IMMORTAL AUTOMATED FLIGHT REPORT              ")
    print("============================================================")
    print(f"  Flight Target:      {target_key} (target={args.target})")
    print(f"  Overall Result:     {'PASS' if passed else 'FAIL / TIMEOUT'}")
    print(f"  Total Duration:     {total_flight_duration}s / {timeout_sec}s max")
    print(f"  Recording:          {rec_file or 'None'} ({round(rec_size_bytes / 1024, 2)} KB)")
    print(f"  Telemetry Summary:  {summary_path}")
    print("\nMilestones:")
    for m_name in MILESTONE_ORDER:
        m_data = milestones[m_name]
        status_str = (
            f"[PASS]  {m_name:<18} (+{m_data['elapsed']}s)"
            if m_data["detected"]
            else f"[----]  {m_name:<18} (not reached)"
        )
        line_preview = f"  {m_data['line'][:70]}" if m_data["line"] else ""
        print(f"  {status_str}{line_preview}")

    if diagnostics:
        print(f"\nDiagnostics ({len(diagnostics)}/{MAX_DIAGNOSTICS} max):")
        for diag in diagnostics:
            print(f"  - {diag}")

    if extracted_keyframes:
        print("\nKeyframes:")
        for kf_name, kf_p in extracted_keyframes.items():
            print(f"  - {kf_name}: {kf_p}")
    print("============================================================\n")


def _parse_flight_args() -> argparse.Namespace:
    """Parses CLI arguments for the Vector 4 flight harness."""
    parser = argparse.ArgumentParser(
        prog="agyis flight",
        description="Vector 4 automated flight test runner and watchdog",
    )
    parser.add_argument("--timeout", type=int, default=90, help="Max flight run duration in seconds (default: 90)")
    parser.add_argument(
        "--target",
        choices=list(FLIGHT_TARGET_MAP.keys()),
        default="map",
        help="Target milestone to reach (default: map)",
    )
    parser.add_argument(
        "--record",
        dest="record",
        action="store_true",
        default=True,
        help="Enable screen recording with agentic preset 480p 3fps (default: True)",
    )
    parser.add_argument("--no-record", dest="record", action="store_false", help="Disable screen recording")
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Disable automated input/click interaction on match invite",
    )
    parser.add_argument(
        "--post-hold",
        type=float,
        default=None,
        help="Seconds to continue tailing logs after target milestone (default: 5.0 for world/actors/spawn, 0.5 otherwise)",
    )
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Force release rebuild of immortal-server before starting flight",
    )
    parser.add_argument("--json", action="store_true", help="Output flight test results as JSON")
    return parser.parse_args()


def _monitor_flight_logs(
    target_key: str,
    timeout_sec: int,
    post_hold_sec: float,
    manual: bool,
    launch_log: str,
    flight_server_log: Path,
    server_proc: subprocess.Popen,
    client_proc: Optional[subprocess.Popen],
    milestones: Dict[str, Dict[str, Any]],
    diagnostics: List[str],
    flight_start_time: float,
) -> None:
    """Tails both client Launch.log and server flight_server.log until target/hold or exit."""
    invite_handled = False
    client_seen_running = False
    target_reached_at: Optional[float] = None
    client_tailer = LogTailer(launch_log, "client")
    server_tailer = LogTailer(flight_server_log, "server")

    def handle_milestone(m_name: str) -> None:
        nonlocal invite_handled
        if m_name == "MATCH_INVITE" and not manual and not invite_handled:
            invite_handled = True
            perform_flight_auto_accept()

    print(f"[*] [FLIGHT] Monitoring Launch.log and {flight_server_log.name} (timeout: {timeout_sec}s)...")
    try:
        while (time.time() - flight_start_time < timeout_sec) or (
            target_reached_at is not None and (time.time() - target_reached_at) < post_hold_sec
        ):
            process_log_lines(
                client_tailer.read_new_lines(),
                "client",
                milestones,
                diagnostics,
                flight_start_time,
                on_milestone=handle_milestone,
            )
            process_log_lines(
                server_tailer.read_new_lines(),
                "server",
                milestones,
                diagnostics,
                flight_start_time,
                on_milestone=handle_milestone,
            )

            if milestones[target_key]["detected"]:
                if target_reached_at is None:
                    target_reached_at = time.time()
                    print(
                        f"[+] [FLIGHT] Target milestone '{target_key}' reached! "
                        f"Holding {post_hold_sec:.2f}s before concluding..."
                    )
                if (time.time() - target_reached_at) >= post_hold_sec:
                    break

            if server_proc.poll() is not None:
                print(
                    f"[!] [FLIGHT] immortal-server exited unexpectedly (code={server_proc.returncode}). Aborting flight.",
                    file=sys.stderr,
                )
                break

            running_procs = find_game_and_server_processes()
            client_active = any("shippingpc-chaosgame" in m["cmdline"].lower() for m in running_procs)
            if client_active:
                client_seen_running = True
            elif client_seen_running and (client_proc is None or client_proc.poll() is not None):
                print(
                    "[!] [FLIGHT] Paladins client process exited before concluding flight. Aborting flight.",
                    file=sys.stderr,
                )
                break
            elif (
                not client_seen_running
                and (time.time() - flight_start_time) > 10.0
                and client_proc is not None
                and client_proc.poll() is not None
            ):
                print(
                    f"[!] [FLIGHT] Client launcher exited early (code={client_proc.returncode}) without game process. Aborting flight.",
                    file=sys.stderr,
                )
                break

            time.sleep(0.2)
    finally:
        client_tailer.close()
        server_tailer.close()


def main() -> int:
    """Entrypoint for agyis flight."""
    args = _parse_flight_args()
    target_key = FLIGHT_TARGET_MAP[args.target]
    timeout_sec = int(args.timeout)
    post_hold_sec = compute_post_hold(target_key, args.post_hold)

    print("============================================================")
    print("            IMMORTAL AUTOMATED FLIGHT RUNNER                ")
    print("============================================================")
    print(f"[*] Target Milestone:  {target_key} (option: {args.target})")
    print(f"[*] Timeout Limit:     {timeout_sec}s (post-hold: {post_hold_sec:.2f}s)")
    print(f"[*] Screen Recording:  {'ENABLED (agent preset 480p 3fps)' if args.record else 'DISABLED'}")
    print(f"[*] Match Auto-Input:  {'DISABLED (manual mode)' if args.manual else 'ENABLED'}")
    print("============================================================")

    if not args.manual and not is_ydotoold_running():
        print(
            "[!] Warning: ydotoold does not appear to be running; match invite auto-accept may fail. "
            "Start ydotoold or pass --manual to disable automated input.",
            file=sys.stderr,
        )

    # 1. Pre-flight sanity & cleanup
    sdd_info = inspect_sdd_status()
    if sdd_info.get("current_mode") == "retail":
        print(
            "[!] Error: Service Discovery (.sdd) is in RETAIL mode; "
            "restore to IMMORTAL mode ('agyis capture restore --mode immortal') before flight.",
            file=sys.stderr,
        )
        return 1
    print(f"[*] [FLIGHT] Service Discovery mode: {sdd_info.get('current_mode', 'unknown').upper()}")

    print("[*] [FLIGHT] Pre-flight cleanup: terminating lingering game & server processes...")
    kill_game_and_server()
    if os.path.exists(RECORD_PID_FILE):
        try:
            stop_recording()
        except OSError as e:
            print(f"[!] Warning: Could not stop leftover recording: {e}", file=sys.stderr)

    server_bin = ensure_immortal_server_built(force_rebuild=args.force_rebuild)
    if not server_bin or not os.path.isfile(server_bin):
        print("[!] Error: immortal-server binary unavailable. Cannot start flight.", file=sys.stderr)
        return 1

    launch_log = get_launch_log_path()
    if os.path.exists(launch_log):
        try:
            with open(launch_log, "w") as f:
                f.truncate(0)
            print(f"[*] [FLIGHT] Truncated client log: {launch_log}")
        except OSError as e:
            print(f"[!] Warning: Could not truncate {launch_log}: {e}", file=sys.stderr)
    else:
        os.makedirs(os.path.dirname(launch_log), exist_ok=True)
        try:
            open(launch_log, "w").close()
            print(f"[*] [FLIGHT] Initialized client log file: {launch_log}")
        except OSError as e:
            print(f"[!] Warning: Could not initialize {launch_log}: {e}", file=sys.stderr)

    # 2. Start release server daemon in background
    scratch_dir = REPO_ROOT / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    flight_server_log = scratch_dir / "flight_server.log"
    senv = os.environ.copy()
    senv["RUST_LOG"] = "info,immortal_net=debug,immortal_server=debug"
    with open(flight_server_log, "w") as slog:
        server_proc = subprocess.Popen(
            [server_bin], env=senv, stdout=slog, stderr=subprocess.STDOUT, start_new_session=True
        )
    print(f"[*] [FLIGHT] immortal-server daemon started (PID: {server_proc.pid}, logging to {flight_server_log}).")
    time.sleep(0.5)

    # 3. Start recording if enabled
    rec_file = None
    rec_start_time = None
    if args.record:
        rec_res = start_recording(agent_preset=True, window="screen")
        if rec_res != 0:
            print(
                f"[!] Warning: Screen recording failed to start (code: {rec_res}); continuing without video.",
                file=sys.stderr,
            )
        elif os.path.exists(RECORD_PID_FILE):
            try:
                with open(RECORD_PID_FILE, "r") as f:
                    rec_state = json.load(f)
                    rec_file = rec_state.get("output_file")
                    rec_start_time = rec_state.get("start_time", time.time())
            except (OSError, json.JSONDecodeError) as e:
                print(f"[!] Warning: Failed to read recording state {RECORD_PID_FILE}: {e}", file=sys.stderr)

    # 4. Launch Paladins client
    print("[*] [FLIGHT] Launching Paladins game client...")
    client_proc = launch_client()

    # 5. Real-time dual-log monitoring loop
    milestones = create_milestones()
    diagnostics: List[str] = []
    flight_start_time = time.time()
    if rec_start_time is None:
        rec_start_time = flight_start_time

    _monitor_flight_logs(
        target_key=target_key,
        timeout_sec=timeout_sec,
        post_hold_sec=post_hold_sec,
        manual=args.manual,
        launch_log=launch_log,
        flight_server_log=flight_server_log,
        server_proc=server_proc,
        client_proc=client_proc,
        milestones=milestones,
        diagnostics=diagnostics,
        flight_start_time=flight_start_time,
    )

    total_flight_duration = round(time.time() - flight_start_time, 2)
    print("[*] [FLIGHT] Initiating post-flight shutdown and evidence extraction...")

    # Stop screen recording
    rec_size_bytes = 0
    if args.record:
        stop_recording()
        if rec_file and os.path.exists(rec_file):
            rec_size_bytes = os.path.getsize(rec_file)

    # Extract keyframes
    ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    keyframes_dir = REPO_ROOT / "scratch" / "recordings" / f"keyframes_{ts_tag}"
    extracted_keyframes: Dict[str, str] = {}

    if rec_file and os.path.exists(rec_file):
        print(f"[*] [FLIGHT] Extracting milestone keyframes from {rec_file}...")
        for m_name, info in milestones.items():
            if info["detected"] and info["timestamp"] is not None:
                offset_in_rec = max(0.0, info["timestamp"] - rec_start_time)
                img_out = str(keyframes_dir / f"{m_name.lower()}.jpg")
                kf_path = extract_keyframe(rec_file, offset_in_rec, img_out)
                if kf_path:
                    info["keyframe"] = kf_path
                    extracted_keyframes[m_name] = kf_path

    # Cleanup processes
    kill_game_and_server()

    # Compile Telemetry Report
    passed = milestones[target_key]["detected"]
    summary_path = REPO_ROOT / "scratch" / "recordings" / f"flight_summary_{ts_tag}.md"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_content = build_summary_markdown(
        ts_tag=ts_tag,
        target_key=target_key,
        passed=passed,
        total_flight_duration=total_flight_duration,
        timeout_sec=timeout_sec,
        rec_file=rec_file,
        rec_size_bytes=rec_size_bytes,
        milestones=milestones,
        diagnostics=diagnostics,
    )
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_content)
    print(f"[*] [FLIGHT] Flight telemetry summary saved to: {summary_path}")

    if args.json:
        report_data = {
            "target": target_key,
            "passed": passed,
            "duration": total_flight_duration,
            "post_hold": post_hold_sec,
            "recording": rec_file,
            "recording_size_bytes": rec_size_bytes,
            "summary_file": str(summary_path),
            "milestones": milestones,
            "diagnostics": diagnostics,
        }
        print(json.dumps(report_data, indent=2))
        return 0 if passed else 1

    print_flight_report(
        args=args,
        target_key=target_key,
        passed=passed,
        total_flight_duration=total_flight_duration,
        timeout_sec=timeout_sec,
        rec_file=rec_file,
        rec_size_bytes=rec_size_bytes,
        summary_path=summary_path,
        milestones=milestones,
        extracted_keyframes=extracted_keyframes,
        diagnostics=diagnostics,
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
