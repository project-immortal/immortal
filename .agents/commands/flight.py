#!/usr/bin/env python3
# Vector 4 automated flight test runner and watchdog
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import (
    DIRTYROOM_ROOT,
    RECORD_PID_FILE,
    REPO_ROOT,
    button_to_hex,
    ensure_immortal_server_built,
    get_launch_log_path,
    get_window_info,
    kill_game_and_server,
    pid_is_running,
    run_ydotool,
    send_key,
    start_recording,
    stop_recording,
)

FLIGHT_TARGET_MAP = {
    "menu": "LOBBY_MENU",
    "invite": "MATCH_INVITE",
    "gazebo": "GAZEBO",
    "map": "MAP_CHANGE",
    "range": "BROWSE_RANGE",
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
    "BROWSE_RANGE": ["Browse: Shootingrange_P"],
}


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
    log_file = open(log_path, "w")
    subprocess.Popen(cmd_args, env=env, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
    print(f"[*] Paladins client process dispatched (logging to {log_path}).")


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


def main():
    parser = argparse.ArgumentParser(
        prog="agyis flight",
        description="Vector 4 automated flight test runner and watchdog",
    )
    parser.add_argument("--timeout", type=int, default=90, help="Max flight run duration in seconds (default: 90)")
    parser.add_argument(
        "--target",
        choices=["menu", "invite", "gazebo", "map", "range"],
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
    parser.add_argument("--json", action="store_true", help="Output flight test results as JSON")
    args = parser.parse_args()

    target_key = FLIGHT_TARGET_MAP[args.target]
    timeout_sec = int(args.timeout)
    print("============================================================")
    print("            IMMORTAL AUTOMATED FLIGHT RUNNER                ")
    print("============================================================")
    print(f"[*] Target Milestone:  {target_key} (option: {args.target})")
    print(f"[*] Timeout Limit:     {timeout_sec}s")
    print(f"[*] Screen Recording:  {'ENABLED (agent preset 480p 3fps)' if args.record else 'DISABLED'}")
    print(f"[*] Match Auto-Input:  {'DISABLED (manual mode)' if args.manual else 'ENABLED'}")
    print("============================================================")

    # 1. Pre-flight sanity & cleanup
    print("[*] [FLIGHT] Pre-flight cleanup: terminating lingering game & server processes...")
    kill_game_and_server()
    if os.path.exists(RECORD_PID_FILE):
        try:
            stop_recording()
        except Exception:
            pass

    server_bin = ensure_immortal_server_built()
    if not server_bin or not os.path.isfile(server_bin):
        print("[!] Error: immortal-server binary unavailable. Cannot start flight.", file=sys.stderr)
        return 1

    launch_log = get_launch_log_path()
    if os.path.exists(launch_log):
        try:
            with open(launch_log, "w") as f:
                f.truncate(0)
            print(f"[*] [FLIGHT] Truncated client log: {launch_log}")
        except Exception as e:
            print(f"[!] Warning: Could not truncate {launch_log}: {e}", file=sys.stderr)
    else:
        os.makedirs(os.path.dirname(launch_log), exist_ok=True)
        try:
            open(launch_log, "w").close()
            print(f"[*] [FLIGHT] Initialized client log file: {launch_log}")
        except Exception as e:
            print(f"[!] Warning: Could not initialize {launch_log}: {e}", file=sys.stderr)

    # 2. Start release server daemon in background
    scratch_dir = REPO_ROOT / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    flight_server_log = scratch_dir / "flight_server.log"
    slog = open(flight_server_log, "w")
    senv = os.environ.copy()
    senv["RUST_LOG"] = "info,immortal_net=debug,immortal_server=debug"
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
        if rec_res == 0 and os.path.exists(RECORD_PID_FILE):
            try:
                with open(RECORD_PID_FILE, "r") as f:
                    rec_state = json.load(f)
                    rec_file = rec_state.get("output_file")
                    rec_start_time = rec_state.get("start_time", time.time())
            except Exception:
                pass

    # 4. Launch Paladins client
    print("[*] [FLIGHT] Launching Paladins game client...")
    launch_client()

    # 5. Real-time log monitoring loop
    milestones = {
        m: {"detected": False, "timestamp": None, "elapsed": None, "line": None, "keyframe": None}
        for m in ["LOBBY_MENU", "MATCH_INVITE", "GAZEBO", "MAP_CHANGE", "BROWSE_RANGE"]
    }
    flight_start_time = time.time()
    if rec_start_time is None:
        rec_start_time = flight_start_time

    invite_handled = False
    log_handle = None
    current_ino = None
    current_pos = 0

    print(f"[*] [FLIGHT] Monitoring Launch.log for milestone progression (timeout: {timeout_sec}s)...")

    try:
        while time.time() - flight_start_time < timeout_sec:
            if milestones[target_key]["detected"]:
                print(f"[+] [FLIGHT] Target milestone '{target_key}' reached! Concluding flight.")
                time.sleep(0.5)
                break

            if os.path.exists(launch_log):
                try:
                    st = os.stat(launch_log)
                    if log_handle is None or st.st_ino != current_ino or st.st_size < current_pos:
                        if log_handle:
                            log_handle.close()
                        log_handle = open(launch_log, "r", encoding="utf-8", errors="replace")
                        current_ino = st.st_ino
                        current_pos = 0

                    new_lines = log_handle.readlines()
                    if new_lines:
                        current_pos = log_handle.tell()
                        for line in new_lines:
                            clean_line = line.strip()
                            for m_name, patterns in FLIGHT_PATTERNS.items():
                                if not milestones[m_name]["detected"]:
                                    for pat in patterns:
                                        if pat in clean_line:
                                            now = time.time()
                                            elapsed = now - flight_start_time
                                            milestones[m_name]["detected"] = True
                                            milestones[m_name]["timestamp"] = now
                                            milestones[m_name]["elapsed"] = round(elapsed, 2)
                                            milestones[m_name]["line"] = clean_line
                                            print(f"[+] [FLIGHT] Milestone REACHED: {m_name} (+{elapsed:.2f}s)")

                                            if m_name == "MATCH_INVITE" and not args.manual and not invite_handled:
                                                invite_handled = True
                                                perform_flight_auto_accept()
                                            break
                except Exception:
                    pass

            time.sleep(0.2)
    finally:
        if log_handle:
            try:
                log_handle.close()
            except Exception:
                pass

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
    extracted_keyframes = {}

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
    for m_name in ["LOBBY_MENU", "MATCH_INVITE", "GAZEBO", "MAP_CHANGE", "BROWSE_RANGE"]:
        m_data = milestones[m_name]
        det = "✅ PASS" if m_data["detected"] else "❌"
        el = f"+{m_data['elapsed']}s" if m_data["detected"] else "-"
        kf = f"`{m_data['keyframe']}`" if m_data["keyframe"] else "-"
        ln = f"`{m_data['line'][:60]}...`" if m_data["line"] else "-"
        summary_lines.append(f"| **{m_name}** | {det} | {el} | {kf} | {ln} |")

    summary_content = "\n".join(summary_lines)
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_content)
    print(f"[*] [FLIGHT] Flight telemetry summary saved to: {summary_path}")

    if args.json:
        report_data = {
            "target": target_key,
            "passed": passed,
            "duration": total_flight_duration,
            "recording": rec_file,
            "recording_size_bytes": rec_size_bytes,
            "summary_file": str(summary_path),
            "milestones": milestones,
        }
        print(json.dumps(report_data, indent=2))
        return 0 if passed else 1

    print("\n============================================================")
    print("              IMMORTAL AUTOMATED FLIGHT REPORT              ")
    print("============================================================")
    print(f"  Flight Target:      {target_key} (target={args.target})")
    print(f"  Overall Result:     {'PASS' if passed else 'FAIL / TIMEOUT'}")
    print(f"  Total Duration:     {total_flight_duration}s / {timeout_sec}s max")
    print(f"  Recording:          {rec_file or 'None'} ({round(rec_size_bytes / 1024, 2)} KB)")
    print(f"  Telemetry Summary:  {summary_path}")
    print("\nMilestones:")
    for m_name in ["LOBBY_MENU", "MATCH_INVITE", "GAZEBO", "MAP_CHANGE", "BROWSE_RANGE"]:
        m_data = milestones[m_name]
        status_str = f"[PASS]  {m_name:<14} (+{m_data['elapsed']}s)" if m_data["detected"] else f"[----]  {m_name:<14} (not reached)"
        line_preview = f"  {m_data['line'][:70]}" if m_data["line"] else ""
        print(f"  {status_str}{line_preview}")

    if extracted_keyframes:
        print("\nKeyframes:")
        for kf_name, kf_p in extracted_keyframes.items():
            print(f"  - {kf_name}: {kf_p}")
    print("============================================================\n")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
