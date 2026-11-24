#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Headless Wine retail dedicated server oracle control and live verification (ADOPT-09).
Provides management, lifecycle control, diagnostic telemetry, and client connection
for the authentic Paladins UE3 dedicated server running under Wine.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import (
    DIRTYROOM_ROOT,
    pid_is_running,
)

# Paths and configuration
ORACLE_DIR = DIRTYROOM_ROOT / "oracle"
ORACLE_RUNTIME_BIN = ORACLE_DIR / "runtime" / "Binaries" / "Win64" / "ShippingPC-ChaosGame-Server.exe"
WINE_PREFIX = ORACLE_DIR / "prefix"
PID_FILE = ORACLE_DIR / "retail_server.pid"
LOG_FILE = ORACLE_DIR / "retail_server.log"
UE3_LAUNCH_LOG = Path(os.path.expanduser("~/Documents/My Games/Tempest/ChaosGame/Logs/Launch.log"))

DEFAULT_MAP = "SG_JaguarFalls_Rework_P"
DEFAULT_PORT = 7000
DEFAULT_MULTIHOME = "127.0.0.1"
STARTUP_WAIT_SECONDS = 5.0

CANDIDATE_BINS = [
    ORACLE_RUNTIME_BIN,
    ORACLE_DIR / "bin" / "ShippingPC-ChaosGame-Server.exe",
    DIRTYROOM_ROOT / "binaries" / "ShippingPC-ChaosGame-Server.exe",
    Path("/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64/ShippingPC-ChaosGame-Server.exe"),
    DIRTYROOM_ROOT / "binaries" / "ShippingPC-ChaosGame.exe",
    Path("/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64/ShippingPC-ChaosGame.exe"),
]


def resolve_binary_and_dir() -> Tuple[Optional[Path], Optional[Path]]:
    """Resolves target binary and working directory where ../../ChaosGame is accessible."""
    # Priority 1: Candidate with ../../ChaosGame directory intact
    for bin_path in CANDIDATE_BINS:
        if bin_path.is_file():
            bdir = bin_path.parent
            if (bdir / ".." / ".." / "ChaosGame").resolve().is_dir():
                return bin_path, bdir
            real_bin = bin_path.resolve()
            real_dir = real_bin.parent
            if (real_dir / ".." / ".." / "ChaosGame").resolve().is_dir():
                return real_bin, real_dir

    # Priority 2: Any existing candidate
    for bin_path in CANDIDATE_BINS:
        real_bin = bin_path.resolve()
        if real_bin.is_file():
            return real_bin, real_bin.parent

    return None, None


def get_active_pid() -> Optional[int]:
    """Reads PID file and verifies if process is actively executing."""
    if PID_FILE.is_file():
        try:
            pid = int(PID_FILE.read_text().strip())
            if pid_is_running(pid):
                return pid
        except (ValueError, OSError):
            pass
    return None


def is_udp_port_bound(port: int) -> bool:
    """Checks whether the specified UDP port is listening."""
    try:
        proc = subprocess.run(
            ["ss", "-ulnp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        pattern = re.compile(rf":{port}(?:\s|$)")
        for line in proc.stdout.splitlines():
            if pattern.search(line):
                return True
    except (OSError, subprocess.SubprocessError):
        return False
    return False


def get_process_rss_mb(pid: int) -> Optional[float]:
    """Returns the RSS memory usage of the process in MB."""
    try:
        proc = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        out = proc.stdout.strip()
        if out:
            return float(out) / 1024.0
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return None


def cmd_status(args: argparse.Namespace) -> int:
    """Reports status, PID, memory, and UDP socket state of the server oracle."""
    pid = get_active_pid()
    port = getattr(args, "port", DEFAULT_PORT)
    map_name = getattr(args, "map", DEFAULT_MAP)

    print("=== Headless Wine Retail Dedicated Server Oracle Status ===")
    print(f"Oracle Directory: {ORACLE_DIR}")
    print(f"Wine Prefix:      {WINE_PREFIX}")
    print(f"PID File:         {PID_FILE}")
    print(f"Log File:         {LOG_FILE}")
    print(f"Configured Port:  {port}")
    print(f"Configured Map:   {map_name}")

    if pid is not None:
        rss = get_process_rss_mb(pid)
        mem_str = f"{rss:.1f} MB" if rss else "N/A"
        print(f"State:            RUNNING (PID: {pid})")
        print(f"Memory RSS:       {mem_str}")

        if is_udp_port_bound(port):
            print(f"UDP Port {port}:     LISTENING (bound to network)")
        else:
            print(f"UDP Port {port}:     INITIALIZING (UE3 engine load phase)")
        return 0

    if PID_FILE.is_file():
        try:
            stale_pid = PID_FILE.read_text().strip()
            print(f"State:            STOPPED (stale PID file {stale_pid} cleaned)")
            PID_FILE.unlink(missing_ok=True)
        except OSError:
            print("State:            STOPPED")
    else:
        print("State:            STOPPED")
    return 1


def cmd_stop(args: Optional[argparse.Namespace] = None) -> int:
    """Stops the server gracefully via SIGTERM, then SIGKILL and wineserver cleanup."""
    print("=== Stopping Headless Wine Retail Server Oracle ===")
    pid = get_active_pid()
    if pid is None:
        if PID_FILE.is_file():
            PID_FILE.unlink(missing_ok=True)
        print("Server is not running.")
        if shutil.which("wineserver"):
            env = os.environ.copy()
            env["WINEPREFIX"] = str(WINE_PREFIX)
            subprocess.run(["wineserver", "-k"], env=env, stderr=subprocess.DEVNULL)
        return 0

    print(f"Sending SIGTERM to PID {pid}...")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass

    waited = 0.0
    while pid_is_running(pid) and waited < 5.0:
        time.sleep(0.5)
        waited += 0.5

    if pid_is_running(pid):
        print(f"PID {pid} did not exit gracefully; sending SIGKILL...")
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        time.sleep(0.5)

    if shutil.which("wineserver"):
        env = os.environ.copy()
        env["WINEPREFIX"] = str(WINE_PREFIX)
        subprocess.run(["wineserver", "-k"], env=env, stderr=subprocess.DEVNULL)

    PID_FILE.unlink(missing_ok=True)
    print(f"Server (PID {pid}) stopped successfully.")
    return 0


def resolve_server_runner() -> Tuple[str, List[str], dict]:
    """
    Standardizes on headless system Wine (fast startup, lightweight, no GPU overhead).
    Falls back to GE-Proton9-15 if system wine is not present.
    """
    wine_bin = shutil.which("wine") or "/usr/bin/wine"
    if os.path.isfile(wine_bin) and os.access(wine_bin, os.X_OK):
        env = {
            "WINEPREFIX": str(WINE_PREFIX),
            "WINEDLLOVERRIDES": "mscoree,mshtml=",
            "WINEDEBUG": "-all",
            "OPENSSL_ia32cap": "~0x20000000",
        }
        return wine_bin, [], env

    # Fallback to GE-Proton9-15 if system wine is not installed
    proton_bin = os.path.expanduser("~/.local/share/Steam/compatibilitytools.d/GE-Proton9-15/proton")
    if os.path.isfile(proton_bin):
        env = {
            "STEAM_COMPAT_CLIENT_INSTALL_PATH": os.path.expanduser("~/.local/share/Steam"),
            "STEAM_COMPAT_DATA_PATH": str(ORACLE_DIR / "compatdata"),
            "STEAM_COMPAT_APP_ID": "444090",
            "SteamAppId": "444090",
            "SteamGameId": "444090",
            "OPENSSL_ia32cap": "~0x20000000",
            "WINEDLLOVERRIDES": "mscoree,mshtml=",
            "WINEDEBUG": "-all",
        }
        return proton_bin, ["run"], env

    return "", [], {}


def cmd_start(args: argparse.Namespace) -> int:
    """Launches the server headlessly under Wine."""
    ORACLE_DIR.mkdir(parents=True, exist_ok=True)
    WINE_PREFIX.mkdir(parents=True, exist_ok=True)

    existing_pid = get_active_pid()
    if existing_pid is not None:
        print(f"Server is already running with PID {existing_pid}.")
        return 0

    target_bin, bin_dir = resolve_binary_and_dir()
    if not target_bin or not target_bin.is_file():
        print("[!] Error: Could not locate ShippingPC-ChaosGame server binary at candidate paths:", file=sys.stderr)
        for b in CANDIDATE_BINS:
            print(f"  - {b}", file=sys.stderr)
        return 1

    runner_bin, runner_prefix_args, runner_env = resolve_server_runner()
    if not runner_bin:
        print("[!] Error: Neither system Wine nor Proton was found on this system.", file=sys.stderr)
        return 1

    # Check for EAC directory bypass (only in non-isolated dirs that carry EasyAntiCheat)
    eac_dir = bin_dir / "EasyAntiCheat"
    eac_renamed = bin_dir / "_EasyAntiCheat"
    if eac_dir.is_dir() and not eac_renamed.is_dir():
        print(f"Renaming {eac_dir} to {eac_renamed} for Wine bypass...")
        try:
            eac_dir.rename(eac_renamed)
        except OSError as e:
            print(f"[!] Warning: Failed to rename EasyAntiCheat: {e}", file=sys.stderr)

    # Environment configuration
    env = os.environ.copy()
    env.update(runner_env)

    is_server_bin = "Server" in target_bin.name

    if is_server_bin:
        # Authentic dedicated server mode (ADOPT-09): NullRHI, strictly headless with zero display windows
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
    else:
        # Fallback client/listen server mode: ensure DISPLAY is available for D3D viewport
        if not env.get("DISPLAY"):
            if os.environ.get("DISPLAY"):
                env["DISPLAY"] = os.environ["DISPLAY"]
            elif os.path.exists("/tmp/.X11-unix/X0"):
                env["DISPLAY"] = ":0"
            elif os.path.exists("/tmp/.X11-unix/X1"):
                env["DISPLAY"] = ":1"

    map_name = getattr(args, "map", None) or DEFAULT_MAP
    port = getattr(args, "port", None) or DEFAULT_PORT
    multihome = getattr(args, "multihome", None) or DEFAULT_MULTIHOME
    is_daemon = getattr(args, "daemon", True)

    common_flags = [
        f"-port={port}",
        f"-multihome={multihome}",
        "-seekfreeloadingpcconsole",
        "-pid=402",
        "-eac-nop-loaded",
        "-homedir=Tempest",
        "-log",
    ]
    if is_server_bin:
        map_query = f"{map_name}?game=TgGame.TgGame_Paladins?maxplayers=2"
        launch_tail = [str(target_bin), "server", map_query] + common_flags
    else:
        map_query = f"{map_name}?listen?game=TgGame.TgGame_Paladins?maxplayers=2"
        launch_tail = [str(target_bin), map_query] + common_flags

    server_args = [runner_bin] + runner_prefix_args + launch_tail

    print("=== Launching Headless Wine Retail Dedicated Server Oracle ===")
    print(f"Binary:        {target_bin}")
    print(f"Working Dir:   {bin_dir}")
    print(f"Runner:        {runner_bin} {' '.join(runner_prefix_args)}".strip())
    print(f"WINEPREFIX:    {WINE_PREFIX}")
    print(f"Port:          {port}")
    print(f"Multihome:     {multihome}")
    print(f"Map:           {map_name}")
    print(f"Command:       {' '.join(server_args)}")
    print(f"Log:           {LOG_FILE}")

    if is_daemon:
        with open(LOG_FILE, "w") as log_out:
            proc = subprocess.Popen(
                server_args,
                cwd=str(bin_dir),
                env=env,
                stdout=log_out,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        PID_FILE.write_text(str(proc.pid))
        print(f"Server started as daemon with PID {proc.pid}.")

        waited = 0.0
        step = 0.5
        while waited < STARTUP_WAIT_SECONDS:
            time.sleep(step)
            waited += step
            if not pid_is_running(proc.pid):
                PID_FILE.unlink(missing_ok=True)
                print(
                    f"[!] Warning: Process {proc.pid} exited {waited:.1f}s after start. Check {LOG_FILE}.",
                    file=sys.stderr,
                )
                return 1

        print(f"Process {proc.pid} confirmed active after {STARTUP_WAIT_SECONDS:.1f}s.")
        return 0

    try:
        with open(LOG_FILE, "a") as log_out:
            proc = subprocess.Popen(
                server_args,
                cwd=str(bin_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            PID_FILE.write_text(str(proc.pid))
            if proc.stdout is not None:
                for line in proc.stdout:
                    sys.stdout.write(line)
                    log_out.write(line)
            proc.wait()
            return proc.returncode
    except KeyboardInterrupt:
        cmd_stop()
        return 0


def cmd_restart(args: argparse.Namespace) -> int:
    """Restarts the server oracle."""
    cmd_stop(args)
    time.sleep(1.0)
    return cmd_start(args)


def cmd_logs(args: argparse.Namespace) -> int:
    """Displays or follows server log outputs."""
    lines_count = getattr(args, "lines", 50)
    follow = getattr(args, "follow", False)

    print(f"=== Console Output Log ({LOG_FILE}) ===")
    if LOG_FILE.is_file():
        subprocess.run(["tail", "-n", str(lines_count), str(LOG_FILE)])
    else:
        print("(none)")

    if UE3_LAUNCH_LOG.is_file():
        print(f"\n=== UE3 Engine Launch Log ({UE3_LAUNCH_LOG}) ===")
        subprocess.run(["tail", "-n", str(lines_count), str(UE3_LAUNCH_LOG)])

    if follow:
        files_to_follow = [str(f) for f in [LOG_FILE, UE3_LAUNCH_LOG] if f.is_file()]
        if files_to_follow:
            try:
                subprocess.run(["tail", "-n", str(lines_count), "-f"] + files_to_follow)
            except KeyboardInterrupt:
                return 0
    return 0


def _prepare_fresh_logs() -> None:
    """Archives and truncates stale UE3 Launch.log before a live verification run."""
    if UE3_LAUNCH_LOG.is_file():
        try:
            if UE3_LAUNCH_LOG.stat().st_size > 0:
                ORACLE_DIR.mkdir(parents=True, exist_ok=True)
                shutil.copy2(UE3_LAUNCH_LOG, ORACLE_DIR / "Launch.prev.log")
            with open(UE3_LAUNCH_LOG, "w", encoding="utf-8") as f:
                f.truncate(0)
        except OSError as e:
            print(f"[!] Warning: Could not archive/truncate {UE3_LAUNCH_LOG}: {e}", file=sys.stderr)


def cmd_test(args: argparse.Namespace) -> int:
    """Runs a live verification flight: starts server, observes telemetry/UDP socket, stops cleanly."""
    timeout = getattr(args, "timeout", 15)
    port = getattr(args, "port", DEFAULT_PORT)
    map_name = getattr(args, "map", DEFAULT_MAP)
    multihome = getattr(args, "multihome", DEFAULT_MULTIHOME)

    print(f"[*] Starting live test of Retail Dedicated Server Oracle on port {port} (timeout {timeout}s)...")
    cmd_stop()
    time.sleep(0.5)

    _prepare_fresh_logs()

    if is_udp_port_bound(port):
        print(
            f"[!] Test failed: UDP port {port} is already bound before oracle start.",
            file=sys.stderr,
        )
        return 1

    target_bin, _ = resolve_binary_and_dir()
    is_server_bin = bool(target_bin and "Server" in target_bin.name)
    candidate_ports = [port] if (is_server_bin or port == 7777) else [port, 7777]

    start_args = argparse.Namespace(map=map_name, port=port, multihome=multihome, daemon=True)
    if cmd_start(start_args) != 0:
        print("[!] Test failed: Server process failed to stay active during startup.", file=sys.stderr)
        return 1

    pid = get_active_pid()
    if pid is None:
        print("[!] Test failed: PID not recorded or process exited immediately.", file=sys.stderr)
        return 1

    print(f"[*] Server active (PID: {pid}). Monitoring initialization for {timeout}s (ports {candidate_ports})...")
    bound_port = None
    start_time = time.time()
    while time.time() - start_time < timeout:
        if not pid_is_running(pid):
            print(f"[*] Process {pid} completed or exited after {time.time() - start_time:.1f}s.")
            break
        for p in candidate_ports:
            if is_udp_port_bound(p):
                print(f"[✓] SUCCESS: UDP port {p} bound and listening after {time.time() - start_time:.1f}s!")
                bound_port = p
                break
        if bound_port is not None:
            break
        time.sleep(1.0)

    # Check logs for engine milestones across both console stdout and UE3 Launch.log
    print("[*] Diagnostic log extraction:")
    combined_log = ""
    for log_path in (LOG_FILE, UE3_LAUNCH_LOG):
        if log_path.is_file():
            try:
                combined_log += log_path.read_text(errors="replace") + "\n"
            except OSError as e:
                print(f"    - Warning: failed to read {log_path}: {e}", file=sys.stderr)

    test_milestones = [
        "WinSock:",
        "Assembly Loaded Version:",
        "Initializing Game Engine",
        "Browse:",
        "LoadMap:",
        "[FSocketWin::Bind]",
    ]
    milestones_reached = 0
    for milestone in test_milestones:
        found = milestone in combined_log
        if found:
            milestones_reached += 1
        print(f"    - Milestone '{milestone}': {'FOUND' if found else 'NOT REACHED'}")

    cmd_stop()

    if bound_port is not None:
        print(
            f"[✓] Live test complete: UDP port {bound_port} bound, "
            f"{milestones_reached}/{len(test_milestones)} milestones reached."
        )
        return 0
    print(
        f"[!] Live test finished without UDP port bound "
        f"({milestones_reached}/{len(test_milestones)} milestones reached).",
        file=sys.stderr,
    )
    return 1


def cmd_client(args: argparse.Namespace) -> int:
    """Launches the retail Paladins game client connected to the oracle server."""
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", DEFAULT_PORT)
    map_query = getattr(args, "map", "") or "?game=TgGame.TgGame_Paladins?name=Player"

    connect_url = f"{host}:{port}{map_query}"
    print(f"[*] Launching Paladins client connected to Oracle ({connect_url})...")

    client_path = "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64/ShippingPC-ChaosGame.exe"
    proton_bin = os.path.expanduser("~/.local/share/Steam/compatibilitytools.d/GE-Proton9-15/proton")

    if not os.path.isfile(client_path):
        print(f"[!] Error: Client binary not found at {client_path}", file=sys.stderr)
        return 1
    if not os.path.isfile(proton_bin):
        print(f"[!] Error: Proton binary not found at {proton_bin}", file=sys.stderr)
        return 1

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
        connect_url,
        "-steam",
        "-NoEAC",
        "-nomovie",
        "-seekfreeloadingPCConsole",
    ]

    client_log = DIRTYROOM_ROOT / "logs" / "oracle_client.log"
    client_log.parent.mkdir(parents=True, exist_ok=True)
    with open(client_log, "w") as log_file:
        proc = subprocess.Popen(cmd_args, env=env, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
        print(f"[*] Paladins client process dispatched (PID: {proc.pid}, logging to {client_log}).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agyis oracle",
        description="Headless Wine retail dedicated server oracle control and live verification (ADOPT-09)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Oracle action to perform")

    # status
    p_status = subparsers.add_parser("status", help="Check running server status, PID, and UDP port")
    p_status.add_argument("--port", type=int, default=DEFAULT_PORT, help="Configured UDP port")
    p_status.add_argument("--map", default=DEFAULT_MAP, help="Configured map name")
    p_status.add_argument("--multihome", default=DEFAULT_MULTIHOME, help=f"Bound IP interface (default: {DEFAULT_MULTIHOME})")

    # start
    p_start = subparsers.add_parser("start", help="Start the headless dedicated server oracle")
    p_start.add_argument("--map", default=DEFAULT_MAP, help=f"Map package name (default: {DEFAULT_MAP})")
    p_start.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"UDP port (default: {DEFAULT_PORT})")
    p_start.add_argument("--multihome", default=DEFAULT_MULTIHOME, help=f"Bind host/interface (default: {DEFAULT_MULTIHOME})")
    p_start.add_argument("--daemon", action="store_true", default=True, help="Run as background daemon (default)")
    p_start.add_argument("--foreground", dest="daemon", action="store_false", help="Run in foreground")

    # stop
    subparsers.add_parser("stop", help="Stop the running dedicated server oracle and wineserver")

    # restart
    p_restart = subparsers.add_parser("restart", help="Restart the dedicated server oracle")
    p_restart.add_argument("--map", default=DEFAULT_MAP, help=f"Map package name (default: {DEFAULT_MAP})")
    p_restart.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"UDP port (default: {DEFAULT_PORT})")
    p_restart.add_argument("--multihome", default=DEFAULT_MULTIHOME, help=f"Bind host/interface (default: {DEFAULT_MULTIHOME})")
    p_restart.add_argument("--daemon", action="store_true", default=True, help="Run as background daemon")

    # logs
    p_logs = subparsers.add_parser("logs", help="View recent server and UE3 logs")
    p_logs.add_argument("-n", "--lines", type=int, default=50, help="Number of log lines to show (default: 50)")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow log output")

    # test
    p_test = subparsers.add_parser("test", help="Execute live server lifecycle test and milestone inspection")
    p_test.add_argument("--map", default=DEFAULT_MAP, help="Map package name")
    p_test.add_argument("--port", type=int, default=DEFAULT_PORT, help="UDP port")
    p_test.add_argument("--multihome", default=DEFAULT_MULTIHOME, help=f"Bind host/interface (default: {DEFAULT_MULTIHOME})")
    p_test.add_argument("--timeout", type=int, default=15, help="Observation timeout in seconds (default: 15)")

    # client
    p_client = subparsers.add_parser("client", help="Launch retail Paladins client connected to Oracle")
    p_client.add_argument("--host", default="127.0.0.1", help="Target server host (default: 127.0.0.1)")
    p_client.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Target server UDP port (default: {DEFAULT_PORT})")
    p_client.add_argument("--map", default="", help="Connection URL query string")

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        return 0

    dispatch = {
        "status": cmd_status,
        "start": cmd_start,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "logs": cmd_logs,
        "test": cmd_test,
        "client": cmd_client,
    }

    handler = dispatch.get(args.subcommand)
    if handler:
        return handler(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
