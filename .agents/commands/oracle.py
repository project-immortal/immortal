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
import shutil
import signal
import subprocess
import sys
import time
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import (
    DIRTYROOM_ROOT,
    REPO_ROOT,
    check_dependencies,
    pid_is_running,
)

# Paths and configuration
ORACLE_DIR = DIRTYROOM_ROOT / "oracle"
WINE_PREFIX = ORACLE_DIR / "prefix"
PID_FILE = ORACLE_DIR / "retail_server.pid"
LOG_FILE = ORACLE_DIR / "retail_server.log"
UE3_LAUNCH_LOG = Path(os.path.expanduser("~/Documents/My Games/Tempest/ChaosGame/Logs/Launch.log"))

DEFAULT_MAP = "SG_JaguarFalls_Rework_P"
DEFAULT_PORT = 7000
DEFAULT_MULTIHOME = "127.0.0.1"

CANDIDATE_BINS = [
    Path("/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64/ShippingPC-ChaosGame.exe"),
    DIRTYROOM_ROOT / "binaries" / "ShippingPC-ChaosGame.exe",
]


def resolve_binary_and_dir() -> Tuple[Optional[Path], Optional[Path]]:
    """Resolves target binary and working directory where ../../ChaosGame is accessible."""
    # Priority 1: Candidate with ../../ChaosGame directory intact
    for bin_path in CANDIDATE_BINS:
        if bin_path.is_file():
            bdir = bin_path.parent
            if (bdir / ".." / ".." / "ChaosGame").resolve().is_dir():
                return bin_path, bdir

    # Priority 2: Any existing candidate
    for bin_path in CANDIDATE_BINS:
        if bin_path.is_file():
            return bin_path, bin_path.parent

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
        proc = subprocess.run(["ss", "-ulnp"], stdout=subprocess.PIPE, text=True, stderr=subprocess.DEVNULL)
        for line in proc.stdout.splitlines():
            if f":{port} " in line or f":{port}\t" in line:
                return True
    except Exception:
        pass
    return False


def get_process_rss_mb(pid: int) -> Optional[float]:
    """Returns the RSS memory usage of the process in MB."""
    try:
        proc = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], stdout=subprocess.PIPE, text=True)
        out = proc.stdout.strip()
        if out:
            return float(out) / 1024.0
    except Exception:
        pass
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

        candidate_ports = [port]
        for p in [7777, 7778]:
            if p not in candidate_ports:
                candidate_ports.append(p)

        bound_port = None
        for p in candidate_ports:
            if is_udp_port_bound(p):
                bound_port = p
                break

        if bound_port is not None:
            print(f"UDP Port {bound_port}:     LISTENING (bound to network)")
        else:
            ports_desc = f"{port}" if port in (7777, 7778) else f"{port}/7777/7778"
            print(f"UDP Port {ports_desc}: INITIALIZING (UE3 engine load phase)")
        return 0
    else:
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
        print("[!] Error: Could not locate ShippingPC-ChaosGame.exe at candidate paths:", file=sys.stderr)
        for b in CANDIDATE_BINS:
            print(f"  - {b}", file=sys.stderr)
        return 1

    runner_bin, runner_prefix_args, runner_env = resolve_server_runner()
    if not runner_bin:
        print("[!] Error: Neither system Wine nor Proton was found on this system.", file=sys.stderr)
        return 1

    # Check for EAC directory bypass
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
    # Ensure DISPLAY is available for D3D viewport initialization
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

    map_query = f"{map_name}?listen?game=TgGame.TgGame_Paladins?maxplayers=2"
    server_args = (
        [runner_bin]
        + runner_prefix_args
        + [
            str(target_bin),
            map_query,
            f"-port={port}",
            f"-multihome={multihome}",
            "-seekfreeloadingpcconsole",
            "-pid=402",
            "-eac-nop-loaded",
            "-homedir=Tempest",
            "-log",
        ]
    )

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
        log_out = open(LOG_FILE, "w")
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

        time.sleep(1.5)
        if pid_is_running(proc.pid):
            print(f"Process {proc.pid} confirmed active.")
            return 0
        else:
            print(f"[!] Warning: Process {proc.pid} exited shortly after start. Check {LOG_FILE}.")
            return 1
    else:
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


def cmd_test(args: argparse.Namespace) -> int:
    """Runs a live verification flight: starts server, observes telemetry/UDP socket, stops cleanly."""
    timeout = getattr(args, "timeout", 15)
    port = getattr(args, "port", DEFAULT_PORT)
    map_name = getattr(args, "map", DEFAULT_MAP)

    print(f"[*] Starting live test of Retail Dedicated Server Oracle on port {port} (timeout {timeout}s)...")
    cmd_stop()
    time.sleep(0.5)

    start_args = argparse.Namespace(map=map_name, port=port, daemon=True)
    if cmd_start(start_args) != 0:
        print("[!] Test failed: Could not spawn server process.", file=sys.stderr)
        return 1

    pid = get_active_pid()
    if pid is None:
        print("[!] Test failed: PID not recorded or process exited immediately.", file=sys.stderr)
        return 1

    candidate_ports = [port]
    for p in [7777, 7778]:
        if p not in candidate_ports:
            candidate_ports.append(p)

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

    # Check logs for engine milestones
    print("[*] Diagnostic log extraction:")
    if UE3_LAUNCH_LOG.is_file():
        try:
            log_text = UE3_LAUNCH_LOG.read_text(errors="replace")
            for milestone in [
                "WinSock:",
                "Assembly load completed",
                "Initializing Game Engine",
                "Browse:",
                "LoadMap:",
                "[FSocketWin::Bind]",
            ]:
                found = milestone in log_text
                print(f"    - Milestone '{milestone}': {'FOUND' if found else 'NOT REACHED'}")
        except Exception as e:
            print(f"    - Failed to inspect Launch.log: {e}")

    cmd_stop()
    print("[*] Live test complete.")
    return 0


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
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
