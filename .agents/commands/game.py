#!/usr/bin/env python3
# Control and inspect Paladins game and server processes
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)

import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import DIRTYROOM_ROOT, REPO_ROOT, kill_game_and_server


def main():
    parser = argparse.ArgumentParser(
        prog="agyis game",
        description="Control and inspect Paladins game and server processes",
    )
    parser.add_argument(
        "action",
        choices=["status", "start", "kill", "logs", "client"],
        help="Action to perform",
    )
    parser.add_argument("target", nargs="?", default="client", help="Target component for logs (client/server)")
    parser.add_argument("--map", help="Target map URL to load")
    args = parser.parse_args()

    action = args.action
    if action == "status":
        proc = subprocess.run(
            ["pgrep", "-a", "-f", "ShippingPC-ChaosGame.exe|immortal-server"],
            text=True,
            stdout=subprocess.PIPE,
        )
        lines = [l for l in proc.stdout.splitlines() if "immortal-server" in l or "ShippingPC-ChaosGame.exe" in l]
        lines = [l for l in lines if "pgrep" not in l]
        if lines:
            print("[*] Running game/server processes:")
            for l in lines:
                print(f"  {l}")
        else:
            print("[*] No Paladins client or Immortal server processes running.")
        return 0

    elif action == "kill":
        kill_game_and_server()
        print("[*] Terminated all game and server processes.")
        return 0

    elif action == "logs":
        target = args.target or "client"
        log_file = DIRTYROOM_ROOT / "logs" / f"{target}.log"
        if log_file.is_file():
            print(f"[*] Showing last 30 lines of {log_file}:")
            proc = subprocess.run(["tail", "-n", "30", str(log_file)], text=True, stdout=subprocess.PIPE)
            print(proc.stdout)
        else:
            print(f"[*] Log file not found: {log_file}")
        return 0

    elif action in ("start", "client"):
        server_bin = REPO_ROOT / "target" / "release" / "immortal-server"
        if not server_bin.is_file():
            server_bin = REPO_ROOT / "target" / "debug" / "immortal-server"

        if action == "start":
            proc = subprocess.run(["pgrep", "-f", "immortal-server"], stdout=subprocess.PIPE, text=True)
            if not proc.stdout.strip():
                if server_bin.is_file():
                    server_log = DIRTYROOM_ROOT / "logs" / "server.log"
                    server_log.parent.mkdir(parents=True, exist_ok=True)
                    senv = os.environ.copy()
                    senv["RUST_LOG"] = "info,immortal_net=debug,immortal_server=debug"
                    slog = open(server_log, "a")
                    subprocess.Popen(
                        [str(server_bin)],
                        env=senv,
                        stdout=slog,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                    print(f"[*] immortal-server daemon started (logging to {server_log}).")
                    time.sleep(0.5)
                else:
                    print(f"[!] Warning: immortal-server binary not found at {server_bin}.")
            else:
                print("[*] immortal-server is already running.")

        default_map_url = (
            "Shootingrange_P?game=TgGame.TgGame_Paladins_ShootingRange"
            "?GameState=OGS_NoSession?GameMode=0?name=Player"
            "?map_instance_id=1282927737?Team=255"
        )
        map_arg = args.map
        if not map_arg and args.target and args.target not in ("client", "server"):
            map_arg = args.target

        chosen_map = default_map_url
        if map_arg:
            if map_arg in ("Shootingrange_P", "shootingrange", "ShootingRange"):
                chosen_map = default_map_url
            else:
                chosen_map = map_arg

        print(f"[*] Launching game client ({action} mode with map: {chosen_map})...")
        client_path = "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64/ShippingPC-ChaosGame.exe"
        proton_bin = os.path.expanduser("~/.local/share/Steam/compatibilitytools.d/GE-Proton9-15/proton")
        env = os.environ.copy()
        env["STEAM_COMPAT_CLIENT_INSTALL_PATH"] = os.path.expanduser("~/.local/share/Steam")
        env["STEAM_COMPAT_DATA_PATH"] = "/mnt/fast_data/games/SteamLibrary/steamapps/compatdata/444090"
        env["STEAM_COMPAT_APP_ID"] = "444090"
        env["SteamAppId"] = "444090"
        env["SteamGameId"] = "444090"
        cmd_args = [proton_bin, "run", client_path]
        if action == "client" or map_arg:
            cmd_args.append(chosen_map)
        cmd_args.extend([
            "-steam",
            "-NoEAC",
            "-nomovie",
            "-hostx=127.0.0.1:9000",
            "-tcp=1",
            "-dumpmar",
            "-dumpallmar",
            "-seekfreeloadingPCConsole",
        ])
        log_path = DIRTYROOM_ROOT / "logs" / "client.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "w")
        subprocess.Popen(cmd_args, env=env, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
        print(f"[*] Paladins client process dispatched (logging to {log_path}).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
