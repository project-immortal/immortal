#!/usr/bin/env python3
# Game window and uinput automation via ydotoold + xdotool
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import (
    button_to_hex,
    check_dependencies,
    get_window_info,
    run_ydotool,
    send_key,
)


def cmd_window(args):
    check_dependencies(["xdotool"])
    name = getattr(args, "name", "Paladins") or "Paladins"
    win = get_window_info(name)
    if not win:
        if getattr(args, "json", False):
            print(json.dumps({"found": False, "name": name}))
        else:
            print(f"[!] Window matching '{name}' not found.")
        return 1

    if getattr(args, "json", False):
        print(json.dumps(win, indent=2))
        return 0

    print("=== Window Information ===")
    print(f"  Name:       {win['name']}")
    print(f"  Window ID:  {win['window_id']} ({win['window_id_hex']})")
    print(f"  Position:   X={win['x']}, Y={win['y']}")
    print(f"  Dimensions: Width={win['width']}, Height={win['height']}")
    return 0


def cmd_click(args):
    win = get_window_info(getattr(args, "window_name", "Paladins"))
    if win:
        subprocess.run(["xdotool", "windowactivate", "--sync", str(win["window_id"])], check=False)
        time.sleep(0.05)

    x = float(args.x)
    y = float(args.y)
    if getattr(args, "relative", False):
        if not win:
            print("[!] Error: --relative specified but target window was not found.", file=sys.stderr)
            return 1
        target_x = int(win["x"] + x * win["width"])
        target_y = int(win["y"] + y * win["height"])
    else:
        target_x = int(x)
        target_y = int(y)

    btn_hex = button_to_hex(getattr(args, "button", 1), state="click")
    run_ydotool("mousemove", "--absolute", str(target_x), str(target_y))
    time.sleep(0.02)
    run_ydotool("click", btn_hex)
    print(f"[*] Clicked at ({target_x}, {target_y}) [button: {btn_hex}]")
    return 0


def cmd_key(args):
    res = send_key(args.key_name)
    if res.returncode == 0:
        print(f"[*] Sent key: {args.key_name}")
        return 0
    else:
        print(f"[!] Failed to send key: {args.key_name} (code: {res.returncode})", file=sys.stderr)
        return 1


def cmd_type(args):
    res = run_ydotool("type", "--", args.text)
    if res.returncode == 0:
        print(f"[*] Typed: {args.text}")
        return 0
    else:
        print(f"[!] Failed to type text (code: {res.returncode})", file=sys.stderr)
        return 1


def cmd_console(args):
    win = get_window_info(getattr(args, "window_name", "Paladins"))
    if win:
        subprocess.run(["xdotool", "windowactivate", "--sync", str(win["window_id"])], check=False)
        time.sleep(0.1)

    send_key("F10")
    time.sleep(0.1)
    run_ydotool("type", "--", args.command)
    time.sleep(0.05)
    send_key("Return")
    print(f"[*] Dispatched console command: '{args.command}'")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="agyis input",
        description="Game window and uinput automation via ydotoold + xdotool",
    )
    sub = parser.add_subparsers(dest="input_cmd", help="Input subcommand")

    # window
    p_win = sub.add_parser("window", help="Inspect game window geometry")
    p_win.add_argument("--name", default="Paladins", help="Window name substring")
    p_win.add_argument("--json", action="store_true", help="Output JSON")

    # click
    p_click = sub.add_parser("click", help="Click at coordinate")
    p_click.add_argument("x", help="X coordinate (absolute or relative 0.0-1.0)")
    p_click.add_argument("y", help="Y coordinate (absolute or relative 0.0-1.0)")
    p_click.add_argument("--relative", action="store_true", help="Treat coordinates as relative to window")
    p_click.add_argument("--button", type=int, default=1, help="Mouse button (1=Left, 2=Middle, 3=Right)")
    p_click.add_argument("--window-name", default="Paladins", help="Target window name")

    # key
    p_key = sub.add_parser("key", help="Send single key")
    p_key.add_argument("key_name", help="Key name (e.g. Return, Escape, Space, F10)")

    # type
    p_type = sub.add_parser("type", help="Type string")
    p_type.add_argument("text", help="Text to type")

    # console
    p_cons = sub.add_parser("console", help="Execute in-game UE3 console command via F10")
    p_cons.add_argument("command", help="Console command string (e.g. 'stat fps')")
    p_cons.add_argument("--window-name", default="Paladins", help="Target window name")

    args = parser.parse_args()
    if not args.input_cmd or args.input_cmd == "window":
        return cmd_window(args)
    if args.input_cmd == "click":
        return cmd_click(args)
    if args.input_cmd == "key":
        return cmd_key(args)
    if args.input_cmd == "type":
        return cmd_type(args)
    if args.input_cmd == "console":
        return cmd_console(args)


if __name__ == "__main__":
    sys.exit(main())
