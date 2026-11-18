#!/usr/bin/env python3
# Process-isolated retail network capture and preservation workflow
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
CLI entrypoint for immortal retail capture workflow (ADR-034).
Governed by SPEC-2026-IMMORTAL-CAPTURE-PLAN-001, PSL-INV-007, and PSL-INV-011.
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import (
    DIRTYROOM_ROOT,
    get_launch_log_path,
    kill_game_and_server,
    pid_is_running,
)
from lib.capture_core import (
    CAPTURE_STATE_PATH,
    DEFAULT_CAP_DIR,
    DEFAULT_SDD_DIR,
    NFT_TABLE_NAME,
    SLICE_NAME,
    STEAM_LAUNCH_BACKUP_PATH,
    analyze_launch_log,
    append_sha256sums,
    apply_nftables_rules,
    calculate_sha256,
    check_nftables_table_exists,
    clear_capture_state,
    find_active_localconfig_vdf,
    generate_bpf_filter,
    generate_nftables_rules,
    get_cgroup_paths,
    get_egress_interface,
    get_qbittorrent_ports,
    inspect_sdd_status,
    is_steam_running,
    load_capture_state,
    parse_steam_launch_options,
    prep_sdd,
    quiesce_process,
    relaunch_process,
    restore_sdd,
    rotate_launch_log,
    save_capture_state,
    start_packet_capture,
    start_slice_holder,
    stop_packet_capture,
    stop_slice_holder,
    summarize_conversations,
    teardown_nftables,
    unwrap_launch_options_from_slice,
    update_steam_launch_options,
    wrap_launch_options_with_slice,
)


# --- Subcommand Implementations ---

def cmd_status(args: argparse.Namespace) -> int:
    """Displays comprehensive pre-flight status dashboard."""
    print("=== Immortal Retail Network Capture Dashboard ===")
    print(f"Dirtyroom Root: {DIRTYROOM_ROOT}\n")

    # 1. Capture Tools & Hardware Readiness
    dumpcap_bin = shutil.which("dumpcap")
    tshark_bin = shutil.which("tshark")
    systemd_run = shutil.which("systemd-run")

    tools_ok = bool(dumpcap_bin and systemd_run)
    print("Capture Engines & Toolchain:")
    print(f"  dumpcap:     {'[✓] ' + dumpcap_bin if dumpcap_bin else '[!] MISSING'}")
    print(f"  tshark:      {'[✓] ' + tshark_bin if tshark_bin else '[!] MISSING'}")
    print(f"  systemd-run: {'[✓] ' + systemd_run if systemd_run else '[!] MISSING'}")

    # Check sudo -n nft
    res_nft = subprocess.run(
        ["sudo", "-n", "nft", "list", "tables"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    can_sudo_nft = res_nft.returncode == 0
    print(f"  nftables:    {'[✓] Passwordless sudo available' if can_sudo_nft else '[!] Sudo authentication required'}")

    # 2. nftables and cgroup isolation status
    nft_active = check_nftables_table_exists(NFT_TABLE_NAME)
    _, abs_cgroup = get_cgroup_paths()
    cgroup_exists = abs_cgroup.exists()

    print("\nIsolation Stack (cgroup v2 + nftables NFLOG):")
    print(f"  Table '{NFT_TABLE_NAME}': {'[ARMED / ACTIVE]' if nft_active else '[INACTIVE]'}")
    print(f"  Slice Directory:         {abs_cgroup} ({'EXISTS' if cgroup_exists else 'NOT PRESENT'})")

    # Check for active holder
    state = load_capture_state()
    holder_pid = state.get("holder_pid")
    holder_active = holder_pid and pid_is_running(holder_pid)
    print(f"  Slice Holder Scope:      {'PID ' + str(holder_pid) + ' (ACTIVE)' if holder_active else 'NONE'}")

    # 3. Service Discovery Status
    sdd_dir = Path(getattr(args, "sdd_dir", None) or DEFAULT_SDD_DIR)
    sdd_info = inspect_sdd_status(sdd_dir)
    print("\nService Discovery (.sdd) Configuration:")
    print(f"  Directory:    {sdd_dir}")
    print(f"  Current Mode: {sdd_info['current_mode'].upper()}")
    print(f"  Target SDD:   {sdd_info['target_sha256'] or 'NOT FOUND'} (8.1.5839.0-PC-402.sdd)")
    print(f"  Retail Orig:  {sdd_info['orig_sha256'] or 'NOT FOUND'} (.sdd.orig)")
    print(f"  Emulator BKP: {sdd_info['immortal_sha256'] or 'NONE'} (.sdd.immortal)")

    # 4. Steam AppID 444090 Launch Options
    vdf_path = find_active_localconfig_vdf()
    print("\nSteam Launch Options (AppID 444090):")
    if vdf_path:
        print(f"  Active VDF:  {vdf_path}")
        try:
            vdf_text = vdf_path.read_text(encoding="utf-8", errors="replace")
            opts = parse_steam_launch_options(vdf_text) or ""
            is_wrapped = f"--slice={SLICE_NAME}" in opts
            print(f"  LaunchOpts:  {opts if opts else '(none)'}")
            print(f"  Slice Wrap:  {'[✓] INSTALLED' if is_wrapped else '[!] NOT INSTALLED'}")
        except OSError as e:
            print(f"  LaunchOpts:  Error reading VDF: {e}")
    else:
        print("  Active VDF:  [!] No Steam localconfig.vdf found with AppID 444090")
    print(f"  Steam Proc:  {'RUNNING' if is_steam_running() else 'STOPPED'}")

    # 5. Lingering Processes
    print("\nLingering Game & Server Processes:")
    pgrep_res = subprocess.run(
        ["pgrep", "-a", "-f", "ShippingPC-ChaosGame.exe|immortal-server"],
        stdout=subprocess.PIPE,
        text=True,
    )
    lines = [l for l in pgrep_res.stdout.splitlines() if "pgrep" not in l]
    if lines:
        for l in lines:
            print(f"  [!] {l}")
    else:
        print("  [✓] Zero lingering game/server processes.")

    # 6. Launch Log Status
    log_path = Path(get_launch_log_path())
    print("\nClient Launch Log:")
    if log_path.is_file():
        sz_kb = round(log_path.stat().st_size / 1024, 1)
        mtime = datetime.fromtimestamp(log_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  Path: {log_path} ({sz_kb} KB, modified {mtime})")
    else:
        print(f"  Path: {log_path} (NOT FOUND)")

    # 7. Runtime State
    print(f"\nCapture State Ledger ({CAPTURE_STATE_PATH.name}):")
    if state:
        print(f"  Status:          {state.get('status', 'unknown')}")
        print(f"  Mode:            {state.get('mode', 'unknown')}")
        print(f"  Pre-Capture SDD: {state.get('pre_capture_sdd_mode', 'unknown')}")
        if state.get("run_id"):
            print(f"  Active Run ID:   {state.get('run_id')}")
    else:
        print("  State: [IDLE / CLEAN]")

    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """
    Executes a fast, live, end-to-end verification of the process-isolated capture stack.
    Validates that:
    1. A UDP datagram sent inside immortalcapture.slice is captured.
    2. A UDP datagram sent outside the slice on the host is NOT captured.
    3. The nftables table and slice holder are cleanly deleted on exit.
    """
    print("[*] Running immortal capture selftest (<3s)...")

    # Verify tooling prerequisites
    if not shutil.which("tshark") and not shutil.which("dumpcap"):
        print("[!] Error: neither tshark nor dumpcap found in PATH.", file=sys.stderr)
        return 1

    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tf:
        temp_pcap = tf.name
    holder_pid: Optional[int] = None
    capture_proc: Optional[subprocess.Popen] = None

    try:
        # Step 1: Pin slice open
        holder_pid = start_slice_holder()
        print(f"[*] Pinned {SLICE_NAME} (holder PID: {holder_pid})")

        # Step 2: Apply nftables isolation rules
        rules = generate_nftables_rules()
        apply_nftables_rules(rules)
        print(f"[*] Applied atomic nftables isolation rules ({NFT_TABLE_NAME})")

        # Step 3: Start packet capture on nflog:42
        capture_proc = start_packet_capture(temp_pcap, mode="cgroup")
        print(f"[*] Started packet recorder on nflog:42 -> {Path(temp_pcap).name}")
        time.sleep(0.8)

        # Step 4: Send slice probe packet (inside slice)
        slice_probe_cmd = [
            "systemd-run",
            "--user",
            "--scope",
            f"--slice={SLICE_NAME}",
            "--",
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'IMMORTAL_CGROUP_PROBE', ('198.51.100.42', 44441)); s.close()",
        ]
        res_probe = subprocess.run(slice_probe_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res_probe.returncode != 0:
            print(f"[!] Warning: systemd-run probe command exited with code {res_probe.returncode}", file=sys.stderr)

        # Step 5: Send host probe packet (outside slice)
        host_probe_cmd = [
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'IMMORTAL_HOST_PROBE', ('198.51.100.99', 44442)); s.close()",
        ]
        subprocess.run(host_probe_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(0.5)

    finally:
        # Step 6: Stop capture
        if capture_proc:
            stop_packet_capture(capture_proc)

        # Step 7: Teardown isolation rules
        teardown_nftables()

        # Step 8: Stop slice holder
        if holder_pid:
            stop_slice_holder(holder_pid)

    # Step 9: Analyze captured packets
    slice_packets = 0
    host_packets = 0

    if os.path.exists(temp_pcap):
        if os.path.getsize(temp_pcap) > 0:
            res_tshark = subprocess.run(
                ["tshark", "-r", temp_pcap],
                capture_output=True,
                text=True,
            )
            for line in res_tshark.stdout.splitlines():
                if "44441" in line:
                    slice_packets += 1
                if "44442" in line:
                    host_packets += 1
        try:
            os.remove(temp_pcap)
        except OSError:
            pass

    table_left = check_nftables_table_exists(NFT_TABLE_NAME)

    print("\n--- Selftest Results ---")
    print(f"  Slice Probe Packets Captured: {slice_packets} (expected >= 1)")
    print(f"  Host Leak Packets Captured:  {host_packets} (expected == 0)")
    print(f"  Residual nftables Table:     {'PRESENT [FAIL]' if table_left else 'CLEAN [OK]'}")

    if slice_packets >= 1 and host_packets == 0 and not table_left:
        print("\n[✓] Selftest passed: slice isolation active, 0 host leak, teardown clean.")
        return 0
    else:
        print("\n[!] Selftest FAILED.", file=sys.stderr)
        return 1


def cmd_prep(args: argparse.Namespace) -> int:
    """Prepares the workspace for capture idempotently."""
    mode = getattr(args, "mode", "cgroup") or "cgroup"
    sdd_dir = getattr(args, "sdd_dir", None)
    quiesce = getattr(args, "quiesce", False)
    no_rotate = getattr(args, "no_rotate", False)

    print(f"[*] Preparing workspace for retail network capture ({mode} mode)...")

    # 1. State initialization
    state = load_capture_state()
    sdd_info = inspect_sdd_status(sdd_dir)

    # Record pre-capture mode on initial transition from idle
    if "pre_capture_sdd_mode" not in state:
        state["pre_capture_sdd_mode"] = sdd_info["current_mode"]

    # 2. Service Discovery preparation
    try:
        prep_info = prep_sdd(sdd_dir)
        print(f"[*] Service Discovery configured to retail (SHA-256: {prep_info['target_sha256'][:16]}...)")
        if prep_info["immortal_created"]:
            print(f"[*] Backed up local emulator SDD -> 8.1.5839.0-PC-402.sdd.immortal")
    except FileNotFoundError as e:
        print(f"[!] Error preparing Service Discovery: {e}", file=sys.stderr)
        return 1

    # 3. Terminate lingering game and server processes
    kill_game_and_server()
    print("[*] Terminated any lingering Paladins or Immortal server processes.")

    # 4. Rotate Launch.log unless opted out
    if not no_rotate:
        archived_log = rotate_launch_log()
        if archived_log:
            print(f"[*] Rotated previous client log -> {archived_log}")
        else:
            print("[*] Client Launch.log was empty or absent; rotation skipped.")

    # 5. Quiesce background applications if requested
    if quiesce:
        q_pid = quiesce_process("qbittorrent")
        if q_pid:
            print(f"[*] Quiesced qBittorrent (PID: {q_pid}) via graceful SIGTERM.")
            state["quiesced_apps"] = ["qbittorrent"]

    state["status"] = "prepped"
    state["mode"] = mode
    save_capture_state(state)

    print(f"[✓] Prep complete. Environment armed for capture.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Executes single-command end-to-end capture session."""
    run_id = args.run_id
    mode = args.mode
    preset = args.preset
    custom_flags = args.flags
    should_launch = args.launch
    watch_exit = args.watch_exit
    no_restore = args.no_restore
    relaunch_apps = args.relaunch_apps
    cap_dir = Path(args.cap_dir or DEFAULT_CAP_DIR)

    stamp = datetime.now().strftime("%Y%m%d")
    output_pcap = cap_dir / f"{run_id}_{stamp}.pcapng"

    # Step 1: Prep environment
    prep_args = argparse.Namespace(
        mode=mode,
        sdd_dir=None,
        quiesce=args.quiesce,
        no_rotate=False,
    )
    if cmd_prep(prep_args) != 0:
        return 1

    state = load_capture_state()
    holder_pid: Optional[int] = None
    capture_proc: Optional[subprocess.Popen] = None

    try:
        # Step 2: Arm isolation
        if mode == "cgroup":
            holder_pid = start_slice_holder()
            apply_nftables_rules(generate_nftables_rules())
            state["holder_pid"] = holder_pid
            capture_proc = start_packet_capture(output_pcap, mode="cgroup")
            print(f"[*] Isolation armed: slice {SLICE_NAME} pinned, nftables active.")
        else:
            qb_ports = get_qbittorrent_ports()
            bpf = generate_bpf_filter(qb_ports)
            iface = get_egress_interface()
            capture_proc = start_packet_capture(output_pcap, mode="host-bpf", iface=iface, bpf_filter=bpf)
            print(f"[*] Host-BPF capture armed on {iface} (excluding ports: {qb_ports}).")

        state["status"] = "capturing"
        state["run_id"] = run_id
        state["pcap_file"] = str(output_pcap)
        save_capture_state(state)

        print(f"[*] Capturing to: {output_pcap}")

        # Step 3: Determine game launch flags
        if custom_flags:
            flags = custom_flags
        elif preset == "pf1":
            flags = "-log -dumpallmar"
        else:
            flags = "-log"

        # Step 4: Dispatch or instruct game launch
        if should_launch:
            if mode == "cgroup":
                print("[*] Launching Steam AppID 444090 via xdg-open steam://run/444090 (cgroup mode: bypassing steam -applaunch to preserve localconfig systemd slice wrapper)")
                subprocess.run(["xdg-open", "steam://run/444090"])
            else:
                print(f"[*] Launching Steam AppID 444090 with flags: {flags}")
                subprocess.run(["steam", "-applaunch", "444090", *flags.split()])
        else:
            print(f"\n[*] Paladins client ready for launch.")
            if mode == "cgroup":
                print("    Launch Command:  xdg-open steam://run/444090 (or launch from Steam library GUI)")
            else:
                print(f"    Launch Command:  steam -applaunch 444090 {flags}")
            print(f"    Target Run:      {run_id}")

        # Step 5: Wait loop
        if watch_exit:
            print("[*] Watching for Paladins client lifecycle (waiting up to 120s for Proton launch)...")
            appeared = False
            for _ in range(120):
                proc = subprocess.run(["pgrep", "-f", "ShippingPC-ChaosGame.exe|Paladins.exe"], stdout=subprocess.PIPE, text=True)
                if proc.stdout.strip():
                    appeared = True
                    break
                time.sleep(1.0)

            if appeared:
                print("[*] Paladins process detected. Capturing until client exits...")
                while True:
                    proc = subprocess.run(["pgrep", "-f", "ShippingPC-ChaosGame.exe|Paladins.exe"], stdout=subprocess.PIPE, text=True)
                    if not proc.stdout.strip():
                        print("[*] Paladins client exited cleanly.")
                        break
                    time.sleep(1.0)
            else:
                print("[!] Paladins did not appear within 120s. Stopping capture.")
        else:
            print("[*] Capture active. Press Ctrl-C when match session is finished...")
            try:
                while True:
                    time.sleep(1.0)
            except KeyboardInterrupt:
                print("\n[*] Capture stop requested by operator.")

        # Step 6: Stop capture
        if capture_proc:
            stop_packet_capture(capture_proc)
            capture_proc = None

        # Step 7: Archive artifacts
        archive_args = argparse.Namespace(
            run_id=run_id,
            pcap=str(output_pcap),
            cap_dir=str(cap_dir),
        )
        cmd_archive(archive_args)

    finally:
        # Step 8: Teardown & Restore
        if capture_proc:
            stop_packet_capture(capture_proc)

        if not no_restore:
            restore_args = argparse.Namespace(
                mode="auto",
                relaunch_apps=relaunch_apps,
                sdd_dir=None,
            )
            cmd_restore(restore_args)

    return 0


def cmd_archive(args: argparse.Namespace) -> int:
    """Pairs capture artifacts, analyzes log, and updates SHA256SUMS.txt."""
    run_id = args.run_id
    cap_dir = Path(args.cap_dir or DEFAULT_CAP_DIR)
    cap_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d")

    # Resolve pcap path
    if args.pcap:
        pcap_path = Path(args.pcap)
    else:
        pcap_path = cap_dir / f"{run_id}_{stamp}.pcapng"
        if not pcap_path.is_file():
            # Check for existing match
            candidates = list(cap_dir.glob(f"{run_id}_*.pcapng"))
            if candidates:
                candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                pcap_path = candidates[0]

    if not pcap_path.is_file():
        print(f"[!] Warning: Capture file {pcap_path} not found for archiving.", file=sys.stderr)

    # Pair client Launch.log
    launch_log_src = Path(get_launch_log_path())
    paired_log_dst = cap_dir / f"{run_id}_{stamp}_Launch.log"
    if launch_log_src.is_file():
        try:
            shutil.copy2(launch_log_src, paired_log_dst)
            print(f"[*] Paired client log -> {paired_log_dst.name}")
        except OSError as e:
            print(f"[!] Warning: Failed to copy Launch.log: {e}", file=sys.stderr)

    # Analyze log
    log_analysis = analyze_launch_log(paired_log_dst if paired_log_dst.is_file() else launch_log_src)

    # Summarize traffic
    convs = summarize_conversations(pcap_path) if pcap_path.is_file() else {"udp": "N/A", "tcp": "N/A"}

    # Compute digests
    pcap_sha = calculate_sha256(pcap_path) if pcap_path.is_file() else "N/A"
    log_sha = calculate_sha256(paired_log_dst) if paired_log_dst.is_file() else "N/A"

    # Write operator notes scaffold
    notes_file = cap_dir / f"{run_id}_{stamp}_notes.md"
    endpoints_str = (
        "\n".join([f"- `Browse: {ep}`" for ep in log_analysis["browse_endpoints"]])
        if log_analysis["browse_endpoints"]
        else "- None observed in log."
    )
    maps_str = ", ".join(log_analysis["maps"]) if log_analysis["maps"] else "None detected"

    state = load_capture_state()
    capture_mode = state.get("mode", "cgroup")

    notes_content = f"""# Capture Run Notes: {run_id}

- **Date / Timestamp**: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")}
- **Capture File**: `{pcap_path.name}` (SHA-256: `{pcap_sha}`)
- **Paired Log**: `{paired_log_dst.name}` (SHA-256: `{log_sha}`)
- **Isolation Mode**: `{capture_mode}`

## 1. Dedicated Server Routing & Observed Endpoints
{endpoints_str}

## 2. Protocol Analysis & PF-1 Marshal Status
- **PF-1 (-dumpallmar) Active**: {'YES (Decoded MCTS markers detected)' if log_analysis['dumpallmar_detected'] else 'NO / UNCONFIRMED'}
- **Maps / Game Modes Detected**: {maps_str}

## 3. Network Conversations (tshark)
### UDP Conversations
```
{convs['udp']}
```

### TCP Conversations
```
{convs['tcp']}
```

## 4. Operator Timeline & In-Match Actions
- [ ] Queue Selected:
- [ ] Gazebo Match Accept:
- [ ] Champion Selected:
- [ ] Map Loading:
- [ ] In-Match Actions (Abilities, Store Purchases, Combat):
- [ ] Match End / Scoreboard:
"""
    notes_file.write_text(notes_content, encoding="utf-8")
    print(f"[*] Generated operator notes scaffold -> {notes_file.name}")

    # Append immutable hashes to SHA256SUMS.txt
    files_to_hash = [p for p in (pcap_path, paired_log_dst) if p and p.is_file()]
    manifest_file = cap_dir / "SHA256SUMS.txt"
    append_sha256sums(manifest_file, files_to_hash)
    print(f"[*] Updated cryptographic manifest -> {manifest_file.name}")

    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    """Restores the capture environment and Service Discovery idempotently."""
    state = load_capture_state()
    target_mode = getattr(args, "mode", "auto")
    pre_mode = state.get("pre_capture_sdd_mode")
    relaunch = getattr(args, "relaunch_apps", False)

    print("[*] Restoring environment state...")

    # 1. Teardown nftables
    if not teardown_nftables():
        print(f"[!] Warning: Failed to cleanly tear down nftables table '{NFT_TABLE_NAME}'.", file=sys.stderr)

    # 2. Stop slice holder
    holder_pid = state.get("holder_pid")
    if holder_pid:
        stop_slice_holder(holder_pid)

    # Check for any other slice holder scopes
    try:
        proc = subprocess.run(
            ["pgrep", "-f", f"slice={SLICE_NAME}.*sleep infinity"],
            stdout=subprocess.PIPE,
            text=True,
        )
        for pid_s in proc.stdout.splitlines():
            if pid_s.strip().isdigit():
                stop_slice_holder(int(pid_s.strip()))
    except OSError:
        pass

    # 3. Restore Service Discovery
    sdd_dir = getattr(args, "sdd_dir", None)
    restored_mode = restore_sdd(target_mode=target_mode, pre_capture_mode=pre_mode, sdd_dir=sdd_dir)
    print(f"[*] Service Discovery restored to: {restored_mode.upper()}")

    # 4. Relaunch quiesced apps if requested
    if relaunch:
        quiesced = state.get("quiesced_apps", [])
        if "qbittorrent" in quiesced:
            relaunch_process(["qbittorrent"])
            print("[*] Relaunched quiesced applications: qbittorrent")

    # 5. Clear state
    clear_capture_state()
    print("[✓] Restoration complete. Workspace returned to clean state.")
    return 0


def cmd_steam_opts(args: argparse.Namespace) -> int:
    """Inspects and manages Steam LaunchOptions for Paladins (AppID 444090)."""
    subaction = args.subaction or "show"
    force = args.force
    custom_vdf = getattr(args, "vdf", None)

    vdf_path = Path(custom_vdf) if custom_vdf else find_active_localconfig_vdf()
    if not vdf_path or not vdf_path.is_file():
        print("[!] Error: No active Steam localconfig.vdf found with AppID 444090.", file=sys.stderr)
        return 1

    try:
        vdf_content = vdf_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[!] Error reading {vdf_path}: {e}", file=sys.stderr)
        return 1

    current_opts = parse_steam_launch_options(vdf_content) or ""
    is_wrapped = f"--slice={SLICE_NAME}" in current_opts and "STEAM_LAUNCH_WRAPPER_SCOPE=0" in current_opts

    if subaction == "show":
        print("=== Steam AppID 444090 Launch Options ===")
        print(f"Active VDF:       {vdf_path}")
        print(f"Current Options:  {current_opts if current_opts else '(none)'}")
        print(f"Slice Installed:  {'YES' if is_wrapped else 'NO'}")
        print(f"Steam Running:    {'YES' if is_steam_running() else 'NO'}")
        print("\nRecommended Wrapper:")
        print(f"  {wrap_launch_options_with_slice(current_opts)}")
        return 0

    # Write operations require Steam to be stopped unless --force is given
    if is_steam_running() and not force:
        print(
            "[!] Error: Steam is currently running. Steam overwrites localconfig.vdf on shutdown.",
            file=sys.stderr,
        )
        print("    Please exit Steam completely before modifying LaunchOptions, or pass --force.", file=sys.stderr)
        return 1

    if subaction == "install-slice":
        if is_wrapped:
            print("[*] immortalcapture.slice wrapper already installed.")
            return 0

        # Backup current options
        STEAM_LAUNCH_BACKUP_PATH.parent.mkdir(parents=True, exist_ok=True)
        backup_data = {
            "vdf_path": str(vdf_path),
            "original_options": current_opts,
            "timestamp": datetime.utcnow().isoformat(),
        }
        STEAM_LAUNCH_BACKUP_PATH.write_text(json.dumps(backup_data, indent=2), encoding="utf-8")

        new_opts = wrap_launch_options_with_slice(current_opts)
        updated_vdf = update_steam_launch_options(vdf_content, new_opts)
        vdf_path.write_text(updated_vdf, encoding="utf-8")
        print(f"[*] Installed slice wrapper -> {new_opts}")
        print(f"[*] Backed up original options to {STEAM_LAUNCH_BACKUP_PATH}")
        return 0

    elif subaction == "set":
        if not args.options:
            print("[!] Error: 'set' requires an options string.", file=sys.stderr)
            return 1
        new_opts = args.options
        updated_vdf = update_steam_launch_options(vdf_content, new_opts)
        vdf_path.write_text(updated_vdf, encoding="utf-8")
        print(f"[*] Set LaunchOptions -> {new_opts}")
        return 0

    elif subaction == "restore":
        restored_opts = ""
        if STEAM_LAUNCH_BACKUP_PATH.is_file():
            try:
                bdata = json.loads(STEAM_LAUNCH_BACKUP_PATH.read_text(encoding="utf-8"))
                restored_opts = bdata.get("original_options", "")
            except (OSError, json.JSONDecodeError):
                restored_opts = unwrap_launch_options_from_slice(current_opts)
        else:
            restored_opts = unwrap_launch_options_from_slice(current_opts)

        updated_vdf = update_steam_launch_options(vdf_content, restored_opts)
        vdf_path.write_text(updated_vdf, encoding="utf-8")
        if STEAM_LAUNCH_BACKUP_PATH.is_file():
            STEAM_LAUNCH_BACKUP_PATH.unlink()
        print(f"[*] Restored LaunchOptions -> '{restored_opts}'")
        return 0

    return 0


# --- Main CLI Argument Parser ---

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agyis capture",
        description="Process-isolated retail network capture and preservation workflow (ADR-034)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Capture subcommands")

    # status
    p_status = subparsers.add_parser("status", help="Read-only pre-flight status dashboard")
    p_status.add_argument("--sdd-dir", help="Service Discovery directory override")

    # selftest
    subparsers.add_parser("selftest", help="Live 2-second isolation stack verification")

    # prep
    p_prep = subparsers.add_parser("prep", help="Idempotent pre-flight workspace preparation")
    p_prep.add_argument("--mode", choices=["cgroup", "host-bpf"], default="cgroup", help="Isolation mode")
    p_prep.add_argument("--quiesce", action="store_true", help="Gracefully stop heavy background apps")
    p_prep.add_argument("--no-rotate", action="store_true", help="Skip rotating client Launch.log")
    p_prep.add_argument("--sdd-dir", help="Service Discovery directory override")

    # run
    p_run = subparsers.add_parser("run", help="Single-command end-to-end capture session")
    p_run.add_argument("run_id", help="Single-domain run identifier (e.g. CAP-01_bot_siege)")
    p_run.add_argument("--mode", choices=["cgroup", "host-bpf"], default="cgroup", help="Isolation mode")
    p_run.add_argument("--preset", choices=["pf1", "retail"], default="pf1", help="Game flags preset")
    p_run.add_argument("--flags", help="Custom game flags override")
    p_run.add_argument("--launch", action="store_true", help="Automatically launch Paladins via steam -applaunch")
    p_run.add_argument("--watch-exit", action="store_true", help="Capture until game process exits")
    p_run.add_argument("--quiesce", action="store_true", help="Gracefully stop heavy background apps")
    p_run.add_argument("--no-restore", action="store_true", help="Skip automatic post-capture restoration")
    p_run.add_argument("--relaunch-apps", action="store_true", help="Relaunch quiesced apps on restore")
    p_run.add_argument("--cap-dir", help="Output pcaps directory override")

    # archive
    p_arch = subparsers.add_parser("archive", help="Archive capture artifacts, analyze log and update manifest")
    p_arch.add_argument("run_id", help="Run identifier to archive")
    p_arch.add_argument("--pcap", help="Specific pcap file path override")
    p_arch.add_argument("--cap-dir", help="Output pcaps directory override")

    # restore
    p_rest = subparsers.add_parser("restore", help="Idempotent teardown and restoration")
    p_rest.add_argument("--mode", choices=["auto", "immortal", "retail"], default="auto", help="SDD mode to restore")
    p_rest.add_argument("--relaunch-apps", action="store_true", help="Relaunch previously quiesced apps")
    p_rest.add_argument("--sdd-dir", help="Service Discovery directory override")

    # steam-opts
    p_steam = subparsers.add_parser("steam-opts", help="Inspect and manage Steam LaunchOptions for 444090")
    p_steam.add_argument("subaction", choices=["show", "install-slice", "set", "restore"], nargs="?", default="show")
    p_steam.add_argument("options", nargs="?", help="Options string for 'set' action")
    p_steam.add_argument("--force", action="store_true", help="Allow modifying VDF while Steam is running")
    p_steam.add_argument("--vdf", help="Path to localconfig.vdf override")

    args = parser.parse_args()

    if not args.subcommand or args.subcommand == "status":
        return cmd_status(args)
    elif args.subcommand == "selftest":
        return cmd_selftest(args)
    elif args.subcommand == "prep":
        return cmd_prep(args)
    elif args.subcommand == "run":
        return cmd_run(args)
    elif args.subcommand == "archive":
        return cmd_archive(args)
    elif args.subcommand == "restore":
        return cmd_restore(args)
    elif args.subcommand == "steam-opts":
        return cmd_steam_opts(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
