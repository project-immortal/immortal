# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Core primitives for process-isolated retail network capture and preservation.
Governed by SPEC-2026-IMMORTAL-CAPTURE-PLAN-001, PSL-INV-007, and PSL-INV-011.
"""

from datetime import datetime
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.common import DIRTYROOM_ROOT, get_launch_log_path, pid_is_running

# Canonical defaults and constants
DEFAULT_SDD_DIR = Path("/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/ChaosGame/ServiceDiscovery")
DEFAULT_CAP_DIR = DIRTYROOM_ROOT / "pcaps"
CAPTURE_STATE_PATH = DIRTYROOM_ROOT / "capture_state.json"
STEAM_LAUNCH_BACKUP_PATH = DIRTYROOM_ROOT / "steam_launch_options_backup.json"

SLICE_NAME = "immortalcapture.slice"
NFT_TABLE_NAME = "immortal_capture"
NFLOG_GROUP = 42
CT_MARK = "0x4242"

DEFAULT_RETAIL_IP = "20.153.141.49"
QBIT_CONFIG_PATH = Path(os.path.expanduser("~/.config/qBittorrent/qBittorrent.conf"))
STEAM_CONFIG_GLOB = os.path.expanduser("~/.local/share/Steam/userdata/*/config/localconfig.vdf")


def calculate_sha256(filepath: Union[str, Path]) -> str:
    """Computes the SHA-256 hex digest of a file in streaming chunks."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for SHA-256 calculation: {path}")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# --- Idempotent .sdd Service Discovery Handling ---

def inspect_sdd_status(sdd_dir: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Inspects the Service Discovery directory to determine the active mode.
    Returns details on target (402.sdd), retail original (.orig), and immortal backup (.immortal).
    """
    base = Path(sdd_dir or DEFAULT_SDD_DIR)
    target = base / "8.1.5839.0-PC-402.sdd"
    orig = base / "8.1.5839.0-PC-402.sdd.orig"
    immortal = base / "8.1.5839.0-PC-402.sdd.immortal"

    target_sha = calculate_sha256(target) if target.is_file() else None
    orig_sha = calculate_sha256(orig) if orig.is_file() else None
    immortal_sha = calculate_sha256(immortal) if immortal.is_file() else None

    if not target.is_file():
        current_mode = "missing"
    elif orig_sha and target_sha == orig_sha:
        current_mode = "retail"
    elif immortal_sha and target_sha == immortal_sha:
        current_mode = "immortal"
    else:
        current_mode = "custom"

    return {
        "sdd_dir": str(base),
        "target_path": str(target),
        "target_exists": target.is_file(),
        "target_sha256": target_sha,
        "orig_path": str(orig),
        "orig_exists": orig.is_file(),
        "orig_sha256": orig_sha,
        "immortal_path": str(immortal),
        "immortal_exists": immortal.is_file(),
        "immortal_sha256": immortal_sha,
        "current_mode": current_mode,
    }


def prep_sdd(sdd_dir: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Idempotently configures Service Discovery for retail capture:
    1. Asserts .sdd.orig exists.
    2. If .immortal does NOT exist and sha256(402.sdd) != sha256(.orig), backup 402.sdd -> .immortal.
       NEVER clobbers an existing .immortal backup with .orig!
    3. Copies .orig -> 402.sdd if hashes differ.
    """
    base = Path(sdd_dir or DEFAULT_SDD_DIR)
    orig = base / "8.1.5839.0-PC-402.sdd.orig"
    if not orig.is_file():
        raise FileNotFoundError(f"Retail original SDD missing: {orig}")

    orig_sha = calculate_sha256(orig)
    target = base / "8.1.5839.0-PC-402.sdd"
    immortal = base / "8.1.5839.0-PC-402.sdd.immortal"

    target_sha = calculate_sha256(target) if target.is_file() else None

    # Step 2: Backup local emulator SDD if backup absent and target is not retail
    immortal_created = False
    if not immortal.is_file() and target.is_file() and target_sha != orig_sha:
        shutil.copy2(target, immortal)
        immortal_created = True

    # Determine previous mode prior to modification
    if target_sha == orig_sha:
        previous_mode = "retail"
    elif (immortal.is_file() and target_sha == calculate_sha256(immortal)) or immortal_created:
        previous_mode = "immortal"
    elif target.is_file():
        previous_mode = "custom"
    else:
        previous_mode = "missing"

    # Step 3: Switch target to retail if needed
    if target_sha != orig_sha:
        shutil.copy2(orig, target)

    return {
        "status": "ok",
        "previous_mode": previous_mode,
        "current_mode": "retail",
        "immortal_created": immortal_created,
        "target_sha256": calculate_sha256(target),
    }


def restore_sdd(
    target_mode: str = "auto",
    pre_capture_mode: Optional[str] = None,
    sdd_dir: Optional[Union[str, Path]] = None,
) -> str:
    """
    Restores Service Discovery .sdd to the requested mode (or previously recorded mode).
    Mode resolution:
    - If explicit 'immortal' or 'retail', use that.
    - If 'auto': prefer pre_capture_mode if specified; else if .immortal exists restore to immortal; else retail.
    Safe to execute repeatedly.
    """
    base = Path(sdd_dir or DEFAULT_SDD_DIR)
    target = base / "8.1.5839.0-PC-402.sdd"
    orig = base / "8.1.5839.0-PC-402.sdd.orig"
    immortal = base / "8.1.5839.0-PC-402.sdd.immortal"

    mode = target_mode.lower()
    if mode == "auto":
        if pre_capture_mode in ("immortal", "retail"):
            mode = pre_capture_mode
        elif immortal.is_file():
            mode = "immortal"
        else:
            mode = "retail"

    if mode == "immortal":
        if immortal.is_file():
            shutil.copy2(immortal, target)
            return "immortal"
        elif orig.is_file():
            shutil.copy2(orig, target)
            return "retail"
    elif mode == "retail":
        if orig.is_file():
            shutil.copy2(orig, target)
            return "retail"

    return mode


# --- cgroup v2 & nftables Isolation Primitives ---

def get_cgroup_paths(uid: Optional[int] = None) -> Tuple[str, Path]:
    """
    Returns (relative_cgroup_path_for_nft, absolute_sys_fs_cgroup_path).
    Slice name immortalcapture.slice has depth 4:
    user.slice/user-<UID>.slice/user@<UID>.service/immortalcapture.slice
    """
    u = os.getuid() if uid is None else uid
    rel = f"user.slice/user-{u}.slice/user@{u}.service/{SLICE_NAME}"
    sys_fs = Path(f"/sys/fs/cgroup/{rel}")
    return rel, sys_fs


def generate_nftables_rules(uid: Optional[int] = None) -> str:
    """
    Generates the complete, atomic, idempotent nftables ruleset for process isolation.
    Uses 'queue-threshold 1' on nflog statements to prevent netlink queue delay.
    """
    rel, _ = get_cgroup_paths(uid)
    return f"""table inet {NFT_TABLE_NAME}
delete table inet {NFT_TABLE_NAME}
table inet {NFT_TABLE_NAME} {{
    chain output {{
        type filter hook output priority mangle - 10; policy accept;
        socket cgroupv2 level 4 "{rel}" ct mark set {CT_MARK};
        ct mark {CT_MARK} log group {NFLOG_GROUP} queue-threshold 1 snaplen 65535;
    }}
    chain input {{
        type filter hook input priority mangle - 10; policy accept;
        iifname != "lo" ct mark {CT_MARK} log group {NFLOG_GROUP} queue-threshold 1 snaplen 65535;
        iifname != "lo" socket cgroupv2 level 4 "{rel}" ct mark != {CT_MARK} log group {NFLOG_GROUP} queue-threshold 1 snaplen 65535;
    }}
}}
"""


def generate_nftables_teardown() -> str:
    """Generates the idempotent teardown script for immortal_capture table."""
    return f"""table inet {NFT_TABLE_NAME}
delete table inet {NFT_TABLE_NAME}
"""


def check_nftables_table_exists(table_name: str = NFT_TABLE_NAME) -> bool:
    """Checks whether the given nftables table currently exists."""
    proc = subprocess.run(
        ["sudo", "-n", "nft", "list", "table", "inet", table_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def apply_nftables_rules(rules: str) -> None:
    """Atomically loads nftables rules via sudo -n nft -f -."""
    proc = subprocess.run(
        ["sudo", "-n", "nft", "-f", "-"],
        input=rules,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Failed to apply nftables rules (code {proc.returncode}): {proc.stderr.strip()}"
        )


def teardown_nftables() -> bool:
    """Idempotently tears down the immortal_capture nftables table."""
    script = generate_nftables_teardown()
    proc = subprocess.run(
        ["sudo", "-n", "nft", "-f", "-"],
        input=script,
        text=True,
        capture_output=True,
    )
    return proc.returncode == 0


def start_slice_holder(slice_name: str = SLICE_NAME, timeout: float = 2.0) -> int:
    """
    Pins the systemd slice open by spawning a background sleep infinity scope.
    Waits for the sysfs cgroup directory to appear before returning holder PID.
    """
    _, abs_cgroup = get_cgroup_paths()
    cmd = [
        "systemd-run",
        "--user",
        "--scope",
        f"--slice={slice_name}",
        "--",
        "sleep",
        "infinity",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    start_t = time.time()
    while time.time() - start_t < timeout:
        if abs_cgroup.exists():
            return proc.pid
        time.sleep(0.05)

    # Clean up on failure
    stop_slice_holder(proc.pid)
    raise TimeoutError(f"Cgroup directory {abs_cgroup} did not appear within {timeout}s")


def stop_slice_holder(holder_pid: int) -> None:
    """Gracefully terminates the background slice holder scope."""
    if not pid_is_running(holder_pid):
        return
    try:
        os.kill(holder_pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return

    start_t = time.time()
    while time.time() - start_t < 1.5:
        if not pid_is_running(holder_pid):
            return
        time.sleep(0.05)

    try:
        os.kill(holder_pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


# --- Host-BPF Fallback Primitives ---

def get_egress_interface(target_ip: str = DEFAULT_RETAIL_IP) -> str:
    """Discovers the active network egress interface towards target_ip."""
    try:
        proc = subprocess.run(
            ["ip", "route", "get", target_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout:
            tokens = proc.stdout.split()
            for idx, token in enumerate(tokens):
                if token == "dev" and idx + 1 < len(tokens):
                    return tokens[idx + 1]
    except OSError:
        pass
    return "any"


def get_qbittorrent_ports(config_path: Optional[Union[str, Path]] = None) -> List[int]:
    """Reads configured listening ports from qBittorrent.conf."""
    path = Path(config_path or QBIT_CONFIG_PATH)
    ports: List[int] = []
    if not path.is_file():
        return ports

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if "Port=" in line:
                    parts = line.split("Port=")
                    if len(parts) == 2 and parts[1].strip().isdigit():
                        ports.append(int(parts[1].strip()))
    except OSError:
        pass
    return sorted(list(set(ports)))


def generate_bpf_filter(exclude_ports: Optional[List[int]] = None) -> str:
    """Generates the clean single-domain BPF filter matching RETAIL_CAPTURE_PLAN.md §1.4."""
    exclusions = ""
    if exclude_ports:
        exclusion_clauses = [f"and not port {p}" for p in exclude_ports]
        exclusions = " " + " ".join(exclusion_clauses)

    return f"""(
  (tcp port 9000) or
  (udp port 9002) or
  (udp port 6250) or
  (udp port 53 or tcp port 53) or
  (host 20.153.141.49 or host 20.153.141.80 or host 51.8.226.76 or host 85.236.98.253) or
  (udp and not broadcast and not multicast
    and not port 5353 and not port 1900 and not port 123 and not port 443
    and not portrange 137-138 and not portrange 19302-19350 and not portrange 27000-27060{exclusions})
)"""


# --- Steam localconfig.vdf Launch Options Management ---

def find_active_localconfig_vdf() -> Optional[Path]:
    """Finds the most recently modified Steam localconfig.vdf containing Paladins AppID 444090."""
    candidates = glob.glob(STEAM_CONFIG_GLOB)
    matching: List[Path] = []
    for cand in candidates:
        p = Path(cand)
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            if '"444090"' in content:
                matching.append(p)
        except OSError:
            continue

    if not matching:
        return None
    matching.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return matching[0]


def parse_steam_launch_options(vdf_content: str) -> Optional[str]:
    """Extracts the LaunchOptions string for 444090 from Steam localconfig.vdf content."""
    # Find block starting with "444090"
    m_block = re.search(r'"444090"\s*\{([^}]*)\}', vdf_content, re.DOTALL)
    if not m_block:
        return None
    block_text = m_block.group(1)
    m_opts = re.search(r'"LaunchOptions"\s*"([^"]*)"', block_text)
    if m_opts:
        return m_opts.group(1)
    return None


def wrap_launch_options_with_slice(options: str, slice_name: str = SLICE_NAME) -> str:
    """
    Wraps existing Steam LaunchOptions inside the systemd slice runner.
    Idempotent: if already wrapped, returns unchanged.
    """
    prefix = f"systemd-run --user --scope --slice={slice_name} -- "
    clean = options.strip()
    if clean.startswith("systemd-run") and f"--slice={slice_name}" in clean:
        return clean

    if not clean:
        return f"{prefix}%command%"
    return f"{prefix}{clean}"


def unwrap_launch_options_from_slice(options: str) -> str:
    """Removes the systemd-run slice wrapper from Steam LaunchOptions."""
    return re.sub(r"^systemd-run\s+--user\s+--scope\s+--slice=[^\s]+\s+--\s*", "", options).strip()


def update_steam_launch_options(vdf_content: str, new_options: str) -> str:
    """
    Updates or inserts the LaunchOptions field inside the 444090 app block.
    Preserves all other settings, indentation, and structure.
    """
    m_block = re.search(r'("444090"\s*\{)([^}]*)(\})', vdf_content, re.DOTALL)
    if not m_block:
        raise ValueError('Could not find "444090" app block in VDF content.')

    prefix_hdr = m_block.group(1)
    block_body = m_block.group(2)
    suffix_tail = m_block.group(3)

    if re.search(r'"LaunchOptions"\s*"[^"]*"', block_body):
        new_body = re.sub(
            r'"LaunchOptions"\s*"[^"]*"',
            lambda _: f'"LaunchOptions"\t\t"{new_options}"',
            block_body,
        )
    else:
        # Prepend LaunchOptions at the beginning of the block body
        new_body = f'\n\t\t\t\t\t\t"LaunchOptions"\t\t"{new_options}"' + block_body

    return vdf_content[: m_block.start()] + prefix_hdr + new_body + suffix_tail + vdf_content[m_block.end() :]


def is_steam_running() -> bool:
    """Checks if any native steam process is running."""
    try:
        proc = subprocess.run(["pgrep", "-x", "steam"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0
    except OSError:
        return False


# --- Log Rotation and Analysis ---

def rotate_launch_log(launch_log_path: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """
    Rotates active Launch.log (and any MCTS-*.log) to ChaosGame/Logs/archive/.
    Returns the archived Launch.log path if rotated, or None if file was absent/empty.
    """
    log_p = Path(launch_log_path or get_launch_log_path())
    if not log_p.is_file() or log_p.stat().st_size == 0:
        return None

    archive_dir = log_p.parent / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archived_target = archive_dir / f"Launch_{ts}.log"

    try:
        shutil.move(str(log_p), str(archived_target))
    except OSError as e:
        print(f"[!] Warning: Could not rotate {log_p}: {e}", file=sys.stderr)
        return None

    # Rotate any auxiliary MCTS-*.log files
    for mcts_log in log_p.parent.glob("MCTS-*.log"):
        if mcts_log.is_file():
            try:
                shutil.move(str(mcts_log), str(archive_dir / f"{mcts_log.stem}_{ts}.log"))
            except OSError:
                pass

    return archived_target


def analyze_launch_log(log_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Analyzes a Launch.log to extract dedicated server connection endpoints,
    map URLs, and verify PF-1 marshal dump (-dumpallmar) markers.
    """
    path = Path(log_path)
    if not path.is_file():
        return {
            "exists": False,
            "line_count": 0,
            "browse_endpoints": [],
            "dumpallmar_detected": False,
            "maps": [],
        }

    browse_endpoints: List[str] = []
    maps: List[str] = []
    dumpallmar_detected = False
    line_count = 0

    re_browse = re.compile(r"Browse:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+)")
    re_map = re.compile(r"mapGameId\s*=\s*([0-9]+)", re.IGNORECASE)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_count += 1
                if "dumpallmar" in line.lower() or "tgmar" in line.lower() or "mcts frame" in line.lower():
                    dumpallmar_detected = True

                m_b = re_browse.search(line)
                if m_b:
                    endpoint = m_b.group(1)
                    if endpoint not in browse_endpoints:
                        browse_endpoints.append(endpoint)

                m_m = re_map.search(line)
                if m_m:
                    map_id = m_m.group(1)
                    if map_id not in maps:
                        maps.append(map_id)
    except OSError:
        pass

    return {
        "exists": True,
        "line_count": line_count,
        "browse_endpoints": browse_endpoints,
        "dumpallmar_detected": dumpallmar_detected,
        "maps": maps,
    }


def summarize_conversations(pcap_path: Union[str, Path]) -> Dict[str, str]:
    """Generates UDP and TCP conversation summaries via tshark."""
    path = Path(pcap_path)
    if not path.is_file():
        return {"udp": "PCAP not found.", "tcp": "PCAP not found."}

    udp_res = subprocess.run(
        ["tshark", "-r", str(path), "-q", "-z", "conv,udp"],
        capture_output=True,
        text=True,
    )
    tcp_res = subprocess.run(
        ["tshark", "-r", str(path), "-q", "-z", "conv,tcp"],
        capture_output=True,
        text=True,
    )

    return {
        "udp": udp_res.stdout.strip() or "No UDP conversations detected.",
        "tcp": tcp_res.stdout.strip() or "No TCP conversations detected.",
    }


# --- SHA256 Manifest Appender ---

def append_sha256sums(manifest_path: Union[str, Path], file_paths: List[Union[str, Path]]) -> None:
    """
    Appends SHA-256 digests of the given files to SHA256SUMS.txt.
    Idempotent: prevents duplicate lines for identical hash + basename pairs.
    """
    mpath = Path(manifest_path)
    existing_entries: set = set()
    if mpath.is_file():
        try:
            with open(mpath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line_s = line.strip()
                    if line_s:
                        existing_entries.add(line_s)
        except OSError:
            pass

    new_lines: List[str] = []
    for fp in file_paths:
        p = Path(fp)
        if p.is_file():
            h = calculate_sha256(p)
            entry = f"{h}  {p.name}"
            if entry not in existing_entries:
                existing_entries.add(entry)
                new_lines.append(entry)

    if new_lines:
        mpath.parent.mkdir(parents=True, exist_ok=True)
        with open(mpath, "a", encoding="utf-8") as f:
            for l in new_lines:
                f.write(l + "\n")


# --- Capture State Ledger ---

def load_capture_state(state_file: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Loads runtime capture state from dirtyroom ledger."""
    p = Path(state_file or CAPTURE_STATE_PATH)
    if not p.is_file():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_capture_state(state: Dict[str, Any], state_file: Optional[Union[str, Path]] = None) -> None:
    """Atomically saves runtime capture state to dirtyroom ledger."""
    p = Path(state_file or CAPTURE_STATE_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = p.with_suffix(".json.tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp_path, p)


def clear_capture_state(state_file: Optional[Union[str, Path]] = None) -> None:
    """Cleans up the runtime capture state ledger."""
    p = Path(state_file or CAPTURE_STATE_PATH)
    if p.exists():
        try:
            p.unlink()
        except OSError:
            pass


# --- Process Quiesce and Relaunch ---

def quiesce_process(name: str = "qbittorrent") -> Optional[int]:
    """
    Sends graceful SIGTERM to a named process.
    Waits up to 3 seconds for exit. Never uses SIGKILL.
    Returns the PID if terminated, or None.
    """
    try:
        proc = subprocess.run(["pgrep", "-x", name], stdout=subprocess.PIPE, text=True)
        pids = [int(p) for p in proc.stdout.splitlines() if p.strip().isdigit()]
        if not pids:
            return None
        target_pid = pids[0]
        os.kill(target_pid, signal.SIGTERM)

        start_t = time.time()
        while time.time() - start_t < 3.0:
            if not pid_is_running(target_pid):
                return target_pid
            time.sleep(0.1)
        return target_pid
    except (OSError, ProcessLookupError):
        return None


def relaunch_process(cmd: List[str]) -> None:
    """Relaunches a background application cleanly."""
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        print(f"[!] Warning: Failed to relaunch {' '.join(cmd)}: {e}", file=sys.stderr)


# --- Packet Capture Process Lifecycle ---

def start_packet_capture(
    output_pcap: Union[str, Path],
    mode: str = "cgroup",
    iface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
) -> subprocess.Popen:
    """
    Spawns the packet capture recorder (dumpcap or tshark).
    For mode 'cgroup': captures on unprivileged nflog:42.
    For mode 'host-bpf': captures on the specified interface with BPF filter.
    """
    out_path = str(Path(output_pcap).resolve())
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    # Prefer dumpcap directly if available, fallback to tshark
    capture_bin = shutil.which("dumpcap") or shutil.which("tshark")
    if not capture_bin:
        raise RuntimeError("Neither dumpcap nor tshark found in PATH.")

    if mode == "cgroup":
        cmd = [capture_bin, "-i", f"nflog:{NFLOG_GROUP}", "-w", out_path]
    else:
        target_iface = iface or get_egress_interface()
        target_filter = bpf_filter or generate_bpf_filter()
        cmd = [capture_bin, "-i", target_iface, "-f", target_filter, "-w", out_path]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc


def stop_packet_capture(proc: subprocess.Popen, timeout: float = 4.0) -> None:
    """
    Stops packet capture process cleanly via SIGINT so pcap headers/trailers are written.
    """
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            proc.terminate()
            proc.wait(timeout=1.0)
        except (subprocess.TimeoutExpired, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
