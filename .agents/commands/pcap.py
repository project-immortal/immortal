#!/usr/bin/env python3
# Inspect and decode PCAP/PCAPNG network captures and UE3 datagrams
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Agyis Extension CLI: PCAP inspection and UE3 bit-packed bunch decoding (ADR-034).
Subcommands:
  agyis pcap status   - Summary of capture directory, files, sizes, and checksums
  agyis pcap decode   - Decodes packets using Ue3Packet bitstream decoder or tshark
  agyis pcap convert  - Converts NFLOG PCAPNG to standard DLT_RAW classic PCAP
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import DIRTYROOM_ROOT
from lib.capture_core import DEFAULT_CAP_DIR, calculate_sha256
from lib.pcapng import convert_to_raw_pcap, extract_udp_packets

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]


def format_bytes(size: int) -> str:
    """Formats raw byte count into human-readable representation."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    return f"{size:.1f} TB"


def get_decoder_bin(max_packet_bits: Optional[int] = None) -> List[str]:
    """Returns command to execute decode_pcap example."""
    compiled_bin = WORKSPACE_ROOT / "target" / "debug" / "examples" / "decode_pcap"
    cmd = []
    if compiled_bin.is_file() and os.access(compiled_bin, os.X_OK):
        cmd = [str(compiled_bin)]
    else:
        cmd = [
            "cargo", "run", "--quiet",
            "--manifest-path", str(WORKSPACE_ROOT / "Cargo.toml"),
            "-p", "immortal-net",
            "--example", "decode_pcap",
            "--",
        ]
    if max_packet_bits:
        cmd.extend(["--max-packet-bits", str(max_packet_bits)])
    return cmd


def cmd_status(args: argparse.Namespace) -> int:
    """Summarizes available captures in DEFAULT_CAP_DIR or custom directory."""
    cap_dir = Path(args.dir) if args.dir else DEFAULT_CAP_DIR

    if not cap_dir.exists():
        if args.json:
            print(json.dumps({"error": f"Directory not found: {cap_dir}", "files": []}))
        else:
            print(f"[!] Capture directory does not exist: {cap_dir}")
        return 1

    files_info = []
    sha256_map = {}
    sha_file = cap_dir / "SHA256SUMS.txt"
    if sha_file.is_file():
        try:
            with open(sha_file, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        sha256_map[Path(parts[1]).name] = parts[0]
        except Exception:
            pass

    for entry in sorted(cap_dir.iterdir()):
        if entry.is_file() and not entry.name.startswith("."):
            stat = entry.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            sha256 = sha256_map.get(entry.name)
            files_info.append({
                "name": entry.name,
                "path": str(entry),
                "size_bytes": stat.st_size,
                "size_human": format_bytes(stat.st_size),
                "modified": mtime,
                "sha256": sha256,
            })

    if args.json:
        payload = {
            "capture_directory": str(cap_dir),
            "file_count": len(files_info),
            "total_bytes": sum(f["size_bytes"] for f in files_info),
            "files": files_info,
        }
        print(json.dumps(payload, indent=2))
        return 0

    print("=== Immortal Network Capture Status ===")
    print(f"Directory: {cap_dir}")
    print(f"Files Found: {len(files_info)}\n")

    if not files_info:
        print("No capture files found in directory.")
        return 0

    header = f"{'Filename':<35} {'Size':<12} {'Modified':<20} {'Checksum':<12}"
    print(header)
    print("-" * len(header))
    for f in files_info:
        chk = f["sha256"][:8] + "..." if f["sha256"] else "unverified"
        print(f"{f['name']:<35} {f['size_human']:<12} {f['modified']:<20} {chk:<12}")

    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    """Decodes UE3 packets from a pcap file or raw hex stream."""
    target_path = Path(args.file) if args.file and args.file != "-" else None

    # Handle direct stdin hex stream if no file or '-' is provided
    if target_path is None:
        if sys.stdin.isatty():
            print("Error: No pcap file specified and stdin is a TTY.", file=sys.stderr)
            print("Usage: agyis pcap decode [<file.pcap|pcapng>] or pipe hex into stdin", file=sys.stderr)
            return 1
        decoder_cmd = get_decoder_bin()
        proc = subprocess.run(decoder_cmd, stdin=sys.stdin, cwd=WORKSPACE_ROOT)
        return proc.returncode

    if not target_path.is_file():
        print(f"Error: Capture file not found: {target_path}", file=sys.stderr)
        return 1

    # If it's a text/hex file (.raw, .hex, .txt), feed directly to decoder
    if target_path.suffix.lower() in [".hex", ".txt"]:
        decoder_cmd = get_decoder_bin(max_packet_bits=args.max_packet_bits)
        with open(target_path, "r") as f:
            proc = subprocess.run(decoder_cmd, stdin=f, cwd=WORKSPACE_ROOT)
            return proc.returncode

    # For pcap / pcapng, extract UDP datagrams natively using pure-Python extractor
    if target_path.suffix.lower() in [".pcap", ".pcapng"]:
        decoder_cmd = get_decoder_bin(max_packet_bits=args.max_packet_bits)
        decoder_proc = subprocess.Popen(
            decoder_cmd,
            stdin=subprocess.PIPE,
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
            cwd=WORKSPACE_ROOT,
        )
        try:
            for frame_num, time_sec, src_ip, src_port, dst_ip, dst_port, payload in extract_udp_packets(
                target_path, port_filter=args.port, limit=args.limit
            ):
                meta = f"{frame_num} {time_sec:.6f} {src_ip}:{src_port} {dst_ip}:{dst_port}"
                line = f"{meta} {payload.hex()}\n"
                decoder_proc.stdin.write(line)
        except (BrokenPipeError, IOError):
            pass
        finally:
            if decoder_proc.stdin:
                try:
                    decoder_proc.stdin.close()
                except (BrokenPipeError, IOError):
                    pass
            decoder_proc.wait()

        return decoder_proc.returncode


def cmd_convert(args: argparse.Namespace) -> int:
    """Converts a PCAPNG file to classic PCAP with DLT_RAW linktype."""
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: Input capture file not found: {input_path}", file=sys.stderr)
        return 1

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_suffix(".pcap")
        if output_path == input_path:
            output_path = input_path.with_name(f"{input_path.stem}_raw.pcap")

    count = convert_to_raw_pcap(input_path, output_path, port_filter=args.port)
    print(f"[✓] Converted {count} packets to {output_path} (Linktype: RAW_IP / DLT_RAW)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agyis pcap",
        description="Inspect and decode PCAP/PCAPNG network captures and UE3 datagrams",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Status subcommand
    status_parser = subparsers.add_parser(
        "status",
        help="Summary of capture directory, files, sizes, and checksums",
    )
    status_parser.add_argument(
        "--dir",
        type=str,
        default=None,
        help="Custom capture directory (default: DIRTYROOM_ROOT/pcaps)",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit status as JSON",
    )

    # Decode subcommand
    decode_parser = subparsers.add_parser(
        "decode",
        help="Decode packets using Ue3Packet bitstream decoder",
    )
    decode_parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Path to .pcap, .pcapng, or hex file (omit or use '-' for stdin)",
    )
    decode_parser.add_argument(
        "-Y", "--filter",
        type=str,
        default="udp",
        help="tshark display filter (default: 'udp')",
    )
    decode_parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Filter packets by UDP port (e.g. 7777, 9198)",
    )
    decode_parser.add_argument(
        "-n", "--limit",
        type=int,
        default=None,
        help="Maximum number of packets to decode",
    )
    decode_parser.add_argument(
        "--max-packet-bits",
        type=int,
        default=None,
        help="Override maximum bit length for UE3 packets (e.g. 11520 for 1440B MTU)",
    )

    # Convert subcommand
    convert_parser = subparsers.add_parser(
        "convert",
        help="Convert NFLOG PCAPNG to standard DLT_RAW classic PCAP",
    )
    convert_parser.add_argument(
        "input",
        help="Path to input .pcapng or .pcap file",
    )
    convert_parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output .pcap path (default: <input_stem>.pcap)",
    )
    convert_parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Filter packets by UDP port",
    )

    args = parser.parse_args()

    if args.subcommand == "status":
        return cmd_status(args)
    elif args.subcommand == "decode":
        return cmd_decode(args)
    elif args.subcommand == "convert":
        return cmd_convert(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
