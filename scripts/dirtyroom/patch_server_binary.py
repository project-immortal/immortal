#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
scripts/dirtyroom/patch_server_binary.py
ADOPT-09: Dedicated Server Assembly Loader Hook Patcher.

Patches an isolated copy of ShippingPC-ChaosGame.exe to create
ShippingPC-ChaosGame-Server.exe inside a quarantined runtime directory
(.dirtyroom/oracle/runtime/Binaries/Win64/) so Steam's Binaries/Win64/
remains untouched.

Ground Truth Problem (Hi-Rez Bug):
  In Paladins UE3 64-bit, FEngineLoop::PreInit (FUN_140d18380) runs
  Engine.ServerCommandlet synchronously at 0x140d1ac13 and never returns to
  GuardedMain to run FEngineLoop::Init (0x140d16a30), where
  CTgAssemblyManager::LoadFile (VA 0x140ee2600) is normally invoked.
  As a result, ChaosGame/CookedPCConsole/assembly.dat is never mounted, causing
  LoadMap to fail immediately with:
    Critical error: Bad name index 2101657905/7555

Surgical Binary Patch:
  1. SeekFree Guard: VA 0x140d19c23 (File offset 0xD19C23, inside FEngineLoop::PreInit)
     Original instruction: mov dword ptr [rip+0x2b4c5fa], r14d (44 89 35 fa c5 b4 02)
                           forces GUseSeekFreeLoading (0x143866224) = 0 for server/commandlets.
     Patched instruction:  7x nop (90 90 90 90 90 90 90) so -seekfreeloadingpcconsole holds.
  2. Hook site: VA 0x140d1a9df (File offset 0xD1A9DF, inside FEngineLoop::PreInit
     after GIsServer=1, GFileManager, GConfig, GLog, and UObject init, right
     before UGameEngine::StaticClass()):
     Original instruction: call 0x14055bf30 (e8 4c 15 84 ff)
     Patched instruction:  call 0x1424628a0 (e8 bc 7e 74 01)
  3. Code Cave: VA 0x1424628a0 (File offset 0x24628A0, inside .text padding, 37 bytes):
     - mov dword ptr [rip+0x152f4f2], 3    (c7 05 f2 f4 52 01 03 00 00 00 -> GRHIShaderPlatform = 3)
       so cooked maps cleanly seek past stale SM3/uninitialized SM5 shader caches under NullRHI.
     - sub rsp, 0x28                       (48 83 ec 28)
     - mov dl, 1                           (b2 01)
     - lea rcx, [rip + 0x18f8d41]          (48 8d 0d 41 8d 8f 01 -> 0x143d5b5f8)
     - call 0x140ee2600                    (e8 44 fd a7 fe -> CTgAssemblyManager::LoadFile)
     - add rsp, 0x28                       (48 83 c4 28)
     - jmp 0x14055bf30                     (e9 6b 96 0f fe -> tail-call UGameEngine::StaticClass)
  4. Clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) so RIP/0x140... image
     base remains pinned at 0x140000000 under Wine.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _resolve_dirtyroom_root() -> Path:
    env_dir = os.environ.get("IMMORTAL_DIRTYROOM")
    if env_dir:
        return Path(env_dir)
    repo_dirty = REPO_ROOT / ".dirtyroom"
    if repo_dirty.exists():
        return repo_dirty.resolve()
    return Path("/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0")


DIRTYROOM_ROOT = _resolve_dirtyroom_root()
DIRTYROOM_BIN = DIRTYROOM_ROOT / "binaries"
ORACLE_RUNTIME_DIR = DIRTYROOM_ROOT / "oracle" / "runtime"
STEAM_PALADINS_ROOT = Path("/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins")
FALLBACK_STEAM_SRC = STEAM_PALADINS_ROOT / "Binaries" / "Win64" / "ShippingPC-ChaosGame.exe"
DEFAULT_SRC = DIRTYROOM_BIN / "ShippingPC-ChaosGame.exe"
DEFAULT_DST = ORACLE_RUNTIME_DIR / "Binaries" / "Win64" / "ShippingPC-ChaosGame-Server.exe"

# Verified offsets and payloads (ImageBase 0x140000000, .text raw diff 0x140000000)
HOOK_OFFSET = 0xD1A9DF
HOOK_VA = 0x140D1A9DF
HOOK_ORIGINAL_BYTES = b"\xe8\x4c\x15\x84\xff"  # call 0x14055bf30 (UGameEngine::StaticClass)
HOOK_PATCHED_BYTES = b"\xe8\xbc\x7e\x74\x01"   # call 0x1424628a0

# PreInit forces GUseSeekFreeLoading (DAT_143866224) to 0 for commandlet/server mode,
# skipping seek-free startup packages and crashing LoadMap on cooked maps (Bad name index).
SEEKFREE_OFFSET = 0xD19C23
SEEKFREE_VA = 0x140D19C23
SEEKFREE_ORIGINAL_BYTES = b"\x44\x89\x35\xfa\xc5\xb4\x02"  # mov dword ptr [0x143866224], r14d
SEEKFREE_PATCHED_BYTES = b"\x90" * 7                       # 7x nop (preserve -seekfreeloadingpcconsole)

CAVE_OFFSET = 0x24628A0
CAVE_VA = 0x1424628A0
DYNAMIC_BASE_FLAG = 0x0040

# 37-byte authentic assembly loader + shader cache skip code cave:
# Sets GRHIShaderPlatform (0x143991d9c) = 3 (unused platform <= 10) so cooked maps
# cleanly seek past SM3/SM5 shader caches under NullRHI, calls CTgAssemblyManager::LoadFile(0x143d5b5f8, 1),
# then tail-calls UGameEngine::StaticClass().
CAVE_PAYLOAD = bytes([
    0xC7, 0x05, 0xF2, 0xF4, 0x52, 0x01, 0x03, 0x00, 0x00, 0x00,  # 0x00: mov dword ptr [rip+0x152f4f2], 3 -> 0x143991d9c
    0x48, 0x83, 0xEC, 0x28,                                      # 0x0a: sub rsp, 0x28
    0xB2, 0x01,                                                  # 0x0e: mov dl, 1
    0x48, 0x8D, 0x0D, 0x41, 0x8D, 0x8F, 0x01,                    # 0x10: lea rcx, [rip + 0x18f8d41] -> 0x143d5b5f8
    0xE8, 0x44, 0xFD, 0xA7, 0xFE,                                # 0x17: call 0x140ee2600 (CTgAssemblyManager::LoadFile)
    0x48, 0x83, 0xC4, 0x28,                                      # 0x1c: add rsp, 0x28
    0xE9, 0x6B, 0x96, 0x0F, 0xFE,                                # 0x20: jmp 0x14055bf30 (UGameEngine::StaticClass)
])


def compute_sha256(path: Path) -> str:
    """Calculates SHA-256 of file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _dll_characteristics_offset(f) -> int | None:
    """Returns file offset of PE OptionalHeader.DllCharacteristics, or None if invalid."""
    f.seek(0)
    if f.read(2) != b"MZ":
        return None
    f.seek(0x3C)
    raw_pe = f.read(4)
    if len(raw_pe) < 4:
        return None
    pe_offset = struct.unpack("<I", raw_pe)[0]
    f.seek(pe_offset)
    if f.read(4) != b"PE\x00\x00":
        return None
    dll_chars_offset = pe_offset + 24 + 70
    f.seek(0, os.SEEK_END)
    if dll_chars_offset + 2 > f.tell():
        return None
    return dll_chars_offset


def get_dll_characteristics(path: Path) -> int | None:
    """Reads PE DllCharacteristics field, or returns None if not a valid PE."""
    if not path.is_file():
        return None
    with open(path, "rb") as f:
        off = _dll_characteristics_offset(f)
        if off is None:
            return None
        f.seek(off)
        return struct.unpack("<H", f.read(2))[0]


def verify_patch(path: Path) -> bool:
    """Checks if a binary contains the server hook, seekfree guard NOP, cave payload, and cleared DYNAMIC_BASE."""
    if not path.is_file():
        return False
    size = path.stat().st_size
    if size < CAVE_OFFSET + len(CAVE_PAYLOAD):
        return False
    dll_chars = get_dll_characteristics(path)
    if dll_chars is None or (dll_chars & DYNAMIC_BASE_FLAG) != 0:
        return False
    with open(path, "rb") as f:
        f.seek(HOOK_OFFSET)
        hook = f.read(len(HOOK_PATCHED_BYTES))
        f.seek(SEEKFREE_OFFSET)
        seekfree = f.read(len(SEEKFREE_PATCHED_BYTES))
        f.seek(CAVE_OFFSET)
        cave = f.read(len(CAVE_PAYLOAD))
    return hook == HOOK_PATCHED_BYTES and seekfree == SEEKFREE_PATCHED_BYTES and cave == CAVE_PAYLOAD


def clear_aslr_flag(dst: Path) -> bool:
    """Clears IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) from PE header."""
    with open(dst, "r+b") as f:
        dll_chars_offset = _dll_characteristics_offset(f)
        if dll_chars_offset is None:
            raise ValueError(f"Invalid PE header in {dst}")
        f.seek(dll_chars_offset)
        chars = struct.unpack("<H", f.read(2))[0]
        if chars & DYNAMIC_BASE_FLAG:
            chars &= ~DYNAMIC_BASE_FLAG
            f.seek(dll_chars_offset)
            f.write(struct.pack("<H", chars))
            return True
    return False


def prepare_isolated_runtime(src: Path, dst: Path) -> None:
    """
    Populates a quarantined runtime tree (e.g. .dirtyroom/oracle/runtime/) so
    Wine resolves all Win64 DLLs and ../../ChaosGame, ../../Engine without
    writing patched binaries into Steam's Binaries/Win64/ directory.
    """
    src_real = src.resolve()
    src_win64 = src_real.parent
    src_binaries = src_win64.parent
    src_root = src_binaries.parent

    if not (src_root / "ChaosGame").is_dir():
        return

    dst_win64 = dst.parent
    dst_binaries = dst_win64.parent
    dst_root = dst_binaries.parent

    # Only prepare runtime tree when dst follows .../Binaries/Win64/<exe> layout
    if dst_win64.name != "Win64" or dst_binaries.name != "Binaries":
        return

    dst_win64.mkdir(parents=True, exist_ok=True)
    (dst_binaries / "Logs").mkdir(parents=True, exist_ok=True)

    # Symlink top-level ChaosGame and Engine directories
    for top_dir in ("ChaosGame", "Engine"):
        src_item = src_root / top_dir
        dst_item = dst_root / top_dir
        if src_item.exists() and not dst_item.exists() and not dst_item.is_symlink():
            dst_item.symlink_to(src_item)

    # Symlink Binaries/* helpers (except Win64, Logs, EasyAntiCheat)
    for entry in src_binaries.iterdir():
        if entry.name in ("Win64", "Logs", "EasyAntiCheat", "_EasyAntiCheat"):
            continue
        link_path = dst_binaries / entry.name
        if not link_path.exists() and not link_path.is_symlink():
            link_path.symlink_to(entry)

    # Symlink DLLs and support dirs in Binaries/Win64/ (never link/touch client exe or EAC)
    skip_names = {
        "ShippingPC-ChaosGame.exe",
        "ShippingPC-ChaosGame-Server.exe",
        "EasyAntiCheat",
        "_EasyAntiCheat",
        dst.name,
    }
    for entry in src_win64.iterdir():
        if entry.name in skip_names:
            continue
        link_path = dst_win64 / entry.name
        if not link_path.exists() and not link_path.is_symlink():
            link_path.symlink_to(entry)


def patch_binary(src: Path, dst: Path, force: bool = False) -> int:
    """Creates patched dedicated server binary."""
    print("=== Paladins UE3 Headless Server Binary Patcher (ADOPT-09) ===")
    print(f"Source: {src}")
    print(f"Target: {dst}")

    # Resolve source binary (never mutate or overwrite Steam's source binary)
    actual_src = src
    if not actual_src.is_file():
        if FALLBACK_STEAM_SRC.is_file():
            print(f"[*] Source {actual_src} not found; reading clean Steam source: {FALLBACK_STEAM_SRC}")
            actual_src = FALLBACK_STEAM_SRC
        else:
            print(f"[!] Error: Source binary not found at {src} or fallback {FALLBACK_STEAM_SRC}", file=sys.stderr)
            return 1

    if actual_src.resolve() == dst.resolve():
        print("[!] Error: Source and target resolve to the same file; refusing in-place patch.", file=sys.stderr)
        return 1

    src_size = actual_src.stat().st_size
    print(f"[*] Source binary size: {src_size:,} bytes")

    if src_size < CAVE_OFFSET + len(CAVE_PAYLOAD):
        print(
            f"[!] Error: Source binary too small ({src_size} bytes) for cave at 0x{CAVE_OFFSET:X}.",
            file=sys.stderr,
        )
        return 1

    # Check if target already patched
    if dst.is_file() and not force:
        if verify_patch(dst):
            prepare_isolated_runtime(actual_src, dst)
            print(f"[✓] Target binary {dst} already exists and has verified patch signatures.")
            print(f"    SHA-256: {compute_sha256(dst)}")
            return 0
        print("[*] Target exists but patch signature not detected. Overwriting...")

    # Validate hook site, seekfree guard, and cave padding in source
    with open(actual_src, "rb") as f:
        f.seek(HOOK_OFFSET)
        actual_hook = f.read(len(HOOK_ORIGINAL_BYTES))
        f.seek(SEEKFREE_OFFSET)
        actual_seekfree = f.read(len(SEEKFREE_ORIGINAL_BYTES))
        f.seek(CAVE_OFFSET)
        actual_cave = f.read(len(CAVE_PAYLOAD))

    if actual_hook == HOOK_PATCHED_BYTES or actual_seekfree == SEEKFREE_PATCHED_BYTES:
        print(
            f"[!] Error: Source binary {actual_src} is already patched!",
            file=sys.stderr,
        )
        return 1

    if actual_hook != HOOK_ORIGINAL_BYTES:
        print(
            f"[!] Error: Hook site byte mismatch at 0x{HOOK_OFFSET:X} (VA 0x{HOOK_VA:x})!\n"
            f"    Expected: {HOOK_ORIGINAL_BYTES.hex()}\n"
            f"    Actual:   {actual_hook.hex()}",
            file=sys.stderr,
        )
        return 1

    if actual_seekfree != SEEKFREE_ORIGINAL_BYTES:
        print(
            f"[!] Error: SeekFree guard byte mismatch at 0x{SEEKFREE_OFFSET:X} (VA 0x{SEEKFREE_VA:x})!\n"
            f"    Expected: {SEEKFREE_ORIGINAL_BYTES.hex()}\n"
            f"    Actual:   {actual_seekfree.hex()}",
            file=sys.stderr,
        )
        return 1

    if actual_cave != b"\x00" * len(CAVE_PAYLOAD):
        print(
            f"[!] Error: Cave area at 0x{CAVE_OFFSET:X} (VA 0x{CAVE_VA:x}) is not pure null padding!\n"
            f"    Actual: {actual_cave[:16].hex()}...",
            file=sys.stderr,
        )
        return 1

    print(f"[*] Copying source {actual_src.name} -> {dst}...")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(actual_src, dst)
    prepare_isolated_runtime(actual_src, dst)

    print(
        f"[*] Writing {len(CAVE_PAYLOAD)}-byte RIP-relative cave payload at offset "
        f"0x{CAVE_OFFSET:X} (VA 0x{CAVE_VA:x})..."
    )
    with open(dst, "r+b") as f:
        f.seek(CAVE_OFFSET)
        f.write(CAVE_PAYLOAD)

        print(
            f"[*] Writing {len(HOOK_PATCHED_BYTES)}-byte hook call at offset "
            f"0x{HOOK_OFFSET:X} (VA 0x{HOOK_VA:x})..."
        )
        f.seek(HOOK_OFFSET)
        f.write(HOOK_PATCHED_BYTES)

        print(
            f"[*] NOPing {len(SEEKFREE_PATCHED_BYTES)}-byte GUseSeekFreeLoading zero-out at offset "
            f"0x{SEEKFREE_OFFSET:X} (VA 0x{SEEKFREE_VA:x})..."
        )
        f.seek(SEEKFREE_OFFSET)
        f.write(SEEKFREE_PATCHED_BYTES)

    print("[*] Clearing IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR) in PE header...")
    clear_aslr_flag(dst)

    # Make executable
    st = os.stat(dst)
    os.chmod(dst, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Verification
    if verify_patch(dst):
        sha = compute_sha256(dst)
        print("[✓] SUCCESS: Dedicated server binary patched and verified!")
        print(f"    Path:    {dst}")
        print(f"    Size:    {dst.stat().st_size:,} bytes")
        print(f"    SHA-256: {sha}")
        return 0
    print("[!] Error: Verification after patching failed!", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch ShippingPC-ChaosGame.exe to mount assembly.dat in dedicated server mode (ADOPT-09)"
    )
    parser.add_argument("--src", type=Path, default=DEFAULT_SRC, help=f"Source binary (default: {DEFAULT_SRC})")
    parser.add_argument("--dst", type=Path, default=DEFAULT_DST, help=f"Target server binary (default: {DEFAULT_DST})")
    parser.add_argument("--check", action="store_true", help="Only verify existing target binary")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing target even if verified")

    args = parser.parse_args()

    if args.check:
        if verify_patch(args.dst):
            print(f"[✓] Verified: {args.dst} contains valid ADOPT-09 server hook.")
            print(f"    SHA-256: {compute_sha256(args.dst)}")
            return 0
        print(f"[✗] Unverified: {args.dst} is not patched or does not exist.")
        return 1

    return patch_binary(args.src, args.dst, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
