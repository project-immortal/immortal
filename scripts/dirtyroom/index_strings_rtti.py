#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Dirty-Room High-Performance String & RTTI Indexer
Extracts ASCII/UTF-16 strings and RTTI type descriptors from target PE binaries,
computes their virtual addresses, and indexes them into paladins_symbols.sqlite.
"""

import os
import re
import sqlite3
import struct
import sys
import time

def parse_pe_sections(file_path):
    with open(file_path, "rb") as f:
        if f.read(2) != b"MZ":
            return None, []
        f.seek(0x3C)
        e_lfanew = struct.unpack("<I", f.read(4))[0]
        
        f.seek(e_lfanew)
        if f.read(4) != b"PE\x00\x00":
            return None, []
            
        machine, num_sections = struct.unpack("<HH", f.read(4))
        f.seek(12, 1)
        size_opt_header, characteristics = struct.unpack("<HH", f.read(4))
        
        opt_magic = struct.unpack("<H", f.read(2))[0]
        is_64 = (opt_magic == 0x20B)
        
        if is_64:
            f.seek(22, 1)
            image_base = struct.unpack("<Q", f.read(8))[0]
            f.seek(size_opt_header - 32, 1)
        else:
            f.seek(26, 1)
            image_base = struct.unpack("<I", f.read(4))[0]
            f.seek(size_opt_header - 32, 1)
            
        sections = []
        for _ in range(num_sections):
            name_bytes = f.read(8).rstrip(b"\x00")
            name = name_bytes.decode("ascii", errors="replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack("<IIII", f.read(16))
            f.seek(16, 1)
            sections.append({
                "name": name,
                "vaddr": vaddr,
                "vsize": vsize,
                "raw_ptr": raw_ptr,
                "raw_size": raw_size
            })
            
        return image_base, sections

def file_offset_to_va(offset, image_base, sections):
    for s in sections:
        if s["raw_ptr"] <= offset < s["raw_ptr"] + s["raw_size"]:
            rva = offset - s["raw_ptr"] + s["vaddr"]
            return image_base + rva
    return None

def extract_strings_and_rtti(binary_path, binary_id, image_base, sections, min_len=4):
    print(f"[*] Scanning binary: {os.path.basename(binary_path)} ({os.path.getsize(binary_path):,} bytes)...")
    t0 = time.time()
    
    with open(binary_path, "rb") as f:
        data = f.read()
        
    strings_batch = []
    rtti_batch = []
    
    # ASCII regex (printable chars between 0x20 and 0x7E)
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    # UTF-16LE regex
    utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    # RTTI type descriptor regex: .?AV...@@ or .?AU...@@
    rtti_pattern = re.compile(rb"\.\?A[VU][A-Za-z0-9_@]+@@")
    
    # 1. ASCII strings
    for m in ascii_pattern.finditer(data):
        offset = m.start()
        val_bytes = m.group()
        va = file_offset_to_va(offset, image_base, sections)
        if va is not None:
            val_str = val_bytes.decode("ascii", errors="replace")
            strings_batch.append((binary_id, va, "ascii", val_str, len(val_str)))
            
    # 2. UTF-16LE strings
    for m in utf16_pattern.finditer(data):
        offset = m.start()
        val_bytes = m.group()
        va = file_offset_to_va(offset, image_base, sections)
        if va is not None:
            try:
                val_str = val_bytes.decode("utf-16le")
                strings_batch.append((binary_id, va, "utf16", val_str, len(val_str)))
            except Exception:
                pass
                
    # 3. RTTI Classes
    for m in rtti_pattern.finditer(data):
        offset = m.start()
        val_bytes = m.group()
        va = file_offset_to_va(offset, image_base, sections)
        if va is not None:
            mangled = val_bytes.decode("ascii", errors="replace")
            # Basic demangler for MSVC: .?AV<class>@@ or .?AV<class>@<namespace>@@
            demangled = mangled.replace(".?AV", "").replace(".?AU", "").replace("@@", "").replace("@", "::")
            rtti_batch.append((binary_id, mangled, demangled, va, 0, 0, 0, "[]"))

    t_scan = time.time() - t0
    print(f"    Found {len(strings_batch):,} strings and {len(rtti_batch):,} RTTI types in {t_scan:.2f}s")
    return strings_batch, rtti_batch

def main():
    REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    dirtyroom_root = os.environ.get("IMMORTAL_DIRTYROOM")
    if not dirtyroom_root:
        local_sym = os.path.join(REPO_ROOT, ".dirtyroom")
        if os.path.exists(local_sym):
            dirtyroom_root = local_sym
        else:
            dirtyroom_root = "/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0"
            
    db_path = os.path.join(dirtyroom_root, "symbols", "paladins_symbols.sqlite")
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}", file=sys.stderr)
        sys.exit(1)
        
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Optimization pragmas for bulk ingest
    cur.execute("PRAGMA synchronous = OFF;")
    cur.execute("PRAGMA journal_mode = MEMORY;")
    cur.execute("PRAGMA temp_store = MEMORY;")
    cur.execute("PRAGMA cache_size = -500000;") # ~500MB cache
    
    binaries = cur.execute("SELECT id, name FROM binaries;").fetchall()
    
    paladins_bin_dir = os.environ.get(
        "PALADINS_BIN_DIR",
        "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64"
    )
    
    for bin_id, bin_name in binaries:
        bin_path = os.path.join(paladins_bin_dir, bin_name)
        if not os.path.exists(bin_path):
            print(f"[!] Binary {bin_path} not found, skipping...")
            continue
            
        base, sections = parse_pe_sections(bin_path)
        if not sections:
            print(f"[!] Failed to parse PE sections for {bin_name}")
            continue
            
        strings_data, rtti_data = extract_strings_and_rtti(bin_path, bin_id, base, sections)
        
        print(f"[*] Ingesting strings for {bin_name} into database...")
        t_insert = time.time()
        
        # Clear existing for this binary
        cur.execute("DELETE FROM strings WHERE binary_id = ?;", (bin_id,))
        cur.execute("DELETE FROM rtti_classes WHERE binary_id = ?;", (bin_id,))
        
        cur.executemany(
            "INSERT OR IGNORE INTO strings (binary_id, address, string_type, value, length) VALUES (?, ?, ?, ?, ?);",
            strings_data
        )
        cur.executemany(
            "INSERT OR IGNORE INTO rtti_classes (binary_id, class_name, demangled_name, type_descriptor_addr, complete_object_locator_addr, class_hierarchy_addr, vtable_addr, base_classes_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            rtti_data
        )
        conn.commit()
        print(f"    Committed in {time.time() - t_insert:.2f}s")
        
    print("[+] String and RTTI indexing complete!")
    
    # Print summary
    counts = cur.execute("SELECT count(*) FROM strings;").fetchone()[0]
    rtti_count = cur.execute("SELECT count(*) FROM rtti_classes;").fetchone()[0]
    print(f"[+] Total strings indexed: {counts:,}")
    print(f"[+] Total RTTI classes indexed: {rtti_count:,}")
    conn.close()

if __name__ == "__main__":
    main()
