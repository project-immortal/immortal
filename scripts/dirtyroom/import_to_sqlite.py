#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Imports exported Ghidra JSONLines dumps into paladins_symbols.sqlite.
"""

import glob
import hashlib
import json
import os
import sqlite3
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DIRTYROOM_ROOT = os.environ.get("IMMORTAL_DIRTYROOM")
if not DIRTYROOM_ROOT:
    local_sym = os.path.join(REPO_ROOT, ".dirtyroom")
    if os.path.exists(local_sym):
        DIRTYROOM_ROOT = local_sym
    else:
        DIRTYROOM_ROOT = "/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0"

SYMBOLS_DIR = os.path.join(DIRTYROOM_ROOT, "symbols")
DB_PATH = os.path.join(SYMBOLS_DIR, "paladins_symbols.sqlite")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

PALADINS_BIN_DIR = os.environ.get(
    "PALADINS_BIN_DIR",
    "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64"
)

BIN_PATHS = {
    "ShippingPC-ChaosGame.exe": os.path.join(PALADINS_BIN_DIR, "ShippingPC-ChaosGame.exe"),
    "MctsInterface.dll": os.path.join(PALADINS_BIN_DIR, "MctsInterface.dll"),
    "vivoxsdk_x64.dll": os.path.join(PALADINS_BIN_DIR, "vivoxsdk_x64.dll")
}

def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def init_db(conn):
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()

def register_binaries(conn):
    cursor = conn.cursor()
    binary_ids = {}
    for name, path in BIN_PATHS.items():
        if not os.path.exists(path):
            continue
        sha = compute_sha256(path)
        size = os.path.getsize(path)
        image_base = 0x140000000 if name.endswith(".exe") else 0x180000000
        cursor.execute("""
            INSERT INTO binaries (name, sha256, image_base, file_size)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET sha256=excluded.sha256, file_size=excluded.file_size
        """, (name, sha, image_base, size))
        cursor.execute("SELECT id FROM binaries WHERE name = ?", (name,))
        binary_ids[name] = cursor.fetchone()[0]
    conn.commit()
    return binary_ids

def import_functions(conn, binary_ids):
    cursor = conn.cursor()
    func_files = glob.glob(os.path.join(SYMBOLS_DIR, "functions_*.jsonl"))
    for fpath in func_files:
        print(f"Importing functions from {fpath}...")
        batch = []
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                prog = record["program"]
                bin_id = binary_ids.get(prog)
                if not bin_id:
                    for bname, bid in binary_ids.items():
                        if prog in bname or bname in prog:
                            bin_id = bid
                            break
                if not bin_id:
                    continue
                batch.append((
                    bin_id,
                    record["address"],
                    record["address"],
                    record["name"],
                    record["name"],
                    record["signature"],
                    record["size"],
                    1 if record.get("is_thunk") else 0,
                    0
                ))
                if len(batch) >= 10000:
                    cursor.executemany("""
                        INSERT OR REPLACE INTO functions
                        (binary_id, address, entry_point, name, demangled_name, signature, size, is_thunk, is_exported)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                    batch = []
        if batch:
            cursor.executemany("""
                INSERT OR REPLACE INTO functions
                (binary_id, address, entry_point, name, demangled_name, signature, size, is_thunk, is_exported)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, batch)
        conn.commit()
    print("Function import complete.")

def main():
    os.makedirs(SYMBOLS_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    print(f"Initializing database: {DB_PATH}")
    init_db(conn)
    binary_ids = register_binaries(conn)
    print(f"Registered binaries: {binary_ids}")
    import_functions(conn, binary_ids)
    conn.close()

if __name__ == "__main__":
    main()
