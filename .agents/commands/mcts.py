#!/usr/bin/env python3
# Look up or calculate MCTS marshal tokens and group headers
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)

import argparse
import json
from pathlib import Path
import sys

# Support direct execution
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.common import get_db


def main():
    parser = argparse.ArgumentParser(
        prog="agyis mcts",
        description="Look up or calculate MCTS marshal tokens and group headers",
    )
    parser.add_argument("token", help="Decimal or hex function hash (e.g. 0x847de68b)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    conn = get_db()
    token_str = args.token
    try:
        val = int(token_str, 0)
        hex_val = f"0x{val:08x}"
    except ValueError:
        val = None
        hex_val = "unknown"

    matched = None
    if conn and val is not None:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT hash_uint32, hash_hex, token_name, raw_handler, notes FROM mcts_hashes WHERE hash_uint32 = ?",
                (val,),
            )
            row = cursor.fetchone()
            if row:
                matched = {
                    "token_name": row[2],
                    "handler": row[3],
                    "notes": row[4],
                }
        except Exception:
            pass
        finally:
            conn.close()

    if args.json:
        print(
            json.dumps(
                {
                    "query": token_str,
                    "decimal": val,
                    "hex": hex_val,
                    "matched": matched,
                },
                indent=2,
            )
        )
        return 0

    print(f"[*] Resolving MCTS token/function: {token_str}")
    print(f"  Decimal: {val}")
    print(f"  Hex:     {hex_val}")
    if matched:
        print("  Matched MCTS Hash Record:")
        print(f"    Token:   {matched['token_name']}")
        print(f"    Handler: {matched['handler']}")
        print(f"    Notes:   {matched['notes']}")
    else:
        print("  (Hash not yet mapped in database)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
