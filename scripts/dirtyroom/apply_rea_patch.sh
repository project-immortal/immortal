#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Cleanroom reverse engineering Dirtyroom REA patcher.
#
# Idempotently applies the dirtyroom project acceleration patch to rea-agents
# so REA MCP tools can directly use pre-analyzed Ghidra projects with zero timeouts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="${SCRIPT_DIR}/patches/rea_dirtyroom_project_acceleration.diff"

if [[ ! -f "${PATCH_FILE}" ]]; then
    echo "[-] Patch file not found at ${PATCH_FILE}" >&2
    exit 1
fi

# Locate rea-agents installation
TARGET_DIR=""
POSSIBLE_DIRS=(
    "/home/kuasha/.local/share/pnpm/global/5/.pnpm/rea-agents@6.8.0/node_modules/rea-agents"
    "$(pnpm root -g 2>/dev/null)/rea-agents"
)

for dir in "${POSSIBLE_DIRS[@]}"; do
    if [[ -d "${dir}/dist/mcp" ]]; then
        TARGET_DIR="${dir}"
        break
    fi
done

if [[ -z "${TARGET_DIR}" ]]; then
    # Try finding via glob
    FOUND=$(find /home/kuasha/.local/share/pnpm/global -type d -path "*/node_modules/rea-agents" 2>/dev/null | head -n 1 || true)
    if [[ -n "${FOUND}" && -d "${FOUND}/dist/mcp" ]]; then
        TARGET_DIR="${FOUND}"
    fi
fi

if [[ -z "${TARGET_DIR}" ]]; then
    echo "[-] Could not find installed rea-agents package" >&2
    exit 1
fi

echo "[+] Located rea-agents at: ${TARGET_DIR}"

# Check if already patched
if grep -q "REA_GHIDRA_PROJECT_DIR" "${TARGET_DIR}/dist/mcp/binary-DR8ElrdQ.js" 2>/dev/null; then
    echo "[+] rea-agents is already patched for dirtyroom project acceleration."
    exit 0
fi

# Create backup if not already present
if [[ -f "${TARGET_DIR}/dist/mcp/binary-DR8ElrdQ.js" && ! -f "${TARGET_DIR}/dist/mcp/binary-DR8ElrdQ.js.orig" ]]; then
    cp "${TARGET_DIR}/dist/mcp/binary-DR8ElrdQ.js" "${TARGET_DIR}/dist/mcp/binary-DR8ElrdQ.js.orig"
fi
if [[ -f "${TARGET_DIR}/dist/ghidra/GhidraLauncher.js" && ! -f "${TARGET_DIR}/dist/ghidra/GhidraLauncher.js.orig" ]]; then
    cp "${TARGET_DIR}/dist/ghidra/GhidraLauncher.js" "${TARGET_DIR}/dist/ghidra/GhidraLauncher.js.orig"
fi

echo "[+] Applying patch..."
cd "${TARGET_DIR}"
patch -p0 --forward < "${PATCH_FILE}" || {
    echo "[-] Failed to apply patch cleanly. Please inspect files manually." >&2
    exit 1
}

echo "[+] Successfully patched rea-agents for dirtyroom project acceleration!"
