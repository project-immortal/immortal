#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

set -euo pipefail

# 1. Resolve Root Paths
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIRTYROOM_ROOT="${IMMORTAL_DIRTYROOM:-"${REPO_ROOT}/.dirtyroom"}"

if [[ ! -d "${DIRTYROOM_ROOT}" ]]; then
    # Fallback to local default if symlink not yet created
    DIRTYROOM_ROOT="/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0"
fi

GHIDRA_DIR="${DIRTYROOM_ROOT}/ghidra"
LOG_FILE="${DIRTYROOM_ROOT}/logs/ghidra_analysis.log"
PROJECT_NAME="PaladinsProject"

# 2. Locate Paladins Win64 Binaries
BIN_DIR="${PALADINS_BIN_DIR:-"/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64"}"
TARGETS=(
    "${BIN_DIR}/ShippingPC-ChaosGame.exe"
    "${BIN_DIR}/MctsInterface.dll"
    "${BIN_DIR}/vivoxsdk_x64.dll"
)

for target in "${TARGETS[@]}"; do
    if [[ ! -f "${target}" ]]; then
        echo "Error: Target binary not found: ${target}" >&2
        echo "Please set PALADINS_BIN_DIR to your Paladins Binaries/Win64 directory." >&2
        exit 1
    fi
done

# 3. Environment & Hardware Tuning
export GHIDRA_HEADLESS_MAXMEM="${GHIDRA_HEADLESS_MAXMEM:-"32G"}"
export JAVA_HOME="${JAVA_HOME:-"/usr/lib/jvm/java-21-openjdk"}"
export PATH="${JAVA_HOME}/bin:${PATH}"

GHIDRA_HOME="${GHIDRA_HOME:-"/opt/ghidra"}"
ANALYZE_HEADLESS="${GHIDRA_HOME}/support/analyzeHeadless"

if [[ ! -x "${ANALYZE_HEADLESS}" ]]; then
    echo "Error: analyzeHeadless not found at ${ANALYZE_HEADLESS}" >&2
    echo "Please set GHIDRA_HOME to your Ghidra installation directory." >&2
    exit 1
fi

CORES="${MAX_CPU:-$(nproc)}"

mkdir -p "${GHIDRA_DIR}"
mkdir -p "$(dirname "${LOG_FILE}")"

echo "=== Starting Headless Ghidra Maximal Pre-Analysis ==="
echo "Project Directory: ${GHIDRA_DIR}"
echo "Project Name:      ${PROJECT_NAME}"
echo "Memory Allocation: ${GHIDRA_HEADLESS_MAXMEM}"
echo "CPU Cores:         ${CORES}"
echo "Targets:           ${TARGETS[*]}"
echo "Log File:          ${LOG_FILE}"
echo "====================================================="

"${ANALYZE_HEADLESS}" \
    "${GHIDRA_DIR}" \
    "${PROJECT_NAME}" \
    -import "${TARGETS[@]}" \
    -max-cpu "${CORES}" \
    -commit \
    -overwrite \
    -log "${LOG_FILE}"

echo "=== Headless Ghidra Pre-Analysis Successfully Completed ==="
