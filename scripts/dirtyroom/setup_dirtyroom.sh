#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="${REPO_ROOT}/scripts/dirtyroom"

echo "=========================================================="
echo "    Project Immortal - Dirty-Room Scaffolding Pipeline   "
echo "=========================================================="

# 1. Dependency Checks
echo "[1/5] Checking prerequisites..."
command -v java >/dev/null 2>&1 || { echo "Error: 'java' not found. OpenJDK 21 is required." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: 'python3' not found." >&2; exit 1; }
command -v sqlite3 >/dev/null 2>&1 || { echo "Error: 'sqlite3' not found." >&2; exit 1; }

GHIDRA_HOME="${GHIDRA_HOME:-"/opt/ghidra"}"
ANALYZE_HEADLESS="${GHIDRA_HOME}/support/analyzeHeadless"
if [[ ! -x "${ANALYZE_HEADLESS}" ]]; then
    echo "Error: analyzeHeadless not found at ${ANALYZE_HEADLESS}" >&2
    echo "Please set GHIDRA_HOME to your Ghidra installation path." >&2
    exit 1
fi
echo "  [✓] OpenJDK: $(${JAVA_HOME:-$(dirname $(dirname $(which java)))}/bin/java -version 2>&1 | head -n 1)"
echo "  [✓] Ghidra:  ${GHIDRA_HOME}"
echo "  [✓] Python:  $(python3 --version)"
echo "  [✓] SQLite:  $(sqlite3 --version | cut -d' ' -f1)"

# 2. Directory & Storage Configuration
DIRTYROOM_ROOT="${IMMORTAL_DIRTYROOM:-"${REPO_ROOT}/.dirtyroom"}"
echo "[2/5] Configuring dirty-room storage at: ${DIRTYROOM_ROOT}"
mkdir -p "${DIRTYROOM_ROOT}/ghidra"
mkdir -p "${DIRTYROOM_ROOT}/symbols"
mkdir -p "${DIRTYROOM_ROOT}/logs"
mkdir -p "${DIRTYROOM_ROOT}/pcaps"

# If DIRTYROOM_ROOT is an external NVMe path and .dirtyroom symlink doesn't exist, create it
if [[ "${DIRTYROOM_ROOT}" != "${REPO_ROOT}/.dirtyroom" && ! -e "${REPO_ROOT}/.dirtyroom" ]]; then
    echo "  Creating symlink ${REPO_ROOT}/.dirtyroom -> ${DIRTYROOM_ROOT}"
    ln -s "${DIRTYROOM_ROOT}" "${REPO_ROOT}/.dirtyroom"
fi

# 3. Headless Ghidra Pre-Analysis
echo "[3/5] Checking Ghidra Pre-Analysis project..."
PROJECT_FILE="${DIRTYROOM_ROOT}/ghidra/PaladinsProject.gpr"
if [[ -f "${PROJECT_FILE}" ]]; then
    echo "  [✓] Existing Ghidra project found: ${PROJECT_FILE}"
else
    echo "  [i] Launching Ghidra pre-analysis (this may take several minutes)..."
    "${SCRIPT_DIR}/launch_ghidra_preanalysis.sh"
fi

# 4. Symbol & Function Ingestion
DB_FILE="${DIRTYROOM_ROOT}/symbols/paladins_symbols.sqlite"
echo "[4/5] Checking SQLite symbol & string database..."
if [[ -f "${DB_FILE}" ]]; then
    echo "  [✓] Database exists at: ${DB_FILE}"
else
    echo "  [i] Ingesting functions from Ghidra into SQLite..."
    python3 "${SCRIPT_DIR}/import_to_sqlite.py"
fi

# 5. String & RTTI Fast Indexing
echo "[5/5] Checking string and RTTI indexes..."
STR_COUNT=$(sqlite3 "${DB_FILE}" "SELECT count(*) FROM strings;" 2>/dev/null || echo "0")
if [[ "${STR_COUNT}" -gt 0 ]]; then
    echo "  [✓] Strings and RTTI already indexed (${STR_COUNT} strings)."
else
    echo "  [i] Running fast string & RTTI indexing..."
    python3 "${SCRIPT_DIR}/index_strings_rtti.py"
fi

echo ""
echo "=========================================================="
echo "    Dirty-Room Environment Ready! Verification Status:    "
echo "=========================================================="
"${SCRIPT_DIR}/dirty" status
echo ""
echo "You can now use './scripts/dirtyroom/dirty' for zero-latency queries:"
echo "  ./scripts/dirtyroom/dirty find <symbol>"
echo "  ./scripts/dirtyroom/dirty string <term>"
echo "  ./scripts/dirtyroom/dirty rtti <class>"
echo "  ./scripts/dirtyroom/dirty decompile <address> [--binary <name>]"
