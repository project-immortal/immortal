#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)
#
# scripts/dirtyroom/launch_retail_server.sh
# ADOPT-09: Headless Wine Retail Dedicated Server Oracle
# Launches and manages authentic retail Paladins dedicated server under Wine.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ORACLE_DIR="$REPO_ROOT/.dirtyroom/oracle"
PID_FILE="$ORACLE_DIR/retail_server.pid"
LOG_FILE="$ORACLE_DIR/retail_server.log"
WINE_PREFIX="$ORACLE_DIR/prefix"

# Defaults
DEFAULT_MAP="sg_jaguarfalls_rework_p"
DEFAULT_PORT="7000"
DEFAULT_MULTIHOME="127.0.0.1"
MAP="$DEFAULT_MAP"
PORT="$DEFAULT_PORT"
MULTIHOME="$DEFAULT_MULTIHOME"
MODE="foreground" # foreground | daemon | stop | status | logs
TAIL_LINES=50

# Candidate binaries in priority order
CANDIDATE_BINS=(
    "/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins/Binaries/Win64/ShippingPC-ChaosGame.exe"
    "$REPO_ROOT/.dirtyroom/binaries/ShippingPC-ChaosGame.exe"
)

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

ADOPT-09 Headless Wine Retail Dedicated Server Oracle Launcher

Options:
    --map <MAP>       Map package name (default: $DEFAULT_MAP)
    --port <PORT>     UDP game server port (default: $DEFAULT_PORT)
    --daemon          Run server in background as a daemon
    --stop            Stop the running retail server and wineserver
    --status          Check running server status and port listener
    --logs            Display recent server logs (follow with -f)
    -h, --help        Show this help message

Examples:
    $(basename "$0") --daemon --port 7000
    $(basename "$0") --status
    $(basename "$0") --logs
    $(basename "$0") --stop
EOF
    exit 0
}

# Parse CLI arguments
FOLLOW_LOGS=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --map)
            MAP="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --multihome)
            MULTIHOME="$2"
            shift 2
            ;;
        --daemon)
            MODE="daemon"
            shift
            ;;
        --stop)
            MODE="stop"
            shift
            ;;
        --status)
            MODE="status"
            shift
            ;;
        --logs)
            MODE="logs"
            shift
            ;;
        -f)
            FOLLOW_LOGS=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

ensure_oracle_dir() {
    mkdir -p "$ORACLE_DIR"
    mkdir -p "$WINE_PREFIX"
}

resolve_binary_and_dir() {
    # Check candidates that have ../../ChaosGame intact
    for bin in "${CANDIDATE_BINS[@]}"; do
        if [[ -f "$bin" ]]; then
            local bdir
            bdir="$(dirname "$bin")"
            if [[ -d "$bdir/../../ChaosGame" ]]; then
                echo "$bin|$bdir"
                return 0
            fi
        fi
    done

    # Fallback to any existing candidate binary
    for bin in "${CANDIDATE_BINS[@]}"; do
        if [[ -f "$bin" ]]; then
            local bdir
            bdir="$(dirname "$bin")"
            echo "$bin|$bdir"
            return 0
        fi
    done
    echo ""
}

is_running() {
    local pid="$1"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

get_active_pid() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if is_running "$pid"; then
            echo "$pid"
            return 0
        fi
    fi
    echo ""
}

do_status() {
    local pid
    pid=$(get_active_pid)
    echo "=== Headless Wine Retail Dedicated Server Oracle Status ==="
    echo "Oracle Directory: $ORACLE_DIR"
    echo "Wine Prefix:      $WINE_PREFIX"
    echo "PID File:         $PID_FILE"
    echo "Log File:         $LOG_FILE"
    echo "Configured Port:  $PORT"
    echo "Configured Map:   $MAP"

    if [[ -n "$pid" ]]; then
        echo "State:            RUNNING (PID: $pid)"
        local mem
        mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}' || echo "N/A")
        echo "Memory RSS:       $mem"

        # Check UDP listener on configured port
        if ss -ulnp 2>/dev/null | grep -q ":$PORT "; then
            echo "UDP Port $PORT:     LISTENING (bound to network)"
        else
            echo "UDP Port $PORT:     INITIALIZING (UE3 engine load phase)"
        fi
        return 0
    else
        if [[ -f "$PID_FILE" ]]; then
            echo "State:            STOPPED (stale PID file $(cat "$PID_FILE") cleaned)"
            rm -f "$PID_FILE"
        else
            echo "State:            STOPPED"
        fi
        return 1
    fi
}

do_stop() {
    local pid
    pid=$(get_active_pid)
    echo "=== Stopping Headless Wine Retail Server Oracle ==="
    if [[ -z "$pid" ]]; then
        if [[ -f "$PID_FILE" ]]; then
            rm -f "$PID_FILE"
        fi
        echo "Server is not running."
        # Clean up any lingering processes in this prefix
        if command -v wineserver >/dev/null 2>&1; then
            WINEPREFIX="$WINE_PREFIX" wineserver -k 2>/dev/null || true
        fi
        return 0
    fi

    echo "Sending SIGTERM to PID $pid..."
    kill -15 "$pid" 2>/dev/null || true

    # Wait up to 5 seconds for graceful shutdown
    local waited=0
    while is_running "$pid" && [[ $waited -lt 5 ]]; do
        sleep 1
        waited=$((waited + 1))
    done

    if is_running "$pid"; then
        echo "PID $pid did not exit gracefully; sending SIGKILL..."
        kill -9 "$pid" 2>/dev/null || true
        sleep 1
    fi

    # Terminate Wine server for this prefix
    if command -v wineserver >/dev/null 2>&1; then
        WINEPREFIX="$WINE_PREFIX" wineserver -k 2>/dev/null || true
    fi

    rm -f "$PID_FILE"
    echo "Server (PID $pid) stopped successfully."
}

do_logs() {
    local ue3_log="$HOME/Documents/My Games/Tempest/ChaosGame/Logs/Launch.log"
    echo "=== Console Output Log ($LOG_FILE) ==="
    if [[ -f "$LOG_FILE" ]]; then
        tail -n "$TAIL_LINES" "$LOG_FILE"
    else
        echo "(none)"
    fi

    if [[ -f "$ue3_log" ]]; then
        echo ""
        echo "=== UE3 Engine Launch Log ($ue3_log) ==="
        tail -n "$TAIL_LINES" "$ue3_log"
    fi

    if [[ "$FOLLOW_LOGS" == "true" ]]; then
        if [[ -f "$ue3_log" ]]; then
            exec tail -n "$TAIL_LINES" -f "$LOG_FILE" "$ue3_log"
        else
            exec tail -n "$TAIL_LINES" -f "$LOG_FILE"
        fi
    fi
}

do_start() {
    ensure_oracle_dir

    local existing_pid
    existing_pid=$(get_active_pid)
    if [[ -n "$existing_pid" ]]; then
        echo "Server is already running with PID $existing_pid."
        return 0
    fi

    local bin_info
    bin_info=$(resolve_binary_and_dir)
    if [[ -z "$bin_info" ]]; then
        echo "Error: Could not locate ShippingPC-ChaosGame.exe at candidate paths:" >&2
        for bin in "${CANDIDATE_BINS[@]}"; do
            echo "  - $bin" >&2
        done
        exit 1
    fi

    local target_bin="${bin_info%%|*}"
    local bin_dir="${bin_info##*|}"

    # Ensure Wine binary exists
    local wine_bin="/usr/bin/wine"
    if [[ ! -x "$wine_bin" ]]; then
        wine_bin=$(command -v wine || true)
        if [[ -z "$wine_bin" ]]; then
            echo "Error: Wine binary not found on PATH or at /usr/bin/wine." >&2
            exit 1
        fi
    fi

    # Check for EAC directory bypass
    if [[ -d "$bin_dir/EasyAntiCheat" ]] && [[ ! -d "$bin_dir/_EasyAntiCheat" ]]; then
        echo "Renaming $bin_dir/EasyAntiCheat to _EasyAntiCheat for Wine bypass..."
        mv "$bin_dir/EasyAntiCheat" "$bin_dir/_EasyAntiCheat" 2>/dev/null || true
    fi

    # Headless Wine environment configuration
    export WINEPREFIX="$WINE_PREFIX"
    export WINEDLLOVERRIDES="mscoree,mshtml="
    export WINEDEBUG="-all"
    export OPENSSL_ia32cap="~0x20000000"
    unset DISPLAY
    unset WAYLAND_DISPLAY

    # Assemble server arguments per ADOPT-09 specification
    local map_query="${MAP}?game=TgGame.TgGame_Paladins?maxplayers=2"
    local server_args=(
        "server"
        "$map_query"
        "-port=$PORT"
        "-multihome=$MULTIHOME"
        "-seekfreeloadingpcconsole"
        "-pid=402"
        "-eac-nop-loaded"
        "-homedir=Tempest"
        "-log"
    )

    echo "=== Launching Headless Wine Retail Dedicated Server Oracle ==="
    echo "Binary:        $target_bin"
    echo "Working Dir:   $bin_dir"
    echo "Wine:          $wine_bin"
    echo "WINEPREFIX:    $WINEPREFIX"
    echo "Port:          $PORT"
    echo "Map:           $MAP"
    echo "Command:       $wine_bin $target_bin ${server_args[*]}"
    echo "Log:           $LOG_FILE"

    cd "$bin_dir"

    if [[ "$MODE" == "daemon" ]]; then
        # Launch background process with nohup
        nohup "$wine_bin" "$target_bin" "${server_args[@]}" > "$LOG_FILE" 2>&1 &
        local pid=$!
        echo "$pid" > "$PID_FILE"
        echo "Server started as daemon with PID $pid."

        # Short verification loop to confirm process spawned cleanly
        sleep 2
        if is_running "$pid"; then
            echo "Process $pid confirmed active."
        else
            echo "Warning: Process $pid terminated shortly after spawn. Check $LOG_FILE for details."
        fi
    else
        # Foreground mode
        trap 'do_stop' INT TERM EXIT
        "$wine_bin" "$target_bin" "${server_args[@]}" 2>&1 | tee -a "$LOG_FILE"
    fi
}

case "$MODE" in
    daemon|foreground)
        do_start
        ;;
    stop)
        do_stop
        ;;
    status)
        do_status
        ;;
    logs)
        do_logs
        ;;
esac
