# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Hermetic unit test suite for agyis flight harness and common build/input helpers.
Tests execute purely in temporary directories with mocked subprocess/process calls
and zero game, Wine, display, or network side effects.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock, patch

COMMANDS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COMMANDS_DIR))

import flight
from lib import common


def _make_fake_repo(tmp_path: Path, mtime_base: float = 1_700_000_000.0) -> dict[str, Path]:
    """Creates a minimal fake Cargo workspace with deterministic mtimes."""
    cargo_toml = tmp_path / "Cargo.toml"
    cargo_lock = tmp_path / "Cargo.lock"
    crate_toml = tmp_path / "crates" / "immortal-server" / "Cargo.toml"
    crate_rs = tmp_path / "crates" / "immortal-server" / "src" / "nested" / "game_server.rs"
    server_bin = tmp_path / "target" / "release" / "immortal-server"

    crate_rs.parent.mkdir(parents=True, exist_ok=True)
    server_bin.parent.mkdir(parents=True, exist_ok=True)

    for p, content in (
        (cargo_toml, "[workspace]\n"),
        (cargo_lock, "# lock\n"),
        (crate_toml, "[package]\nname = 'immortal-server'\n"),
        (crate_rs, "fn main() {}\n"),
    ):
        p.write_text(content, encoding="utf-8")
        os.utime(p, (mtime_base, mtime_base))

    return {
        "cargo_toml": cargo_toml,
        "cargo_lock": cargo_lock,
        "crate_toml": crate_toml,
        "crate_rs": crate_rs,
        "server_bin": server_bin,
    }


def test_ensure_immortal_server_built_missing_triggers_build(tmp_path: Path) -> None:
    paths = _make_fake_repo(tmp_path)
    assert not paths["server_bin"].exists()

    ok_res = subprocess.CompletedProcess(args=["cargo"], returncode=0)
    with patch.object(common, "REPO_ROOT", tmp_path), patch.object(
        common.subprocess, "run", return_value=ok_res
    ) as mock_run:
        result = common.ensure_immortal_server_built()

    assert result == str(paths["server_bin"])
    mock_run.assert_called_once_with(
        ["cargo", "build", "--release", "-p", "immortal-server"],
        cwd=tmp_path,
    )


def test_ensure_immortal_server_built_fresh_skips_build(tmp_path: Path) -> None:
    base = 1_700_000_000.0
    paths = _make_fake_repo(tmp_path, mtime_base=base)
    paths["server_bin"].write_text("ELF", encoding="utf-8")
    os.utime(paths["server_bin"], (base + 10.0, base + 10.0))

    with patch.object(common, "REPO_ROOT", tmp_path), patch.object(common.subprocess, "run") as mock_run:
        result = common.ensure_immortal_server_built()

    assert result == str(paths["server_bin"])
    mock_run.assert_not_called()


def test_ensure_immortal_server_built_stale_sources_trigger_rebuild(tmp_path: Path) -> None:
    base = 1_700_000_000.0
    for stale_key in ("cargo_toml", "cargo_lock", "crate_toml", "crate_rs"):
        sub_root = tmp_path / stale_key
        paths = _make_fake_repo(sub_root, mtime_base=base)
        paths["server_bin"].write_text("ELF", encoding="utf-8")
        os.utime(paths["server_bin"], (base + 10.0, base + 10.0))
        os.utime(paths[stale_key], (base + 20.0, base + 20.0))

        ok_res = subprocess.CompletedProcess(args=["cargo"], returncode=0)
        with patch.object(common, "REPO_ROOT", sub_root), patch.object(
            common.subprocess, "run", return_value=ok_res
        ) as mock_run:
            result = common.ensure_immortal_server_built()

        assert result == str(paths["server_bin"])
        mock_run.assert_called_once()


def test_ensure_immortal_server_built_force_rebuild_and_failure(tmp_path: Path) -> None:
    base = 1_700_000_000.0
    paths = _make_fake_repo(tmp_path, mtime_base=base)
    paths["server_bin"].write_text("ELF", encoding="utf-8")
    os.utime(paths["server_bin"], (base + 10.0, base + 10.0))

    ok_res = subprocess.CompletedProcess(args=["cargo"], returncode=0)
    with patch.object(common, "REPO_ROOT", tmp_path), patch.object(
        common.subprocess, "run", return_value=ok_res
    ) as mock_run:
        result = common.ensure_immortal_server_built(force_rebuild=True)

    assert result == str(paths["server_bin"])
    mock_run.assert_called_once()

    fail_res = subprocess.CompletedProcess(args=["cargo"], returncode=101)
    with patch.object(common, "REPO_ROOT", tmp_path), patch.object(
        common.subprocess, "run", return_value=fail_res
    ):
        assert common.ensure_immortal_server_built(force_rebuild=True) is None


def test_is_ydotoold_running_via_socket_and_ps(tmp_path: Path) -> None:
    sock_file = tmp_path / ".ydotool_socket"
    sock_file.write_text("", encoding="utf-8")
    with patch.dict(os.environ, {"YDOTOOL_SOCKET": str(sock_file)}, clear=False), patch.object(
        common.subprocess, "run"
    ) as mock_run:
        assert common.is_ydotoold_running() is True
        mock_run.assert_not_called()

    missing_sock = tmp_path / "missing.sock"
    ps_active = subprocess.CompletedProcess(
        args=["ps"],
        returncode=0,
        stdout="/usr/bin/python3 pytest\n/usr/bin/ydotoold --socket-path=/tmp/ys\n",
        stderr="",
    )
    with patch.dict(os.environ, {"YDOTOOL_SOCKET": str(missing_sock)}, clear=False), patch.object(
        common.subprocess, "run", return_value=ps_active
    ):
        assert common.is_ydotoold_running() is True

    ps_inactive = subprocess.CompletedProcess(
        args=["ps"],
        returncode=0,
        stdout="/usr/bin/bash\n/usr/bin/grep ydotoold\n",
        stderr="",
    )
    with patch.dict(os.environ, {"YDOTOOL_SOCKET": str(missing_sock)}, clear=False), patch.object(
        common.subprocess, "run", return_value=ps_inactive
    ):
        assert common.is_ydotoold_running() is False


def test_flight_target_map_patterns_and_post_hold() -> None:
    expected_targets = {
        "menu": "LOBBY_MENU",
        "invite": "MATCH_INVITE",
        "gazebo": "GAZEBO",
        "map": "MAP_CHANGE",
        "range": "BROWSE_RANGE",
        "welcome": "WELCOMED",
        "world": "WORLD_READY",
        "actors": "ACTORS_REPLICATED",
        "spawn": "ACTORS_REPLICATED",
    }
    assert flight.FLIGHT_TARGET_MAP == expected_targets
    for milestone_key in set(expected_targets.values()) | {"MAP_LOADED"}:
        assert milestone_key in flight.FLIGHT_PATTERNS
        assert milestone_key in flight.MILESTONE_ORDER

    assert flight.FLIGHT_PATTERNS["WELCOMED"] == ["DevNet: Welcomed by server"]
    assert flight.FLIGHT_PATTERNS["WORLD_READY"] == [
        "Bringing World shootingrange_p.TheWorld up for play",
        "Bringing World Shootingrange_P.TheWorld up for play",
    ]
    assert flight.FLIGHT_PATTERNS["MAP_LOADED"] == ["NMT_MapLoaded 0x2A"]
    assert flight.FLIGHT_PATTERNS["ACTORS_REPLICATED"] == ["emitting UActorChannel opens (ch=3, 4, 80, 81)"]

    assert flight.compute_post_hold("WORLD_READY", None) == 5.0
    assert flight.compute_post_hold("ACTORS_REPLICATED", None) == 5.0
    assert flight.compute_post_hold("BROWSE_RANGE", None) == 0.5
    assert flight.compute_post_hold("WORLD_READY", 0.0) == 0.0
    assert flight.compute_post_hold("MAP_CHANGE", 2.25) == 2.25


def test_dual_log_tailing_milestones_and_bounded_diagnostics(tmp_path: Path) -> None:
    launch_log = tmp_path / "Launch.log"
    server_log = tmp_path / "flight_server.log"

    # Cross-source lines must NOT trigger milestones on the wrong log source
    launch_log.write_text(
        "\n".join(
            [
                "NMT_MapLoaded 0x2A",
                "DevNet: Welcomed by server",
                "Bringing World Shootingrange_P.TheWorld up for play",
                "Log: Bunch overflow on channel 3",
                "Critical: Validation failed for pawn",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    server_log.write_text(
        "\n".join(
            [
                "DevNet: Welcomed by server",
                "DEBUG Ingested Actor Channel 3 bunch (len: 12)",
                "INFO Client 127.0.0.1 loaded map (NMT_MapLoaded 0x2A)",
                "INFO Client 127.0.0.1 satisfied NMT_Have + NMT_MapLoaded + NMT_Join — emitting UActorChannel opens (ch=3, 4, 80, 81)",
                "WARN Error processing datagram from 127.0.0.1: Bunch protocol error",
                "WARN Received NMT_Failure from peer",
                "WARN Buffer Overflow in net driver",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    milestones = flight.create_milestones()
    diagnostics: list[str] = []
    client_tailer = flight.LogTailer(launch_log, "client")
    server_tailer = flight.LogTailer(server_log, "server")
    try:
        flight.process_log_lines(client_tailer.read_new_lines(), "client", milestones, diagnostics, 100.0, now_fn=lambda: 101.5)
        flight.process_log_lines(server_tailer.read_new_lines(), "server", milestones, diagnostics, 100.0, now_fn=lambda: 102.0)

        assert milestones["WELCOMED"]["detected"] is True
        assert milestones["WELCOMED"]["elapsed"] == 1.5
        assert milestones["WORLD_READY"]["detected"] is True
        assert milestones["MAP_LOADED"]["detected"] is True
        assert milestones["ACTORS_REPLICATED"]["detected"] is True
        assert milestones["LOBBY_MENU"]["detected"] is False

        # Verify lowercase "bunch" debug line was NOT captured as an error diagnostic
        assert len(diagnostics) == 5
        assert all("Ingested Actor Channel" not in d for d in diagnostics)

        # Append 60 error lines to test MAX_DIAGNOSTICS (50) bound and incremental tailing
        with open(server_log, "a", encoding="utf-8") as f:
            for idx in range(60):
                f.write(f"WARN Error processing datagram #{idx}\n")

        flight.process_log_lines(server_tailer.read_new_lines(), "server", milestones, diagnostics, 100.0, now_fn=lambda: 103.0)
        assert len(diagnostics) == flight.MAX_DIAGNOSTICS == 50

        md = flight.build_summary_markdown(
            ts_tag="20261124_000000",
            target_key="ACTORS_REPLICATED",
            passed=True,
            total_flight_duration=3.0,
            timeout_sec=90,
            rec_file=None,
            rec_size_bytes=0,
            milestones=milestones,
            diagnostics=diagnostics,
        )
        assert "## Diagnostics (50/50 max)" in md
        assert "**ACTORS_REPLICATED**" in md
        assert "**MAP_LOADED**" in md
    finally:
        client_tailer.close()
        server_tailer.close()


def test_main_warns_missing_ydotoold_and_passes_force_rebuild_json(tmp_path: Path, capsys) -> None:
    launch_log = tmp_path / "Launch.log"
    fake_bin = tmp_path / "target" / "release" / "immortal-server"
    fake_bin.parent.mkdir(parents=True, exist_ok=True)
    fake_bin.write_text("ELF", encoding="utf-8")

    fake_server_proc = MagicMock(pid=1111)
    fake_server_proc.poll.return_value = None
    fake_client_proc = MagicMock(pid=2222)
    fake_client_proc.poll.return_value = None

    def fake_launch_client():
        launch_log.write_text(
            "DevNet: Welcomed by server\nBringing World shootingrange_p.TheWorld up for play\n",
            encoding="utf-8",
        )
        return fake_client_proc

    def fake_popen(cmd, **kwargs):
        # Write server milestone directly to scratch/flight_server.log
        (tmp_path / "scratch").mkdir(parents=True, exist_ok=True)
        (tmp_path / "scratch" / "flight_server.log").write_text(
            "NMT_MapLoaded 0x2A\nemitting UActorChannel opens (ch=3, 4, 80, 81)\nError processing datagram: test\n",
            encoding="utf-8",
        )
        return fake_server_proc

    argv = ["agyis flight", "--target", "spawn", "--no-record", "--post-hold", "0", "--force-rebuild", "--json"]
    with patch.object(sys, "argv", argv), \
         patch.object(flight, "REPO_ROOT", tmp_path), \
         patch.object(flight, "inspect_sdd_status", return_value={"current_mode": "immortal"}), \
         patch.object(flight, "kill_game_and_server"), \
         patch.object(flight, "is_ydotoold_running", return_value=False), \
         patch.object(flight, "ensure_immortal_server_built", return_value=str(fake_bin)) as mock_build, \
         patch.object(flight, "get_launch_log_path", return_value=str(launch_log)), \
         patch.object(flight, "launch_client", side_effect=fake_launch_client), \
         patch.object(flight, "find_game_and_server_processes", return_value=[]), \
         patch.object(flight.subprocess, "Popen", side_effect=fake_popen), \
         patch.object(flight.time, "sleep"):
        rc = flight.main()

    assert rc == 0
    mock_build.assert_called_once_with(force_rebuild=True)
    captured = capsys.readouterr()
    assert "ydotoold does not appear to be running" in captured.err
    assert "--manual" in captured.err

    json_start = captured.out.index("{")
    payload = json.loads(captured.out[json_start:])
    assert payload["target"] == "ACTORS_REPLICATED"
    assert payload["passed"] is True
    assert payload["post_hold"] == 0.0
    assert payload["milestones"]["WELCOMED"]["detected"] is True
    assert payload["milestones"]["WORLD_READY"]["detected"] is True
    assert payload["milestones"]["MAP_LOADED"]["detected"] is True
    assert payload["milestones"]["ACTORS_REPLICATED"]["detected"] is True
    assert payload["diagnostics"] == ["[server] Error processing datagram: test"]
