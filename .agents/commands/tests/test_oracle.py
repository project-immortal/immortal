# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Hermetic unit test suite for Headless Wine Retail Dedicated Server Oracle (ADOPT-09),
the dirtyroom binary patcher, and process-matching helpers.
Tests execute purely in temporary directories with zero wine, display, or host network side effects.
"""

import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
COMMANDS_DIR = Path(__file__).resolve().parent.parent
PATCHER_DIR = REPO_ROOT / "scripts" / "dirtyroom"

sys.path.insert(0, str(COMMANDS_DIR))
sys.path.insert(0, str(PATCHER_DIR))

import input as agyis_input
from lib import common
import oracle
import patch_server_binary as patcher


def _build_synthetic_pe(
    path: Path,
    dll_chars: int = 0x8160,
    hook_bytes: bytes = patcher.HOOK_ORIGINAL_BYTES,
    seekfree_bytes: bytes = patcher.SEEKFREE_ORIGINAL_BYTES,
) -> None:
    """Writes a minimal valid PE64 sparse file with hook site, seekfree guard, and zeroed cave padding."""
    total_size = patcher.CAVE_OFFSET + len(patcher.CAVE_PAYLOAD) + 64
    pe_offset = 0x80
    dll_chars_offset = pe_offset + 24 + 70
    with open(path, "wb") as f:
        f.truncate(total_size)
        f.seek(0)
        f.write(b"MZ")
        f.seek(0x3C)
        f.write(struct.pack("<I", pe_offset))
        f.seek(pe_offset)
        f.write(b"PE\x00\x00")
        f.seek(dll_chars_offset)
        f.write(struct.pack("<H", dll_chars))
        f.seek(patcher.HOOK_OFFSET)
        f.write(hook_bytes)
        f.seek(patcher.SEEKFREE_OFFSET)
        f.write(seekfree_bytes)


class TestOracleConfiguration(unittest.TestCase):
    """Hermetic unit tests for default configuration and constants."""

    def test_default_constants(self):
        self.assertEqual(oracle.DEFAULT_MAP, "SG_JaguarFalls_Rework_P")
        self.assertEqual(oracle.DEFAULT_PORT, 7000)
        self.assertEqual(oracle.DEFAULT_MULTIHOME, "127.0.0.1")

    def test_candidate_bins_priority(self):
        first_candidate = oracle.CANDIDATE_BINS[0]
        self.assertIn("ShippingPC-ChaosGame-Server.exe", str(first_candidate))


class TestOracleBinaryResolution(unittest.TestCase):
    """Hermetic unit tests for target binary and working directory discovery."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_resolve_binary_with_chaosgame_dir(self):
        bin_dir = self.base / "Binaries" / "Win64"
        bin_dir.mkdir(parents=True)
        (self.base / "ChaosGame").mkdir(parents=True)
        mock_bin = bin_dir / "ShippingPC-ChaosGame-Server.exe"
        mock_bin.write_text("MZ")

        with patch.object(oracle, "CANDIDATE_BINS", [mock_bin]):
            resolved_bin, resolved_dir = oracle.resolve_binary_and_dir()
            self.assertEqual(resolved_bin, mock_bin)
            self.assertEqual(resolved_dir, bin_dir)

    def test_resolve_binary_fallback_without_chaosgame_dir(self):
        bin_dir = self.base / "Other"
        bin_dir.mkdir(parents=True)
        mock_bin = bin_dir / "ShippingPC-ChaosGame.exe"
        mock_bin.write_text("MZ")

        with patch.object(oracle, "CANDIDATE_BINS", [mock_bin]):
            resolved_bin, resolved_dir = oracle.resolve_binary_and_dir()
            self.assertEqual(resolved_bin, mock_bin)
            self.assertEqual(resolved_dir, bin_dir)

    def test_resolve_binary_none_when_missing(self):
        non_existent = self.base / "nonexistent.exe"
        with patch.object(oracle, "CANDIDATE_BINS", [non_existent]):
            resolved_bin, resolved_dir = oracle.resolve_binary_and_dir()
            self.assertIsNone(resolved_bin)
            self.assertIsNone(resolved_dir)


class TestOraclePidAndPorts(unittest.TestCase):
    """Hermetic unit tests for PID handling and UDP port boundary detection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pid_file = Path(self.temp_dir.name) / "retail_server.pid"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_active_pid_valid_and_running(self):
        self.pid_file.write_text("12345\n")
        with patch.object(oracle, "PID_FILE", self.pid_file):
            with patch("oracle.pid_is_running", return_value=True):
                self.assertEqual(oracle.get_active_pid(), 12345)

    def test_get_active_pid_not_running(self):
        self.pid_file.write_text("12345\n")
        with patch.object(oracle, "PID_FILE", self.pid_file):
            with patch("oracle.pid_is_running", return_value=False):
                self.assertIsNone(oracle.get_active_pid())

    def test_get_active_pid_corrupt(self):
        self.pid_file.write_text("not_a_number\n")
        with patch.object(oracle, "PID_FILE", self.pid_file):
            self.assertIsNone(oracle.get_active_pid())

    def test_is_udp_port_bound_exact_boundary(self):
        ss_out = "UNCONN 0 0 127.0.0.1:70000 0.0.0.0:*\nUNCONN 0 0 0.0.0.0:7777 0.0.0.0:*\n"
        with patch("oracle.subprocess.run", return_value=MagicMock(stdout=ss_out)):
            self.assertFalse(oracle.is_udp_port_bound(7000))
            self.assertTrue(oracle.is_udp_port_bound(7777))

        ss_out_eol = "UNCONN 0 0 127.0.0.1:7000"
        with patch("oracle.subprocess.run", return_value=MagicMock(stdout=ss_out_eol)):
            self.assertTrue(oracle.is_udp_port_bound(7000))


class TestOracleRunnerResolution(unittest.TestCase):
    """Hermetic unit tests for Wine / GE-Proton runner resolution."""

    def test_resolve_server_runner_prefers_system_wine(self):
        with patch("oracle.shutil.which", return_value="/usr/bin/wine"), \
             patch("oracle.os.path.isfile", return_value=True), \
             patch("oracle.os.access", return_value=True):
            runner, prefix, env = oracle.resolve_server_runner()
            self.assertEqual(runner, "/usr/bin/wine")
            self.assertEqual(prefix, [])
            self.assertEqual(env["WINEPREFIX"], str(oracle.WINE_PREFIX))
            self.assertEqual(env["WINEDLLOVERRIDES"], "mscoree,mshtml=")

    def test_resolve_server_runner_falls_back_to_proton(self):
        def fake_isfile(p):
            return str(p).endswith("GE-Proton9-15/proton")

        with patch("oracle.shutil.which", return_value=None), \
             patch("oracle.os.path.isfile", side_effect=fake_isfile), \
             patch("oracle.os.access", return_value=False):
            runner, prefix, env = oracle.resolve_server_runner()
            self.assertTrue(runner.endswith("GE-Proton9-15/proton"))
            self.assertEqual(prefix, ["run"])
            self.assertEqual(env["SteamAppId"], "444090")

    def test_resolve_server_runner_none_available(self):
        with patch("oracle.shutil.which", return_value=None), \
             patch("oracle.os.path.isfile", return_value=False):
            runner, prefix, env = oracle.resolve_server_runner()
            self.assertEqual(runner, "")
            self.assertEqual(prefix, [])
            self.assertEqual(env, {})


class TestOracleMainAndCommands(unittest.TestCase):
    """Hermetic unit tests exercising oracle.main(), cmd_start, cmd_stop, cmd_test."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)
        self.oracle_dir = self.base / "oracle"
        self.wine_prefix = self.oracle_dir / "prefix"
        self.pid_file = self.oracle_dir / "retail_server.pid"
        self.log_file = self.oracle_dir / "retail_server.log"
        self.ue3_log = self.base / "Launch.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_main_no_subcommand_prints_help(self):
        with patch.object(sys, "argv", ["agyis oracle"]):
            rc = oracle.main()
            self.assertEqual(rc, 0)

    def test_main_dispatches_subcommands(self):
        with patch.object(sys, "argv", ["agyis oracle", "status", "--port", "7005"]), \
             patch("oracle.cmd_status", return_value=0) as mock_status:
            rc = oracle.main()
            self.assertEqual(rc, 0)
            args = mock_status.call_args[0][0]
            self.assertEqual(args.port, 7005)

        with patch.object(sys, "argv", ["agyis oracle", "start", "--map", "SG_FrogIsle_P", "--port", "7002", "--foreground"]), \
             patch("oracle.cmd_start", return_value=0) as mock_start:
            rc = oracle.main()
            self.assertEqual(rc, 0)
            args = mock_start.call_args[0][0]
            self.assertEqual(args.map, "SG_FrogIsle_P")
            self.assertEqual(args.port, 7002)
            self.assertFalse(args.daemon)

        with patch.object(sys, "argv", ["agyis oracle", "test", "--timeout", "30", "--port", "7001"]), \
             patch("oracle.cmd_test", return_value=0) as mock_test:
            rc = oracle.main()
            self.assertEqual(rc, 0)
            args = mock_test.call_args[0][0]
            self.assertEqual(args.timeout, 30)
            self.assertEqual(args.port, 7001)

    def test_cmd_start_server_mode_strips_display_and_uses_server_commandlet(self):
        bin_dir = self.base / "Binaries" / "Win64"
        bin_dir.mkdir(parents=True)
        server_exe = bin_dir / "ShippingPC-ChaosGame-Server.exe"
        server_exe.write_text("MZ")

        mock_proc = MagicMock(pid=4242)
        with patch.object(oracle, "ORACLE_DIR", self.oracle_dir), \
             patch.object(oracle, "WINE_PREFIX", self.wine_prefix), \
             patch.object(oracle, "PID_FILE", self.pid_file), \
             patch.object(oracle, "LOG_FILE", self.log_file), \
             patch.object(oracle, "STARTUP_WAIT_SECONDS", 0.5), \
             patch("oracle.resolve_binary_and_dir", return_value=(server_exe, bin_dir)), \
             patch("oracle.resolve_server_runner", return_value=("/usr/bin/wine", [], {"WINEPREFIX": str(self.wine_prefix)})), \
             patch("oracle.pid_is_running", side_effect=[True]), \
             patch("oracle.time.sleep"), \
             patch.dict(os.environ, {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"}, clear=False), \
             patch("oracle.subprocess.Popen", return_value=mock_proc) as mock_popen:
            args = argparse.Namespace(map="SG_JaguarFalls_Rework_P", port=7000, multihome="127.0.0.1", daemon=True)
            rc = oracle.cmd_start(args)
            self.assertEqual(rc, 0)
            cmd_sent = mock_popen.call_args[0][0]
            env_sent = mock_popen.call_args[1]["env"]
            self.assertEqual(cmd_sent[1], str(server_exe))
            self.assertEqual(cmd_sent[2], "server")
            self.assertEqual(cmd_sent[3], "SG_JaguarFalls_Rework_P?game=TgGame.TgGame_Paladins?maxplayers=2")
            self.assertNotIn("DISPLAY", env_sent)
            self.assertNotIn("WAYLAND_DISPLAY", env_sent)
            self.assertEqual(self.pid_file.read_text(), "4242")

    def test_cmd_start_client_fallback_uses_listen_and_display(self):
        bin_dir = self.base / "Binaries" / "Win64"
        bin_dir.mkdir(parents=True)
        client_exe = bin_dir / "ShippingPC-ChaosGame.exe"
        client_exe.write_text("MZ")

        mock_proc = MagicMock(pid=5151)
        with patch.object(oracle, "ORACLE_DIR", self.oracle_dir), \
             patch.object(oracle, "WINE_PREFIX", self.wine_prefix), \
             patch.object(oracle, "PID_FILE", self.pid_file), \
             patch.object(oracle, "LOG_FILE", self.log_file), \
             patch.object(oracle, "STARTUP_WAIT_SECONDS", 0.5), \
             patch("oracle.resolve_binary_and_dir", return_value=(client_exe, bin_dir)), \
             patch("oracle.resolve_server_runner", return_value=("/usr/bin/wine", [], {"WINEPREFIX": str(self.wine_prefix)})), \
             patch("oracle.pid_is_running", return_value=True), \
             patch("oracle.time.sleep"), \
             patch.dict(os.environ, {"DISPLAY": ":0"}, clear=False), \
             patch("oracle.subprocess.Popen", return_value=mock_proc) as mock_popen:
            args = argparse.Namespace(map="SG_JaguarFalls_Rework_P", port=7000, multihome="127.0.0.1", daemon=True)
            rc = oracle.cmd_start(args)
            self.assertEqual(rc, 0)
            cmd_sent = mock_popen.call_args[0][0]
            env_sent = mock_popen.call_args[1]["env"]
            self.assertEqual(cmd_sent[2], "SG_JaguarFalls_Rework_P?listen?game=TgGame.TgGame_Paladins?maxplayers=2")
            self.assertEqual(env_sent["DISPLAY"], ":0")

    def test_cmd_start_cleans_pid_when_process_dies_during_startup_wait(self):
        bin_dir = self.base / "Binaries" / "Win64"
        bin_dir.mkdir(parents=True)
        server_exe = bin_dir / "ShippingPC-ChaosGame-Server.exe"
        server_exe.write_text("MZ")

        mock_proc = MagicMock(pid=9999)
        with patch.object(oracle, "ORACLE_DIR", self.oracle_dir), \
             patch.object(oracle, "WINE_PREFIX", self.wine_prefix), \
             patch.object(oracle, "PID_FILE", self.pid_file), \
             patch.object(oracle, "LOG_FILE", self.log_file), \
             patch("oracle.resolve_binary_and_dir", return_value=(server_exe, bin_dir)), \
             patch("oracle.resolve_server_runner", return_value=("/usr/bin/wine", [], {})), \
             patch("oracle.pid_is_running", side_effect=[True, True, False]), \
             patch("oracle.time.sleep"), \
             patch("oracle.subprocess.Popen", return_value=mock_proc):
            args = argparse.Namespace(map="SG_JaguarFalls_Rework_P", port=7000, multihome="127.0.0.1", daemon=True)
            rc = oracle.cmd_start(args)
            self.assertEqual(rc, 1)
            self.assertFalse(self.pid_file.exists())

    def test_cmd_stop_sigterm_then_sigkill_and_wineserver_cleanup(self):
        self.oracle_dir.mkdir(parents=True)
        self.pid_file.write_text("77777")
        with patch.object(oracle, "PID_FILE", self.pid_file), \
             patch.object(oracle, "WINE_PREFIX", self.wine_prefix), \
             patch("oracle.get_active_pid", return_value=77777), \
             patch("oracle.os.kill") as mock_kill, \
             patch("oracle.pid_is_running", return_value=True), \
             patch("oracle.time.sleep"), \
             patch("oracle.shutil.which", return_value="/usr/bin/wineserver"), \
             patch("oracle.subprocess.run") as mock_run:
            rc = oracle.cmd_stop()
            self.assertEqual(rc, 0)
            self.assertEqual(mock_kill.call_args_list[0][0], (77777, oracle.signal.SIGTERM))
            self.assertEqual(mock_kill.call_args_list[-1][0], (77777, oracle.signal.SIGKILL))
            mock_run.assert_called_once()
            self.assertFalse(self.pid_file.exists())

    def test_cmd_test_truncates_stale_launch_log_and_checks_configured_port_only(self):
        self.oracle_dir.mkdir(parents=True)
        self.ue3_log.write_text("WinSock: stale old crash from yesterday\n")
        server_exe = self.base / "ShippingPC-ChaosGame-Server.exe"
        server_exe.write_text("MZ")

        def fake_start(start_args):
            self.pid_file.write_text("1234")
            return 0

        # Port 7777 is bound by someone else, configured port 7000 is NOT bound -> must FAIL (1)
        def fake_port_bound(p):
            return p == 7777

        with patch.object(oracle, "ORACLE_DIR", self.oracle_dir), \
             patch.object(oracle, "PID_FILE", self.pid_file), \
             patch.object(oracle, "LOG_FILE", self.log_file), \
             patch.object(oracle, "UE3_LAUNCH_LOG", self.ue3_log), \
             patch("oracle.cmd_stop", return_value=0), \
             patch("oracle.cmd_start", side_effect=fake_start), \
             patch("oracle.resolve_binary_and_dir", return_value=(server_exe, self.base)), \
             patch("oracle.get_active_pid", return_value=1234), \
             patch("oracle.pid_is_running", side_effect=[True, False]), \
             patch("oracle.is_udp_port_bound", side_effect=fake_port_bound), \
             patch("oracle.time.sleep"):
            args = argparse.Namespace(map="SG_JaguarFalls_Rework_P", port=7000, multihome="127.0.0.1", timeout=5)
            rc = oracle.cmd_test(args)
            self.assertEqual(rc, 1)
            # Stale log was archived & truncated before run
            self.assertTrue((self.oracle_dir / "Launch.prev.log").is_file())
            self.assertIn("stale old crash", (self.oracle_dir / "Launch.prev.log").read_text())
            self.assertEqual(self.ue3_log.read_text(), "")

    def test_cmd_test_passes_when_configured_port_binds(self):
        self.oracle_dir.mkdir(parents=True)
        server_exe = self.base / "ShippingPC-ChaosGame-Server.exe"
        server_exe.write_text("MZ")

        def fake_start(start_args):
            self.ue3_log.write_text(
                "WinSock: I am\nAssembly Loaded Version: 8.1\nInitializing Game Engine\nBrowse: SG_JaguarFalls_Rework_P\n"
            )
            return 0

        # Pre-check False, then True inside poll loop
        with patch.object(oracle, "ORACLE_DIR", self.oracle_dir), \
             patch.object(oracle, "PID_FILE", self.pid_file), \
             patch.object(oracle, "LOG_FILE", self.log_file), \
             patch.object(oracle, "UE3_LAUNCH_LOG", self.ue3_log), \
             patch("oracle.cmd_stop", return_value=0), \
             patch("oracle.cmd_start", side_effect=fake_start), \
             patch("oracle.resolve_binary_and_dir", return_value=(server_exe, self.base)), \
             patch("oracle.get_active_pid", return_value=1234), \
             patch("oracle.pid_is_running", return_value=True), \
             patch("oracle.is_udp_port_bound", side_effect=[False, True]), \
             patch("oracle.time.sleep"):
            args = argparse.Namespace(map="SG_JaguarFalls_Rework_P", port=7000, multihome="127.0.0.1", timeout=5)
            rc = oracle.cmd_test(args)
            self.assertEqual(rc, 0)


class TestPatchServerBinary(unittest.TestCase):
    """Hermetic unit tests for scripts/dirtyroom/patch_server_binary.py."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_patch_and_verify_synthetic_pe(self):
        src = self.base / "ShippingPC-ChaosGame.exe"
        dst = self.base / "ShippingPC-ChaosGame-Server.exe"
        _build_synthetic_pe(src, dll_chars=0x8160, hook_bytes=patcher.HOOK_ORIGINAL_BYTES)

        rc = patcher.patch_binary(src, dst, force=True)
        self.assertEqual(rc, 0)
        self.assertTrue(patcher.verify_patch(dst))
        self.assertEqual(patcher.get_dll_characteristics(dst) & patcher.DYNAMIC_BASE_FLAG, 0)
        self.assertEqual(len(patcher.CAVE_PAYLOAD), 37)

        # Verify source was never modified
        self.assertEqual(patcher.get_dll_characteristics(src) & patcher.DYNAMIC_BASE_FLAG, patcher.DYNAMIC_BASE_FLAG)
        self.assertFalse(patcher.verify_patch(src))

    def test_verify_patch_fails_if_dynamic_base_still_set(self):
        dst = self.base / "bad_aslr.exe"
        _build_synthetic_pe(
            dst,
            dll_chars=0x8160,
            hook_bytes=patcher.HOOK_PATCHED_BYTES,
            seekfree_bytes=patcher.SEEKFREE_PATCHED_BYTES,
        )
        with open(dst, "r+b") as f:
            f.seek(patcher.CAVE_OFFSET)
            f.write(patcher.CAVE_PAYLOAD)
        self.assertFalse(patcher.verify_patch(dst))

    def test_patch_fails_if_source_already_patched(self):
        src = self.base / "already_patched.exe"
        dst = self.base / "out.exe"
        _build_synthetic_pe(src, dll_chars=0x8120, hook_bytes=patcher.HOOK_PATCHED_BYTES)
        rc = patcher.patch_binary(src, dst, force=True)
        self.assertEqual(rc, 1)
        self.assertFalse(dst.exists())

    def test_patch_fails_if_cave_not_null_padding(self):
        src = self.base / "dirty_cave.exe"
        dst = self.base / "out.exe"
        _build_synthetic_pe(src, dll_chars=0x8160, hook_bytes=patcher.HOOK_ORIGINAL_BYTES)
        with open(src, "r+b") as f:
            f.seek(patcher.CAVE_OFFSET)
            f.write(b"\x90" * 4)
        rc = patcher.patch_binary(src, dst, force=True)
        self.assertEqual(rc, 1)

    def test_prepare_isolated_runtime_symlinks_without_copying_client(self):
        steam_root = self.base / "Steam" / "Paladins"
        win64 = steam_root / "Binaries" / "Win64"
        win64.mkdir(parents=True)
        (steam_root / "ChaosGame").mkdir()
        (steam_root / "Engine").mkdir()
        (win64 / "MctsInterface.dll").write_text("dll")
        src = win64 / "ShippingPC-ChaosGame.exe"
        _build_synthetic_pe(src)

        runtime_win64 = self.base / "oracle" / "runtime" / "Binaries" / "Win64"
        dst = runtime_win64 / "ShippingPC-ChaosGame-Server.exe"
        rc = patcher.patch_binary(src, dst, force=True)
        self.assertEqual(rc, 0)
        self.assertTrue((self.base / "oracle" / "runtime" / "ChaosGame").is_symlink())
        self.assertTrue((runtime_win64 / "MctsInterface.dll").is_symlink())
        self.assertFalse((runtime_win64 / "ShippingPC-ChaosGame.exe").exists())


class TestCommonProcessFilteringAndInput(unittest.TestCase):
    """Hermetic unit tests for common.py process safety and input.py error checks."""

    def test_process_filter_ignores_re_ghidra_and_matches_wine_server(self):
        self.assertFalse(
            common._is_game_or_server_cmdline(
                "java -jar ghidra.jar -process ShippingPC-ChaosGame.exe -postScript DecompileFunc.java"
            )
        )
        self.assertFalse(
            common._is_game_or_server_cmdline("python3 /home/kuasha/.local/bin/agyis re decompile ShippingPC-ChaosGame.exe")
        )
        self.assertTrue(
            common._is_game_or_server_cmdline(
                "Z:\\mnt\\fast_data\\ShippingPC-ChaosGame-Server.exe server SG_JaguarFalls_Rework_P"
            )
        )
        self.assertTrue(
            common._is_game_or_server_cmdline(
                "/usr/bin/wine /tmp/ShippingPC-ChaosGame-Server.exe server SG_JaguarFalls_Rework_P"
            )
        )
        self.assertTrue(
            common._is_game_or_server_cmdline("/home/kuasha/Dev/immortal/target/release/immortal-server")
        )

    def test_input_no_subcommand_returns_zero(self):
        with patch.object(sys, "argv", ["agyis input"]):
            self.assertEqual(agyis_input.main(), 0)

    def test_input_click_checks_ydotool_exit_code(self):
        fail_res = subprocess.CompletedProcess(args=["ydotool"], returncode=1, stdout="", stderr="ydotoold not running")
        with patch("input.get_window_info", return_value=None), \
             patch("input.run_ydotool", return_value=fail_res):
            args = argparse.Namespace(x="100", y="200", relative=False, button=1, window_name="Paladins")
            self.assertEqual(agyis_input.cmd_click(args), 1)

    def test_input_console_checks_ydotool_exit_code(self):
        fail_res = subprocess.CompletedProcess(args=["ydotool"], returncode=1, stdout="", stderr="ydotoold not running")
        with patch("input.get_window_info", return_value=None), \
             patch("input.send_key", return_value=fail_res):
            args = argparse.Namespace(command="stat fps", window_name="Paladins")
            self.assertEqual(agyis_input.cmd_console(args), 1)


if __name__ == "__main__":
    unittest.main()
