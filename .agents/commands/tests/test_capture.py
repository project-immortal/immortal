# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Hermetic unit test suite for immortal retail capture workflow (SPEC-2026-IMMORTAL-CAPTURE-PLAN-001).
Tests execute purely in temporary directories with zero host, sudo, or network side effects.
"""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.capture_core import (
    NFT_TABLE_NAME,
    SLICE_NAME,
    analyze_launch_log,
    append_sha256sums,
    calculate_sha256,
    clear_capture_state,
    generate_bpf_filter,
    generate_nftables_rules,
    generate_nftables_teardown,
    get_cgroup_paths,
    get_qbittorrent_ports,
    inspect_sdd_status,
    load_capture_state,
    parse_steam_launch_options,
    prep_sdd,
    restore_sdd,
    rotate_launch_log,
    save_capture_state,
    unwrap_launch_options_from_slice,
    update_steam_launch_options,
    wrap_launch_options_with_slice,
)


class TestSddHandling(unittest.TestCase):
    """Hermetic unit tests for Service Discovery (.sdd) state machine."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sdd_dir = Path(self.temp_dir.name)
        self.target = self.sdd_dir / "8.1.5839.0-PC-402.sdd"
        self.orig = self.sdd_dir / "8.1.5839.0-PC-402.sdd.orig"
        self.immortal = self.sdd_dir / "8.1.5839.0-PC-402.sdd.immortal"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_inspect_sdd_status_missing(self):
        status = inspect_sdd_status(self.sdd_dir)
        self.assertEqual(status["current_mode"], "missing")
        self.assertFalse(status["target_exists"])
        self.assertFalse(status["orig_exists"])
        self.assertFalse(status["immortal_exists"])

    def test_inspect_sdd_status_modes(self):
        # Setup retail original
        self.orig.write_text("RETAIL_DATA")
        self.target.write_text("RETAIL_DATA")
        status = inspect_sdd_status(self.sdd_dir)
        self.assertEqual(status["current_mode"], "retail")

        # Setup immortal backup
        self.immortal.write_text("IMMORTAL_DATA")
        self.target.write_text("IMMORTAL_DATA")
        status = inspect_sdd_status(self.sdd_dir)
        self.assertEqual(status["current_mode"], "immortal")

        # Custom modified
        self.target.write_text("SOME_OTHER_DATA")
        status = inspect_sdd_status(self.sdd_dir)
        self.assertEqual(status["current_mode"], "custom")

    def test_prep_sdd_missing_orig_raises(self):
        with self.assertRaises(FileNotFoundError):
            prep_sdd(self.sdd_dir)

    def test_prep_sdd_initial_backup_and_switch(self):
        self.orig.write_text("RETAIL_DATA")
        self.target.write_text("LOCAL_EMULATOR_DATA")

        # Execute prep
        res = prep_sdd(self.sdd_dir)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["previous_mode"], "immortal")
        self.assertEqual(res["current_mode"], "retail")
        self.assertTrue(res["immortal_created"])

        # Assert target is now retail
        self.assertEqual(self.target.read_text(), "RETAIL_DATA")
        # Assert immortal backup holds emulator data
        self.assertTrue(self.immortal.is_file())
        self.assertEqual(self.immortal.read_text(), "LOCAL_EMULATOR_DATA")

    def test_prep_sdd_idempotent_never_overwrites_immortal(self):
        self.orig.write_text("RETAIL_DATA")
        self.immortal.write_text("PRECIOUS_EMULATOR_DATA")
        self.target.write_text("RETAIL_DATA")

        # Execute prep when already in retail
        res = prep_sdd(self.sdd_dir)
        self.assertEqual(res["current_mode"], "retail")
        self.assertFalse(res["immortal_created"])

        # Assert backup was not touched
        self.assertEqual(self.immortal.read_text(), "PRECIOUS_EMULATOR_DATA")

    def test_restore_sdd_auto_to_immortal(self):
        self.orig.write_text("RETAIL_DATA")
        self.immortal.write_text("EMULATOR_DATA")
        self.target.write_text("RETAIL_DATA")

        mode = restore_sdd(target_mode="auto", pre_capture_mode="immortal", sdd_dir=self.sdd_dir)
        self.assertEqual(mode, "immortal")
        self.assertEqual(self.target.read_text(), "EMULATOR_DATA")

    def test_restore_sdd_auto_to_retail(self):
        self.orig.write_text("RETAIL_DATA")
        self.immortal.write_text("EMULATOR_DATA")
        self.target.write_text("EMULATOR_DATA")

        mode = restore_sdd(target_mode="auto", pre_capture_mode="retail", sdd_dir=self.sdd_dir)
        self.assertEqual(mode, "retail")
        self.assertEqual(self.target.read_text(), "RETAIL_DATA")

    def test_restore_sdd_explicit_modes(self):
        self.orig.write_text("RETAIL_DATA")
        self.immortal.write_text("EMULATOR_DATA")

        mode = restore_sdd(target_mode="immortal", sdd_dir=self.sdd_dir)
        self.assertEqual(mode, "immortal")
        self.assertEqual(self.target.read_text(), "EMULATOR_DATA")

        mode = restore_sdd(target_mode="retail", sdd_dir=self.sdd_dir)
        self.assertEqual(mode, "retail")
        self.assertEqual(self.target.read_text(), "RETAIL_DATA")


class TestNftablesRules(unittest.TestCase):
    """Hermetic unit tests for nftables rule generation and cgroup v2 paths."""

    def test_get_cgroup_paths(self):
        rel, abs_path = get_cgroup_paths(uid=1000)
        self.assertEqual(rel, f"user.slice/user-1000.slice/user@1000.service/{SLICE_NAME}")
        self.assertEqual(str(abs_path), f"/sys/fs/cgroup/{rel}")

    def test_generate_nftables_rules(self):
        rules = generate_nftables_rules(uid=1000)
        self.assertIn(f"table inet {NFT_TABLE_NAME}", rules)
        self.assertIn("socket cgroupv2 level 4", rules)
        self.assertIn("ct mark set 0x4242", rules)
        self.assertIn("log group 42 queue-threshold 1 snaplen 65535", rules)
        self.assertIn('iifname != "lo"', rules)

    def test_generate_nftables_teardown(self):
        teardown = generate_nftables_teardown()
        self.assertEqual(teardown.strip(), f"table inet {NFT_TABLE_NAME}\ndelete table inet {NFT_TABLE_NAME}")


class TestBpfFilter(unittest.TestCase):
    """Hermetic tests for BPF filter builder and qBittorrent config parser."""

    def test_generate_bpf_filter_default(self):
        bpf = generate_bpf_filter()
        self.assertIn("tcp port 9000", bpf)
        self.assertIn("udp port 9002", bpf)
        self.assertIn("udp port 6250", bpf)
        self.assertIn("20.153.141.49", bpf)
        self.assertIn("port 5353", bpf)

    def test_generate_bpf_filter_with_exclusions(self):
        bpf = generate_bpf_filter(exclude_ports=[3388, 38794])
        self.assertIn("and not port 3388 and not port 38794", bpf)

    def test_get_qbittorrent_ports_parsing(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("[Preferences]\nSession\\Port=38794\nSession\\SSL\\Port=3388\nOther=123\n")
            cfg_path = tf.name

        try:
            ports = get_qbittorrent_ports(cfg_path)
            self.assertEqual(ports, [3388, 38794])
        finally:
            os.remove(cfg_path)


class TestSteamVdf(unittest.TestCase):
    """Hermetic tests for Steam localconfig.vdf parsing and LaunchOptions manipulation."""

    MOCK_VDF = """
"UserLocalConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"apps"
				{
					"444090"
					{
						"LastPlayed"		"1794983323"
						"Playtime"		"210945"
						"LaunchOptions"		"gamemoderun %command%"
					}
				}
			}
		}
	}
}
"""

    MOCK_VDF_NO_OPTS = """
"UserLocalConfigStore"
{
	"apps"
	{
		"444090"
		{
			"LastPlayed"		"1794983323"
		}
	}
}
"""

    def test_parse_steam_launch_options(self):
        opts = parse_steam_launch_options(self.MOCK_VDF)
        self.assertEqual(opts, "gamemoderun %command%")

        opts_none = parse_steam_launch_options(self.MOCK_VDF_NO_OPTS)
        self.assertIsNone(opts_none)

    def test_wrap_launch_options_with_slice(self):
        expected_prefix = (
            f"PRESSURE_VESSEL_SYSTEMD_SCOPE=0 STEAM_LAUNCH_WRAPPER_SCOPE=0 "
            f"systemd-run --user --scope --slice={SLICE_NAME} "
            f"--setenv=PRESSURE_VESSEL_SYSTEMD_SCOPE=0 --setenv=STEAM_LAUNCH_WRAPPER_SCOPE=0 -- "
        )
        # Empty
        wrapped_empty = wrap_launch_options_with_slice("")
        self.assertEqual(wrapped_empty, f"{expected_prefix}%command%")

        # Existing command
        wrapped = wrap_launch_options_with_slice("gamemoderun %command%")
        self.assertEqual(wrapped, f"{expected_prefix}gamemoderun %command%")

        # Idempotent wrap
        wrapped_again = wrap_launch_options_with_slice(wrapped)
        self.assertEqual(wrapped_again, wrapped)

    def test_unwrap_launch_options_from_slice(self):
        wrapped_legacy = f"systemd-run --user --scope --slice={SLICE_NAME} -- gamemoderun %command%"
        self.assertEqual(unwrap_launch_options_from_slice(wrapped_legacy), "gamemoderun %command%")

        wrapped_new = (
            f"PRESSURE_VESSEL_SYSTEMD_SCOPE=0 STEAM_LAUNCH_WRAPPER_SCOPE=0 "
            f"systemd-run --user --scope --slice={SLICE_NAME} "
            f"--setenv=PRESSURE_VESSEL_SYSTEMD_SCOPE=0 --setenv=STEAM_LAUNCH_WRAPPER_SCOPE=0 -- "
            f"gamemoderun %command%"
        )
        self.assertEqual(unwrap_launch_options_from_slice(wrapped_new), "gamemoderun %command%")

    def test_update_steam_launch_options(self):
        updated = update_steam_launch_options(self.MOCK_VDF, "new_opts %command%")
        self.assertIn('"LaunchOptions"\t\t"new_opts %command%"', updated)
        self.assertEqual(parse_steam_launch_options(updated), "new_opts %command%")

        # Insert when previously absent
        updated_new = update_steam_launch_options(self.MOCK_VDF_NO_OPTS, "inserted_opts %command%")
        self.assertEqual(parse_steam_launch_options(updated_new), "inserted_opts %command%")


class TestLogAnalysis(unittest.TestCase):
    """Hermetic tests for Launch.log analysis and rotation."""

    def test_analyze_launch_log(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(
                "[0001.20] Init: Match initialization\n"
                "[0015.40] Browse: 52.8.226.76:7778?game=TgGame.TgGame_Paladins_Siege?mapGameId=1575\n"
                "[0020.10] Log: dumpallmar executed with 15 frames\n"
            )
            log_path = tf.name

        try:
            analysis = analyze_launch_log(log_path)
            self.assertTrue(analysis["exists"])
            self.assertEqual(analysis["browse_endpoints"], ["52.8.226.76:7778"])
            self.assertTrue(analysis["dumpallmar_detected"])
            self.assertEqual(analysis["maps"], ["1575"])
        finally:
            os.remove(log_path)

    def test_rotate_launch_log(self):
        with tempfile.TemporaryDirectory() as td:
            log_p = Path(td) / "Launch.log"
            log_p.write_text("LOG_CONTENT")

            archived = rotate_launch_log(log_p)
            self.assertIsNotNone(archived)
            self.assertTrue(archived.is_file())
            self.assertEqual(archived.read_text(), "LOG_CONTENT")
            self.assertFalse(log_p.exists())

            # Rotating absent file returns None
            self.assertIsNone(rotate_launch_log(log_p))


class TestStateLedger(unittest.TestCase):
    """Hermetic tests for dirtyroom capture state ledger."""

    def test_load_save_clear_state(self):
        with tempfile.TemporaryDirectory() as td:
            state_p = Path(td) / "test_state.json"

            # Initial load is empty
            self.assertEqual(load_capture_state(state_p), {})

            # Save state
            state_data = {"status": "prepped", "mode": "cgroup", "run_id": "CAP-01"}
            save_capture_state(state_data, state_p)
            self.assertTrue(state_p.is_file())

            # Read back
            loaded = load_capture_state(state_p)
            self.assertEqual(loaded, state_data)

            # Clear state
            clear_capture_state(state_p)
            self.assertFalse(state_p.exists())


class TestSha256Sums(unittest.TestCase):
    """Hermetic tests for SHA256 manifest appending and deduplication."""

    def test_append_sha256sums_deduplicated(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "SHA256SUMS.txt"
            f1 = Path(td) / "file1.txt"
            f1.write_text("HELLO")

            f1_sha = calculate_sha256(f1)

            # First append
            append_sha256sums(manifest, [f1])
            lines1 = manifest.read_text().splitlines()
            self.assertEqual(len(lines1), 1)
            self.assertEqual(lines1[0], f"{f1_sha}  file1.txt")

            # Second append with same file (should not duplicate)
            append_sha256sums(manifest, [f1])
            lines2 = manifest.read_text().splitlines()
            self.assertEqual(len(lines2), 1)


if __name__ == "__main__":
    unittest.main()
