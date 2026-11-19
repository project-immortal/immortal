# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Hermetic unit test suite for agyis pcap extension and pure-Python PCAPNG/NFLOG reader.
Tests execute purely in temporary directories with zero host, sudo, or network side effects.
"""

import argparse
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.pcapng import (
    convert_to_raw_pcap,
    extract_ip_from_linktype,
    extract_udp_packets,
    is_cpack_udp_packet,
    matches_udp_port,
    parse_nflog_payload,
)
from pcap import cmd_convert, cmd_status, format_bytes


def build_synthetic_ipv4_udp(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes
) -> bytes:
    """Builds a minimal synthetic IPv4 UDP packet."""
    src_parts = [int(p) for p in src_ip.split(".")]
    dst_parts = [int(p) for p in dst_ip.split(".")]
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    # IPv4 header: ver_ihl (0x45), dscp_ecn (0), total_len, id (1), flags_frag (0), ttl (64), proto (17), csum (0), src, dst
    ip_hdr = struct.pack(
        "!BBHHHBBH4B4B",
        0x45, 0, total_len, 1, 0, 64, 17, 0,
        *src_parts, *dst_parts
    )
    # UDP header: src_port, dst_port, length, checksum (0)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return ip_hdr + udp_hdr + payload


def build_synthetic_nflog_packet(raw_ip: bytes) -> bytes:
    """Encapsulates raw IP bytes in an NFLOG TLV 9 structure."""
    family = 2  # AF_INET
    version = 0
    res_id = 0
    prefix = struct.pack("<BBH", family, version, res_id)
    tlv_type = 9  # NFULA_PAYLOAD
    tlv_len = 4 + len(raw_ip)
    tlv_hdr = struct.pack("<HH", tlv_len, tlv_type)
    # Padding to 4 bytes boundary
    pad_len = ((tlv_len + 3) & ~3) - tlv_len
    return prefix + tlv_hdr + raw_ip + (b"\x00" * pad_len)


class TestPcapngExtractor(unittest.TestCase):
    """Hermetic unit tests for PCAPNG / NFLOG parsing and conversion."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_nflog_payload(self):
        raw_ip = b"MOCK_IP_PACKET_CONTENT_FOR_TESTING"
        nflog_bytes = build_synthetic_nflog_packet(raw_ip)
        extracted = parse_nflog_payload(nflog_bytes)
        self.assertEqual(extracted, raw_ip)

    def test_extract_ip_from_linktype(self):
        raw_ip = build_synthetic_ipv4_udp("127.0.0.1", 7777, "127.0.0.1", 7777, b"hello")
        nflog_bytes = build_synthetic_nflog_packet(raw_ip)
        # Linktypes 141 (NFLOG) and 239 (NETLINK)
        self.assertEqual(extract_ip_from_linktype(nflog_bytes, 141), raw_ip)
        self.assertEqual(extract_ip_from_linktype(nflog_bytes, 239), raw_ip)
        # Linktype 101 / 12 (Raw IPv4)
        self.assertEqual(extract_ip_from_linktype(raw_ip, 101), raw_ip)
        self.assertEqual(extract_ip_from_linktype(raw_ip, 12), raw_ip)

    def test_matches_udp_port(self):
        pkt_7777 = build_synthetic_ipv4_udp("10.0.0.1", 7777, "10.0.0.2", 9222, b"test")
        self.assertTrue(matches_udp_port(pkt_7777, None))
        self.assertTrue(matches_udp_port(pkt_7777, 7777))
        self.assertTrue(matches_udp_port(pkt_7777, 9222))
        self.assertFalse(matches_udp_port(pkt_7777, 8888))

    def test_is_cpack_udp_packet(self):
        hello_570 = b"\x00" * 570
        hello_650 = b"\x00" * 650
        ping_send = b"\x02" + b"\x00" * 12
        ping_recv = b"\x03" + b"\x00" * 20
        hello_reply = b"\x01" + b"\x00" * 15
        ctrl_frame = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x10\x8d\x47"
        ue3_bunch = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x8d\x47"

        self.assertIn("HelloSend (570 B)", is_cpack_udp_packet(hello_570))
        self.assertIn("HelloSend (650 B)", is_cpack_udp_packet(hello_650))
        self.assertEqual(is_cpack_udp_packet(ping_send), "CPackUdp::PingSend")
        self.assertEqual(is_cpack_udp_packet(ping_recv), "CPackUdp::PingRecv")
        self.assertEqual(is_cpack_udp_packet(hello_reply), "CPackUdp::HelloRecvReply")
        self.assertEqual(is_cpack_udp_packet(ctrl_frame), "Dedicated::ControlFrame (12 B)")
        self.assertIsNone(is_cpack_udp_packet(ue3_bunch))

    def test_pcapng_conversion_and_extraction(self):
        pcapng_path = self.test_root / "test_capture.pcapng"
        pcap_out_path = self.test_root / "test_converted.pcap"

        raw_ip_1 = build_synthetic_ipv4_udp("192.168.1.10", 39301, "20.153.152.2", 9222, b"data1")
        raw_ip_2 = build_synthetic_ipv4_udp("20.153.152.2", 9222, "192.168.1.10", 39301, b"data2")
        raw_ip_3 = build_synthetic_ipv4_udp("127.0.0.1", 5000, "127.0.0.1", 6000, b"data3")

        nflog_1 = build_synthetic_nflog_packet(raw_ip_1)
        nflog_2 = build_synthetic_nflog_packet(raw_ip_2)
        nflog_3 = build_synthetic_nflog_packet(raw_ip_3)

        # Construct minimal PCAPNG with SHB, IDB (linktype 239), and 3 EPBs
        with open(pcapng_path, "wb") as f:
            # Section Header Block (SHB)
            shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
            shb_len = 12 + len(shb_body)
            f.write(struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len))

            # Interface Description Block (IDB): linktype 239, reserved 0, snaplen 65535
            idb_body = struct.pack("<HHI", 239, 0, 65535)
            idb_len = 12 + len(idb_body)
            f.write(struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len))

            # 3 Enhanced Packet Blocks (EPBs)
            for i, nflog_data in enumerate([nflog_1, nflog_2, nflog_3]):
                cap_len = len(nflog_data)
                # EPB body: iface_id=0, ts_high=0, ts_low=1000000*(i+1), cap_len, orig_len
                epb_hdr = struct.pack("<IIIII", 0, 0, 1_000_000 * (i + 1), cap_len, cap_len)
                pad_len = ((cap_len + 3) & ~3) - cap_len
                epb_body = epb_hdr + nflog_data + (b"\x00" * pad_len)
                epb_len = 12 + len(epb_body)
                f.write(struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len))

        # Test extraction
        packets = list(extract_udp_packets(pcapng_path, port_filter=9222))
        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0][6], b"data1")
        self.assertEqual(packets[1][6], b"data2")

        # Test convert with port filter
        count = convert_to_raw_pcap(pcapng_path, pcap_out_path, port_filter=9222)
        self.assertEqual(count, 2)
        self.assertTrue(pcap_out_path.is_file())

        # Verify PCAP file header and records
        with open(pcap_out_path, "rb") as pf:
            ghdr = pf.read(24)
            magic, v_maj, v_min, tz, sig, snap, linktype = struct.unpack("<IHHiIII", ghdr)
            self.assertEqual(magic, 0xA1B2C3D4)
            self.assertEqual(v_maj, 2)
            self.assertEqual(v_min, 4)
            self.assertEqual(linktype, 101)  # DLT_RAW

            # First record
            r1_hdr = pf.read(16)
            sec, usec, c_len, o_len = struct.unpack("<IIII", r1_hdr)
            self.assertEqual(sec, 1)
            self.assertEqual(usec, 0)
            self.assertEqual(c_len, len(raw_ip_1))
            self.assertEqual(pf.read(c_len), raw_ip_1)

            # Second record
            r2_hdr = pf.read(16)
            sec, usec, c_len, o_len = struct.unpack("<IIII", r2_hdr)
            self.assertEqual(sec, 2)
            self.assertEqual(usec, 0)
            self.assertEqual(c_len, len(raw_ip_2))
            self.assertEqual(pf.read(c_len), raw_ip_2)

            # End of file
            self.assertEqual(pf.read(), b"")

    def test_cmd_convert_cli(self):
        pcapng_path = self.test_root / "cli_test.pcapng"
        raw_ip = build_synthetic_ipv4_udp("127.0.0.1", 9222, "127.0.0.1", 9222, b"cli_payload")
        nflog_data = build_synthetic_nflog_packet(raw_ip)

        with open(pcapng_path, "wb") as f:
            shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
            shb_len = 12 + len(shb_body)
            f.write(struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len))

            idb_body = struct.pack("<HHI", 141, 0, 65535)
            idb_len = 12 + len(idb_body)
            f.write(struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len))

            cap_len = len(nflog_data)
            epb_hdr = struct.pack("<IIIII", 0, 0, 500_000, cap_len, cap_len)
            pad_len = ((cap_len + 3) & ~3) - cap_len
            epb_body = epb_hdr + nflog_data + (b"\x00" * pad_len)
            epb_len = 12 + len(epb_body)
            f.write(struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len))

        # Default output name should be cli_test.pcap
        args = argparse.Namespace(input=str(pcapng_path), output=None, port=None)
        rc = cmd_convert(args)
        self.assertEqual(rc, 0)
        expected_out = pcapng_path.with_suffix(".pcap")
        self.assertTrue(expected_out.is_file())


class TestFormatBytes(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(500), "500 B")
        self.assertEqual(format_bytes(2048), "2.0 KB")
        self.assertEqual(format_bytes(1048576), "1.0 MB")


if __name__ == "__main__":
    unittest.main()
