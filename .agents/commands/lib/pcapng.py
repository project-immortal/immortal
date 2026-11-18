# Pure-Python PCAP and PCAPNG / NFLOG UDP stream extractor
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Arafat Zahan (@kuasha420)
# Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
# Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

"""
Extracts UDP datagrams from PCAPNG (including NFLOG linktype 141) and PCAP captures.
"""

from pathlib import Path
import socket
import struct
from typing import Generator, Optional, Tuple, Union


def parse_nflog_payload(packet_data: bytes) -> Optional[bytes]:
    """Extracts raw IPv4 payload from NFLOG TLV structure."""
    if len(packet_data) < 4:
        return None
    # 4 bytes: family(1), version(1), res_id(2)
    offset = 4
    while offset + 4 <= len(packet_data):
        tlv_len, tlv_type = struct.unpack_from("<HH", packet_data, offset)
        tlv_type &= 0x7FFF
        if tlv_len < 4:
            break
        val_len = tlv_len - 4
        if tlv_type == 9:  # NFULA_PAYLOAD
            return packet_data[offset + 4 : offset + 4 + val_len]
        # Pad to 4 bytes boundary
        offset += (tlv_len + 3) & ~3
    return None


def extract_ip_from_linktype(packet_data: bytes, linktype: int) -> Optional[bytes]:
    """Extracts raw IP packet based on PCAP / PCAPNG linktype."""
    if linktype in (141, 239):  # LINKTYPE_NFLOG / NETLINK
        return parse_nflog_payload(packet_data)
    elif linktype == 1:  # LINKTYPE_ETHERNET
        if len(packet_data) >= 14:
            ethertype = struct.unpack_from("!H", packet_data, 12)[0]
            if ethertype == 0x0800:  # IPv4
                return packet_data[14:]
            elif ethertype == 0x8100 and len(packet_data) >= 18:  # 802.1Q VLAN
                inner_ethertype = struct.unpack_from("!H", packet_data, 16)[0]
                if inner_ethertype == 0x0800:
                    return packet_data[18:]
    elif linktype == 113:  # LINKTYPE_LINUX_SLL (cooked)
        if len(packet_data) >= 16:
            protocol = struct.unpack_from("!H", packet_data, 14)[0]
            if protocol == 0x0800:
                return packet_data[16:]
    elif linktype in (12, 101):  # LINKTYPE_RAW / LINKTYPE_IPV4
        return packet_data
    return None


def extract_udp_packets(
    capture_path: Union[str, Path],
    port_filter: Optional[int] = None,
    limit: Optional[int] = None,
) -> Generator[Tuple[int, float, str, int, str, int, bytes], None, None]:
    """
    Yields (frame_num, time_sec, src_ip, src_port, dst_ip, dst_port, udp_payload)
    for all matching UDP packets in a PCAP or PCAPNG capture file.
    """
    path = Path(capture_path)
    with open(path, "rb") as f:
        magic = f.read(4)
        if len(magic) < 4:
            return

        f.seek(0)
        if magic == b"\n\r\r\n":
            # PCAPNG Format
            yield from _iter_pcapng(f, port_filter, limit)
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
            # Classic PCAP Format
            yield from _iter_pcap(f, magic, port_filter, limit)


def _iter_pcapng(f, port_filter: Optional[int], limit: Optional[int]):
    interfaces = []  # List of linktypes
    frame_num = 0
    yielded = 0

    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            break
        block_type, block_len = struct.unpack("<II", hdr)
        if block_len < 8:
            break
        block_body = f.read(block_len - 8)
        if len(block_body) < block_len - 8:
            break

        if block_type == 0x00000001:  # Interface Description Block (IDB)
            if len(block_body) >= 8:
                linktype = struct.unpack_from("<H", block_body, 0)[0]
                interfaces.append(linktype)
        elif block_type == 0x00000006:  # Enhanced Packet Block (EPB)
            if len(block_body) >= 20:
                iface_id = struct.unpack_from("<I", block_body, 0)[0]
                ts_high = struct.unpack_from("<I", block_body, 4)[0]
                ts_low = struct.unpack_from("<I", block_body, 8)[0]
                cap_len = struct.unpack_from("<I", block_body, 12)[0]
                linktype = interfaces[iface_id] if iface_id < len(interfaces) else 141
                packet_data = block_body[20 : 20 + cap_len]
                time_sec = ((ts_high << 32) | ts_low) / 1_000_000.0

                frame_num += 1
                res = _parse_udp_from_raw_packet(packet_data, linktype, port_filter)
                if res is not None:
                    src_ip, src_port, dst_ip, dst_port, payload = res
                    yield (frame_num, time_sec, src_ip, src_port, dst_ip, dst_port, payload)
                    yielded += 1
                    if limit and yielded >= limit:
                        return
        elif block_type == 0x00000003:  # Simple Packet Block (SPB)
            if len(block_body) >= 4:
                orig_len = struct.unpack_from("<I", block_body, 0)[0]
                linktype = interfaces[0] if interfaces else 141
                packet_data = block_body[4 : 4 + orig_len]
                frame_num += 1
                res = _parse_udp_from_raw_packet(packet_data, linktype, port_filter)
                if res is not None:
                    src_ip, src_port, dst_ip, dst_port, payload = res
                    yield (frame_num, 0.0, src_ip, src_port, dst_ip, dst_port, payload)
                    yielded += 1
                    if limit and yielded >= limit:
                        return


def _iter_pcap(f, magic: bytes, port_filter: Optional[int], limit: Optional[int]):
    is_little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
    endian = "<" if is_little else ">"

    ghdr = f.read(20)  # skip rest of 24-byte global header
    if len(ghdr) < 20:
        return
    linktype = struct.unpack_from(endian + "I", ghdr, 16)[0]

    frame_num = 0
    yielded = 0

    while True:
        phdr = f.read(16)
        if len(phdr) < 16:
            break
        ts_sec, ts_sub, cap_len, _ = struct.unpack(endian + "IIII", phdr)
        time_sec = ts_sec + (ts_sub / 1_000_000_000.0 if is_nano else ts_sub / 1_000_000.0)
        packet_data = f.read(cap_len)
        if len(packet_data) < cap_len:
            break

        frame_num += 1
        res = _parse_udp_from_raw_packet(packet_data, linktype, port_filter)
        if res is not None:
            src_ip, src_port, dst_ip, dst_port, payload = res
            yield (frame_num, time_sec, src_ip, src_port, dst_ip, dst_port, payload)
            yielded += 1
            if limit and yielded >= limit:
                return


def _parse_udp_from_raw_packet(
    packet_data: bytes, linktype: int, port_filter: Optional[int]
) -> Optional[Tuple[str, int, str, int, bytes]]:
    ip_pkt = extract_ip_from_linktype(packet_data, linktype)
    if not ip_pkt or len(ip_pkt) < 20:
        return None

    ver_ihl = ip_pkt[0]
    if (ver_ihl >> 4) != 4:  # Must be IPv4
        return None
    ihl = (ver_ihl & 0x0F) * 4
    proto = ip_pkt[9]
    if proto != 17:  # Must be UDP
        return None
    if len(ip_pkt) < ihl + 8:
        return None

    src_ip_bytes = ip_pkt[12:16]
    dst_ip_bytes = ip_pkt[16:20]
    src_ip = socket.inet_ntoa(src_ip_bytes)
    dst_ip = socket.inet_ntoa(dst_ip_bytes)

    src_port, dst_port, udp_len = struct.unpack_from("!HHH", ip_pkt, ihl)
    if port_filter and src_port != port_filter and dst_port != port_filter:
        return None

    if len(ip_pkt) < ihl + udp_len:
        udp_payload = ip_pkt[ihl + 8 :]
    else:
        udp_payload = ip_pkt[ihl + 8 : ihl + udp_len]

    return (src_ip, src_port, dst_ip, dst_port, udp_payload)


def matches_udp_port(ip_pkt: bytes, port: Optional[int]) -> bool:
    """Checks if an IPv4 packet is UDP and matches the specified port."""
    if port is None:
        return True
    if len(ip_pkt) < 20:
        return False
    ver_ihl = ip_pkt[0]
    if (ver_ihl >> 4) != 4:
        return False
    ihl = (ver_ihl & 0x0F) * 4
    if len(ip_pkt) < ihl + 8:
        return False
    if ip_pkt[9] != 17:  # Protocol != UDP
        return False
    src_port, dst_port = struct.unpack_from("!HH", ip_pkt, ihl)
    return src_port == port or dst_port == port


def convert_to_raw_pcap(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    port_filter: Optional[int] = None,
) -> int:
    """
    Converts a PCAPNG (including NFLOG linktypes 141 and 239) or classic PCAP capture
    into a standard classic PCAP with DLT_RAW (Linktype 101) IPv4 packets.
    Returns the number of packets converted.
    """
    in_p = Path(input_path)
    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(in_p, "rb") as in_f, open(out_p, "wb") as out_f:
        # Global header: Magic 0xa1b2c3d4, Version 2.4, thiszone 0, sigfigs 0,
        # snaplen 65535, network Linktype 101 (DLT_RAW)
        out_f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))

        magic = in_f.read(4)
        if len(magic) < 4:
            return 0
        in_f.seek(0)

        if magic == b"\n\r\r\n":
            count = _convert_pcapng_blocks(in_f, out_f, port_filter)
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
            count = _convert_pcap_records(in_f, out_f, magic, port_filter)

    return count


def _convert_pcapng_blocks(in_f, out_f, port_filter: Optional[int]) -> int:
    interfaces = []
    count = 0
    while True:
        hdr = in_f.read(8)
        if len(hdr) < 8:
            break
        block_type, block_len = struct.unpack("<II", hdr)
        if block_len < 8:
            break
        block_body = in_f.read(block_len - 8)
        if len(block_body) < block_len - 8:
            break

        if block_type == 0x00000001:  # IDB
            if len(block_body) >= 8:
                linktype = struct.unpack_from("<H", block_body, 0)[0]
                interfaces.append(linktype)
        elif block_type == 0x00000006:  # EPB
            if len(block_body) >= 20:
                iface_id = struct.unpack_from("<I", block_body, 0)[0]
                ts_high = struct.unpack_from("<I", block_body, 4)[0]
                ts_low = struct.unpack_from("<I", block_body, 8)[0]
                cap_len = struct.unpack_from("<I", block_body, 12)[0]
                linktype = interfaces[iface_id] if iface_id < len(interfaces) else 141
                packet_data = block_body[20 : 20 + cap_len]
                ip_pkt = extract_ip_from_linktype(packet_data, linktype)
                if ip_pkt and matches_udp_port(ip_pkt, port_filter):
                    ts_raw = (ts_high << 32) | ts_low
                    ts_sec = ts_raw // 1_000_000
                    ts_usec = ts_raw % 1_000_000
                    out_f.write(struct.pack("<IIII", ts_sec, ts_usec, len(ip_pkt), len(ip_pkt)))
                    out_f.write(ip_pkt)
                    count += 1
        elif block_type == 0x00000003:  # SPB
            if len(block_body) >= 4:
                orig_len = struct.unpack_from("<I", block_body, 0)[0]
                linktype = interfaces[0] if interfaces else 141
                packet_data = block_body[4 : 4 + orig_len]
                ip_pkt = extract_ip_from_linktype(packet_data, linktype)
                if ip_pkt and matches_udp_port(ip_pkt, port_filter):
                    out_f.write(struct.pack("<IIII", 0, 0, len(ip_pkt), len(ip_pkt)))
                    out_f.write(ip_pkt)
                    count += 1
    return count


def _convert_pcap_records(in_f, out_f, magic: bytes, port_filter: Optional[int]) -> int:
    is_little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
    endian = "<" if is_little else ">"

    ghdr = in_f.read(20)
    if len(ghdr) < 20:
        return 0
    linktype = struct.unpack_from(endian + "I", ghdr, 16)[0]

    count = 0
    while True:
        phdr = in_f.read(16)
        if len(phdr) < 16:
            break
        ts_sec, ts_sub, cap_len, _ = struct.unpack(endian + "IIII", phdr)
        ts_usec = ts_sub // 1000 if is_nano else ts_sub
        packet_data = in_f.read(cap_len)
        if len(packet_data) < cap_len:
            break

        ip_pkt = extract_ip_from_linktype(packet_data, linktype)
        if ip_pkt and matches_udp_port(ip_pkt, port_filter):
            out_f.write(struct.pack("<IIII", ts_sec, ts_usec, len(ip_pkt), len(ip_pkt)))
            out_f.write(ip_pkt)
            count += 1
    return count
