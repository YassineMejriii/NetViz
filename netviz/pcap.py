"""Minimal pcap / pcapng reader (classic, nanosecond, all byte orders)."""

from __future__ import annotations

import struct

_PCAP_MAGICS = (0xA1B2C3D4, 0xA1B23C4D)
_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_PB = 0x00000002
_SPB = 0x00000003
_EPB = 0x00000006


def _int(data, endian: str) -> int:
    return int.from_bytes(data, "little" if endian == "<" else "big")


def iter_pcap(path: str):
    """Yield (timestamp, linktype, frame_bytes, original_length)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            return
        if head == b"\x0a\x0d\x0d\x0a":
            fh.seek(0)
            yield from _iter_pcapng(fh)
            return
        yield from _iter_classic(fh, head)


def _iter_classic(fh, head: bytes):
    le = int.from_bytes(head, "little")
    be = int.from_bytes(head, "big")
    if le in _PCAP_MAGICS:
        endian = "<"
        nano = le == 0xA1B23C4D
    elif be in _PCAP_MAGICS:
        endian = ">"
        nano = be == 0xA1B23C4D
    else:
        raise ValueError("not a pcap file")
    rest = fh.read(20)
    if len(rest) < 20:
        return
    network = struct.unpack(endian + "I", rest[16:20])[0]
    scale = 1e9 if nano else 1e6
    linktype = network & 0x03FFFFFF
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", rec)
        if incl > 0x4000000:
            return
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield ts_sec + ts_frac / scale, linktype, data, orig


class _Section:
    def __init__(self):
        self.endian = "<"
        self.interfaces = []


def _iter_pcapng(fh):
    section = _Section()
    if not _read_shb(fh, section):
        return
    while True:
        header = fh.read(8)
        if len(header) < 8:
            return
        btype = _int(header[0:4], section.endian)
        blen = _int(header[4:8], section.endian)
        if btype == _SHB:
            fh.seek(-8, 1)
            section = _Section()
            if not _read_shb(fh, section):
                return
            continue
        if blen < 12 or blen > 0x8000000:
            return
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        payload = body[:blen - 12]
        if btype == _IDB:
            section.interfaces.append(_parse_idb(payload, section.endian))
        elif btype == _EPB and len(payload) >= 20:
            yield from _parse_epb(payload, section.interfaces, section.endian)
        elif btype == _PB and len(payload) >= 20:
            yield from _parse_pb(payload, section.interfaces, section.endian)
        elif btype == _SPB and len(payload) >= 4:
            if section.interfaces:
                iface = section.interfaces[0]
                orig = _int(payload[0:4], section.endian)
                data = payload[4:]
                if orig and len(data) > orig:
                    data = data[:orig]
                yield 0.0, iface["linktype"], data, orig


def _read_shb(fh, section) -> bool:
    header = fh.read(12)
    if len(header) < 12:
        return False
    bom = header[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":
        section.endian = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        section.endian = ">"
    else:
        return False
    blen = _int(header[4:8], section.endian)
    if blen < 28 or blen > 0x8000000:
        return False
    fh.read(blen - 12)
    section.interfaces = []
    return True


def _parse_idb(payload, endian):
    linktype = _int(payload[0:2], endian)
    tsresol = 6
    pos = 8
    while pos + 4 <= len(payload):
        code = _int(payload[pos:pos + 2], endian)
        olen = _int(payload[pos + 2:pos + 4], endian)
        pos += 4
        if pos + olen > len(payload):
            break
        if code == 0:
            break
        if code == 9 and olen >= 1:
            tsresol = payload[pos]
        pos += (olen + 3) & ~3
    if tsresol & 0x80:
        divisor = float(2 ** (tsresol & 0x7F))
    else:
        divisor = float(10 ** tsresol)
    return {"linktype": linktype, "divisor": divisor}


def _timestamp(high, low, iface):
    return ((high << 32) | low) / iface["divisor"]


def _parse_epb(payload, interfaces, endian):
    iface_id = _int(payload[0:4], endian)
    if iface_id >= len(interfaces) and interfaces:
        iface_id = 0
    high = _int(payload[4:8], endian)
    low = _int(payload[8:12], endian)
    caplen = _int(payload[12:16], endian)
    orig = _int(payload[16:20], endian)
    data = payload[20:20 + caplen]
    iface = interfaces[iface_id] if interfaces else {"linktype": 1, "divisor": 1e6}
    yield _timestamp(high, low, iface), iface["linktype"], data, orig


def _parse_pb(payload, interfaces, endian):
    iface_id = _int(payload[0:2], endian)
    if iface_id >= len(interfaces) and interfaces:
        iface_id = 0
    high = _int(payload[4:8], endian)
    low = _int(payload[8:12], endian)
    caplen = _int(payload[12:16], endian)
    orig = _int(payload[16:20], endian)
    data = payload[20:20 + caplen]
    iface = interfaces[iface_id] if interfaces else {"linktype": 1, "divisor": 1e6}
    yield _timestamp(high, low, iface), iface["linktype"], data, orig
