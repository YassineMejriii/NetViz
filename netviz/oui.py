"""IEEE OUI prefix lookup backed by a bundled, compact vendor table."""

from __future__ import annotations

import gzip
import os
import threading

DATA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "oui.tsv.gz")

_lock = threading.Lock()
_vendors: dict[str, str] | None = None
_failed = False


def _normalise(mac: str | None) -> str | None:
    if not mac:
        return None
    digits = "".join(ch for ch in str(mac).lower() if ch in "0123456789abcdef")
    if len(digits) < 6:
        return None
    return digits


def load() -> dict[str, str] | None:
    global _vendors, _failed
    if _vendors is not None:
        return _vendors
    if _failed:
        return None
    with _lock:
        if _vendors is not None:
            return _vendors
        if _failed:
            return None
        table: dict[str, str] = {}
        try:
            with gzip.open(DATA_PATH, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    prefix, sep, vendor = line.partition("\t")
                    if sep and len(prefix) >= 6:
                        table[prefix.strip().upper()] = vendor.strip()
        except (OSError, EOFError, ValueError):
            _failed = True
            return None
        _vendors = table
        return table


def vendor_for_mac(mac: str | None) -> str | None:
    digits = _normalise(mac)
    if digits is None:
        return None
    try:
        first = int(digits[:2], 16)
    except ValueError:
        return None
    if first & 0x01:
        return None
    table = load()
    if table:
        for width in (9, 7, 6):
            if len(digits) >= width:
                vendor = table.get(digits[:width].upper())
                if vendor:
                    return vendor
    if first & 0x02:
        return "locally administered"
    return None
