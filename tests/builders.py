"""Byte builders for synthetic packets, pcaps and pcapng files."""

from __future__ import annotations

import ipaddress
import socket
import struct


def mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def eth(src: str, dst: str, payload: bytes, etype: int = 0x0800) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64,
         frag: int = 0, ip_id: int = 1) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, ip_id, frag, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return header + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes, hop: int = 64) -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), nxt, hop) + \
        ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload


def ipv6_ext_hop(src: str, dst: str, nxt: int, payload: bytes) -> bytes:
    ext = bytes([nxt, 0]) + b"\x01\x04\x00\x00\x00\x00"
    return ipv6(src, dst, 0, ext + payload)


def tcp(sport: int, dport: int, payload: bytes = b"", flags: int = 0x18,
        seq: int = 1, ack: int = 1, window: int = 65535) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0,
    )
    return header + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tls_client_hello(host: str | None, alpn: bool = True) -> bytes:
    exts = b""
    if host:
        name = host.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        sni = struct.pack("!H", len(entry)) + entry
        exts += struct.pack("!HH", 0, len(sni)) + sni
    groups = b"\x00\x1d\x00\x17\x00\x18"
    exts += struct.pack("!HH", 10, len(groups)) + groups
    formats = b"\x01\x00"
    exts += struct.pack("!HH", 11, len(formats)) + formats
    if alpn:
        names = b"\x02h2\x08http/1.1"
        payload = struct.pack("!H", len(names)) + names
        exts += struct.pack("!HH", 16, len(payload)) + payload
    versions = b"\x04\x03\x04\x03\x03"
    exts += struct.pack("!HH", 43, len(versions)) + versions
    ciphers = struct.pack("!HHHH", 0x1301, 0x1302, 0xC02B, 0xC02F)
    body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00"
    body += struct.pack("!H", len(ciphers)) + ciphers
    body += b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(name: str, qtype: int = 1, tid: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(name: str, ip: str, qtype: int = 1, tid: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + question + answer


def dns_nxdomain(name: str, qtype: int = 1, tid: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0)
    return header + dns_name(name) + struct.pack("!HH", qtype, 1)


def http_request(host: str, path: str = "/", method: str = "GET") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: netviz-test\r\nAccept: */*\r\n\r\n"
    ).encode()


def ethernet_tcp(src_ip: str, dst_ip: str, sport: int, dport: int,
                 payload: bytes = b"", flags: int = 0x18,
                 src_mac: str = "aa:bb:cc:dd:ee:01",
                 dst_mac: str = "aa:bb:cc:dd:ee:02") -> bytes:
    return eth(src_mac, dst_mac, ipv4(src_ip, dst_ip, 6, tcp(sport, dport, payload, flags)))


def ethernet_udp(src_ip: str, dst_ip: str, sport: int, dport: int,
                 payload: bytes = b"",
                 src_mac: str = "aa:bb:cc:dd:ee:01",
                 dst_mac: str = "aa:bb:cc:dd:ee:02") -> bytes:
    return eth(src_mac, dst_mac, ipv4(src_ip, dst_ip, 17, udp(sport, dport, payload)))


def radiotap_udp(src_ip: str, dst_ip: str, sport: int, dport: int,
                 payload: bytes) -> bytes:
    radiotap = b"\x00\x00\x08\x00" + b"\x00\x00\x00\x00"
    frame_control = b"\x08\x00"
    duration = b"\x00\x00"
    addr1 = b"\xff" * 6
    addr2 = mac("aa:bb:cc:dd:ee:01")
    addr3 = mac("aa:bb:cc:dd:ee:02")
    sequence = b"\x00\x00"
    llc = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
    return radiotap + frame_control + duration + addr1 + addr2 + addr3 + \
        sequence + llc + ipv4(src_ip, dst_ip, 17, udp(sport, dport, payload))


def write_pcap(path: str, frames, linktype: int = 1) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for ts, data in frames:
            usec = int(round((ts % 1) * 1_000_000))
            fh.write(struct.pack("<IIII", int(ts), usec, len(data), len(data)))
            fh.write(data)


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _block(btype: int, body: bytes, endian: str = "<") -> bytes:
    body = _pad4(body)
    total = 12 + len(body)
    return struct.pack(endian + "II", btype, total) + body + struct.pack(endian + "I", total)


def write_pcapng(path: str, frames, linktype: int = 1) -> None:
    out = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += _block(1, struct.pack("<HHI", linktype, 0, 262144))
    for ts, data in frames:
        raw = int(round(ts * 1_000_000))
        body = struct.pack(
            "<IIIII", 0, raw >> 32, raw & 0xFFFFFFFF, len(data), len(data),
        ) + _pad4(data)
        out += _block(6, body)
    with open(path, "wb") as fh:
        fh.write(out)
