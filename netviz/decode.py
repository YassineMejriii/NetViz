"""Frame decoding: link layer -> network -> transport -> visible metadata.

Stdlib only. Handles Ethernet, Linux cooked capture, radiotap/802.11,
IPv4/IPv6, TCP/UDP, and the metadata that survives without decryption:
TLS SNI, JA3, ALPN, DNS names/answers and cleartext HTTP requests.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IEEE802_11 = 105
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_LINUX_SLL2 = 276

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)

_TCP_FLAG_CHARS = (
    (0x01, "F"),
    (0x02, "S"),
    (0x04, "R"),
    (0x08, "P"),
    (0x10, "A"),
    (0x20, "U"),
    (0x40, "E"),
    (0x80, "C"),
)

_SERVICES = {
    "TCP": {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "SMTP", 853: "DoT", 993: "IMAPS", 995: "POP3S",
        1080: "SOCKS", 1883: "MQTT", 3306: "MySQL", 3389: "RDP",
        5060: "SIP", 5432: "PostgreSQL", 5672: "AMQP", 6379: "Redis",
        8080: "HTTP", 8443: "HTTPS", 8883: "MQTT", 9092: "Kafka",
        9200: "Elastic", 27017: "MongoDB",
    },
    "UDP": {
        53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
        137: "NetBIOS", 161: "SNMP", 443: "QUIC", 500: "IKE",
        1900: "SSDP", 3478: "STUN", 4500: "IKE", 5353: "mDNS",
        5355: "LLMNR", 51820: "WireGuard",
    },
}

_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
    143: "Ethernet",
}

_TLS_VERSIONS = {
    0x0300: "SSL3", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
    0x0303: "TLS1.2", 0x0304: "TLS1.3",
}

_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG",
    64: "SVCB", 65: "HTTPS", 255: "ANY",
}

_HTTP_METHODS = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
    b"PATCH ", b"CONNECT ", b"TRACE ",
)


@dataclass(slots=True)
class PacketInfo:
    ts: float
    src: str
    dst: str
    proto: str
    app: str
    length: int
    sport: int = 0
    dport: int = 0
    ttl: int = 0
    ip_version: int = 4
    tcp_flags: str = ""
    tcp_window: int = 0
    payload_len: int = 0
    host: str | None = None
    host_source: str | None = None
    sni: str | None = None
    ja3: str | None = None
    alpn: str | None = None
    tls_version: str | None = None
    dns_qname: str | None = None
    dns_qtype: str | None = None
    dns_rcode: int = 0
    dns_response: bool = False
    dns_answers: tuple = ()
    dns_ptr: tuple = ()
    dhcp_hostname: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None


def decode_frame(data: bytes, linktype: int, ts: float) -> PacketInfo | None:
    if linktype == LINKTYPE_ETHERNET:
        return _decode_ethernet(data, ts)
    if linktype == LINKTYPE_LINUX_SLL:
        return _decode_sll(data, ts)
    if linktype == LINKTYPE_LINUX_SLL2:
        return _decode_sll2(data, ts)
    if linktype == LINKTYPE_IEEE802_11_RADIOTAP:
        pkt = _decode_radiotap(data, ts)
        return pkt if pkt is not None else _decode_dot11(data, ts)
    if linktype == LINKTYPE_IEEE802_11:
        return _decode_dot11(data, ts)
    if linktype in (LINKTYPE_RAW, 228):
        return _decode_ip(data, 0, ts)
    return None


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _decode_ethernet(data: bytes, ts: float) -> PacketInfo | None:
    if len(data) < 14:
        return None
    dst_mac = _mac(data[0:6])
    src_mac = _mac(data[6:12])
    etype = int.from_bytes(data[12:14], "big")
    off = 14
    while etype in VLAN_TPIDS:
        if len(data) < off + 4:
            return None
        etype = int.from_bytes(data[off + 2:off + 4], "big")
        off += 4
    return _decode_ethertype(etype, data, off, ts, src_mac, dst_mac)


def _decode_ethertype(etype, data, off, ts, src_mac, dst_mac):
    if etype == ETH_P_IP:
        return _decode_ipv4(data, off, ts, src_mac, dst_mac)
    if etype == ETH_P_IPV6:
        return _decode_ipv6(data, off, ts, src_mac, dst_mac)
    if etype == ETH_P_ARP:
        return _decode_arp(data, off, ts, src_mac, dst_mac)
    return None


def _decode_sll(data: bytes, ts: float) -> PacketInfo | None:
    if len(data) < 16:
        return None
    etype = int.from_bytes(data[14:16], "big")
    return _decode_ethertype(etype, data, 16, ts, None, None)


def _decode_sll2(data: bytes, ts: float) -> PacketInfo | None:
    if len(data) < 20:
        return None
    etype = int.from_bytes(data[0:2], "big")
    return _decode_ethertype(etype, data, 20, ts, None, None)


def _decode_radiotap(data: bytes, ts: float) -> PacketInfo | None:
    if len(data) < 8 or data[0] != 0:
        return None
    length = int.from_bytes(data[2:4], "little")
    if length < 8 or length > len(data):
        return None
    return _decode_dot11(data[length:], ts)


def _decode_dot11(data: bytes, ts: float) -> PacketInfo | None:
    if len(data) < 24:
        return None
    fc = data[0]
    if (fc >> 2) & 0x3 != 2:
        return None
    subtype = (fc >> 4) & 0xF
    flags = data[1]
    if flags & 0x40:
        return None
    tods = flags & 0x01
    fromds = flags & 0x02
    hlen = 24
    if tods and fromds:
        hlen += 6
    if subtype & 0x8:
        hlen += 2
    if flags & 0x80:
        hlen += 4
    if len(data) < hlen + 8:
        return None
    a1 = _mac(data[4:10])
    a2 = _mac(data[10:16])
    a3 = _mac(data[16:22])
    if tods and not fromds:
        dst_mac, src_mac = a3, a2
    elif fromds and not tods:
        dst_mac, src_mac = a1, a3
    elif tods and fromds:
        if len(data) < hlen + 2:
            return None
        dst_mac, src_mac = a3, _mac(data[24:30])
    else:
        dst_mac, src_mac = a1, a2
    p = hlen
    if data[p:p + 3] != b"\xaa\xaa\x03" or len(data) < p + 8:
        return None
    etype = int.from_bytes(data[p + 6:p + 8], "big")
    return _decode_ethertype(etype, data, p + 8, ts, src_mac, dst_mac)


def _decode_ip(data: bytes, off: int, ts: float) -> PacketInfo | None:
    if len(data) <= off:
        return None
    version = data[off] >> 4
    if version == 4:
        return _decode_ipv4(data, off, ts, None, None)
    if version == 6:
        return _decode_ipv6(data, off, ts, None, None)
    return None


def _decode_ipv4(data, off, ts, src_mac, dst_mac):
    if len(data) < off + 20:
        return None
    vihl = data[off]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < off + ihl:
        return None
    total = int.from_bytes(data[off + 2:off + 4], "big")
    if total < ihl:
        total = len(data) - off
    total = min(total, len(data) - off)
    frag = int.from_bytes(data[off + 6:off + 8], "big")
    frag_off = frag & 0x1FFF
    ttl = data[off + 8]
    proto_num = data[off + 9]
    src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
    dst = str(ipaddress.IPv4Address(data[off + 16:off + 20]))
    pkt = PacketInfo(
        ts=ts, src=src, dst=dst, proto=_PROTO_NAMES.get(proto_num, f"IP/{proto_num}"),
        app="", length=total, ip_version=4, ttl=ttl, src_mac=src_mac, dst_mac=dst_mac,
    )
    if frag_off:
        pkt.app = pkt.proto
        pkt.payload_len = max(0, total - ihl)
        return pkt
    _decode_transport(pkt, data, off + ihl, off + total, proto_num)
    return pkt


def _decode_ipv6(data, off, ts, src_mac, dst_mac):
    if len(data) < off + 40:
        return None
    if data[off] >> 4 != 6:
        return None
    plen = int.from_bytes(data[off + 4:off + 6], "big")
    nxt = data[off + 6]
    hop = data[off + 7]
    src = str(ipaddress.IPv6Address(data[off + 8:off + 24]))
    dst = str(ipaddress.IPv6Address(data[off + 24:off + 40]))
    p = off + 40
    end = min(len(data), p + plen) if plen else len(data)
    final = nxt
    fragmented = False
    for _ in range(6):
        if nxt in (0, 43, 60):
            if p + 2 > end:
                break
            hlen = (data[p + 1] + 1) * 8
            final = data[p]
            p += hlen
            nxt = final
        elif nxt == 44:
            if p + 8 > end:
                break
            frag = int.from_bytes(data[p + 2:p + 4], "big")
            final = data[p]
            p += 8
            nxt = final
            if frag & 0xFFF8:
                fragmented = True
                break
        elif nxt == 51:
            if p + 2 > end:
                break
            hlen = (data[p + 1] + 2) * 4
            final = data[p]
            p += hlen
            nxt = final
        else:
            break
    length = (end - off) if plen else (len(data) - off)
    pkt = PacketInfo(
        ts=ts, src=src, dst=dst, proto=_PROTO_NAMES.get(final, f"IPv6/{final}"),
        app="", length=max(40, length), ip_version=6, ttl=hop,
        src_mac=src_mac, dst_mac=dst_mac,
    )
    if fragmented:
        pkt.app = pkt.proto
        pkt.payload_len = max(0, end - p)
        return pkt
    _decode_transport(pkt, data, p, end, final)
    return pkt


def _decode_arp(data, off, ts, src_mac, dst_mac):
    if len(data) < off + 28:
        return None
    op = int.from_bytes(data[off + 6:off + 8], "big")
    sha = _mac(data[off + 8:off + 14])
    spa = str(ipaddress.IPv4Address(data[off + 14:off + 18]))
    tha = _mac(data[off + 18:off + 24])
    tpa = str(ipaddress.IPv4Address(data[off + 24:off + 28]))
    pkt = PacketInfo(
        ts=ts, src=spa, dst=tpa, proto="ARP", app="ARP",
        length=max(28, len(data) - off), ttl=0,
        tcp_flags="request" if op == 1 else "reply",
        src_mac=sha, dst_mac=tha,
    )
    return pkt


def _decode_transport(pkt, data, p, end, proto_num):
    if proto_num == 6:
        _decode_tcp(pkt, data, p, end)
    elif proto_num == 17:
        _decode_udp(pkt, data, p, end)
    elif proto_num in (1, 58):
        pkt.app = "ICMP" if proto_num == 1 else "ICMPv6"
        pkt.payload_len = max(0, end - p)
        if end - p >= 2:
            pkt.icmp_type = data[p]
            pkt.icmp_code = data[p + 1]
    else:
        pkt.app = pkt.proto
        pkt.payload_len = max(0, end - p)


def _decode_tcp(pkt, data, p, end):
    if p + 20 > end:
        return
    sport = int.from_bytes(data[p:p + 2], "big")
    dport = int.from_bytes(data[p + 2:p + 4], "big")
    doff = (data[p + 12] >> 4) * 4
    if doff < 20 or p + doff > end:
        return
    pkt.sport = sport
    pkt.dport = dport
    pkt.tcp_flags = "".join(c for bit, c in _TCP_FLAG_CHARS if data[p + 13] & bit)
    pkt.tcp_window = int.from_bytes(data[p + 14:p + 16], "big")
    payload = data[p + doff:end]
    pkt.payload_len = len(payload)
    pkt.app = _classify("TCP", sport, dport)
    if not payload:
        return
    if payload[:1] == b"\x16":
        tls = parse_client_hello(payload)
        if tls:
            _apply_tls(pkt, tls)
            if pkt.app in ("TCP", "TLS"):
                pkt.app = "TLS"
    if payload.startswith(_HTTP_METHODS):
        http = parse_http(payload)
        if http:
            pkt.http_method, pkt.http_path, host = http
            if host:
                pkt.host = host
                pkt.host_source = "http"
            if pkt.app in ("TCP", "HTTP"):
                pkt.app = "HTTP"


def _decode_udp(pkt, data, p, end):
    if p + 8 > end:
        return
    sport = int.from_bytes(data[p:p + 2], "big")
    dport = int.from_bytes(data[p + 2:p + 4], "big")
    pkt.sport = sport
    pkt.dport = dport
    payload = data[p + 8:end]
    pkt.payload_len = len(payload)
    pkt.app = _classify("UDP", sport, dport)
    if not payload:
        return
    if 53 in (sport, dport) or 5353 in (sport, dport):
        dns = parse_dns(payload)
        if dns:
            pkt.dns_qname = dns["qname"]
            pkt.dns_qtype = dns["qtype"]
            pkt.dns_rcode = dns["rcode"]
            pkt.dns_response = dns["response"]
            pkt.dns_answers = tuple(dns["answers"])
            pkt.dns_ptr = tuple(dns["ptr"])
            if dns["qname"]:
                pkt.host = dns["qname"]
                pkt.host_source = "dns"
    if 67 in (sport, dport) or 68 in (sport, dport):
        hostname = parse_dhcp_hostname(payload)
        if hostname:
            pkt.dhcp_hostname = hostname


def _classify(proto, sport, dport):
    table = _SERVICES.get(proto, {})
    if dport in table:
        return table[dport]
    if sport in table:
        return table[sport]
    return proto


def _apply_tls(pkt, tls):
    if tls.get("sni"):
        pkt.sni = tls["sni"]
        pkt.host = tls["sni"]
        pkt.host_source = "sni"
    if tls.get("ja3"):
        pkt.ja3 = tls["ja3"]
    if tls.get("alpn"):
        pkt.alpn = tls["alpn"]
    if tls.get("version"):
        pkt.tls_version = tls["version"]


def _is_grease(value: int) -> bool:
    return (value >> 8) == (value & 0xFF) and (value & 0x0F0F) == 0x0A0A


def parse_client_hello(data: bytes) -> dict | None:
    if len(data) < 9 or data[0] != 0x16:
        return None
    rec_len = int.from_bytes(data[3:5], "big")
    rec = data[5:5 + rec_len]
    if len(rec) < 4 or rec[0] != 0x01:
        return None
    hs_len = int.from_bytes(rec[1:4], "big")
    body = rec[4:4 + hs_len]
    if len(body) < 35:
        return None
    try:
        p = 0
        legacy = int.from_bytes(body[p:p + 2], "big")
        p += 2 + 32
        sid_len = body[p]
        p += 1 + sid_len
        if p + 2 > len(body):
            return None
        cs_len = int.from_bytes(body[p:p + 2], "big")
        p += 2
        if p + cs_len > len(body):
            return None
        ciphers = []
        for i in range(0, cs_len - 1, 2):
            value = int.from_bytes(body[p + i:p + i + 2], "big")
            if not _is_grease(value):
                ciphers.append(value)
        p += cs_len
        if p + 1 > len(body):
            return None
        comp_len = body[p]
        p += 1 + comp_len
        if p + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[p:p + 2], "big")
        p += 2
        end = min(len(body), p + ext_total)
        sni = alpn = None
        curves: list[int] = []
        points: list[int] = []
        versions: list[int] = []
        ext_order: list[int] = []
        while p + 4 <= end:
            etype = int.from_bytes(body[p:p + 2], "big")
            elen = int.from_bytes(body[p + 2:p + 4], "big")
            p += 4
            if p + elen > end:
                break
            edata = body[p:p + elen]
            if not _is_grease(etype):
                ext_order.append(etype)
            if etype == 0x0000 and len(edata) >= 5:
                nlen = int.from_bytes(edata[3:5], "big")
                if edata[2] == 0 and nlen and len(edata) >= 5 + nlen:
                    sni = edata[5:5 + nlen].decode("ascii", "replace").lower()
            elif etype == 0x000A and len(edata) >= 2:
                total = int.from_bytes(edata[0:2], "big")
                q = 2
                while q + 2 <= min(len(edata), 2 + total):
                    value = int.from_bytes(edata[q:q + 2], "big")
                    if not _is_grease(value):
                        curves.append(value)
                    q += 2
            elif etype == 0x000B and len(edata) >= 1:
                total = edata[0]
                q = 1
                while q < min(len(edata), 1 + total):
                    points.append(edata[q])
                    q += 1
            elif etype == 0x0010 and len(edata) >= 2:
                total = int.from_bytes(edata[0:2], "big")
                q = 2
                names = []
                while q + 1 <= min(len(edata), 2 + total):
                    nlen = edata[q]
                    q += 1
                    if q + nlen > len(edata):
                        break
                    names.append(edata[q:q + nlen].decode("ascii", "replace"))
                    q += nlen
                if names:
                    alpn = ",".join(names)
            elif etype == 0x002B and len(edata) >= 3:
                total = edata[0]
                q = 1
                while q + 2 <= min(len(edata), 1 + total):
                    versions.append(int.from_bytes(edata[q:q + 2], "big"))
                    q += 2
            p += elen
    except (IndexError, ValueError):
        return None
    ja3_input = ",".join((
        str(legacy),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in ext_order),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in points),
    ))
    chosen = versions[0] if versions else legacy
    return {
        "sni": sni,
        "ja3": hashlib.md5(ja3_input.encode()).hexdigest(),
        "ja3_input": ja3_input,
        "alpn": alpn,
        "version": _TLS_VERSIONS.get(chosen, f"0x{chosen:04x}"),
        "legacy_version": legacy,
    }


def _dns_name(buf: bytes, off: int) -> tuple[str, int]:
    labels = []
    pos = off
    end = None
    jumps = 0
    while True:
        if pos >= len(buf) or jumps > 24:
            break
        length = buf[pos]
        if length == 0:
            if end is None:
                end = pos + 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if end is None:
                end = pos + 2
            if ptr >= len(buf):
                break
            pos = ptr
            jumps += 1
            continue
        if length & 0xC0:
            break
        pos += 1
        if pos + length > len(buf):
            break
        labels.append(buf[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def _ptr_to_ip(name: str) -> str | None:
    labels = [label for label in name.strip(".").lower().split(".") if label]
    try:
        if len(labels) >= 6 and labels[-2:] == ["in-addr", "arpa"]:
            parts = labels[:4]
            if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                return str(ipaddress.IPv4Address(".".join(reversed(parts))))
        if labels[-2:] == ["ip6", "arpa"]:
            nibbles = labels[:-2]
            if len(nibbles) == 32 and all(len(n) == 1 for n in nibbles):
                value = int("".join(reversed(nibbles)), 16)
                return str(ipaddress.IPv6Address(value))
    except (IndexError, ValueError):
        return None
    return None


def parse_dns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    _tid, flags, qd, an, _ns, _ar = (
        int.from_bytes(payload[0:2], "big"), int.from_bytes(payload[2:4], "big"),
        int.from_bytes(payload[4:6], "big"), int.from_bytes(payload[6:8], "big"),
        int.from_bytes(payload[8:10], "big"), int.from_bytes(payload[10:12], "big"),
    )
    if qd > 16 or an > 256:
        return None
    qname = None
    qtype = None
    off = 12
    for i in range(qd):
        name, off = _dns_name(payload, off)
        if off + 4 > len(payload):
            break
        rtype = int.from_bytes(payload[off:off + 2], "big")
        off += 4
        if i == 0:
            qname = name
            qtype = _DNS_TYPES.get(rtype, str(rtype))
    answers = []
    ptrs = []
    for _ in range(an):
        name, off = _dns_name(payload, off)
        if off + 10 > len(payload):
            break
        rtype = int.from_bytes(payload[off:off + 2], "big")
        rdlen = int.from_bytes(payload[off + 8:off + 10], "big")
        off += 10
        if off + rdlen > len(payload):
            break
        ip = None
        if rtype == 1 and rdlen == 4:
            ip = str(ipaddress.IPv4Address(payload[off:off + 4]))
        elif rtype == 28 and rdlen == 16:
            ip = str(ipaddress.IPv6Address(payload[off:off + 16]))
        elif rtype == 12 and qname:
            ptr_name, _ = _dns_name(payload, off)
            ptr_ip = _ptr_to_ip(qname)
            if ptr_ip and ptr_name:
                ptrs.append((ptr_ip, ptr_name.strip(".").lower()))
        if ip:
            answers.append((ip, name or qname or ""))
        off += rdlen
    return {
        "qname": (qname or "").lower() or None,
        "qtype": qtype,
        "rcode": flags & 0x000F,
        "response": bool(flags & 0x8000),
        "answers": answers,
        "ptr": ptrs,
    }


def parse_dhcp_hostname(payload: bytes) -> str | None:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    hostname = None
    pos = 240
    while pos < len(payload):
        code = payload[pos]
        pos += 1
        if code == 0:
            continue
        if code == 255:
            break
        if pos >= len(payload):
            break
        length = payload[pos]
        pos += 1
        if pos + length > len(payload):
            break
        if code == 12:
            hostname = payload[pos:pos + length].decode("ascii", "replace").strip()
        pos += length
    if not hostname:
        return None
    return hostname[:255]


def parse_http(payload: bytes):
    head = payload[:8192]
    line_end = head.find(b"\r\n")
    if line_end < 0:
        return None
    request_line = head[:line_end]
    parts = request_line.split(b" ")
    if len(parts) < 2:
        return None
    method = parts[0].decode("ascii", "replace")
    path = parts[1].decode("latin-1", "replace")
    if method.encode() + b" " not in _HTTP_METHODS:
        return None
    if len(path) > 512:
        path = path[:512]
    host = None
    header_end = head.find(b"\r\n\r\n")
    headers = head[line_end + 2:header_end if header_end >= 0 else len(head)]
    for raw_line in headers.split(b"\r\n"):
        if raw_line.lower().startswith(b"host:"):
            host = raw_line[5:].strip().decode("latin-1", "replace").lower()
            if len(host) > 255:
                host = host[:255]
            break
    return method, path, host
