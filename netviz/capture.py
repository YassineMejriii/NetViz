"""Packet sources: live AF_PACKET capture, pcap replay, synthetic demo."""

from __future__ import annotations

import hashlib
import os
import random
import socket
import struct
import time

from .decode import (
    LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP,
    LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2, LINKTYPE_RAW, PacketInfo, decode_frame,
)
from .pcap import iter_pcap

PACKET_MR_PROMISC = 1
ETH_P_ALL = 0x0003
SO_RCVBUF_WANT = 8 * 1024 * 1024


def list_interfaces() -> list[dict]:
    base = "/sys/class/net"
    out = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for name in names:
        if name == "lo":
            continue
        info = {"name": name, "type": "?", "state": "?"}
        try:
            with open(f"{base}/{name}/type") as fh:
                hw = int(fh.read().strip())
            info["type"] = {
                1: "ethernet", 772: "loopback", 801: "802.11",
                803: "802.11+radiotap", 65534: "tunnel",
            }.get(hw, f"hw/{hw}")
        except (OSError, ValueError):
            pass
        try:
            with open(f"{base}/{name}/operstate") as fh:
                info["state"] = fh.read().strip()
        except OSError:
            pass
        out.append(info)
    return out


def default_interface() -> str:
    try:
        with open("/proc/net/route") as fh:
            for line in fh.read().splitlines()[1:]:
                fields = line.split()
                if len(fields) < 4:
                    continue
                if fields[1] == "00000000" and int(fields[3], 16) & 0x1:
                    return fields[0]
    except (OSError, ValueError):
        pass
    return "eth0"


def interface_linktype(iface: str) -> int:
    try:
        with open(f"/sys/class/net/{iface}/type") as fh:
            hw = int(fh.read().strip())
    except (OSError, ValueError):
        return LINKTYPE_ETHERNET
    if hw == 1:
        return LINKTYPE_ETHERNET
    if hw == 772:
        return LINKTYPE_ETHERNET
    if hw == 801:
        return LINKTYPE_IEEE802_11
    if hw == 803:
        return LINKTYPE_IEEE802_11_RADIOTAP
    if hw == 65534:
        return LINKTYPE_RAW
    return LINKTYPE_ETHERNET


class LiveSource:
    kind = "live"

    def __init__(self, iface: str, promisc: bool = True):
        self.iface = iface
        self.promisc = promisc
        self.linktype = interface_linktype(iface)
        self.sock = None

    def _open(self):
        linktype = self.linktype
        if linktype == LINKTYPE_RAW:
            proto = 0x0003
        elif linktype in (LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP):
            proto = 0x0003
        else:
            proto = ETH_P_ALL
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
        sock.bind((self.iface, 0))
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_WANT)
        except OSError:
            pass
        if self.promisc:
            try:
                index = socket.if_nametoindex(self.iface)
                mreq = struct.pack("IHH8s", index, PACKET_MR_PROMISC, 0, b"")
                sock.setsockopt(socket.SOL_PACKET, 1, mreq)
            except OSError:
                pass
        sock.settimeout(0.5)
        self.sock = sock

    def packets(self):
        if self.sock is None:
            self._open()
        try:
            while True:
                try:
                    data, _addr = self.sock.recvfrom(262144)
                except socket.timeout:
                    continue
                ts = time.time()
                pkt = decode_frame(data, self.linktype, ts)
                if pkt is not None:
                    yield pkt
        finally:
            self.close()

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class PcapSource:
    kind = "pcap"

    def __init__(self, path: str, speed: float = 1.0):
        self.path = path
        self.speed = speed
        self.frames: list[tuple[float, int, bytes, int]] = []

    def packets(self):
        t_first = None
        t_wall = None
        start = time.time()
        for ts, linktype, data, orig in iter_pcap(self.path):
            if ts <= 0:
                ts = time.time()
            if t_first is None:
                t_first = ts
                t_wall = time.monotonic()
            if self.speed > 0:
                target = (ts - t_first) / self.speed
                delay = target - (time.monotonic() - t_wall)
                if delay > 0:
                    time.sleep(min(delay, 2.0))
            pkt = decode_frame(data, linktype, ts)
            if pkt is not None:
                yield pkt
        self.finished_at = time.time()
        self.duration = time.time() - start


DEMO_HOSTS = [
    ("github.com", "140.82.121.4", "HTTPS"),
    ("api.github.com", "140.82.121.6", "HTTPS"),
    ("cdn.jsdelivr.net", "151.101.1.229", "HTTPS"),
    ("fonts.gstatic.com", "142.250.185.131", "HTTPS"),
    ("www.google.com", "142.250.185.196", "HTTPS"),
    ("www.youtube.com", "142.250.190.78", "HTTPS"),
    ("i.ytimg.com", "142.250.191.134", "HTTPS"),
    ("api.spotify.com", "35.186.224.47", "HTTPS"),
    ("graph.facebook.com", "31.13.71.36", "HTTPS"),
    ("ocsp.digicert.com", "93.184.220.29", "HTTPS"),
    ("api.openai.com", "104.18.33.45", "HTTPS"),
    ("registry.npmjs.org", "104.16.24.34", "HTTPS"),
    ("cdn.discordapp.com", "162.159.128.233", "HTTPS"),
    ("gateway.discord.gg", "162.159.135.232", "HTTPS"),
    ("slack.com", "3.33.130.190", "HTTPS"),
    ("api.slack.com", "44.213.4.180", "HTTPS"),
    ("www.cloudflare.com", "104.16.132.229", "HTTPS"),
    ("static.cloudflareinsights.com", "104.16.147.203", "HTTPS"),
    ("duckduckgo.com", "52.149.246.39", "HTTPS"),
    ("imgur.com", "151.101.0.193", "HTTPS"),
    ("news.ycombinator.com", "209.216.230.240", "HTTP"),
    ("archive.ubuntu.com", "91.189.91.81", "HTTPS"),
    ("api.stripe.com", "54.187.174.169", "HTTPS"),
    ("s3.amazonaws.com", "52.216.8.131", "HTTPS"),
    ("telemetry.mozilla.org", "35.244.181.201", "HTTPS"),
]

DEMO_CLIENTS = [
    ("192.168.1.10", "a4:83:e7:2b:4c:91"),
    ("192.168.1.11", "3c:22:fb:9a:11:02"),
    ("192.168.1.12", "b8:27:eb:44:0a:7c"),
    ("10.0.0.5", "02:42:ac:11:00:05"),
]

DEMO_JA3 = [
    hashlib.md5(s.encode()).hexdigest()
    for s in (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0",
        "771,4865-4866-4867-49195-49199-52393-52392-49196-49200,0-10-11-35-16-5-13-51-45-43-27-23,29-23-24-25,0",
        "771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,29-23-24-25-256-257,0",
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25-256-257,0",
    )
]

DEMO_DNS = [
    ("192.168.1.1", "router.lan"),
    ("1.1.1.1", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google"),
]


class DemoSource:
    kind = "demo"

    def __init__(self, seed: int = 7):
        self.seed = seed

    def packets(self):
        rng = random.Random(self.seed)
        sessions = []
        started = time.time()
        while True:
            now = time.time()
            if not sessions or rng.random() < 0.08:
                session = self._new_session(rng, now)
                sessions.append(session)
                if len(sessions) > 48:
                    sessions.pop(rng.randrange(len(sessions)))
            else:
                session = rng.choice(sessions)
            reverse = rng.random() < 0.42
            pkt = self._packet_from(session, now, reverse, rng)
            yield pkt
            elapsed = now - started
            if elapsed < 2:
                delay = rng.uniform(0.008, 0.06)
            elif len(sessions) < 12:
                delay = rng.uniform(0.01, 0.09)
            else:
                delay = rng.uniform(0.02, 0.22)
            time.sleep(delay)

    def _new_session(self, rng, now):
        client, mac = rng.choice(DEMO_CLIENTS)
        roll = rng.random()
        if roll < 0.09:
            resolver, resolver_name = rng.choice(DEMO_DNS)
            host, ip, _app = rng.choice(DEMO_HOSTS)
            return {
                "client": client, "mac": mac, "server": resolver,
                "sport": rng.randrange(32768, 60999), "dport": 53,
                "proto": "UDP", "app": "DNS", "host": host, "sni": None,
                "qtype": rng.choice(("A", "AAAA")), "ja3": None,
                "alpn": None, "tls": None, "answers": ((ip, host),),
                "sni_source": "dns", "resolver_name": resolver_name,
            }
        if roll < 0.17:
            host, ip, _app = rng.choice(DEMO_HOSTS)
            return {
                "client": client, "mac": mac, "server": ip,
                "sport": rng.randrange(32768, 60999), "dport": 443,
                "proto": "UDP", "app": "QUIC", "host": None, "sni": None,
                "qtype": None, "ja3": None, "alpn": "h3",
                "tls": "TLS1.3", "answers": (), "sni_source": None,
                "qname": host,
            }
        if roll < 0.22:
            host, ip, _app = rng.choice(DEMO_HOSTS)
            return {
                "client": client, "mac": mac, "server": ip,
                "sport": rng.randrange(32768, 60999), "dport": 80,
                "proto": "TCP", "app": "HTTP", "host": host, "sni": None,
                "qtype": None, "ja3": None, "alpn": None, "tls": None,
                "answers": (), "sni_source": "http",
                "path": rng.choice(("/", "/index.html", "/api/v1/status", "/assets/app.js")),
                "method": rng.choice(("GET", "GET", "POST")),
            }
        host, ip, _app = rng.choice(DEMO_HOSTS)
        return {
            "client": client, "mac": mac, "server": ip,
            "sport": rng.randrange(32768, 60999), "dport": 443,
            "proto": "TCP", "app": "HTTPS", "host": host, "sni": host,
            "qtype": None, "ja3": rng.choice(DEMO_JA3),
            "alpn": rng.choice(("h2", "h2", "http/1.1")),
            "tls": rng.choice(("TLS1.3", "TLS1.3", "TLS1.2")),
            "answers": (), "sni_source": "sni",
        }

    def _packet_from(self, s, ts, reverse, rng):
        sport, dport = s["sport"], s["dport"]
        src, dst = s["client"], s["server"]
        src_mac = s["mac"]
        dst_mac = "ff:ff:ff:ff:ff:ff" if s["app"] == "DNS" else "dc:a6:32:11:22:33"
        if reverse:
            src, dst = dst, src
            sport, dport = dport, sport
            src_mac, dst_mac = dst_mac, src_mac
        app = s["app"]
        if app == "HTTPS":
            length = rng.choice((74, 74, 90, 571, 1200, 1400, 66, 1420, 320, 980))
            flags = "PA" if rng.random() < 0.7 else "A"
        elif app == "QUIC":
            length = rng.choice((1200, 1252, 90, 64, 1350))
            flags = ""
        elif app == "DNS":
            length = rng.choice((73, 89, 121, 137, 105))
            flags = ""
        elif app == "HTTP":
            length = rng.choice((140, 260, 420, 780, 1180, 96))
            flags = "PA"
        else:
            length = rng.choice((60, 66, 120, 300))
            flags = "A"
        pkt = PacketInfo(
            ts=ts, src=src, dst=dst, proto=s["proto"], app=app,
            length=length, sport=sport, dport=dport,
            ttl=rng.choice((64, 64, 128, 255)) if not reverse else rng.choice((52, 55, 57, 64)),
            ip_version=4, tcp_flags=flags, payload_len=max(0, length - 40),
            src_mac=src_mac, dst_mac=dst_mac,
        )
        if app == "HTTPS" and not reverse:
            pkt.sni = s["sni"]
            pkt.host = s["sni"]
            pkt.host_source = "sni"
            pkt.ja3 = s["ja3"]
            pkt.alpn = s["alpn"]
            pkt.tls_version = s["tls"]
        elif app == "HTTP" and not reverse:
            pkt.host = s["host"]
            pkt.host_source = "http"
            pkt.http_method = s["method"]
            pkt.http_path = s["path"]
        elif app == "DNS":
            pkt.dns_qname = s["host"]
            pkt.dns_qtype = s["qtype"]
            pkt.host = s["host"]
            pkt.host_source = "dns"
            if reverse:
                pkt.dns_answers = s["answers"]
        elif app == "QUIC" and not reverse:
            pkt.host = None
        return pkt
