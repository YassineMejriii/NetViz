"""Flow aggregation, counters, timelines and per-tick deltas."""

from __future__ import annotations

import hashlib
import ipaddress
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from math import log2

from . import geoip, oui
from .decode import PacketInfo

_APP_RANK = {"TCP": 0, "UDP": 0, "TLS": 1}
_FLOW_TIMEOUT = 180.0
_LOCAL_SCOPES = {"private", "link-local", "loopback"}
_MAX_DEVICES = 1024
_NAME_RANK = {"mdns": 1, "dns": 1, "ptr": 2, "dhcp": 3}


def _flow_id(key: tuple) -> str:
    raw = "|".join(str(part) for part in key).encode()
    return hashlib.blake2b(raw, digest_size=6).hexdigest()


def _is_well_known(port: int) -> bool:
    return 0 < port < 1024 or port in (1883, 3306, 3389, 5060, 5432, 5672,
                                       6379, 8080, 8443, 8883, 9092, 9200,
                                       27017)


def _is_dga_label(label: str) -> bool:
    label = label.strip(".").lower()
    if len(label) < 12:
        return False
    counts = Counter(label)
    entropy = -sum((count / len(label)) * log2(count / len(label))
                   for count in counts.values())
    if entropy < 3.5:
        return False
    letters = [ch for ch in label if ch.isalpha()]
    vowels = sum(ch in "aeiou" for ch in letters)
    vowel_ratio = vowels / max(1, len(letters))
    digit_ratio = sum(ch.isdigit() for ch in label) / len(label)
    run = longest = 0
    for ch in letters:
        if ch in "aeiou":
            run = 0
            continue
        run += 1
        longest = max(longest, run)
    return digit_ratio >= 0.15 or vowel_ratio <= 0.2 or longest >= 6


def _canonical(pkt: PacketInfo):
    if not pkt.sport or not pkt.dport:
        if pkt.proto in ("ICMP", "ICMPv6") and pkt.icmp_type in (0, 129):
            return pkt.dst, 0, pkt.src, 0
        return pkt.src, 0, pkt.dst, 0
    a, ap = pkt.src, pkt.sport
    b, bp = pkt.dst, pkt.dport
    a_known = _is_well_known(ap)
    b_known = _is_well_known(bp)
    if a_known and not b_known:
        return b, bp, a, ap
    if b_known and not a_known:
        return a, ap, b, bp
    if ap < bp:
        return b, bp, a, ap
    return a, ap, b, bp


def scope_of(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"
    return "public"


@dataclass
class Flow:
    id: str
    client: str
    cport: int
    server: str
    server_port: int
    proto: str
    app: str
    first: float
    last: float
    packets: int = 0
    bytes: int = 0
    c2s_pkts: int = 0
    s2c_pkts: int = 0
    c2s_bytes: int = 0
    s2c_bytes: int = 0
    host: str | None = None
    host_source: str | None = None
    sni: str | None = None
    ja3: str | None = None
    alpn: str | None = None
    tls_version: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    dns_qname: str | None = None
    ttl: int = 0
    flags: str = ""
    client_mac: str | None = None
    server_mac: str | None = None
    scope: str = "public"
    asn: int | None = None
    org: str | None = None
    country: str | None = None
    hosts: dict = field(default_factory=dict)
    c2s_times: deque = field(default_factory=lambda: deque(maxlen=32))


@dataclass
class Device:
    key: str
    mac: str | None
    ip: str
    vendor: str | None = None
    hostname: str | None = None
    hostname_source: str | None = None
    first: float = 0.0
    last: float = 0.0
    bytes: int = 0
    packets: int = 0
    destinations: set = field(default_factory=set)
    apps: dict = field(default_factory=dict)
    ips: set = field(default_factory=set)


class FlowTable:
    def __init__(self, max_flows: int = 8000, dns_ttl: float = 900.0):
        oui.load()
        geoip.load()
        self.max_flows = max_flows
        self.dns_ttl = dns_ttl
        self.lock = threading.RLock()
        self.flows: dict[tuple, Flow] = {}
        self.lru: OrderedDict = OrderedDict()
        self.dirty: set = set()
        self.removed: deque = deque(maxlen=2000)
        self.signals: deque = deque(maxlen=200)
        self.signaled: set = set()
        self.nxdomain: dict[str, deque] = {}
        self.client_volume: dict[str, deque] = {}
        self.ip_hosts: dict[str, tuple[str, float, str]] = {}
        self.series: deque = deque(maxlen=300)
        self.seen_hosts: set = set()
        self.seen_clients: set = set()
        self.devices: dict[str, Device] = {}
        self.device_by_ip: dict[str, str] = {}
        self.mac_names: dict[str, tuple[str, str]] = {}
        self.boot = time.time()
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.total_packets = 0
        self.total_bytes = 0
        self.scope_cache: dict[str, str] = {}

    # -- ingest ---------------------------------------------------------
    def ingest(self, pkt: PacketInfo) -> None:
        with self.lock:
            self.total_packets += 1
            self.total_bytes += pkt.length
            if self.first_ts is None or pkt.ts < self.first_ts:
                self.first_ts = pkt.ts
            if self.last_ts is None or pkt.ts > self.last_ts:
                self.last_ts = pkt.ts
            self._bucket(pkt.ts, pkt.length)
            source = "mdns" if pkt.app == "mDNS" else "dns"
            for ip, name in pkt.dns_answers:
                if ip and name:
                    self._learn_name(ip, name, source)
            for ip, name in pkt.dns_ptr:
                if ip and name:
                    self._learn_name(ip, name, "ptr")

            client, cport, server, sport = _canonical(pkt)
            self._track_client_volume(client, pkt.ts, pkt.length)
            key = (client, server, pkt.proto, sport)
            flow = self.flows.get(key)
            if flow is not None and "S" in pkt.tcp_flags \
                    and pkt.ts - flow.last > _FLOW_TIMEOUT:
                self._drop(key)
                flow = None
            if flow is None:
                scope = self._scope(server)
                geo = geoip.lookup(server) if scope == "public" else None
                flow = Flow(
                    id=_flow_id(key), client=client, cport=cport,
                    server=server, server_port=sport, proto=pkt.proto,
                    app=pkt.app, first=pkt.ts, last=pkt.ts,
                    scope=scope,
                    asn=geo[0] if geo else None,
                    org=geo[1] if geo else None,
                    country=geo[2] if geo else None,
                )
                self.flows[key] = flow
                self.lru[key] = pkt.ts
                self.seen_clients.add(client)
            else:
                self.lru[key] = pkt.ts
                self.lru.move_to_end(key)

            flow.last = max(flow.last, pkt.ts)
            flow.packets += 1
            flow.bytes += pkt.length
            if pkt.src == client:
                flow.c2s_pkts += 1
                flow.c2s_bytes += pkt.length
                flow.c2s_times.append(pkt.ts)
                if pkt.src_mac:
                    flow.client_mac = pkt.src_mac
                if pkt.dst_mac:
                    flow.server_mac = pkt.dst_mac
            else:
                flow.s2c_pkts += 1
                flow.s2c_bytes += pkt.length
                if pkt.src_mac:
                    flow.server_mac = pkt.src_mac
                if pkt.dst_mac:
                    flow.client_mac = pkt.dst_mac

            if _APP_RANK.get(pkt.app, 2) >= _APP_RANK.get(flow.app, 2):
                flow.app = pkt.app
            flow.ttl = pkt.ttl
            if pkt.tcp_flags:
                flow.flags = pkt.tcp_flags
            self._update_host(flow, pkt)
            if pkt.ja3:
                flow.ja3 = pkt.ja3
                self._check_ja3(flow, pkt)
            if pkt.alpn:
                flow.alpn = pkt.alpn
            if pkt.tls_version:
                flow.tls_version = pkt.tls_version
            if pkt.http_method:
                flow.http_method = pkt.http_method
                flow.http_path = pkt.http_path
            if pkt.dns_qname:
                flow.dns_qname = pkt.dns_qname
            self._check_dns(flow, pkt, client)
            self._check_beacon(flow)
            self._update_device(flow, pkt, client, server)
            self.dirty.add(key)

            while len(self.flows) > self.max_flows:
                old_key, _ = self.lru.popitem(last=False)
                if old_key in self.flows:
                    self._drop(old_key, evict=True)

    def _update_host(self, flow: Flow, pkt: PacketInfo) -> None:
        if pkt.sni:
            flow.sni = pkt.sni
            flow.host = pkt.sni
            flow.host_source = "sni"
        elif pkt.host and flow.host_source != "sni":
            flow.host = pkt.host
            flow.host_source = pkt.host_source or "app"
        if pkt.host:
            host = pkt.host
            self.seen_hosts.add(host)
            flow.hosts[host] = flow.hosts.get(host, 0) + 1
            if len(flow.hosts) > 16:
                weakest = min(flow.hosts, key=flow.hosts.get)
                flow.hosts.pop(weakest, None)
            if flow.host:
                self._signal(
                    "new-host", 1, key=flow.host, ts=flow.last,
                    host=flow.host, ip=flow.server, app=flow.app,
                    ja3=flow.ja3, client=flow.client, flow=flow.id,
                    title="new host", detail="first seen destination",
                )

    def _signal(self, kind: str, severity: int, key: str | None = None,
                ts: float | None = None, host: str | None = None,
                ip: str | None = None, app: str | None = None,
                ja3: str | None = None, client: str | None = None,
                flow: str | None = None, title: str = "",
                detail: str = "") -> None:
        if key is not None:
            if key in self.signaled:
                return
            self.signaled.add(key)
        self.signals.append({
            "ts": ts if ts is not None else time.time(),
            "kind": kind, "severity": severity, "title": title or kind,
            "host": host, "ip": ip, "app": app, "ja3": ja3,
            "client": client, "flow": flow, "detail": detail,
        })

    def _check_ja3(self, flow: Flow, pkt: PacketInfo) -> None:
        if not pkt.ja3:
            return
        self._signal(
            "new-ja3", 2, key=f"ja3:{pkt.ja3}", ts=pkt.ts,
            host=self._display_host(flow), ip=flow.server, app=flow.app,
            ja3=pkt.ja3, client=flow.client, flow=flow.id,
            title="new JA3", detail="TLS fingerprint not seen before",
        )

    def _check_beacon(self, flow: Flow) -> None:
        key = f"beacon:{flow.client}:{flow.server}"
        if key in self.signaled:
            return
        times = list(flow.c2s_times)
        if len(times) < 6:
            return
        intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(intervals) < 5:
            return
        mean = sum(intervals) / len(intervals)
        if not 5.0 <= mean <= 3600.0:
            return
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        ratio = (variance ** 0.5) / mean
        if ratio > 0.2:
            return
        self._signal(
            "beacon", 4, key=key, ts=flow.last,
            host=self._display_host(flow), ip=flow.server, app=flow.app,
            ja3=flow.ja3, client=flow.client, flow=flow.id,
            title="beaconing", detail=f"{mean:.1f}s interval · cv {ratio:.2f}",
        )

    def _track_client_volume(self, client: str, ts: float, length: int) -> None:
        if not self._is_local(client):
            return
        series = self.client_volume.get(client)
        if series is None:
            series = deque(maxlen=60)
            self.client_volume[client] = series
        sec = int(ts)
        new_second = not series or sec > series[-1][0]
        if new_second:
            series.append([sec, length])
        elif sec == series[-1][0]:
            series[-1][1] += length
        else:
            return
        if not new_second or len(series) < 8:
            return
        key = f"volume:{client}:{sec // 30}"
        if key in self.signaled:
            return
        current = series[-1][1]
        prior = list(series)[-11:-1]
        if len(prior) < 5:
            return
        baseline = sum(value for _, value in prior) / len(prior)
        if baseline <= 0 or current < max(250_000, baseline * 5):
            return
        self._signal(
            "volume-spike", 3, key=key, ts=ts, ip=client, client=client,
            host=client, title="volume spike",
            detail=f"{current / 1024:.0f} KB/s vs {baseline / 1024:.0f} KB/s baseline",
        )

    def _check_dns(self, flow: Flow, pkt: PacketInfo, client: str) -> None:
        qname = pkt.dns_qname
        if not qname:
            return
        if pkt.dns_response and pkt.dns_rcode == 3 and self._is_local(client):
            events = self.nxdomain.get(client)
            if events is None:
                events = deque(maxlen=64)
                self.nxdomain[client] = events
            events.append(pkt.ts)
            while events and pkt.ts - events[0] > 30:
                events.popleft()
            if len(events) >= 5:
                self._signal(
                    "dns-nxdomain", 3, key=f"nx:{client}:{int(pkt.ts // 60)}",
                    ts=pkt.ts, host=qname, ip=flow.server, app="DNS",
                    client=client, flow=flow.id, title="NXDOMAIN burst",
                    detail=f"{len(events)} NXDOMAIN responses in 30s",
                )
        if not pkt.dns_response:
            label = qname.split(".")[0]
            if _is_dga_label(label):
                self._signal(
                    "dns-dga", 3, key=f"dga:{client}:{qname}", ts=pkt.ts,
                    host=qname, ip=flow.server, app="DNS", client=client,
                    flow=flow.id, title="DGA-like domain",
                    detail=f"random-looking label '{label[:32]}'",
                )

    def _is_local(self, ip: str) -> bool:
        return self._scope(ip) in _LOCAL_SCOPES

    @staticmethod
    def _usable_mac(mac: str | None) -> str | None:
        if not mac:
            return None
        digits = "".join(ch for ch in str(mac).lower() if ch in "0123456789abcdef")
        if len(digits) != 12 or digits == "000000000000":
            return None
        try:
            first = int(digits[:2], 16)
        except ValueError:
            return None
        if first & 0x01:
            return None
        return ":".join(digits[i:i + 2] for i in range(0, 12, 2))

    def _update_device(self, flow: Flow, pkt: PacketInfo, client: str,
                       server: str) -> None:
        if pkt.dhcp_hostname:
            mac = self._usable_mac(pkt.src_mac) or self._usable_mac(pkt.dst_mac)
            if mac:
                self._learn_mac_name(mac, pkt.dhcp_hostname, "dhcp")
        if self._is_local(client):
            ip, peer = client, server
            mac = pkt.src_mac if pkt.src == client else pkt.dst_mac
        elif self._is_local(server):
            ip, peer = server, client
            mac = pkt.src_mac if pkt.src == server else pkt.dst_mac
        else:
            return
        device = self._device_for(ip, self._usable_mac(mac))
        if device is None:
            return
        device.first = pkt.ts if not device.first else min(device.first, pkt.ts)
        device.last = max(device.last, pkt.ts)
        device.bytes += pkt.length
        device.packets += 1
        device.ips.add(ip)
        if peer != ip and len(device.destinations) < 4096:
            device.destinations.add(peer)
        device.apps[pkt.app] = device.apps.get(pkt.app, 0) + 1

    def _device_for(self, ip: str, mac: str | None) -> Device | None:
        old_key = self.device_by_ip.get(ip)
        if mac:
            key = mac
            device = self.devices.get(key)
            if old_key and old_key != key:
                old = self.devices.pop(old_key, None)
                if old is not None:
                    if device is None:
                        old.key = key
                        old.mac = mac
                        if not old.vendor:
                            old.vendor = oui.vendor_for_mac(mac)
                        self.devices[key] = old
                        for old_ip in old.ips:
                            self.device_by_ip[old_ip] = key
                        device = old
                    else:
                        self._merge_device(device, old)
            if device is None:
                device = Device(key=key, mac=mac, ip=ip,
                                vendor=oui.vendor_for_mac(mac))
                self.devices[key] = device
                self._apply_cached_name(device)
                self._trim_devices()
            self.device_by_ip[ip] = key
        else:
            key = old_key or ip
            device = self.devices.get(key)
            if device is None:
                device = Device(key=key, mac=None, ip=ip)
                self.devices[key] = device
                self._apply_cached_name(device)
                self._trim_devices()
            self.device_by_ip[ip] = device.key
        device.ips.add(ip)
        return device

    def _merge_device(self, target: Device, source: Device) -> None:
        target.first = min(target.first or source.first, source.first or target.first)
        target.last = max(target.last, source.last)
        target.bytes += source.bytes
        target.packets += source.packets
        target.destinations.update(source.destinations)
        target.ips.update(source.ips)
        for app, count in source.apps.items():
            target.apps[app] = target.apps.get(app, 0) + count
        if _NAME_RANK.get(source.hostname_source, 0) > _NAME_RANK.get(
                target.hostname_source, 0):
            target.hostname = source.hostname
            target.hostname_source = source.hostname_source
        for ip in source.ips:
            self.device_by_ip[ip] = target.key

    def _apply_cached_name(self, device: Device) -> None:
        entry = self.ip_hosts.get(device.ip)
        if entry is not None and entry[1] >= time.time():
            self._set_device_name(device, entry[0], entry[2])
        cached = self.mac_names.get(device.mac) if device.mac else None
        if cached is not None:
            self._set_device_name(device, cached[0], cached[1])

    def _set_device_name(self, device: Device, name: str, source: str) -> None:
        name = name.strip().strip(".").lower()
        if not name:
            return
        if _NAME_RANK.get(source, 0) < _NAME_RANK.get(device.hostname_source, 0):
            return
        device.hostname = name
        device.hostname_source = source

    def _learn_mac_name(self, mac: str, name: str, source: str) -> None:
        mac = self._usable_mac(mac)
        if not mac:
            return
        self.mac_names[mac] = (name, source)
        if len(self.mac_names) > 4096:
            self.mac_names.pop(next(iter(self.mac_names)), None)
        device = self.devices.get(mac)
        if device is not None:
            self._set_device_name(device, name, source)

    def _trim_devices(self) -> None:
        if len(self.devices) <= _MAX_DEVICES:
            return
        overflow = len(self.devices) - _MAX_DEVICES
        for key in sorted(self.devices, key=lambda k: self.devices[k].last)[:overflow]:
            device = self.devices.pop(key, None)
            if device is None:
                continue
            for ip in device.ips:
                if self.device_by_ip.get(ip) == key:
                    self.device_by_ip.pop(ip, None)

    def _bucket(self, ts: float, length: int) -> None:
        sec = int(ts)
        if not self.series or sec > self.series[-1][0]:
            self.series.append([sec, 1, length])
        elif sec == self.series[-1][0]:
            self.series[-1][1] += 1
            self.series[-1][2] += length

    def _learn_name(self, ip: str, name: str, source: str = "dns") -> None:
        name = name.strip(".").lower()
        if not name or name == "localhost":
            return
        self.ip_hosts[ip] = (name, time.time() + self.dns_ttl, source)
        key = self.device_by_ip.get(ip)
        if key is not None:
            device = self.devices.get(key)
            if device is not None:
                self._set_device_name(device, name, source)
        if len(self.ip_hosts) > 40000:
            for old in list(self.ip_hosts)[:8000]:
                self.ip_hosts.pop(old, None)

    def _resolve(self, ip: str) -> str | None:
        entry = self.ip_hosts.get(ip)
        if entry is None:
            return None
        name, expiry, _source = entry
        if expiry < time.time():
            self.ip_hosts.pop(ip, None)
            return None
        return name

    def _scope(self, ip: str) -> str:
        cached = self.scope_cache.get(ip)
        if cached is None:
            cached = scope_of(ip)
            if len(self.scope_cache) > 20000:
                self.scope_cache.clear()
            self.scope_cache[ip] = cached
        return cached

    def _drop(self, key, evict: bool = False) -> None:
        flow = self.flows.pop(key, None)
        self.lru.pop(key, None)
        self.dirty.discard(key)
        if flow is not None and evict:
            self.removed.append(flow.id)

    def _display_host(self, flow: Flow) -> str | None:
        if flow.host:
            return flow.host
        return self._resolve(flow.server)

    def _flow_device(self, flow: Flow) -> Device | None:
        if self._is_local(flow.client):
            key = self.device_by_ip.get(flow.client)
        elif self._is_local(flow.server):
            key = self.device_by_ip.get(flow.server)
        else:
            return None
        return self.devices.get(key) if key else None

    def _device_export(self, device: Device) -> dict:
        apps = sorted(device.apps.items(), key=lambda kv: -kv[1])[:6]
        return {
            "key": device.key,
            "mac": device.mac,
            "ip": device.ip,
            "ips": sorted(device.ips),
            "vendor": device.vendor,
            "hostname": device.hostname,
            "hostname_source": device.hostname_source,
            "first": device.first,
            "last": device.last,
            "destinations": len(device.destinations),
            "bytes": device.bytes,
            "packets": device.packets,
            "apps": [list(item) for item in apps],
        }

    def _devices(self, limit: int = 400) -> list[dict]:
        devices = sorted(self.devices.values(), key=lambda d: (-d.last, -d.bytes))
        return [self._device_export(device) for device in devices[:limit]]

    # -- export ---------------------------------------------------------
    def _export(self, flow: Flow) -> dict:
        host = self._display_host(flow)
        source = flow.host_source if flow.host else ("dns-cache" if host else None)
        hosts = sorted(flow.hosts.items(), key=lambda kv: -kv[1])[:6]
        device = self._flow_device(flow)
        return {
            "id": flow.id,
            "client": flow.client,
            "cport": flow.cport,
            "server": flow.server,
            "server_port": flow.server_port,
            "proto": flow.proto,
            "app": flow.app,
            "host": host,
            "host_source": source,
            "sni": flow.sni,
            "ja3": flow.ja3,
            "alpn": flow.alpn,
            "tls_version": flow.tls_version,
            "http_method": flow.http_method,
            "http_path": flow.http_path,
            "dns_qname": flow.dns_qname,
            "first": flow.first,
            "last": flow.last,
            "packets": flow.packets,
            "bytes": flow.bytes,
            "c2s_pkts": flow.c2s_pkts,
            "s2c_pkts": flow.s2c_pkts,
            "c2s_bytes": flow.c2s_bytes,
            "s2c_bytes": flow.s2c_bytes,
            "ttl": flow.ttl,
            "flags": flow.flags,
            "client_mac": flow.client_mac,
            "server_mac": flow.server_mac,
            "scope": flow.scope,
            "asn": flow.asn,
            "org": flow.org,
            "country": flow.country,
            "hosts": [list(item) for item in hosts],
            "client_vendor": oui.vendor_for_mac(flow.client_mac),
            "server_vendor": oui.vendor_for_mac(flow.server_mac),
            "device": device.key if device else None,
            "device_hostname": device.hostname if device else None,
        }

    def _top_signals(self, limit: int = 60) -> list[dict]:
        return sorted(
            self.signals,
            key=lambda item: (-int(item.get("severity", 1)), -float(item.get("ts", 0))),
        )[:limit]

    def snapshot(self, info: dict | None = None, limit: int = 6000) -> dict:
        with self.lock:
            flows = sorted(self.flows.values(), key=lambda f: -f.last)[:limit]
            return {
                "type": "snapshot",
                "info": info or {},
                "stats": self._stats(),
                "flows": [self._export(f) for f in flows],
                "devices": self._devices(),
                "series": list(self.series),
                "signals": self._top_signals(),
            }

    def tick(self) -> dict:
        with self.lock:
            keys = list(self.dirty)
            if len(keys) > 2000:
                keys = keys[:2000]
            for key in keys:
                self.dirty.discard(key)
            flows = []
            for key in keys:
                flow = self.flows.get(key)
                if flow is not None:
                    flows.append(self._export(flow))
            removed = list(self.removed)
            self.removed.clear()
            return {
                "type": "tick",
                "flows": flows,
                "removed": removed,
                "devices": self._devices(),
                "stats": self._stats(),
                "series": list(self.series),
                "signals": self._top_signals(),
            }

    def _stats(self) -> dict:
        now = time.time()
        ref = self.series[-1][0] if self.series else now
        window = [s for s in self.series if ref - s[0] < 5]
        pps = sum(s[1] for s in window) / 5.0
        bps = sum(s[2] for s in window) / 5.0
        apps: dict[str, int] = {}
        dests: dict[str, dict] = {}
        orgs: dict[str, dict] = {}
        ja3s: dict[str, dict] = {}
        https_hosts = set()
        vendors: dict[str, int] = {}
        for device in self.devices.values():
            vendor = device.vendor or "unknown"
            vendors[vendor] = vendors.get(vendor, 0) + 1
        for flow in self.flows.values():
            apps[flow.app] = apps.get(flow.app, 0) + 1
            host = self._display_host(flow)
            label = host or flow.server
            if flow.app in ("DNS", "mDNS"):
                label = flow.server
            bucket = dests.get(label)
            if bucket is None:
                bucket = {
                    "label": label, "ip": flow.server, "app": flow.app,
                    "bytes": 0, "packets": 0, "flows": 0,
                }
                dests[label] = bucket
            bucket["bytes"] += flow.bytes
            bucket["packets"] += flow.packets
            bucket["flows"] += 1
            org_label = flow.org or (f"AS{flow.asn}" if flow.asn else None)
            if flow.scope == "public" and org_label:
                bucket = orgs.get(org_label)
                if bucket is None:
                    bucket = {
                        "org": org_label, "asn": flow.asn,
                        "country": flow.country, "bytes": 0,
                        "packets": 0, "flows": 0,
                    }
                    orgs[org_label] = bucket
                bucket["bytes"] += flow.bytes
                bucket["packets"] += flow.packets
                bucket["flows"] += 1
            if flow.ja3:
                item = ja3s.get(flow.ja3)
                if item is None:
                    item = {"ja3": flow.ja3, "flows": 0, "bytes": 0,
                            "app": flow.app}
                    ja3s[flow.ja3] = item
                item["flows"] += 1
                item["bytes"] += flow.bytes
            if flow.app == "HTTPS" and host:
                https_hosts.add(host)
        top_dest = sorted(dests.values(), key=lambda d: -d["bytes"])[:10]
        top_orgs = sorted(orgs.values(), key=lambda d: -d["bytes"])[:10]
        top_ja3 = sorted(ja3s.values(), key=lambda d: -d["flows"])[:6]
        top_apps = sorted(apps.items(), key=lambda kv: -kv[1])[:12]
        return {
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "pps": round(pps, 1),
            "bps": round(bps),
            "flows": len(self.flows),
            "hosts": len(self.seen_hosts),
            "https_hosts": len(https_hosts),
            "clients": len(self.seen_clients),
            "devices": len(self.devices),
            "top_vendors": sorted(vendors.items(), key=lambda kv: -kv[1])[:8],
            "apps": [[name, count] for name, count in top_apps],
            "top_dest": top_dest,
            "top_orgs": top_orgs,
            "top_ja3": top_ja3,
            "uptime": now - self.boot,
            "span": (self.last_ts - self.first_ts) if self.first_ts else 0,
        }
