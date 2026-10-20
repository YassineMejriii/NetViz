"""Generate sample.pcap so the dashboard can be demoed without root."""

from __future__ import annotations

import os
import random
import time

from tests import builders as b

CLIENTS = [
    ("192.168.1.10", "a4:83:e7:2b:4c:91"),
    ("192.168.1.11", "3c:22:fb:9a:11:02"),
    ("192.168.1.12", "b8:27:eb:44:0a:7c"),
]

HOSTS = [
    ("github.com", "140.82.121.4", "140.82.121.6"),
    ("www.google.com", "142.250.185.196", "142.250.185.197"),
    ("fonts.gstatic.com", "142.250.185.131", "142.250.185.132"),
    ("cdn.jsdelivr.net", "151.101.1.229", "151.101.1.230"),
    ("api.spotify.com", "35.186.224.47", "35.186.224.48"),
    ("cdn.discordapp.com", "162.159.128.233", "162.159.128.234"),
    ("api.openai.com", "104.18.33.45", "104.18.33.46"),
    ("api.stripe.com", "54.187.174.169", "54.187.174.170"),
    ("www.cloudflare.com", "104.16.132.229", "104.16.132.230"),
    ("imgur.com", "151.101.0.193", "151.101.0.194"),
]

SERVER_MAC = "dc:a6:32:11:22:33"


def pad(rng, payload: bytes, size: int) -> bytes:
    if size <= len(payload):
        return payload
    return payload + rng.randbytes(size - len(payload))


def build() -> list[tuple[float, bytes]]:
    rng = random.Random(42)
    base = time.time() - 40
    frames: list[tuple[float, bytes]] = []

    def add(t, frame):
        frames.append((t, frame))

    seq = 0
    for index, (host, ip, ip2) in enumerate(HOSTS):
        client, cmac = CLIENTS[index % len(CLIENTS)]
        sport = 41000 + index * 137
        t = base + index * 1.8
        hello = b.tls_client_hello(host)
        add(t, b.eth(cmac, SERVER_MAC,
                     b.ipv4(client, ip, 6, b.tcp(
                         sport, 443, pad(rng, hello, rng.choice((571, 812, 1200))))), 0x0800))
        for step in range(1, 6):
            direction_up = step % 2 == 1
            size = rng.choice((66, 90, 320, 740, 1180, 1400))
            payload = rng.randbytes(max(0, size - 54))
            if direction_up:
                add(t + step * 0.35, b.eth(
                    cmac, SERVER_MAC,
                    b.ipv4(client, ip, 6, b.tcp(sport, 443, payload, flags=0x18)), 0x0800))
            else:
                add(t + step * 0.35, b.eth(
                    SERVER_MAC, cmac,
                    b.ipv4(ip, client, 6, b.tcp(443, sport, payload, flags=0x10)), 0x0800))
        # second address for the same host, client-initiated
        add(t + 2.2, b.eth(cmac, SERVER_MAC,
                           b.ipv4(client, ip2, 6, b.tcp(
                               sport + 1, 443,
                               pad(rng, b.tls_client_hello(host), 640))), 0x0800))

    # DNS lookups
    for i, (host, ip, _) in enumerate(HOSTS[:6]):
        client, cmac = CLIENTS[i % len(CLIENTS)]
        t = base + 4 + i * 2.4
        sport = 52000 + i * 41
        add(t, b.eth(cmac, "dc:a6:32:11:22:33",
                     b.ipv4(client, "192.168.1.1", 17,
                            b.udp(sport, 53, b.dns_query(host))), 0x0800))
        add(t + 0.04, b.eth("dc:a6:32:11:22:33", cmac,
                            b.ipv4("192.168.1.1", client, 17,
                                   b.udp(53, sport, b.dns_response(host, ip))), 0x0800))

    # cleartext HTTP
    client, cmac = CLIENTS[0]
    add(base + 9, b.eth(cmac, SERVER_MAC,
                        b.ipv4(client, "209.216.230.240", 6, b.tcp(
                            49888, 80, b.http_request("news.ycombinator.com", "/news"))), 0x0800))
    add(base + 9.1, b.eth(SERVER_MAC, cmac,
                          b.ipv4("209.216.230.240", client, 6, b.tcp(
                              80, 49888, b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhello, world!",
                              flags=0x18)), 0x0800))

    # QUIC (encrypted, no SNI - host appears after DNS enrichment)
    client, cmac = CLIENTS[1]
    sport = 53000
    for step in range(8):
        add(base + 12 + step * 0.25, b.eth(cmac, SERVER_MAC,
                                           b.ipv4(client, "142.250.190.78", 17,
                                                  b.udp(sport, 443, rng.randbytes(
                                                      rng.choice((1200, 90, 1300))))), 0x0800))
        add(base + 12.12 + step * 0.25, b.eth(SERVER_MAC, cmac,
                                              b.ipv4("142.250.190.78", client, 17,
                                                     b.udp(443, sport, rng.randbytes(
                                                         rng.choice((1200, 1252))))), 0x0800))

    # IPv6 TLS
    client, cmac = CLIENTS[2]
    client6 = "2001:db8::12"
    frame = b.eth(cmac, SERVER_MAC,
                  b.ipv6(client6, "2606:4700:10::6816:84e5", 6,
                         b.tcp(50505, 443, pad(rng, b.tls_client_hello("www.cloudflare.com"), 900))),
                  0x86DD)
    add(base + 18, frame)
    add(base + 18.4, b.eth(SERVER_MAC, cmac,
                           b.ipv6("2606:4700:10::6816:84e5", client6, 6,
                                  b.tcp(443, 50505, rng.randbytes(1200), flags=0x10)), 0x86DD))

    # ssh to the LAN
    client, cmac = CLIENTS[0]
    for step in range(4):
        add(base + 22 + step * 0.6, b.eth(cmac, "b8:27:eb:44:0a:7c",
                                          b.ipv4(client, "192.168.1.5", 6,
                                                 b.tcp(55022, 22, rng.randbytes(
                                                     rng.choice((96, 132, 180))),
                                                     flags=0x18 if step % 2 else 0x10)), 0x0800))

    frames.sort(key=lambda item: item[0])
    return frames


def main() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "sample.pcap")
    frames = build()
    b.write_pcap(path, frames)
    print(f"wrote {path}: {len(frames)} frames")


if __name__ == "__main__":
    main()
