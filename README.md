# netviz

A browser dashboard for live WiFi/LAN traffic. It parses packets the way
Wireshark does at the header level and turns them into **flows**:

- client IP and port → destination IP and port
- destination host from **TLS SNI**, **DNS** queries/answers, or **HTTP Host**
- timing (first seen, last seen, duration, live packet/byte rate)
- protocol, application (HTTPS / QUIC / DNS / HTTP / SSH / …), bytes and
  packet counts per direction, TTL, TCP flags, MAC addresses
- **JA3** TLS fingerprint, ALPN, negotiated TLS version
- DNS answer cache that labels IP-only flows (e.g. QUIC) after the lookup
- pcap/pcapng replay and synthetic demo mode

Everything is pure Python standard library plus vanilla JS. No pip installs,
no build step, no external assets.

## Quick start

```bash
# synthetic traffic, no privileges needed
./run.sh --demo

# replay the bundled capture
./run.sh --pcap sample.pcap --speed 1

# live capture on the default-route interface (needs CAP_NET_RAW)
sudo ./run.sh -i wlan0

# list interfaces
./run.sh --list
```

Open <http://localhost:8710/>. Press `/` to focus the filter, `Esc` to close
the flow drawer.

## What is visible without decryption

| Layer | What netviz reads |
|---|---|
| IP | src/dst address, version, TTL/hop limit, length |
| TCP/UDP | ports, flags, window, payload size |
| TLS | ClientHello **SNI**, **JA3**, ALPN, offered version |
| DNS | query name/type, answer A/AAAA records (with compression) |
| HTTP | method, path, `Host` header (cleartext port 80 only) |

HTTPS **paths and payloads are not visible** — the connection is encrypted
after the handshake. netviz shows the destination host from SNI, the
fingerprint, and the traffic volume. QUIC carries the same limitation; its
host is inferred from DNS answers when available. Encrypted Client Hello
(ECH) hides SNI entirely.

## Live WiFi capture

Normal managed mode only shows traffic to and from your own machine. To see
all frames on the air, put the adapter into monitor mode:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo ./run.sh -i wlan0
```

A monitor interface is locked to one channel. To survey, hop channels while
capturing:

```bash
while true; do
  for ch in 1 6 11 36 40 44 48 149 153 157 161; do
    sudo iw dev wlan0 set channel "$ch"
    sleep 0.5
  done
done
```

The decoder handles radiotap + 802.11 data frames (including QoS and
four-address frames), plus Ethernet, Linux cooked capture, and raw IP.
Monitor mode captures frames from the air; use it on networks you own or are
authorised to monitor.

If live capture prints `permission denied`, either run with `sudo` or grant
the interpreter the capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v python3)")"
```

`setcap` applies to every script using that interpreter, so `sudo` is the
less surprising option.

## Replay and demo

```bash
./run.sh --pcap capture.pcap --speed 0     # as fast as possible
./run.sh --pcap capture.pcapng --speed 2   # 2x real time
python3 -m tests.gen_fixture               # rebuild sample.pcap
```

Capture files produced by `tcpdump`, `dumpcap`, Wireshark, or `tshark` work.
Classic pcap is supported in both byte orders and micro/nanosecond variants;
pcapng supports SHB/IDB/EPB/SPB blocks and per-interface timestamp resolution.
Windows and macOS have no `AF_PACKET`: capture there with `dumpcap`/`tcpdump`
and use `--pcap`.

## Options

```
-i, --iface IFACE    capture interface (default: route interface)
    --pcap PATH      replay a .pcap/.pcapng instead of live capture
    --speed N        replay speed, 1.0 = real time, 0 = unthrottled
    --demo           synthetic traffic (no privileges)
    --port N         HTTP/WebSocket port (default 8710)
    --host ADDR      bind address (default 127.0.0.1)
    --max-flows N    flow table cap (default 8000)
    --no-promisc     disable promiscuous mode
    --open           open the dashboard in a browser
    --list           list interfaces and exit
```

## Interface

- **Flow table** — one row per connection, both directions collapsed.
  Sort by time/packets/bytes, filter by host, IP, port, JA3, or app, toggle
  HTTPS-only. Click a row for the full record.
- **Destinations** — top destinations by bytes.
- **TLS fingerprints** — JA3 groups and how much traffic each carries.
- **New destinations** — hosts as they first appear.
- **Throughput** — bytes/s area and packets/s line over the last 3 minutes.
- **Constellation** — clients on the left, destinations on the right, animated
  edge particles weighted by volume.
- **Pause** — freezes the view and asks the server to stop streaming; resume
  requests a fresh snapshot.
- **CSV / JSON** — exports the currently filtered view.

Exports include first/last timestamps, addresses and ports, host and host
source, SNI, DNS name, HTTP request, TLS metadata, JA3, byte/packet counts
per direction, TTL, flags, MACs and the flow id.

## How it works

```
netviz/
  netviz/decode.py    link/network/transport + TLS/DNS/HTTP parsing
  netviz/capture.py   AF_PACKET live source, pcap replay, demo source
  netviz/pcap.py      classic pcap + pcapng reader
  netviz/flows.py     client/server normalization, aggregation, stats
  netviz/server.py    stdlib HTTP + WebSocket server, broadcast loop
  web/                dashboard (no framework, no CDN)
tests/                frame builders, unit tests, sample capture generator
```

Flow direction is normalized by port: the well-known/low port is the server,
so requests and responses aggregate into one row. TLS ClientHello records are
parsed directly from TCP payload bytes; JA3 is the MD5 of
`version,ciphers,extensions,curves,point_formats` with GREASE values removed.
DNS answers maintain an IP→host cache that enriches flows that carry no
cleartext name.

The capture thread decodes packets, the flow table aggregates them under a
lock, and a broadcast thread pushes deltas plus one-second series buckets over
WebSocket every 250 ms. The browser keeps a flow map and re-renders at most
about five times per second.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

The suite covers Ethernet/IPv4/IPv6, radiotap/802.11, TCP flags, SNI/JA3/ALPN,
DNS compression, HTTP hosts, flow normalization, DNS enrichment, and pcap /
pcapng round trips.

## Notes

- Default bind is `127.0.0.1` and there is no authentication. Binding with
  `--host 0.0.0.0` exposes captured traffic to that network.
- Throughput is limited by single-threaded Python decoding; expect roughly
  tens of thousands of packets per second on a modern machine, not line rate.
- The flow table is in memory and capped (`--max-flows`); the oldest idle
  flows are evicted first.

---

Built by ☠ SYSTEM BREACHED ☠ —◥꧁ SHΔDØW HΛCKΞR ꧂◤
