from __future__ import annotations

import argparse
import os
import sys
import webbrowser

from . import __version__
from .capture import (
    DemoSource, LiveSource, PcapSource, default_interface, list_interfaces,
)
from .server import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netviz",
        description="Live WiFi/network traffic console: IPs, destinations, "
                    "TLS SNI, JA3, DNS and timing in the browser.",
    )
    parser.add_argument("-i", "--iface", help="capture interface (default: route interface)")
    parser.add_argument("--pcap", help="replay a .pcap / .pcapng file instead of live capture")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="pcap replay speed, 1.0 = real time, 0 = unthrottled")
    parser.add_argument("--demo", action="store_true", help="run with synthetic traffic")
    parser.add_argument("--port", type=int, default=8710, help="HTTP/WebSocket port")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost)")
    parser.add_argument("--max-flows", type=int, default=8000, help="flow table cap")
    parser.add_argument("--no-promisc", action="store_true", help="disable promiscuous mode")
    parser.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    parser.add_argument("--list", action="store_true", help="list interfaces and exit")
    parser.add_argument("--version", action="version", version=f"netviz {__version__}")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        print(f"{'IFACE':<18} {'TYPE':<18} STATE")
        for iface in list_interfaces():
            print(f"{iface['name']:<18} {iface['type']:<18} {iface['state']}")
        return 0

    if args.demo and args.pcap:
        print("netviz: choose --demo or --pcap, not both", file=sys.stderr)
        return 2

    if args.demo:
        source = DemoSource()
        iface = "demo"
    elif args.pcap:
        if not os.path.isfile(args.pcap):
            print(f"netviz: no such pcap: {args.pcap}", file=sys.stderr)
            return 2
        source = PcapSource(args.pcap, speed=args.speed)
        iface = os.path.basename(args.pcap)
    else:
        iface = args.iface or default_interface()
        try:
            source = LiveSource(iface, promisc=not args.no_promisc)
        except OSError as exc:
            print(f"netviz: cannot open {iface}: {exc}", file=sys.stderr)
            return 1
        if os.geteuid() != 0:
            print("netviz: live capture needs CAP_NET_RAW - if the socket is refused, "
                  "re-run with sudo or use --demo / --pcap", file=sys.stderr)

    info = {
        "iface": iface,
        "mode": source.kind,
        "source": getattr(source, "path", iface),
        "linktype": getattr(source, "linktype", None),
        "version": __version__,
        "notice": None,
    }

    def ready(server):
        host, port = server.server_address[0], server.server_address[1]
        shown = "localhost" if host in ("127.0.0.1", "::1", "0.0.0.0", "::") else host
        url = f"http://{shown}:{port}/"
        print(f"netviz {__version__} | mode={source.kind} iface={iface}", flush=True)
        print(f"dashboard: {url}", flush=True)
        if host not in ("127.0.0.1", "::1"):
            print("warning: bound beyond localhost, dashboard has no auth - "
                  "captured traffic is exposed to that network")
        if args.open:
            webbrowser.open(url)

    serve(source, args.host, args.port, info, max_flows=args.max_flows, on_ready=ready)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
