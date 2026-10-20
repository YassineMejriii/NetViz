"""Build the bundled IPv4 -> ASN/country/organization table.

Source feed: https://iptoasn.com/data/ip2asn-v4.tsv.gz
The feed is plain TSV: start-IP, end-IP, ASN, country, organization.
This script converts the dotted ranges to integers, sorts them, and writes a
gzipped table under netviz/data/ so runtime lookups stay in-memory and fast.

Usage:
    python3 -m tests.gen_geoip                  # full feed (default)
    python3 -m tests.gen_geoip --subset cloud   # major cloud/CDN ASNs only
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import urllib.request

SOURCE_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"

# Major cloud, CDN and hosting networks. Kept deliberately small so
# ``--subset cloud`` produces a compact demo/offline bundle.
CLOUD_ASNS = {
    714,      # Apple
    16509,    # Amazon
    14618,    # Amazon
    15169,    # Google
    396982,   # Google Cloud
    8075,     # Microsoft
    20940,    # Akamai
    16625,    # Akamai
    54113,    # Fastly
    13335,    # Cloudflare
    14061,    # DigitalOcean
    16276,    # OVH
    24940,    # Hetzner
    20473,    # Vultr
    63949,    # Linode
    32934,    # Meta
    13414,    # X/Twitter
    2906,     # Netflix
    31898,    # Oracle Cloud
    36459,    # GitHub
}

_USER_AGENT = "netviz-gen-geoip/1.0 (+https://github.com/YassineMejriii/NetViz)"


def ip_to_int(value: str) -> int:
    parts = value.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"not an IPv4 address: {value!r}")
    result = 0
    for part in parts:
        octet = int(part)
        if not 0 <= octet <= 255:
            raise ValueError(f"not an IPv4 address: {value!r}")
        result = (result << 8) | octet
    return result


def fetch(url: str = SOURCE_URL) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def parse(raw: bytes, subset: str | None = None) -> list[tuple[int, int, int, str, str]]:
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    allow = CLOUD_ASNS if subset == "cloud" else None
    rows: list[tuple[int, int, int, str, str]] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 5:
            continue
        start, end, asn, country, org = fields[:5]
        try:
            asn_value = int(asn)
            start_value = ip_to_int(start)
            end_value = ip_to_int(end)
        except ValueError:
            continue
        if end_value < start_value:
            continue
        if allow is not None and asn_value not in allow:
            continue
        rows.append((start_value, end_value, asn_value, country, org))
    rows.sort(key=lambda row: (row[0], row[1]))
    return rows


def write(rows: list[tuple[int, int, int, str, str]], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz:
        with io.TextIOWrapper(gz, encoding="utf-8", newline="\n") as fh:
            fh.write("# netviz ip2asn v4 table\n")
            fh.write(f"# source: {SOURCE_URL}\n")
            fh.write("# columns: start end asn country org\n")
            for start, end, asn, country, org in rows:
                fh.write(f"{start}\t{end}\t{asn}\t{country}\t{org}\n")
    with open(path, "wb") as fh:
        fh.write(buffer.getvalue())


def main() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=SOURCE_URL, help="ip2asn TSV(.gz) feed URL")
    parser.add_argument("--out", default=os.path.join(
        root, "netviz", "data", "ip2asn-v4.tsv.gz"), help="output path")
    parser.add_argument("--subset", choices=("cloud",), default=None,
                        help="restrict the bundle to major cloud/CDN ASNs")
    args = parser.parse_args()

    rows = parse(fetch(args.url), args.subset)
    write(rows, args.out)
    size = os.path.getsize(args.out)
    print(f"wrote {args.out}: {len(rows)} ranges, {size} bytes")


if __name__ == "__main__":
    main()
