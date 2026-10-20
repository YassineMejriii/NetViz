from __future__ import annotations

import os
import tempfile
import time
import unittest

from netviz.decode import (
    LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11_RADIOTAP, decode_frame,
)
from netviz.flows import FlowTable
from netviz.pcap import iter_pcap
from tests import builders as b

TS = 1_760_000_000.0
CLIENT = "192.168.1.10"
CLIENT6 = "2001:db8::10"
SERVER = "140.82.121.4"


def decode(frame: bytes, linktype: int = LINKTYPE_ETHERNET, ts: float = TS):
    return decode_frame(frame, linktype, ts)


class TlsTests(unittest.TestCase):
    def test_client_hello_sni_ja3_alpn(self):
        pkt = decode(b.ethernet_tcp(CLIENT, SERVER, 51234, 443,
                                    b.tls_client_hello("github.com")))
        assert pkt is not None
        self.assertEqual(pkt.src, CLIENT)
        self.assertEqual(pkt.dst, SERVER)
        self.assertEqual(pkt.proto, "TCP")
        self.assertEqual(pkt.app, "HTTPS")
        self.assertEqual((pkt.sport, pkt.dport), (51234, 443))
        self.assertEqual(pkt.sni, "github.com")
        self.assertEqual(pkt.host, "github.com")
        self.assertEqual(pkt.host_source, "sni")
        self.assertEqual(pkt.tls_version, "TLS1.3")
        self.assertEqual(pkt.alpn, "h2,http/1.1")
        self.assertEqual(len(pkt.ja3), 32)
        self.assertEqual(pkt.tcp_flags, "PA")

    def test_tls_without_sni_still_has_ja3(self):
        pkt = decode(b.ethernet_tcp(CLIENT, SERVER, 51234, 443,
                                    b.tls_client_hello(None)))
        assert pkt is not None
        self.assertEqual(pkt.app, "HTTPS")
        self.assertIsNone(pkt.sni)
        self.assertEqual(len(pkt.ja3), 32)

    def test_tls_on_unusual_port_is_detected(self):
        pkt = decode(b.ethernet_tcp(CLIENT, SERVER, 51234, 9443,
                                    b.tls_client_hello("internal.example")))
        assert pkt is not None
        self.assertEqual(pkt.sni, "internal.example")
        self.assertEqual(pkt.app, "TLS")


class DnsTests(unittest.TestCase):
    def test_query(self):
        pkt = decode(b.ethernet_udp(CLIENT, "8.8.8.8", 53555, 53,
                                    b.dns_query("example.com")))
        assert pkt is not None
        self.assertEqual(pkt.app, "DNS")
        self.assertEqual(pkt.proto, "UDP")
        self.assertEqual(pkt.dns_qname, "example.com")
        self.assertEqual(pkt.dns_qtype, "A")
        self.assertEqual(pkt.host, "example.com")
        self.assertEqual(pkt.host_source, "dns")

    def test_response_answers_with_compression(self):
        pkt = decode(b.ethernet_udp("8.8.8.8", CLIENT, 53, 53555,
                                    b.dns_response("example.com", "93.184.216.34")))
        assert pkt is not None
        self.assertEqual(pkt.dns_qname, "example.com")
        self.assertIn(("93.184.216.34", "example.com"), pkt.dns_answers)

    def test_mdns_is_parsed(self):
        pkt = decode(b.ethernet_udp(CLIENT, "224.0.0.251", 5353, 5353,
                                    b.dns_query("printer.local", qtype=1)))
        assert pkt is not None
        self.assertEqual(pkt.app, "mDNS")
        self.assertEqual(pkt.dns_qname, "printer.local")


class HttpTests(unittest.TestCase):
    def test_cleartext_host_and_request(self):
        pkt = decode(b.ethernet_tcp(CLIENT, "209.216.230.240", 49555, 80,
                                    b.http_request("news.ycombinator.com", "/news")))
        assert pkt is not None
        self.assertEqual(pkt.app, "HTTP")
        self.assertEqual(pkt.host, "news.ycombinator.com")
        self.assertEqual(pkt.host_source, "http")
        self.assertEqual(pkt.http_method, "GET")
        self.assertEqual(pkt.http_path, "/news")


class LinkLayerTests(unittest.TestCase):
    def test_radiotap_dot11_data_frame(self):
        frame = b.radiotap_udp(CLIENT, "8.8.8.8", 53555, 53,
                               b.dns_query("example.org"))
        pkt = decode(frame, LINKTYPE_IEEE802_11_RADIOTAP)
        assert pkt is not None
        self.assertEqual(pkt.src, CLIENT)
        self.assertEqual(pkt.dst, "8.8.8.8")
        self.assertEqual(pkt.dns_qname, "example.org")
        self.assertEqual(pkt.src_mac, "aa:bb:cc:dd:ee:01")

    def test_ipv6_tcp(self):
        payload = b.tls_client_hello("ipv6.example")
        frame = b.eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                      b.ipv6(CLIENT6, "2606:4700::6810:84e5", 6,
                             b.tcp(51234, 443, payload)), 0x86DD)
        pkt = decode(frame)
        assert pkt is not None
        self.assertEqual(pkt.ip_version, 6)
        self.assertEqual(pkt.proto, "TCP")
        self.assertEqual(pkt.sni, "ipv6.example")
        self.assertEqual(pkt.ttl, 64)

    def test_ipv6_hop_by_hop_extension(self):
        frame = b.eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                      b.ipv6_ext_hop(CLIENT6, "2606:4700::1", 17,
                                     b.udp(53555, 53, b.dns_query("ext.example"))),
                      0x86DD)
        pkt = decode(frame)
        assert pkt is not None
        self.assertEqual(pkt.proto, "UDP")
        self.assertEqual(pkt.app, "DNS")
        self.assertEqual(pkt.dns_qname, "ext.example")


class FlowTests(unittest.TestCase):
    def test_bidirectional_packets_collapse_to_one_flow(self):
        table = FlowTable()
        forward = decode(b.ethernet_tcp(CLIENT, SERVER, 55000, 443,
                                        b.tls_client_hello("example.com")))
        reverse = decode(b.ethernet_tcp(SERVER, CLIENT, 443, 55000, b"", flags=0x10),
                         ts=TS + 0.1)
        table.ingest(forward)
        table.ingest(reverse)
        snap = table.snapshot()
        self.assertEqual(len(snap["flows"]), 1)
        flow = snap["flows"][0]
        self.assertEqual(flow["client"], CLIENT)
        self.assertEqual(flow["server"], SERVER)
        self.assertEqual(flow["c2s_pkts"], 1)
        self.assertEqual(flow["s2c_pkts"], 1)
        self.assertEqual(flow["host"], "example.com")
        self.assertEqual(flow["app"], "HTTPS")

    def test_dns_answer_enriches_later_flow(self):
        table = FlowTable()
        dns = decode(b.ethernet_udp("8.8.8.8", CLIENT, 53, 55000,
                                    b.dns_response("example.com", "93.184.216.34")))
        table.ingest(dns)
        plain = decode(b.ethernet_tcp(CLIENT, "93.184.216.34", 55001, 443,
                                      b"\x16\x03\x03\x00\x04abcd"),
                       ts=TS + 0.2)
        table.ingest(plain)
        flows = table.snapshot()["flows"]
        target = [f for f in flows if f["server"] == "93.184.216.34"]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["host"], "example.com")
        self.assertEqual(target[0]["host_source"], "dns-cache")

    def test_quic_classification(self):
        pkt = decode(b.ethernet_udp(CLIENT, SERVER, 55000, 443, b"\x00" * 40))
        assert pkt is not None
        self.assertEqual(pkt.app, "QUIC")
        self.assertEqual(pkt.proto, "UDP")


class PcapTests(unittest.TestCase):
    def _frames(self):
        frame = b.ethernet_tcp(CLIENT, SERVER, 51234, 443,
                               b.tls_client_hello("github.com"))
        return [(TS + 0.25, frame), (TS + 1.5, frame)]

    def test_classic_pcap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.pcap")
            b.write_pcap(path, self._frames())
            records = list(iter_pcap(path))
            self.assertEqual(len(records), 2)
            ts, linktype, data, orig = records[0]
            self.assertAlmostEqual(ts, TS + 0.25, places=5)
            self.assertEqual(linktype, 1)
            self.assertEqual(orig, len(data))
            pkt = decode_frame(data, linktype, ts)
            self.assertEqual(pkt.sni, "github.com")

    def test_pcapng(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.pcapng")
            b.write_pcapng(path, self._frames())
            records = list(iter_pcap(path))
            self.assertEqual(len(records), 2)
            ts, linktype, data, orig = records[0]
            self.assertAlmostEqual(ts, TS + 0.25, places=5)
            self.assertEqual(linktype, 1)
            pkt = decode_frame(data, linktype, ts)
            self.assertEqual(pkt.sni, "github.com")


if __name__ == "__main__":
    unittest.main()
