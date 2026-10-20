from __future__ import annotations

import unittest

from netviz import geoip
from netviz.decode import PacketInfo
from netviz.flows import FlowTable

CLIENT = "192.168.1.10"


class GeoipLookupTests(unittest.TestCase):
    def test_public_ipv4_ranges(self):
        self.assertEqual(geoip.lookup("1.1.1.1"), (13335, "CLOUDFLARENET", "US"))
        self.assertEqual(geoip.lookup("8.8.8.8")[0], 15169)
        self.assertEqual(geoip.lookup("140.82.121.4")[0], 36459)

    def test_unknown_and_ipv6_are_cleanly_skipped(self):
        self.assertIsNone(geoip.lookup("2001:db8::1"))
        self.assertIsNone(geoip.lookup("not-an-ip"))
        self.assertIsNone(geoip.lookup(None))

    def test_generator_parses_dotted_ranges(self):
        from tests import gen_geoip
        raw = (b"1.2.3.4\t1.2.3.7\t64500\tZZ\tExample Org\n"
               b"# comment\n"
               b"1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARENET\n")
        rows = gen_geoip.parse(raw)
        self.assertEqual(gen_geoip.ip_to_int("1.2.3.4"), 0x01020304)
        self.assertEqual(rows[0][2], 13335)
        self.assertEqual(rows[1][2], 64500)
        self.assertEqual(gen_geoip.parse(raw, "cloud"), [(0x01010100,
                                                          0x010101FF,
                                                          13335, "US",
                                                          "CLOUDFLARENET")])


class FlowGeoipTests(unittest.TestCase):
    def _packet(self, server: str, ts: float = 1.0) -> PacketInfo:
        return PacketInfo(
            ts=ts, src=CLIENT, dst=server, proto="TCP", app="HTTPS",
            length=100, sport=55000, dport=443,
        )

    def test_public_flow_is_enriched_and_rolled_up(self):
        table = FlowTable()
        table.ingest(self._packet("1.1.1.1"))
        snapshot = table.snapshot()
        flow = snapshot["flows"][0]
        self.assertEqual(flow["asn"], 13335)
        self.assertEqual(flow["org"], "CLOUDFLARENET")
        self.assertEqual(flow["country"], "US")
        top = snapshot["stats"]["top_orgs"][0]
        self.assertEqual(top["org"], "CLOUDFLARENET")
        self.assertEqual(top["asn"], 13335)
        self.assertEqual(top["country"], "US")
        self.assertEqual(top["bytes"], 100)
        self.assertEqual(top["flows"], 1)

    def test_private_and_local_flows_are_not_enriched(self):
        table = FlowTable()
        table.ingest(self._packet("192.168.1.5"))
        flow = table.snapshot()["flows"][0]
        self.assertIsNone(flow["asn"])
        self.assertIsNone(flow["org"])
        self.assertIsNone(flow["country"])
        self.assertEqual(table.snapshot()["stats"]["top_orgs"], [])


if __name__ == "__main__":
    unittest.main()
