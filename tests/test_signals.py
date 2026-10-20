from __future__ import annotations

import unittest

from netviz.decode import LINKTYPE_ETHERNET, PacketInfo, decode_frame
from netviz.flows import FlowTable, _is_dga_label
from tests import builders as b

CLIENT = "192.168.1.10"
SERVER = "140.82.121.4"
RESOLVER = "8.8.8.8"


def _packet(ts: float, **kwargs) -> PacketInfo:
    values = {
        "ts": ts, "src": CLIENT, "dst": SERVER, "proto": "TCP",
        "app": "HTTPS", "length": 100, "sport": 55000, "dport": 443,
    }
    values.update(kwargs)
    return PacketInfo(**values)


def _kinds(table: FlowTable) -> list[str]:
    return [signal["kind"] for signal in table.snapshot()["signals"]]


class DnsSignalTests(unittest.TestCase):
    def test_nxdomain_rcode_is_decoded(self):
        frame = b.ethernet_udp(RESOLVER, CLIENT, 53, 55000,
                               b.dns_nxdomain("missing.example"))
        pkt = decode_frame(frame, LINKTYPE_ETHERNET, 1.0)
        assert pkt is not None
        self.assertEqual(pkt.dns_qname, "missing.example")
        self.assertEqual(pkt.dns_rcode, 3)
        self.assertTrue(pkt.dns_response)

    def test_nxdomain_burst_signal(self):
        table = FlowTable()
        for index in range(5):
            table.ingest(_packet(
                100.0 + index, src=RESOLVER, dst=CLIENT, proto="UDP",
                app="DNS", sport=53, dport=55000, length=80,
                dns_qname=f"missing{index}.example", dns_rcode=3,
                dns_response=True,
            ))
        signals = [s for s in table.snapshot()["signals"]
                   if s["kind"] == "dns-nxdomain"]
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["severity"], 3)
        self.assertIn("NXDOMAIN", signals[0]["detail"])

    def test_dga_like_query_signal(self):
        table = FlowTable()
        table.ingest(_packet(
            1.0, dst=RESOLVER, proto="UDP", app="DNS", sport=55000,
            dport=53, length=80, dns_qname="xk3j9q2m8v7p1z.example.com",
        ))
        table.ingest(_packet(
            2.0, dst=RESOLVER, proto="UDP", app="DNS", sport=55001,
            dport=53, length=80, dns_qname="notifications.example.com",
        ))
        signals = [s for s in table.snapshot()["signals"]
                   if s["kind"] == "dns-dga"]
        self.assertEqual(len(signals), 1)
        self.assertIn("xk3j9q2m8v7p1z", signals[0]["host"])
        self.assertTrue(_is_dga_label("xk3j9q2m8v7p1z"))
        self.assertFalse(_is_dga_label("notifications"))
        self.assertFalse(_is_dga_label("qwertyuiopasdfgh"))


class TlsSignalTests(unittest.TestCase):
    def test_new_ja3_is_reported_once(self):
        table = FlowTable()
        table.ingest(_packet(1.0, ja3="a" * 32))
        table.ingest(_packet(2.0, ja3="a" * 32))
        table.ingest(_packet(3.0, dport=8443, ja3="b" * 32))
        signals = [s for s in table.snapshot()["signals"]
                   if s["kind"] == "new-ja3"]
        self.assertEqual(len(signals), 2)
        self.assertEqual(signals[0]["severity"], 2)


class BeaconSignalTests(unittest.TestCase):
    def test_regular_intervals_are_flagged(self):
        table = FlowTable()
        for index in range(6):
            table.ingest(_packet(100.0 + index * 30.0, host="c2.example"))
        snapshot = table.snapshot()
        signals = [s for s in snapshot["signals"] if s["kind"] == "beacon"]
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["severity"], 4)
        self.assertEqual(signals[0]["client"], CLIENT)
        self.assertEqual(snapshot["signals"][0]["kind"], "beacon")

    def test_irregular_intervals_are_not_flagged(self):
        table = FlowTable()
        moment = 100.0
        for gap in (1.0, 20.0, 3.0, 40.0, 7.0, 90.0):
            table.ingest(_packet(moment))
            moment += gap
        self.assertNotIn("beacon", _kinds(table))


class VolumeSignalTests(unittest.TestCase):
    def test_client_volume_spike(self):
        table = FlowTable()
        for index in range(1, 9):
            table.ingest(_packet(float(index), length=1000))
        table.ingest(_packet(9.0, length=1_000_000))
        signals = [s for s in table.snapshot()["signals"]
                   if s["kind"] == "volume-spike"]
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["severity"], 3)
        self.assertIn("volume", signals[0]["title"])


if __name__ == "__main__":
    unittest.main()
