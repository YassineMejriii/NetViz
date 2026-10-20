from __future__ import annotations

import struct
import unittest

from netviz import oui
from netviz.decode import PacketInfo, parse_dhcp_hostname, parse_dns
from netviz.flows import FlowTable

CLIENT = "192.168.1.10"
MAC = "b8:27:eb:44:0a:7c"
SERVER = "140.82.121.4"


def _name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def ptr_response(ip: str, hostname: str) -> bytes:
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = _name(qname) + struct.pack("!HH", 12, 1)
    rdata = _name(hostname)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 60, len(rdata)) + rdata
    return header + question + answer


class OuiTests(unittest.TestCase):
    def test_known_and_local_prefixes(self):
        self.assertIn("Raspberry Pi", oui.vendor_for_mac(MAC))
        self.assertEqual(oui.vendor_for_mac("02:42:ac:11:00:05"),
                         "locally administered")
        self.assertIsNone(oui.vendor_for_mac("ff:ff:ff:ff:ff:ff"))


class HostnameTests(unittest.TestCase):
    def test_dns_ptr_answer(self):
        parsed = parse_dns(ptr_response(CLIENT, "pi.lan"))
        assert parsed is not None
        self.assertEqual(parsed["ptr"], [(CLIENT, "pi.lan")])

    def test_dhcp_option_12(self):
        payload = bytes(236) + b"\x63\x82\x53\x63"
        payload += b"\x0c\x08pi-local\xff"
        self.assertEqual(parse_dhcp_hostname(payload), "pi-local")


class DeviceTests(unittest.TestCase):
    def _packet(self, ts: float, server: str = SERVER, mac: str | None = MAC):
        return PacketInfo(
            ts=ts, src=CLIENT, dst=server, proto="TCP", app="HTTPS",
            length=100, sport=55000, dport=443,
            src_mac=mac, dst_mac="dc:a6:32:11:22:33",
        )

    def test_local_device_rollup(self):
        table = FlowTable()
        table.ingest(self._packet(1.0))
        table.ingest(self._packet(2.0, "93.184.216.34"))
        snapshot = table.snapshot()
        self.assertEqual(snapshot["stats"]["devices"], 1)
        self.assertEqual(len(snapshot["devices"]), 1)
        device = snapshot["devices"][0]
        self.assertEqual(device["key"], MAC)
        self.assertIn("Raspberry Pi", device["vendor"])
        self.assertEqual(device["destinations"], 2)
        self.assertEqual(device["bytes"], 200)
        self.assertEqual(device["apps"], [["HTTPS", 2]])
        self.assertEqual(snapshot["flows"][0]["device"], MAC)
        self.assertIn("Raspberry Pi", snapshot["flows"][0]["client_vendor"])

    def test_ip_fallback_without_mac(self):
        table = FlowTable()
        table.ingest(self._packet(1.0, mac=None))
        device = table.snapshot()["devices"][0]
        self.assertEqual(device["key"], CLIENT)
        self.assertIsNone(device["mac"])

    def test_ptr_and_dhcp_names_attach_to_device(self):
        table = FlowTable()
        table.ingest(self._packet(1.0))
        ptr = PacketInfo(
            ts=2.0, src="192.168.1.1", dst=CLIENT, proto="UDP", app="DNS",
            length=80, sport=53, dport=55001, src_mac="dc:a6:32:11:22:33",
            dst_mac=MAC, dns_ptr=((CLIENT, "pi.lan"),),
        )
        table.ingest(ptr)
        self.assertEqual(table.snapshot()["devices"][0]["hostname"], "pi.lan")
        self.assertEqual(table.snapshot()["devices"][0]["hostname_source"], "ptr")

        dhcp = self._packet(3.0)
        dhcp.sport = 68
        dhcp.dport = 67
        dhcp.proto = "UDP"
        dhcp.app = "DHCP"
        dhcp.dhcp_hostname = "pi-dhcp"
        table.ingest(dhcp)
        device = table.snapshot()["devices"][0]
        self.assertEqual(device["hostname"], "pi-dhcp")
        self.assertEqual(device["hostname_source"], "dhcp")

    def test_public_only_flows_do_not_create_devices(self):
        table = FlowTable()
        packet = PacketInfo(
            ts=1.0, src="8.8.8.8", dst="1.1.1.1", proto="UDP", app="DNS",
            length=80, sport=53, dport=5353,
        )
        table.ingest(packet)
        self.assertEqual(table.snapshot()["devices"], [])


if __name__ == "__main__":
    unittest.main()
