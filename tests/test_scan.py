"""Network scan: parsers for what the network says, and how devices are classified."""

import socket
import struct
import unittest

from collector import scan
from collector.scan import Host, classify, describe


class ArpTests(unittest.TestCase):
    def test_linux_proc_net_arp(self):
        text = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                "192.168.1.1      0x1         0x2         a4:91:b1:12:34:56     *        eth0\n"
                "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n")
        self.assertEqual(scan.parse_arp(text), {"192.168.1.1": "a4:91:b1:12:34:56"})

    def test_windows_arp_a(self):
        text = ("\nInterface: 192.168.1.10 --- 0x5\n"
                "  Internet Address      Physical Address      Type\n"
                "  192.168.1.1           a4-91-b1-12-34-56     dynamic\n"
                "  192.168.1.23          DA-A1-19-00-00-01     dynamic\n"
                "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
                "  224.0.0.251           01-00-5e-00-00-fb     static\n")
        self.assertEqual(scan.parse_arp(text), {"192.168.1.1": "a4:91:b1:12:34:56", "192.168.1.23": "da:a1:19:00:00:01"})

    def test_macos_arp_an(self):
        text = ("? (192.168.1.1) at a4:91:b1:2:34:56 on en0 ifscope [ethernet]\n"
                "? (192.168.1.40) at (incomplete) on en0 ifscope [ethernet]\n")
        self.assertEqual(scan.parse_arp(text), {"192.168.1.1": "a4:91:b1:02:34:56"})

    def test_private_mac(self):
        self.assertTrue(scan.is_private_mac("da:a1:19:00:00:01"))
        self.assertFalse(scan.is_private_mac("a4:91:b1:12:34:56"))


class VendorTests(unittest.TestCase):
    MANUF = ("# comment\n"
             "3C:22:FB\tApple\tApple, Inc.\n"
             "F8:1A:67\tTpLinkTechno\tTp-Link Technologies Co.,Ltd.\n"
             "70:B3:D5:12:30:00/36\tTinyCo\tTiny Devices Ltd\n")

    def test_lookup_prefers_longest_prefix(self):
        oui = scan.OuiDatabase("/nonexistent", download=False)
        oui._db = scan.parse_manuf(self.MANUF)
        self.assertEqual(oui.lookup("3c:22:fb:01:02:03"), "Apple")
        self.assertEqual(oui.lookup("f8:1a:67:01:02:03"), "Tp-Link")
        self.assertEqual(oui.lookup("70:b3:d5:12:30:04"), "Tiny Devices")
        self.assertIsNone(oui.lookup("70:b3:d5:99:99:99"))
        self.assertIsNone(oui.lookup("da:a1:19:00:00:01"))  # private addresses have no maker

    def test_clean_vendor(self):
        self.assertEqual(scan.clean_vendor("Samsung Electronics Co.,Ltd"), "Samsung")
        self.assertEqual(scan.clean_vendor("Sagemcom Broadband SAS"), "Sagemcom Broadband SAS")
        self.assertEqual(scan.clean_vendor("Hewlett Packard"), "Hewlett Packard")


class ProtocolTests(unittest.TestCase):
    def test_nbstat(self):
        header = b"\x13\x37\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
        rr = b"\x00\x21\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x41"
        names = b"\x02" + b"WORKGROUP      \x00\x84\x00" + b"DESKTOP-JM01   \x00\x04\x00"
        self.assertEqual(scan.parse_nbstat(header + rr + names + b"\x00" * 6), "DESKTOP-JM01")
        self.assertIsNone(scan.parse_nbstat(b"short"))

    def test_ssdp_and_upnp_description(self):
        headers = scan.parse_ssdp(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:49152/desc.xml\r\nSERVER: Linux UPnP/1.0\r\n\r\n")
        self.assertEqual(headers["location"], "http://192.168.1.1:49152/desc.xml")
        xml = b"""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <friendlyName>BT Smart Hub 2</friendlyName><manufacturer>Sagemcom</manufacturer>
            <modelName>Smart Hub 2</modelName><serialNumber>+123456</serialNumber>
            <deviceList><device><friendlyName>WAN</friendlyName></device></deviceList></device></root>"""
        info = scan.parse_upnp_description(xml)
        self.assertEqual((info["friendlyName"], info["manufacturer"], info["modelName"]), ("BT Smart Hub 2", "Sagemcom", "Smart Hub 2"))
        self.assertEqual(scan.parse_upnp_description(b"<not xml"), {})

    def test_upnp_fetch_only_follows_the_announcing_address(self):
        self.assertEqual(scan.fetch_upnp("192.168.1.1", "http://203.0.113.9/desc.xml"), {})
        self.assertEqual(scan.fetch_upnp("192.168.1.1", "file:///etc/passwd"), {})

    def test_mdns_query_and_response(self):
        query = scan.mdns_query()
        self.assertEqual(struct.unpack(">H", query[4:6])[0], len(scan.MDNS_SERVICES))

        def name(n):
            return scan._qname(n)

        def rr(owner, rtype, rdata):
            return name(owner) + struct.pack(">HHIH", rtype, 1, 120, len(rdata)) + rdata

        txt = b"".join(bytes([len(x)]) + x for x in (b"md=Chromecast Ultra", b"fn=Living Room TV"))
        packet = struct.pack(">HHHHHH", 0, 0x8400, 0, 3, 0, 1)
        packet += rr("_googlecast._tcp.local", 12, name("Chromecast-Ultra-4d5f._googlecast._tcp.local"))
        packet += rr("Chromecast-Ultra-4d5f._googlecast._tcp.local", 16, txt)
        packet += rr("Chromecast-Ultra-4d5f._googlecast._tcp.local", 33, b"\x00\x00\x00\x00\x1f\x49" + name("4d5f.local"))
        packet += rr("4d5f.local", 1, socket.inet_aton("192.168.1.30"))
        records = scan.parse_mdns(packet)
        self.assertIn(("_googlecast._tcp.local", 12, "Chromecast-Ultra-4d5f._googlecast._tcp.local"), records)
        self.assertIn(("Chromecast-Ultra-4d5f._googlecast._tcp.local", 16, {"md": "Chromecast Ultra", "fn": "Living Room TV"}), records)
        self.assertIn(("4d5f.local", 1, "192.168.1.30"), records)
        self.assertEqual(scan.parse_mdns(b"\x00" * 5), [])


class ClassifyTests(unittest.TestCase):
    def kind(self, vendor=None, **kw):
        return classify(Host("192.168.1.50", **kw), vendor)[0]

    def test_types(self):
        self.assertEqual(self.kind(gateway=True, open_ports={53, 80}), "router")
        self.assertEqual(self.kind("Sagemcom", open_ports={53, 80, 443}), "router")
        self.assertEqual(self.kind("Brother", open_ports={80, 631}), "printer")
        self.assertEqual(self.kind(open_ports={9100}), "printer")
        self.assertEqual(self.kind("Synology", open_ports={5000, 445}), "nas")
        self.assertEqual(self.kind(mdns_services={"_googlecast._tcp"}, mdns_txt={"md": "Chromecast"}), "tv")
        self.assertEqual(self.kind(mdns_services={"_googlecast._tcp"}, mdns_txt={"md": "Google Nest Mini"}), "smart")
        self.assertEqual(self.kind("Amazon Technologies"), "smart")
        self.assertEqual(self.kind(open_ports={62078}), "mobile")
        self.assertEqual(self.kind(mac="da:a1:19:00:00:01"), "mobile")
        self.assertEqual(self.kind("Apple", mdns_txt={"model": "MacBookPro18,3"}), "mac")
        self.assertEqual(self.kind("Intel", open_ports={135, 445}), "windows")
        self.assertEqual(self.kind(netbios="DESKTOP-JM01"), "windows")
        self.assertEqual(self.kind("Raspberry Pi Trading", open_ports={22}), "server")
        self.assertEqual(self.kind(), "other")

    def test_maker_words_match_whole_words_only(self):
        # "ring" (the doorbell maker) must not match "Hon Hai Precision Engineering"
        self.assertEqual(self.kind("Hon Hai Precision Engineering"), "other")

    def test_describe_names_and_presence(self):
        oui = scan.OuiDatabase("/nonexistent", download=False)
        oui._db = scan.parse_manuf("3C:22:FB\tApple\tApple, Inc.\n")
        rec = describe(Host("192.168.1.20", mac="3c:22:fb:01:02:03", open_ports={62078}, rdns="Jos-iPhone.home"), oui)
        self.assertEqual((rec["name"], rec["vendor"], rec["type"], rec["os"], rec["presence"]), ("Jos-iPhone", "Apple", "mobile", "iOS", "intermittent"))
        self.assertEqual(rec["key"], "mac:3c:22:fb:01:02:03")
        router = describe(Host("192.168.1.1", open_ports={53, 80}, gateway=True), oui)
        self.assertEqual((router["name"], router["presence"], router["key"]), ("Router 192.168.1.1", "always", "ip:192.168.1.1"))
        self.assertIn("Internet gateway", router["detail"])


if __name__ == "__main__":
    unittest.main()
