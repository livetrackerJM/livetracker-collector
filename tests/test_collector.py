"""Tests against a simulated SNMP agent that answers like the net-snmp CLI."""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from collector import config as config_mod
from collector.config import Config, ConfigError, expand_targets
from collector.main import State, cycle
from collector.snmp import SnmpClient, parse

TOKEN = "ltc_7_" + "A" * 48


class FakeAgents:
    """Stands in for snmpget/snmpbulkwalk. agents = {ip: {oid: value}}."""

    def __init__(self, agents):
        self.agents = agents
        self.calls = []

    def __call__(self, args, env):
        self.calls.append(args)
        tool = args[0]
        # args: tool, -On -OQ -Oe -Ot -t N -r N [extra...] host oids...
        rest = args[9:]
        if rest and rest[0].startswith("-C"):
            rest = rest[1:]
        host, oids = rest[0], rest[1:]
        agent = self.agents.get(host)
        if agent is None:
            return subprocess.CompletedProcess(args, 1, "", f"Timeout: No Response from {host}.\n")
        lines = []
        if tool == "snmpget":
            for oid in oids:
                if oid in agent:
                    lines.append(f"{oid} = {agent[oid]}")
                else:
                    lines.append(f"{oid} = No Such Object available on this agent at this OID")
        else:
            base = oids[0]
            for oid in sorted(agent, key=lambda o: [int(p) for p in o.strip('.').split('.')]):
                if oid.startswith(base + "."):
                    lines.append(f"{oid} = {agent[oid]}")
        return subprocess.CompletedProcess(args, 0, "\n".join(lines) + "\n", "")


def system(descr, oid, name, uptime_ticks=1_900_000_000, location="Server room"):
    return {
        ".1.3.6.1.2.1.1.1.0": descr, ".1.3.6.1.2.1.1.2.0": oid, ".1.3.6.1.2.1.1.3.0": str(uptime_ticks),
        ".1.3.6.1.2.1.1.4.0": '"IT team"', ".1.3.6.1.2.1.1.5.0": f'"{name}"', ".1.3.6.1.2.1.1.6.0": f'"{location}"',
    }


def synology(raid_status="11"):
    a = system('"Linux nas01 4.4.302+ #69057 SMP x86_64"', ".1.3.6.1.4.1.8072.3.2.10", "nas01")
    a.update({
        ".1.3.6.1.4.1.6574.1.1.0": "1", ".1.3.6.1.4.1.6574.1.2.0": "41",
        ".1.3.6.1.4.1.6574.1.5.1.0": '"DS1621+"', ".1.3.6.1.4.1.6574.1.5.2.0": '"2140QXR123456"', ".1.3.6.1.4.1.6574.1.5.3.0": '"DSM 7.2.1-69057"',
        ".1.3.6.1.4.1.6574.2.1.1.5.0": "1", ".1.3.6.1.4.1.6574.2.1.1.5.1": "1", ".1.3.6.1.4.1.6574.2.1.1.5.2": "5",
        ".1.3.6.1.4.1.6574.3.1.1.2.0": '"Volume 1"', ".1.3.6.1.4.1.6574.3.1.1.3.0": raid_status,
        # hrStorage: /volume1 at 93% and a small /dev tmpfs that must be ignored
        ".1.3.6.1.2.1.25.2.3.1.2.31": ".1.3.6.1.2.1.25.2.1.4", ".1.3.6.1.2.1.25.2.3.1.3.31": '"/volume1"',
        ".1.3.6.1.2.1.25.2.3.1.4.31": "4096", ".1.3.6.1.2.1.25.2.3.1.5.31": "1000000000", ".1.3.6.1.2.1.25.2.3.1.6.31": "930000000",
        ".1.3.6.1.2.1.25.2.3.1.2.32": ".1.3.6.1.2.1.25.2.1.4", ".1.3.6.1.2.1.25.2.3.1.3.32": '"/dev"',
        ".1.3.6.1.2.1.25.2.3.1.4.32": "4096", ".1.3.6.1.2.1.25.2.3.1.5.32": "999999999", ".1.3.6.1.2.1.25.2.3.1.6.32": "999999999",
    })
    return a


def netgear(errors_port2=10):
    a = system('"GS728TPv2 ProSAFE 24-port Gigabit Smart Switch, 6.0.1.34"', ".1.3.6.1.4.1.4526.100.4.33", "core-sw")
    a.update({".1.3.6.1.2.1.17.1.2.0": "28",
              ".1.3.6.1.2.1.47.1.1.1.1.5.1": "3", ".1.3.6.1.2.1.47.1.1.1.1.11.1": '"4VL1234567890"',
              ".1.3.6.1.2.1.47.1.1.1.1.13.1": '"GS728TPv2"', ".1.3.6.1.2.1.47.1.1.1.1.10.1": '"6.0.1.34"'})
    for i in range(1, 5):
        a[f".1.3.6.1.2.1.2.2.1.3.{i}"] = "6"
        a[f".1.3.6.1.2.1.2.2.1.8.{i}"] = "1" if i < 4 else "2"
        a[f".1.3.6.1.2.1.2.2.1.14.{i}"] = str(errors_port2 if i == 2 else 0)
        a[f".1.3.6.1.2.1.31.1.1.1.1.{i}"] = f'"g{i}"'
    a[".1.3.6.1.2.1.2.2.1.3.100"] = "24"  # loopback - not a port
    return a


def idrac(status="4"):
    a = system('"Linux idrac-ABC1234 4.9.232"', ".1.3.6.1.4.1.674.10892.5", "srv-dc01")
    a.update({".1.3.6.1.4.1.674.10892.5.1.3.2.0": '"ABC1234"', ".1.3.6.1.4.1.674.10892.5.1.3.12.0": '"PowerEdge R650"',
              ".1.3.6.1.4.1.674.10892.5.2.1.0": status})
    return a


def powerconnect():
    a = system('"Dell Networking N1548P, 6.6.3.10"', ".1.3.6.1.4.1.674.10895.3083", "dell-sw")
    a[".1.3.6.1.2.1.17.1.2.0"] = "52"
    return a


def apc_ups():
    a = system('"APC Web/SNMP Management Card"', ".1.3.6.1.4.1.318.1.3.27", "ups-01")
    a.update({".1.3.6.1.2.1.33.1.1.1.0": '"APC"', ".1.3.6.1.2.1.33.1.1.2.0": '"Smart-UPS 1500"',
              ".1.3.6.1.2.1.33.1.2.1.0": "2", ".1.3.6.1.2.1.33.1.2.4.0": "96", ".1.3.6.1.2.1.33.1.4.1.0": "5"})
    return a


def hp_printer():
    a = system('"HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153"', ".1.3.6.1.4.1.11.2.3.9.1", "printer-2f")
    a.update({".1.3.6.1.2.1.25.3.5.1.1.1": "3", ".1.3.6.1.2.1.43.5.1.1.17.1": '"CNB1234567"',
              ".1.3.6.1.2.1.25.3.2.1.3.1": '"HP LaserJet Pro M404dn"',
              ".1.3.6.1.2.1.43.11.1.1.6.1.1": '"Black Cartridge HP CF259A"', ".1.3.6.1.2.1.43.11.1.1.8.1.1": "100",
              ".1.3.6.1.2.1.43.11.1.1.9.1.1": "6"})
    return a


def make_cfg(state_dir, hosts):
    return Config(url="https://livetracker.example", token=TOKEN, targets=hosts, snmp_version="2c",
                  community="public", hosts=hosts, state_dir=state_dir, workers=4, scan=False)


class ParseTests(unittest.TestCase):
    def test_parse_quotes_missing_and_multiline(self):
        out = (".1.3.6.1.2.1.1.5.0 = \"core-sw\"\n"
               ".1.3.6.1.2.1.1.1.0 = \"Line one\nline two\"\n"
               ".1.3.6.1.2.1.1.6.0 = No Such Object available on this agent at this OID\n"
               ".1.3.6.1.2.1.1.3.0 = 123456\n")
        v = parse(out)
        self.assertEqual(v[".1.3.6.1.2.1.1.5.0"], "core-sw")
        self.assertEqual(v[".1.3.6.1.2.1.1.1.0"], "Line one\nline two")
        self.assertNotIn(".1.3.6.1.2.1.1.6.0", v)
        self.assertEqual(v[".1.3.6.1.2.1.1.3.0"], "123456")


class ConfigTests(unittest.TestCase):
    def test_expand_targets(self):
        hosts = expand_targets(["10.0.0.0/30", "10.0.1.5-10.0.1.7", "nas.lan", "10.0.0.1"])
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.1.5", "10.0.1.6", "10.0.1.7", "nas.lan"])

    def test_rejects_huge_ranges_and_junk(self):
        with self.assertRaises(ConfigError):
            expand_targets(["10.0.0.0/16"])
        with self.assertRaises(ConfigError):
            expand_targets(["10.0.0.0/24; rm -rf /"])

    def test_load_validates_token_url_and_v3(self):
        env = {"LT_URL": "https://livetracker.example", "LT_TOKEN": TOKEN, "LT_TARGETS": "192.168.1.0/30",
               "SNMP_VERSION": "3", "SNMP_USER": "lt", "SNMP_AUTH_PASS": "authpass123", "SNMP_PRIV_PASS": "privpass123"}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = config_mod.load()
            self.assertEqual(cfg.hosts, ["192.168.1.1", "192.168.1.2"])
        for bad in ({"LT_TOKEN": "nope"}, {"LT_URL": "http://insecure"}, {"SNMP_AUTH_PASS": "short"},
                    {"SNMP_USER": "", "LT_SCAN": "off"}):
            with mock.patch.dict(os.environ, {**env, **bad}, clear=True):
                with self.assertRaises(ConfigError):
                    config_mod.load()

    def test_snmp_is_optional_with_the_network_scan(self):
        env = {"LT_URL": "https://livetracker.example", "LT_TOKEN": TOKEN, "LT_TARGETS": "192.168.1.0/30"}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = config_mod.load()
        self.assertEqual((cfg.snmp, cfg.scan), (False, True))

    def test_env_file_and_auto_targets(self):
        path = os.path.join(tempfile.mkdtemp(), "collector.env")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# comment\nLT_URL=https://livetracker.example\nLT_TOKEN=\"{TOKEN}\"\nLT_TARGETS=auto\nnot a setting\n")
        with mock.patch.dict(os.environ, {"LT_URL": "https://wins.example"}, clear=True), \
                mock.patch.object(config_mod, "auto_targets", return_value=["192.168.7.0/30"]):
            config_mod.load_env_file(path)
            cfg = config_mod.load()
        self.assertEqual(cfg.url, "https://wins.example")  # real environment variables win
        self.assertEqual(cfg.token, TOKEN)
        self.assertEqual(cfg.hosts, ["192.168.7.1", "192.168.7.2"])


def assert_contract(test, report):
    """Mirror of the validation rules in LiveTracker's CollectorReportController."""
    import ipaddress
    from datetime import datetime
    test.assertIsInstance(report["devices"], list)
    allowed = {"key", "ip", "name", "type", "vendor", "model", "serial", "firmware", "os", "location", "contact",
               "health", "detail", "uptime_seconds", "last_seen", "metrics", "mac", "discovery", "presence", "online", "services"}
    limits = {"key": 191, "name": 255, "vendor": 255, "model": 255, "serial": 255, "firmware": 60, "os": 60,
              "location": 255, "contact": 255, "detail": 255}
    types = ("windows", "mac", "mobile", "server", "router", "switch", "nas", "printer", "ups", "tv", "smart", "other")
    for d in report["devices"]:
        test.assertLessEqual(set(d), allowed)
        test.assertIn(d["type"], types)
        test.assertIn(d["health"], ("healthy", "warn", "crit"))
        test.assertTrue(d["key"])
        test.assertIn(d.get("discovery", "snmp"), ("snmp", "scan"))
        test.assertIn(d.get("presence", "always"), ("always", "intermittent"))
        for k, n in limits.items():
            if k in d:
                test.assertIsInstance(d[k], str, k)
                test.assertLessEqual(len(d[k]), n, k)
        if "ip" in d:
            ipaddress.ip_address(d["ip"])
        if "mac" in d:
            test.assertRegex(d["mac"], r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
        if "online" in d:
            test.assertIsInstance(d["online"], bool)
        if "services" in d:
            test.assertLessEqual(len(d["services"]), 20)
            for name in d["services"]:
                test.assertLessEqual(len(name), 40)
        if "uptime_seconds" in d:
            test.assertIsInstance(d["uptime_seconds"], int)
        datetime.fromisoformat(d["last_seen"])
    c = report["collector"]
    test.assertTrue(60 <= c["interval"] <= 86400)
    test.assertLessEqual(len(c["version"]), 40)
    test.assertLessEqual(len(c["hostname"]), 120)


class CycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def run_cycle(self, agents, hosts, state=None):
        cfg = make_cfg(self.tmp, hosts)
        client = SnmpClient(cfg, runner=FakeAgents(agents))
        state = state or State(self.tmp)
        return cycle(client, cfg, state), state

    def by_ip(self, report):
        return {d["ip"]: d for d in report["devices"]}

    def test_full_estate(self):
        agents = {"10.0.0.2": synology(), "10.0.0.3": netgear(), "10.0.0.4": idrac(), "10.0.0.5": apc_ups(),
                  "10.0.0.6": hp_printer(), "10.0.0.7": powerconnect()}
        report, _ = self.run_cycle(agents, [f"10.0.0.{i}" for i in range(1, 9)])
        d = self.by_ip(report)
        self.assertEqual(len(d), 6)  # .1 and .8 are silent

        nas = d["10.0.0.2"]
        self.assertEqual((nas["type"], nas["vendor"], nas["model"], nas["serial"]), ("nas", "Synology", "DS1621+", "2140QXR123456"))
        self.assertEqual(nas["health"], "crit")
        self.assertIn("Volume 1 degraded", nas["detail"])
        self.assertIn("Disk 2 crashed", nas["detail"])
        self.assertIn("/volume1 93% full", nas["detail"])
        self.assertNotIn("/dev", nas["detail"])
        self.assertEqual(nas["key"], "sn:synology:2140QXR123456")

        sw = d["10.0.0.3"]
        self.assertEqual((sw["type"], sw["vendor"], sw["model"], sw["serial"], sw["firmware"]), ("switch", "Netgear", "GS728TPv2", "4VL1234567890", "6.0.1.34"))
        self.assertEqual(sw["health"], "healthy")
        self.assertIn("3/4 ports up", sw["detail"])

        srv = d["10.0.0.4"]
        self.assertEqual((srv["type"], srv["vendor"], srv["model"], srv["serial"], srv["health"]), ("server", "Dell", "PowerEdge R650", "ABC1234", "warn"))
        self.assertIn("Hardware warning", srv["detail"])

        ups = d["10.0.0.5"]
        self.assertEqual((ups["type"], ups["model"], ups["health"]), ("ups", "Smart-UPS 1500", "warn"))
        self.assertIn("Running on battery", ups["detail"])

        prn = d["10.0.0.6"]
        self.assertEqual((prn["type"], prn["model"], prn["serial"], prn["health"]), ("printer", "HP LaserJet Pro M404dn", "CNB1234567", "warn"))
        self.assertIn("Black Cartridge HP CF259A 6%", prn["detail"])

        self.assertEqual(d["10.0.0.7"]["type"], "switch")  # Dell PowerConnect, not a server
        self.assertEqual(report["collector"]["targets"], 8)

    def test_rising_errors_and_device_going_quiet(self):
        hosts = ["10.0.0.3"]
        first, state = self.run_cycle({"10.0.0.3": netgear(errors_port2=10)}, hosts)
        self.assertEqual(self.by_ip(first)["10.0.0.3"]["health"], "healthy")

        second, state = self.run_cycle({"10.0.0.3": netgear(errors_port2=900)}, hosts, State(self.tmp))
        sw = self.by_ip(second)["10.0.0.3"]
        self.assertEqual(sw["health"], "warn")
        self.assertIn("Input errors rising on g2", sw["detail"])

        third, _ = self.run_cycle({}, hosts, State(self.tmp))
        gone = self.by_ip(third)["10.0.0.3"]
        self.assertEqual((gone["health"], gone["detail"]), ("crit", "Not responding to SNMP"))
        self.assertEqual(gone["key"], sw["key"])

    def test_hostname_targets_do_not_send_invalid_ip(self):
        report, _ = self.run_cycle({"nas.lan": netgear()}, ["nas.lan"])
        dev = report["devices"][0]
        self.assertNotIn("ip", dev)
        self.assertEqual(dev["name"], "core-sw")

    def test_report_matches_livetracker_contract(self):
        agents = {"10.0.0.2": synology(), "10.0.0.3": netgear(), "10.0.0.4": idrac(), "10.0.0.5": apc_ups(), "10.0.0.6": hp_printer()}
        report, _ = self.run_cycle(agents, [f"10.0.0.{i}" for i in range(2, 7)])
        assert_contract(self, report)

    def test_network_scan_merges_with_snmp_and_handles_devices_leaving(self):
        from collector import scan as netscan
        hosts = [f"10.0.0.{i}" for i in range(1, 8)]
        phone = netscan.Host("10.0.0.7", mac="da:a1:19:00:00:01", responded=False, mdns_names=["Jo's iPhone"])
        router = netscan.Host("10.0.0.1", mac="00:1d:d8:00:00:01", open_ports={53, 80, 443}, gateway=True,
                              upnp={"friendlyName": "BT Smart Hub 2", "manufacturer": "Sagemcom", "modelName": "Smart Hub 2",
                                    "deviceType": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"})
        nas_seen = netscan.Host("10.0.0.2", mac="00:11:32:00:00:02", open_ports={5000, 445})
        present = {"10.0.0.1": router, "10.0.0.2": nas_seen, "10.0.0.7": phone}

        cfg = make_cfg(self.tmp, hosts)
        cfg.scan = True
        oui = netscan.OuiDatabase(self.tmp, download=False)
        oui._db = netscan.parse_manuf("00:11:32\tSynology\tSynology Incorporated\n00:1D:D8\tMicrosoft\tMicrosoft Corporation\n")
        client = SnmpClient(cfg, runner=FakeAgents({"10.0.0.2": synology()}))

        report = cycle(client, cfg, State(self.tmp), scanner=lambda *a, **k: present, oui=oui)
        d = self.by_ip(report)
        self.assertEqual(len(d), 3)
        self.assertEqual((d["10.0.0.2"]["discovery"], d["10.0.0.2"]["mac"], d["10.0.0.2"]["type"]), ("snmp", "00:11:32:00:00:02", "nas"))
        self.assertEqual((d["10.0.0.1"]["type"], d["10.0.0.1"]["name"], d["10.0.0.1"]["vendor"], d["10.0.0.1"]["key"]),
                         ("router", "BT Smart Hub 2", "Sagemcom", "mac:00:1d:d8:00:00:01"))
        self.assertEqual((d["10.0.0.7"]["type"], d["10.0.0.7"]["name"], d["10.0.0.7"]["presence"]), ("mobile", "Jo's iPhone", "intermittent"))
        self.assertIn("Private Wi-Fi address", d["10.0.0.7"]["detail"])
        assert_contract(self, report)

        # Phone goes home, router dies: the phone is just offline, the router is a fault.
        report = cycle(client, cfg, State(self.tmp), scanner=lambda *a, **k: {"10.0.0.2": nas_seen}, oui=oui)
        d = self.by_ip(report)
        self.assertEqual((d["10.0.0.7"]["health"], d["10.0.0.7"]["online"], d["10.0.0.7"]["detail"]), ("healthy", False, "Offline"))
        self.assertEqual((d["10.0.0.1"]["health"], d["10.0.0.1"]["detail"]), ("crit", "Not responding"))
        assert_contract(self, report)

        # Same phone back on a new address: still one asset.
        moved = netscan.Host("10.0.0.5", mac="da:a1:19:00:00:01", mdns_names=["Jo's iPhone"])
        report = cycle(client, cfg, State(self.tmp), scanner=lambda *a, **k: {"10.0.0.2": nas_seen, "10.0.0.5": moved}, oui=oui)
        phones = [x for x in report["devices"] if x["key"] == "mac:da:a1:19:00:00:01"]
        self.assertEqual(len(phones), 1)
        self.assertEqual((phones[0]["ip"], phones[0]["online"]), ("10.0.0.5", True))


    def test_credentials_never_in_arguments(self):
        cfg = Config(url="https://x", token=TOKEN, targets=["10.0.0.3"], snmp_version="3", snmp_user="lt",
                     auth_pass="supersecret1", priv_pass="supersecret2", hosts=["10.0.0.3"], state_dir=self.tmp, workers=2, scan=False)
        fake = FakeAgents({"10.0.0.3": netgear()})
        client = SnmpClient(cfg, runner=fake)
        cycle(client, cfg, State(self.tmp))
        joined = " ".join(" ".join(c) for c in fake.calls)
        self.assertNotIn("supersecret", joined)
        with open(os.path.join(client.env["SNMPCONFPATH"], "snmp.conf"), encoding="utf-8") as f:
            conf = f.read()
        self.assertIn("defSecurityLevel authPriv", conf)
        self.assertIn("defPrivPassphrase supersecret2", conf)


class SendTests(unittest.TestCase):
    def test_posts_bearer_json_and_handles_revoked_key(self):
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from collector.main import send

        received = []
        status = {"code": 200}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, dict(self.headers), json.loads(body)))
                payload = b'{"ok":true,"accepted":1,"retired":0}' if status["code"] == 200 else b'{"ok":false}'
                self.send_response(status["code"])
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            cfg = make_cfg(tempfile.mkdtemp(), ["10.0.0.3"])
            cfg.url = f"http://127.0.0.1:{server.server_address[1]}"
            report = {"collector": {"version": "0.1.0"}, "devices": [{"key": "ip:10.0.0.3", "type": "switch", "health": "healthy"}]}

            self.assertTrue(send(cfg, report))
            path, headers, body = received[0]
            self.assertEqual(path, "/api/collector/v1/report")
            self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(body, report)

            status["code"] = 401
            with self.assertLogs("collector", level="ERROR") as logs:
                self.assertFalse(send(cfg, report))
            self.assertIn("revoked or rotated", logs.output[0])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
