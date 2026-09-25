"""Network discovery without SNMP - finds everything on the network, not just managed kit.

For every target address:
  1. knock on a few common TCP ports - an answer (open OR refused) means a host is there,
     and every knock makes the OS resolve the address, so the ARP table then also lists
     devices that silently drop connections (most phones);
  2. read the ARP table for MAC addresses -> maker (Wireshark's public OUI list, cached);
  3. ask the network who's there: UPnP/SSDP (routers, TVs, printers announce make + model),
     mDNS/Bonjour (Apple, Chromecast, printers, NAS, smart speakers), NetBIOS (Windows
     computer names) and reverse DNS (names the router's DHCP handed out);
  4. classify from all of that - router, printer, NAS, TV, smart device, phone, PC...

Read-only and polite: a handful of TCP connects per address (closed immediately, nothing
sent), one multicast query each for SSDP and mDNS, and a GET of each UPnP description.
ARP/multicast only work on the local network segment, so run the collector on the same
LAN (Docker needs --network host; Docker Desktop on Windows/Mac can't - run it with Python).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field

log = logging.getLogger("collector")

# Knocked on every address; enough to find almost anything that accepts connections.
QUICK_PORTS = (80, 443, 22, 445, 62078, 8080, 139, 5000)
# Checked on hosts that turned out to be there, to tell what they are.
DETAIL_PORTS = (21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1883, 3389,
                5000, 5001, 7000, 8008, 8009, 8080, 8443, 9100, 62078)
PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
              445: "SMB", 515: "LPD", 548: "AFP", 554: "RTSP", 631: "IPP", 1883: "MQTT", 3389: "RDP",
              5000: "HTTP-5000", 5001: "HTTPS-5001", 7000: "AirPlay", 8008: "Cast", 8009: "Cast", 8080: "HTTP-8080",
              8443: "HTTPS-8443", 9100: "JetDirect", 62078: "iOS sync"}

MDNS_SERVICES = ("_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp",
                 "_pdl-datastream._tcp", "_smb._tcp", "_afpovertcp._tcp", "_hap._tcp", "_device-info._tcp",
                 "_companion-link._tcp", "_sonos._tcp", "_spotify-connect._tcp", "_workstation._tcp",
                 "_http._tcp", "_ssh._tcp", "_amzn-wplay._tcp", "_homekit._tcp", "_matter._tcp")

OUI_URL = "https://www.wireshark.org/download/automated/data/manuf"
OUI_MAX_AGE = 90 * 86400
UPNP_MAX_BYTES = 64 * 1024

TV_MAKERS = ("samsung", "lg electronics", "sony", "roku", "hisense", "tcl", "vizio", "panasonic", "sharp", "philips tv", "tp vision")
SMART_MAKERS = ("amazon", "sonos", "espressif", "tuya", "ring", "signify", "philips lighting", "shelly", "hikvision",
                "dahua", "reolink", "wyze", "ecobee", "nest", "google", "arlo", "eufy", "anker", "xiaomi", "meross",
                "tado", "hive", "netatmo", "bose", "belkin", "lifx", "ezviz", "blink")
ROUTER_MAKERS = ("sagemcom", "technicolor", "arris", "zte", "huawei", "draytek", "askey", "sercomm", "fritz", "avm",
                 "ubiquiti", "mikrotik", "eero", "plume", "cisco meraki", "netgear", "tp-link", "linksys", "asus")
NAS_MAKERS = ("synology", "qnap", "western digital", "buffalo", "asustor", "terramaster")
PRINTER_MAKERS = ("brother", "canon", "epson", "seiko epson", "kyocera", "lexmark", "ricoh", "xerox", "konica", "oki")


@dataclass
class Host:
    ip: str
    mac: str | None = None
    open_ports: set[int] = field(default_factory=set)
    responded: bool = False
    rdns: str | None = None
    netbios: str | None = None
    upnp: dict = field(default_factory=dict)
    mdns_services: set[str] = field(default_factory=set)
    mdns_names: list[str] = field(default_factory=list)
    mdns_txt: dict = field(default_factory=dict)
    gateway: bool = False
    this_machine: bool = False


# ---------------------------------------------------------------- TCP knock

def knock(ip: str, port: int, timeout: float) -> str | None:
    """"open", "closed" (refused = a host is there), or None (nothing answered)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return None


# ---------------------------------------------------------------- ARP table

_MAC = r"([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})"
_ARP_LINE = re.compile(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?" + _MAC)


def normalise_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    parts = re.split(r"[:-]", mac.strip())
    if len(parts) != 6:
        return None
    mac = ":".join(p.zfill(2) for p in parts).lower()
    first = int(mac[:2], 16)
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or first & 1:  # empty, broadcast, multicast
        return None
    return mac


def is_private_mac(mac: str) -> bool:
    """Locally administered - phones/laptops use a random 'private' address per Wi-Fi network."""
    return bool(int(mac[:2], 16) & 2)


def parse_arp(text: str) -> dict[str, str]:
    """{ip: mac} from /proc/net/arp, Windows `arp -a` or BSD/macOS `arp -an` output."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        cols = line.split()
        # /proc/net/arp: IP HWtype Flags MAC Mask Device - flags 0x0 = incomplete
        if len(cols) >= 6 and cols[2].startswith("0x"):
            if cols[2] != "0x0":
                mac = normalise_mac(cols[3])
                if mac:
                    table[cols[0]] = mac
            continue
        m = _ARP_LINE.search(line)
        if m:
            mac = normalise_mac(m.group(2))
            if mac:
                table[m.group(1)] = mac
    return table


def read_arp() -> dict[str, str]:
    try:
        with open("/proc/net/arp", encoding="ascii", errors="replace") as f:
            return parse_arp(f.read())
    except OSError:
        pass
    try:
        out = subprocess.run(["arp", "-a"] if sys.platform == "win32" else ["arp", "-an"],
                             capture_output=True, text=True, timeout=15, errors="replace").stdout
        return parse_arp(out)
    except (OSError, subprocess.SubprocessError):
        return {}


def default_gateway() -> str | None:
    try:
        with open("/proc/net/route", encoding="ascii") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) > 2 and cols[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(cols[2], 16)))
    except OSError:
        pass
    try:
        if sys.platform == "win32":
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True, timeout=15, errors="replace").stdout
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        else:
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=15, errors="replace").stdout
            m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def local_address() -> str | None:
    """The address this machine uses to reach the internet (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return None


# ---------------------------------------------------------------- MAC vendors

class OuiDatabase:
    """MAC prefix -> maker, from Wireshark's manuf file, downloaded and cached in the state dir."""

    def __init__(self, state_dir: str, download: bool = True):
        self.path = os.path.join(state_dir, "manuf.txt")
        self.download = download
        self._db: dict[int, dict[int, str]] | None = None

    def lookup(self, mac: str | None) -> str | None:
        if not mac or is_private_mac(mac):
            return None
        if self._db is None:
            self._db = self._load()
        value = int(mac.replace(":", ""), 16)
        for bits in (36, 28, 24):
            name = self._db.get(bits, {}).get(value >> (48 - bits))
            if name:
                return name
        return None

    def _load(self) -> dict[int, dict[int, str]]:
        fresh = os.path.exists(self.path) and time.time() - os.path.getmtime(self.path) < OUI_MAX_AGE
        if not fresh and self.download:
            try:
                req = urllib.request.Request(OUI_URL, headers={"User-Agent": "LiveTracker-Collector"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read(20 * 1024 * 1024)
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(self.path, "wb") as f:
                    f.write(data)
                log.info("Downloaded MAC vendor list (%d KB)", len(data) // 1024)
            except OSError as e:
                log.warning("Could not download the MAC vendor list (%s) - makers will be missing", e)
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                return parse_manuf(f.read())
        except OSError:
            return {}


_SUFFIXES = re.compile(r"[\s,]+(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|ag|sa|s\.a|bv|b\.v|"
                       r"plc|pte|oy|ab|srl|kk|technologies|technology|electronics|international)\.?$", re.I)


def clean_vendor(name: str) -> str:
    name = re.sub(r"\s+", " ", name.replace("Co.,Ltd", "").replace("Co., Ltd", "")).strip(" ,.")
    for _ in range(4):
        shorter = _SUFFIXES.sub("", name).strip(" ,.")
        if shorter == name or not shorter:
            break
        name = shorter
    return name[:60]


def parse_manuf(text: str) -> dict[int, dict[int, str]]:
    db: dict[int, dict[int, str]] = {24: {}, 28: {}, 36: {}}
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        prefix, _, bits = cols[0].strip().partition("/")
        bits = int(bits) if bits.isdigit() else 24
        if bits not in db:
            continue
        hexstr = prefix.replace(":", "").replace("-", "")
        try:
            value = int(hexstr.ljust(12, "0")[:12], 16) >> (48 - bits)
        except ValueError:
            continue
        long_name = (cols[2] if len(cols) > 2 else cols[1]).strip()
        db[bits][value] = clean_vendor(long_name)
    return db


# ---------------------------------------------------------------- names

def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        return None
    return None if not name or name == ip or re.fullmatch(r"[\d.\-]+", name.split(".")[0]) else name


NBSTAT_QUERY = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")


def parse_nbstat(data: bytes) -> str | None:
    """Workstation name (suffix 0x00, unique) from a NetBIOS node status response."""
    offset = 56
    if len(data) < offset + 1:
        return None
    count = data[offset]
    for i in range(count):
        start = offset + 1 + i * 18
        entry = data[start:start + 18]
        if len(entry) < 18:
            break
        name, suffix, flags = entry[:15], entry[15], int.from_bytes(entry[16:18], "big")
        if suffix == 0x00 and not flags & 0x8000:
            text = name.decode("ascii", "replace").strip()
            return text or None
    return None


def netbios_names(ips: list[str], timeout: float = 1.5) -> dict[str, str]:
    found: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.2)
            for ip in ips:
                try:
                    s.sendto(NBSTAT_QUERY, (ip, 137))
                except OSError:
                    pass
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, (src, _) = s.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                name = parse_nbstat(data)
                if name and src in ips:
                    found[src] = name
    except OSError as e:
        log.debug("NetBIOS query failed: %s", e)
    return found


# ---------------------------------------------------------------- SSDP / UPnP

SSDP_SEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
               b"MX: 2\r\nST: ssdp:all\r\n\r\n")


def parse_ssdp(data: bytes) -> dict[str, str]:
    headers = {}
    for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def ssdp_search(timeout: float = 3.0) -> dict[str, set[str]]:
    """{ip: {description URLs}} from everything that answers an SSDP search."""
    found: dict[str, set[str]] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(0.3)
            s.sendto(SSDP_SEARCH, ("239.255.255.250", 1900))
            s.sendto(SSDP_SEARCH, ("239.255.255.250", 1900))
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, (src, _) = s.recvfrom(4096)
                except OSError:
                    continue
                location = parse_ssdp(data).get("location")
                if location:
                    found.setdefault(src, set()).add(location)
    except OSError as e:
        log.debug("SSDP search failed: %s", e)
    return found


_NS = re.compile(r"^\{[^}]*\}")


def parse_upnp_description(xml: bytes) -> dict[str, str]:
    """Root device's friendlyName / manufacturer / modelName / modelNumber / serialNumber / deviceType."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {}
    device = next((el for el in root.iter() if _NS.sub("", el.tag) == "device"), None)
    if device is None:
        return {}
    info = {}
    for child in device:
        tag = _NS.sub("", child.tag)
        if tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "serialNumber", "deviceType", "modelDescription"):
            text = (child.text or "").strip()
            if text:
                info[tag] = text[:120]
    return info


def fetch_upnp(ip: str, location: str, timeout: float = 3.0) -> dict[str, str]:
    """GET the description - only plain http:// on the address that announced it (no redirects)."""
    url = urllib.parse.urlsplit(location)
    if url.scheme != "http" or url.hostname != ip:
        return {}

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: ARG002
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(location, headers={"User-Agent": "LiveTracker-Collector"}), timeout=timeout) as resp:
            return parse_upnp_description(resp.read(UPNP_MAX_BYTES))
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------- mDNS

def _qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def mdns_query() -> bytes:
    questions = b"".join(_qname(f"{svc}.local") + b"\x00\x0c\x00\x01" for svc in MDNS_SERVICES)
    return struct.pack(">HHHHHH", 0, 0, len(MDNS_SERVICES), 0, 0, 0) + questions


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    while True:
        if offset >= len(data) or depth > 20:
            raise ValueError("bad name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if jumped_end is None:
                jumped_end = offset + 2
            offset = pointer
            depth += 1
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    return ".".join(labels), (jumped_end if jumped_end is not None else offset)


def parse_mdns(data: bytes) -> list[tuple[str, int, object]]:
    """[(owner name, type, value)] for PTR (target name), SRV (target host), TXT ({k: v}) and A (ip) records."""
    records = []
    try:
        _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            _, offset = _read_name(data, offset)
            offset += 4
        for _ in range(an + ns + ar):
            name, offset = _read_name(data, offset)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata_at, offset = offset, offset + rdlen
            if rtype == 12:  # PTR
                records.append((name, rtype, _read_name(data, rdata_at)[0]))
            elif rtype == 33:  # SRV
                records.append((name, rtype, _read_name(data, rdata_at + 6)[0]))
            elif rtype == 16:  # TXT
                txt, i = {}, rdata_at
                while i < offset:
                    n = data[i]
                    key, _, value = data[i + 1:i + 1 + n].decode("utf-8", "replace").partition("=")
                    if key:
                        txt[key.lower()] = value
                    i += 1 + n
                records.append((name, rtype, txt))
            elif rtype == 1 and rdlen == 4:  # A
                records.append((name, rtype, socket.inet_ntoa(data[rdata_at:offset])))
    except (ValueError, struct.error, IndexError):
        pass
    return records


def mdns_browse(timeout: float = 3.0) -> dict[str, dict]:
    """{ip: {"services": set, "names": [..], "txt": {..}}} - legacy unicast query, answers come straight back."""
    found: dict[str, dict] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            s.settimeout(0.3)
            query = mdns_query()
            s.sendto(query, ("224.0.0.251", 5353))
            s.sendto(query, ("224.0.0.251", 5353))
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, (src, _) = s.recvfrom(9000)
                except OSError:
                    continue
                entry = found.setdefault(src, {"services": set(), "names": [], "txt": {}})
                for name, rtype, value in parse_mdns(data):
                    if rtype == 12 and isinstance(value, str):
                        svc = name.removesuffix(".local")
                        if svc in MDNS_SERVICES:
                            entry["services"].add(svc)
                            instance = value.removesuffix(f".{name}")
                            if instance and instance not in entry["names"]:
                                entry["names"].append(instance)
                    elif rtype == 33 and isinstance(value, str):
                        host = value.removesuffix(".local").removesuffix(".")
                        if host and host not in entry["names"]:
                            entry["names"].append(host)
                    elif rtype == 16 and isinstance(value, dict):
                        for key in ("md", "model", "fn", "ty", "am", "usb_mfg", "usb_mdl", "manufacturer"):
                            if value.get(key) and key not in entry["txt"]:
                                entry["txt"][key] = value[key][:120]
    except OSError as e:
        log.debug("mDNS query failed: %s", e)
    return found


# ---------------------------------------------------------------- the scan

def scan(hosts: list[str], workers: int = 64, timeout: float = 0.8, arp_reader=read_arp,
         netbios=netbios_names, ssdp=ssdp_search, mdns=mdns_browse, upnp=fetch_upnp, rdns=reverse_dns,
         gateway=default_gateway, local=local_address) -> dict[str, Host]:
    """{ip: Host} for everything found among the target addresses."""
    targets = [h for h in hosts if _is_ipv4(h)]
    wanted = set(targets)
    found: dict[str, Host] = {}

    def quick(ip: str):
        for port in QUICK_PORTS:
            state = knock(ip, port, timeout)
            if state:
                return ip, port if state == "open" else None
        return ip, False

    # Multicast discovery runs alongside the sweep.
    with ThreadPoolExecutor(max_workers=2) as side:
        ssdp_future = side.submit(ssdp)
        mdns_future = side.submit(mdns)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for ip, result in pool.map(quick, targets):
                if result is not False:
                    host = found.setdefault(ip, Host(ip))
                    host.responded = True
                    if result:
                        host.open_ports.add(result)
        ssdp_found, mdns_found = ssdp_future.result(), mdns_future.result()

    for ip, mac in arp_reader().items():
        if ip in wanted:
            found.setdefault(ip, Host(ip)).mac = mac
    for ip, info in mdns_found.items():
        if ip in wanted:
            host = found.setdefault(ip, Host(ip))
            host.mdns_services, host.mdns_names, host.mdns_txt = info["services"], info["names"], info["txt"]

    gw, me = gateway(), local()
    for ip in (gw, me):
        if ip in wanted:
            found.setdefault(ip, Host(ip))
    if gw in found:
        found[gw].gateway = True
    if me in found:
        found[me].this_machine = True

    # A closer look at what's there.
    def detail(host: Host):
        for port in DETAIL_PORTS:
            if port not in host.open_ports and knock(host.ip, port, timeout) == "open":
                host.open_ports.add(port)
        host.rdns = rdns(host.ip)
        for location in sorted(ssdp_found.get(host.ip, ()))[:4]:
            info = upnp(host.ip, location)
            # prefer the root device that names a model
            if info and (not host.upnp or ("modelName" in info and "modelName" not in host.upnp)):
                host.upnp = info

    with ThreadPoolExecutor(max_workers=max(4, workers // 4)) as pool:
        wait([pool.submit(detail, h) for h in found.values()])

    for ip, name in netbios(list(found)).items():
        found[ip].netbios = name

    log.info("Network scan of %d addresses: %d devices found (%d via ARP only)", len(targets), len(found),
             sum(1 for h in found.values() if not h.responded and h.mac))
    return found


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


# ---------------------------------------------------------------- classification

def _has(text: str | None, words) -> bool:
    """Any of the words at the start of a word in text ("ring" must not match "engineering")."""
    t = (text or "").lower()
    return any(re.search(r"(?<![a-z0-9])" + re.escape(w), t) for w in words)


def classify(host: Host, vendor: str | None) -> tuple[str, str | None]:
    """(type, operating system guess) - types match LiveTracker's asset types."""
    p = host.open_ports
    svc = host.mdns_services
    upnp_type = host.upnp.get("deviceType", "").lower()
    model = " ".join(filter(None, [host.upnp.get("modelName"), host.upnp.get("modelDescription"),
                                   host.mdns_txt.get("md"), host.mdns_txt.get("model"), host.mdns_txt.get("am")])).lower()
    names = " ".join(filter(None, [host.upnp.get("friendlyName"), host.rdns, host.netbios, *host.mdns_names])).lower()
    maker = " ".join(filter(None, [vendor, host.upnp.get("manufacturer")])).lower()

    if host.gateway or "internetgatewaydevice" in upnp_type or "wandevice" in upnp_type or "wlanaccesspoint" in upnp_type \
            or _has(names, ("router", "gateway", "smart hub", "smarthub", "superhub", "hub-", "bthub", "skyrouter", "fritz!box", "eero")) \
            or (_has(maker, ROUTER_MAKERS) and 53 in p and (80 in p or 443 in p)):
        return "router", None
    if svc & {"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"} or 9100 in p or "printer" in upnp_type \
            or (_has(maker, PRINTER_MAKERS) and (631 in p or 515 in p or 80 in p)):
        return "printer", None
    if _has(maker, NAS_MAKERS) or _has(model, ("diskstation", "ds2", "ds9", "ts-", "my cloud")):
        return "nas", "Linux"
    if (svc & {"_googlecast._tcp"} and not _has(model, ("nest mini", "home mini", "google home", "nest audio"))) \
            or "mediarenderer" in upnp_type and _has(maker, TV_MAKERS) or _has(model, ("appletv", "apple tv", "chromecast", "fire tv", "roku")) \
            or _has(names, ("tv", "chromecast", "roku", "firestick", "fire-tv")) or {8008, 8009} <= p:
        return "tv", None
    if svc & {"_sonos._tcp", "_hap._tcp", "_homekit._tcp", "_matter._tcp", "_amzn-wplay._tcp", "_spotify-connect._tcp"} \
            or _has(maker, SMART_MAKERS) or 1883 in p or 554 in p \
            or _has(model, ("nest", "home mini", "echo", "homepod", "audiopod")) or _has(names, ("echo", "alexa", "sonos", "nest", "camera", "ring-")):
        return "smart", None
    if 62078 in p or _has(names, ("iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "redmi")) \
            or _has(model, ("iphone", "ipad")):
        return "mobile", "iOS" if (62078 in p or _has(names + model, ("iphone", "ipad"))) else None
    if _has(model, ("macbook", "imac", "macmini", "mac mini", "macpro", "mac studio")) or "_afpovertcp._tcp" in svc \
            or ("_companion-link._tcp" in svc and _has(maker, ("apple",))) or _has(names, ("macbook", "imac", "mac-mini", "macmini")):
        return "mac", "macOS"
    if {135, 139, 445, 3389} & p or host.netbios or _has(names, ("desktop-", "laptop-", "win-")):
        return "windows", "Windows"
    if host.mac and is_private_mac(host.mac) and not p - {80, 443}:
        return "mobile", None  # private Wi-Fi address and nothing listening: almost always a phone or tablet
    if 22 in p or "_ssh._tcp" in svc or _has(maker, ("raspberry",)):
        return "server", "Linux"
    return "other", None


INFRASTRUCTURE = ("router", "switch", "server", "nas", "ups")


def describe(host: Host, oui: OuiDatabase) -> dict:
    """The report record for a device found by the scan (no SNMP)."""
    mac_vendor = oui.lookup(host.mac)
    dtype, os_guess = classify(host, mac_vendor)
    vendor = host.upnp.get("manufacturer") or host.mdns_txt.get("usb_mfg") or host.mdns_txt.get("manufacturer") or mac_vendor
    model = host.upnp.get("modelName") or host.mdns_txt.get("md") or host.mdns_txt.get("model") \
        or host.mdns_txt.get("ty") or host.mdns_txt.get("usb_mdl") or host.mdns_txt.get("am")
    if model and host.upnp.get("modelNumber") and host.upnp["modelNumber"] not in model:
        model = f"{model} {host.upnp['modelNumber']}"

    short_rdns = host.rdns.split(".")[0] if host.rdns else None
    name = (host.upnp.get("friendlyName") or host.mdns_txt.get("fn") or (host.mdns_names[0] if host.mdns_names else None)
            or host.netbios or short_rdns)
    if not name:
        label = {"router": "Router", "printer": "Printer", "nas": "NAS", "tv": "TV", "smart": "Smart device",
                 "mobile": "Phone/tablet", "mac": "Mac", "windows": "PC", "server": "Linux device"}.get(dtype, "Device")
        name = f"{vendor} {label}" if vendor and label != "Device" else (f"{vendor} device" if vendor else f"{label} {host.ip}")

    services = sorted({PORT_NAMES[p] for p in host.open_ports if p in PORT_NAMES})
    bits = ["Online"]
    if host.gateway:
        bits.append("Internet gateway")
    if host.this_machine:
        bits.append("Runs the collector")
    if host.mac and is_private_mac(host.mac) and dtype not in INFRASTRUCTURE:
        bits.append("Private Wi-Fi address")
    if services:
        bits.append(", ".join(services[:6]))

    return {k: v for k, v in {
        "key": f"mac:{host.mac}" if host.mac else f"ip:{host.ip}",
        "ip": host.ip,
        "mac": host.mac,
        "name": str(name)[:120],
        "type": dtype,
        "vendor": str(vendor)[:120] if vendor else None,
        "model": str(model)[:120] if model else None,
        "serial": host.upnp["serialNumber"][:120] if host.upnp.get("serialNumber") else None,
        "os": os_guess,
        "health": "healthy",
        "detail": " · ".join(bits)[:255],
        "discovery": "scan",
        "presence": "always" if dtype in INFRASTRUCTURE else "intermittent",
        "online": True,
        "services": services[:20] or None,
    }.items() if v is not None}
