"""Identify a device, read its inventory and work out its health.

Standard MIBs first (SNMPv2-MIB, ENTITY-MIB, IF-MIB, HOST-RESOURCES-MIB,
Printer-MIB, UPS-MIB), then vendor MIBs where they add real signal
(Synology system/disk/RAID status, Dell iDRAC global status).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .snmp import SnmpClient, column, to_int

# SNMPv2-MIB system group
SYS_DESCR = ".1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = ".1.3.6.1.2.1.1.2.0"
SYS_UPTIME = ".1.3.6.1.2.1.1.3.0"
SYS_CONTACT = ".1.3.6.1.2.1.1.4.0"
SYS_NAME = ".1.3.6.1.2.1.1.5.0"
SYS_LOCATION = ".1.3.6.1.2.1.1.6.0"
SYSTEM_OIDS = [SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_CONTACT, SYS_NAME, SYS_LOCATION]

# ENTITY-MIB entPhysicalTable columns
ENT_CLASS = ".1.3.6.1.2.1.47.1.1.1.1.5"
ENT_FIRMWARE = ".1.3.6.1.2.1.47.1.1.1.1.9"
ENT_SOFTWARE = ".1.3.6.1.2.1.47.1.1.1.1.10"
ENT_SERIAL = ".1.3.6.1.2.1.47.1.1.1.1.11"
ENT_MFG = ".1.3.6.1.2.1.47.1.1.1.1.12"
ENT_MODEL = ".1.3.6.1.2.1.47.1.1.1.1.13"
ENT_TABLE = ".1.3.6.1.2.1.47.1.1.1.1"

# IF-MIB
IF_TYPE = ".1.3.6.1.2.1.2.2.1.3"
IF_ADMIN = ".1.3.6.1.2.1.2.2.1.7"
IF_OPER = ".1.3.6.1.2.1.2.2.1.8"
IF_IN_ERRORS = ".1.3.6.1.2.1.2.2.1.14"
IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1"
ETHERNET_IF_TYPES = {"6", "62", "69", "117"}  # ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet

BRIDGE_NUM_PORTS = ".1.3.6.1.2.1.17.1.2.0"

# HOST-RESOURCES-MIB hrStorageTable
HR_STORAGE = ".1.3.6.1.2.1.25.2.3.1"
HR_STORAGE_TYPE = HR_STORAGE + ".2"
HR_STORAGE_DESCR = HR_STORAGE + ".3"
HR_STORAGE_UNITS = HR_STORAGE + ".4"
HR_STORAGE_SIZE = HR_STORAGE + ".5"
HR_STORAGE_USED = HR_STORAGE + ".6"
HR_FIXED_DISK = ".1.3.6.1.2.1.25.2.1.4"
SYSTEM_MOUNT_PREFIXES = ("/boot", "/dev", "/run", "/sys", "/proc", "/tmp", "/var", "/etc", "/usr", "/mnt/HDA_ROOT", "/snap")
HR_DEVICE_DESCR_1 = ".1.3.6.1.2.1.25.3.2.1.3.1"
HR_PRINTER_STATUS_1 = ".1.3.6.1.2.1.25.3.5.1.1.1"

# Printer-MIB
PRT_SERIAL = ".1.3.6.1.2.1.43.5.1.1.17.1"
PRT_SUPPLIES = ".1.3.6.1.2.1.43.11.1.1"
PRT_SUPPLY_DESCR = PRT_SUPPLIES + ".6"
PRT_SUPPLY_MAX = PRT_SUPPLIES + ".8"
PRT_SUPPLY_LEVEL = PRT_SUPPLIES + ".9"

# UPS-MIB (RFC 1628)
UPS_MFG = ".1.3.6.1.2.1.33.1.1.1.0"
UPS_MODEL = ".1.3.6.1.2.1.33.1.1.2.0"
UPS_SOFTWARE = ".1.3.6.1.2.1.33.1.1.3.0"
UPS_BATTERY_STATUS = ".1.3.6.1.2.1.33.1.2.1.0"
UPS_CHARGE = ".1.3.6.1.2.1.33.1.2.4.0"
UPS_OUTPUT_SOURCE = ".1.3.6.1.2.1.33.1.4.1.0"

# Synology (SYNOLOGY-SYSTEM/DISK/RAID-MIB)
SYNO_SYSTEM_STATUS = ".1.3.6.1.4.1.6574.1.1.0"
SYNO_TEMPERATURE = ".1.3.6.1.4.1.6574.1.2.0"
SYNO_MODEL = ".1.3.6.1.4.1.6574.1.5.1.0"
SYNO_SERIAL = ".1.3.6.1.4.1.6574.1.5.2.0"
SYNO_VERSION = ".1.3.6.1.4.1.6574.1.5.3.0"
SYNO_DISK_STATUS = ".1.3.6.1.4.1.6574.2.1.1.5"
SYNO_RAID_NAME = ".1.3.6.1.4.1.6574.3.1.1.2"
SYNO_RAID_STATUS = ".1.3.6.1.4.1.6574.3.1.1.3"

# Dell iDRAC (IDRAC-MIB-SMIv2)
IDRAC_SERVICE_TAG = ".1.3.6.1.4.1.674.10892.5.1.3.2.0"
IDRAC_MODEL = ".1.3.6.1.4.1.674.10892.5.1.3.12.0"
IDRAC_GLOBAL_STATUS = ".1.3.6.1.4.1.674.10892.5.2.1.0"

# IANA private enterprise numbers -> (vendor, likely type or None)
VENDORS: dict[int, tuple[str, str | None]] = {
    9: ("Cisco", "switch"), 11: ("HP", None), 171: ("D-Link", "switch"), 232: ("HPE", "server"),
    311: ("Microsoft", "server"), 318: ("APC", "ups"), 367: ("Ricoh", "printer"), 534: ("Eaton", "ups"),
    641: ("Lexmark", "printer"), 674: ("Dell", "server"), 890: ("Zyxel", "switch"), 1347: ("Kyocera", "printer"),
    1602: ("Canon", "printer"), 2435: ("Brother", "printer"), 2636: ("Juniper", "switch"), 4526: ("Netgear", "switch"),
    5227: ("Buffalo", "nas"), 6574: ("Synology", "nas"), 6876: ("VMware", "server"), 7367: ("DrayTek", "switch"),
    8072: ("Net-SNMP", None), 11863: ("TP-Link", "switch"), 12356: ("Fortinet", "switch"), 14823: ("Aruba", "switch"),
    14988: ("MikroTik", "switch"), 18334: ("Konica Minolta", "printer"), 24681: ("QNAP", "nas"), 25461: ("Palo Alto Networks", "switch"),
    41112: ("Ubiquiti", "switch"), 47196: ("HPE Aruba", "switch"), 253: ("Xerox", "printer"), 1248: ("Epson", "printer"),
}

TYPES = ("switch", "server", "nas", "printer", "ups", "other")


@dataclass
class Finding:
    severity: str  # "warn" | "crit"
    message: str


@dataclass
class Device:
    ip: str
    key: str = ""
    name: str | None = None
    type: str = "other"
    vendor: str | None = None
    model: str | None = None
    serial: str | None = None
    firmware: str | None = None
    os: str | None = None
    location: str | None = None
    contact: str | None = None
    uptime_seconds: int | None = None
    findings: list[Finding] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    counters: dict = field(default_factory=dict)

    @property
    def health(self) -> str:
        if any(f.severity == "crit" for f in self.findings):
            return "crit"
        return "warn" if self.findings else "healthy"

    @property
    def detail(self) -> str:
        ordered = sorted(self.findings, key=lambda f: 0 if f.severity == "crit" else 1)
        parts = [f.message for f in ordered] or self.summary
        return " · ".join(parts)[:255]


def enterprise_number(sys_object_id: str | None) -> int | None:
    m = re.match(r"^\.?1\.3\.6\.1\.4\.1\.(\d+)", sys_object_id or "")
    return int(m.group(1)) if m else None


def clean(value: str | None, limit: int = 255) -> str | None:
    if value is None:
        return None
    value = re.sub(r"\s+", " ", value).strip().strip('"').strip()
    if not value or value.lower() in ("unknown", "n/a", "none", "not specified", "0"):
        return None
    return value[:limit]


def humanise_uptime(seconds: int) -> str:
    days = seconds // 86400
    if days >= 1:
        return f"up {days} day{'s' if days != 1 else ''}"
    hours = seconds // 3600
    return f"up {hours} hour{'s' if hours != 1 else ''}" if hours else "up <1 hour"


def probe(client: SnmpClient, ip: str, system: dict[str, str], previous_counters: dict | None = None) -> Device:
    """Build a Device from an already-answered system group + further queries."""
    dev = Device(ip=ip)
    dev.name = clean(system.get(SYS_NAME), 120)
    dev.location = clean(system.get(SYS_LOCATION))
    dev.contact = clean(system.get(SYS_CONTACT))
    descr = clean(system.get(SYS_DESCR), 2000) or ""
    ticks = to_int(system.get(SYS_UPTIME))
    dev.uptime_seconds = ticks // 100 if ticks is not None else None

    ent = enterprise_number(system.get(SYS_OBJECT_ID))
    # Synology DSM answers with the generic Net-SNMP sysObjectID (8072), so
    # ask for its model OID to recognise it.
    if ent == 8072 and SYNO_MODEL in client.get(ip, [SYNO_MODEL]):
        ent = 6574
    vendor, vendor_type = VENDORS.get(ent, (None, None)) if ent else (None, None)
    dev.vendor = vendor if vendor != "Net-SNMP" else None

    _entity_inventory(client, ip, dev)

    extra = client.get(ip, [BRIDGE_NUM_PORTS, HR_PRINTER_STATUS_1, UPS_MFG, UPS_MODEL, UPS_SOFTWARE])
    sys_oid = system.get(SYS_OBJECT_ID, "")
    # Dell shares enterprise 674 between iDRAC servers (674.10892) and
    # PowerConnect / Dell Networking switches (674.10895).
    if ent == 674 and ".674.10895" in sys_oid:
        vendor_type = "switch"
    dev.type = _classify(ent, vendor_type, descr, extra)

    if ent == 6574:
        _synology(client, ip, dev)
    elif ent == 674 and dev.type == "server":
        _idrac(client, ip, dev)

    if dev.type == "switch":
        _interfaces(client, ip, dev, previous_counters or {})
    if dev.type in ("server", "nas"):
        _storage(client, ip, dev)
    if dev.type == "printer":
        _printer(client, ip, dev, extra)
    if dev.type == "ups":
        _ups(client, ip, dev, extra)

    if not dev.vendor and dev.type == "ups":
        dev.vendor = clean(extra.get(UPS_MFG))
    if not dev.model:
        dev.model = clean(descr.split(",")[0].split("\n")[0], 120) if descr else None
    if not dev.os:
        dev.os = _os_from_descr(descr)
    if dev.uptime_seconds is not None:
        dev.summary.append(humanise_uptime(dev.uptime_seconds))

    dev.key = f"sn:{(dev.vendor or 'unknown').lower()}:{dev.serial}" if dev.serial else f"ip:{ip}"
    return dev


def _classify(ent: int | None, vendor_type: str | None, descr: str, extra: dict[str, str]) -> str:
    d = descr.lower()
    if UPS_MFG in extra or vendor_type == "ups":
        return "ups"
    if HR_PRINTER_STATUS_1 in extra or vendor_type == "printer":
        return "printer"
    if vendor_type == "nas" or any(w in d for w in ("synology", "qnap", "readynas", "terastation", "linkstation", "truenas")):
        return "nas"
    if ent == 11:  # HP: printers, ProCurve switches and servers share one enterprise number
        if "jetdirect" in d or "laserjet" in d or "officejet" in d:
            return "printer"
        if "procurve" in d or "switch" in d or "aruba" in d:
            return "switch"
    if vendor_type == "switch":
        return "switch"
    ports = to_int(extra.get(BRIDGE_NUM_PORTS))
    if ports and ports > 1 and ent not in (311, 8072, 674, 232):
        return "switch"
    if vendor_type == "server" or ent in (311, 8072) or any(w in d for w in ("windows", "linux", "vmware esxi", "idrac", "ilo")):
        return "server"
    if ports and ports > 1:
        return "switch"
    return "other"


def _os_from_descr(descr: str) -> str | None:
    d = descr.lower()
    for needle, name in (("windows", "Windows"), ("vmware esxi", "VMware ESXi"), ("linux", "Linux"), ("freebsd", "FreeBSD"),
                         ("cisco ios", "Cisco IOS"), ("junos", "Junos"), ("routeros", "RouterOS"), ("fortios", "FortiOS")):
        if needle in d:
            return name
    return None


def _entity_inventory(client: SnmpClient, ip: str, dev: Device) -> None:
    table = client.walk(ip, ENT_TABLE)
    if not table:
        return
    classes = column(table, ENT_CLASS)
    # chassis (3) first, then stack (11), module (9), then any entry with a serial
    order = sorted(classes, key=lambda i: {"3": 0, "11": 1, "9": 2}.get(classes[i], 3))
    serials = column(table, ENT_SERIAL)
    models = column(table, ENT_MODEL)
    for idx in order + [i for i in serials if i not in classes]:
        serial = clean(serials.get(idx), 120)
        if serial:
            dev.serial = serial
            dev.model = clean(models.get(idx), 120) or dev.model
            dev.vendor = dev.vendor or clean(column(table, ENT_MFG).get(idx), 120)
            dev.firmware = clean(column(table, ENT_SOFTWARE).get(idx), 60) or clean(column(table, ENT_FIRMWARE).get(idx), 60)
            break


def _synology(client: SnmpClient, ip: str, dev: Device) -> None:
    info = client.get(ip, [SYNO_SYSTEM_STATUS, SYNO_TEMPERATURE, SYNO_MODEL, SYNO_SERIAL, SYNO_VERSION])
    dev.vendor = "Synology"
    dev.model = clean(info.get(SYNO_MODEL), 120) or dev.model
    dev.serial = clean(info.get(SYNO_SERIAL), 120) or dev.serial
    dev.firmware = clean(info.get(SYNO_VERSION), 60) or dev.firmware
    dev.os = "DSM"
    if to_int(info.get(SYNO_SYSTEM_STATUS)) == 2:
        dev.findings.append(Finding("crit", "System status failed"))
    temp = to_int(info.get(SYNO_TEMPERATURE))
    if temp is not None:
        dev.metrics["temperature_c"] = temp

    for idx, status in column(client.walk(ip, SYNO_DISK_STATUS), SYNO_DISK_STATUS).items():
        s = to_int(status)
        if s in (4, 5):
            dev.findings.append(Finding("crit", f"Disk {idx} {'crashed' if s == 5 else 'system partition failed'}"))
        elif s == 3:
            dev.findings.append(Finding("warn", f"Disk {idx} not initialised"))

    raid = client.walk(ip, ".1.3.6.1.4.1.6574.3.1.1")
    names = column(raid, SYNO_RAID_NAME)
    for idx, status in column(raid, SYNO_RAID_STATUS).items():
        s = to_int(status)
        name = clean(names.get(idx)) or f"RAID {idx}"
        if s in (11, 12):
            dev.findings.append(Finding("crit", f"{name} {'degraded' if s == 11 else 'crashed'}"))
        elif s is not None and s != 1:
            dev.findings.append(Finding("warn", f"{name} {'repairing' if s == 2 else 'busy (migrating/expanding)'}"))


def _idrac(client: SnmpClient, ip: str, dev: Device) -> None:
    info = client.get(ip, [IDRAC_SERVICE_TAG, IDRAC_MODEL, IDRAC_GLOBAL_STATUS])
    dev.vendor = "Dell"
    dev.serial = clean(info.get(IDRAC_SERVICE_TAG), 120) or dev.serial
    dev.model = clean(info.get(IDRAC_MODEL), 120) or dev.model
    status = to_int(info.get(IDRAC_GLOBAL_STATUS))
    if status == 4:
        dev.findings.append(Finding("warn", "Hardware warning (iDRAC)"))
    elif status in (5, 6):
        dev.findings.append(Finding("crit", "Hardware fault (iDRAC)"))
    elif status == 3:
        dev.summary.append("Hardware OK")


def _interfaces(client: SnmpClient, ip: str, dev: Device, previous: dict) -> None:
    types = column(client.walk(ip, IF_TYPE), IF_TYPE)
    ports = [i for i, t in types.items() if t in ETHERNET_IF_TYPES]
    if not ports:
        return
    oper = column(client.walk(ip, IF_OPER), IF_OPER)
    errors = column(client.walk(ip, IF_IN_ERRORS), IF_IN_ERRORS)
    names = column(client.walk(ip, IF_NAME), IF_NAME)

    up = sum(1 for i in ports if oper.get(i) == "1")
    dev.summary.append(f"{up}/{len(ports)} ports up")
    dev.metrics["ports_total"] = len(ports)
    dev.metrics["ports_up"] = up

    rising = []
    for i in ports:
        now = to_int(errors.get(i))
        if now is None:
            continue
        dev.counters[i] = now
        before = previous.get(i)
        if before is not None and 0 <= before < now and now - before >= 100:
            rising.append(clean(names.get(i), 30) or f"port {i}")
    if rising:
        shown = ", ".join(rising[:3]) + (f" +{len(rising) - 3} more" if len(rising) > 3 else "")
        dev.findings.append(Finding("warn", f"Input errors rising on {shown}"))


def _storage(client: SnmpClient, ip: str, dev: Device) -> None:
    table = client.walk(ip, HR_STORAGE)
    if not table:
        return
    types, descrs = column(table, HR_STORAGE_TYPE), column(table, HR_STORAGE_DESCR)
    units, sizes, used = column(table, HR_STORAGE_UNITS), column(table, HR_STORAGE_SIZE), column(table, HR_STORAGE_USED)
    worst = None
    for idx, t in types.items():
        if t.lstrip(".") != HR_FIXED_DISK.lstrip("."):
            continue
        u, s, n = to_int(units.get(idx)), to_int(sizes.get(idx)), to_int(used.get(idx))
        if not u or not s or n is None or s * u < 1_000_000_000:  # ignore < 1 GB (boot/system partitions)
            continue
        name = clean(descrs.get(idx), 60) or f"volume {idx}"
        drive = re.match(r"^([A-Za-z]:\\)", name)  # Windows: "C:\ Label:  Serial Number ..." -> "C:\"
        if drive:
            name = drive.group(1)
        if name.startswith(SYSTEM_MOUNT_PREFIXES) or (dev.type == "nas" and name == "/"):
            continue  # OS/system mounts - only real data volumes matter
        pct = round(n / s * 100)
        if worst is None or pct > worst[1]:
            worst = (name, pct, s * u)
        if pct >= 97:
            dev.findings.append(Finding("crit", f"{name} {pct}% full"))
        elif pct >= 90:
            dev.findings.append(Finding("warn", f"{name} {pct}% full"))
    if worst:
        dev.metrics["fullest_volume_pct"] = worst[1]
        if worst[1] < 90:
            dev.summary.append(f"fullest volume {worst[1]}%")


def _printer(client: SnmpClient, ip: str, dev: Device, extra: dict[str, str]) -> None:
    info = client.get(ip, [PRT_SERIAL, HR_DEVICE_DESCR_1])
    dev.serial = dev.serial or clean(info.get(PRT_SERIAL), 120)
    dev.model = dev.model or clean(info.get(HR_DEVICE_DESCR_1), 120)
    table = client.walk(ip, PRT_SUPPLIES)
    descrs, maxes, levels = column(table, PRT_SUPPLY_DESCR), column(table, PRT_SUPPLY_MAX), column(table, PRT_SUPPLY_LEVEL)
    lowest = None
    for idx, level in levels.items():
        lv, mx = to_int(level), to_int(maxes.get(idx))
        if lv is None or mx is None or lv < 0 or mx <= 0:  # -2 unknown, -3 "some remaining"
            continue
        pct = round(lv / mx * 100)
        name = clean(descrs.get(idx), 40) or f"supply {idx}"
        if lowest is None or pct < lowest[1]:
            lowest = (name, pct)
        if pct <= 10:
            dev.findings.append(Finding("warn", f"{name} {'empty' if pct == 0 else f'{pct}%'}"))
    if lowest:
        dev.metrics["lowest_supply_pct"] = lowest[1]
        if lowest[1] > 10:
            dev.summary.append(f"supplies OK (lowest {lowest[1]}%)")


def _ups(client: SnmpClient, ip: str, dev: Device, extra: dict[str, str]) -> None:
    info = client.get(ip, [UPS_BATTERY_STATUS, UPS_CHARGE, UPS_OUTPUT_SOURCE])
    dev.model = dev.model or clean(extra.get(UPS_MODEL), 120)
    dev.firmware = dev.firmware or clean(extra.get(UPS_SOFTWARE), 60)
    battery, charge, source = to_int(info.get(UPS_BATTERY_STATUS)), to_int(info.get(UPS_CHARGE)), to_int(info.get(UPS_OUTPUT_SOURCE))
    if charge is not None:
        dev.metrics["battery_charge_pct"] = charge
    if battery in (3, 4):
        dev.findings.append(Finding("crit", "Battery low" if battery == 3 else "Battery depleted"))
    if source == 5:
        dev.findings.append(Finding("warn", "Running on battery"))
    elif source == 3:
        dev.summary.append(f"on mains{f' · {charge}% charge' if charge is not None else ''}")
