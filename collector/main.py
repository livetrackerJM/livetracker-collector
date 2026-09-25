"""Poll loop: SNMP poll + network scan -> report, every LT_INTERVAL seconds.

  python -m collector            run forever (the container default)
  python -m collector --once     one cycle then exit
  python -m collector --dry-run  one cycle, print the report JSON, send nothing
  python -m collector --env-file collector.env   read settings from a file (default: ./collector.env if present)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import shutil
import signal
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from . import __version__
from . import scan as netscan
from .config import Config, ConfigError, load, load_env_file
from .probe import SYSTEM_OIDS, Device, probe
from .snmp import SnmpClient, SnmpTimeout

log = logging.getLogger("collector")

FORGET_AFTER = timedelta(days=30)
# Phones, laptops, TVs come and go - forget them sooner than infrastructure.
FORGET_INTERMITTENT_AFTER = timedelta(days=14)
_stop = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class State:
    """Known devices + interface error counters, persisted between cycles."""

    def __init__(self, directory: str):
        self.path = os.path.join(directory, "state.json")
        self.devices: dict[str, dict] = {}
        self.counters: dict[str, dict] = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.devices = data.get("devices", {})
            self.counters = data.get("counters", {})
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning("Ignoring unreadable state file %s: %s", self.path, e)

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), prefix=".state-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"devices": self.devices, "counters": self.counters}, f)
        os.replace(tmp, self.path)


def discover(client: SnmpClient, cfg: Config, known_ips: set[str]) -> dict[str, dict[str, str]]:
    """{ip: system group} for every target that answers SNMP."""
    def ask(ip: str):
        # known devices get the normal timeout/retries; unknown addresses a quick knock
        known = ip in known_ips
        try:
            return ip, client.get(ip, SYSTEM_OIDS,
                                  timeout=cfg.timeout if known else cfg.discovery_timeout,
                                  retries=cfg.retries if known else 0)
        except SnmpTimeout:
            return ip, None
        except Exception as e:  # noqa: BLE001 - one bad host must not stop the sweep
            log.debug("probe %s failed: %s", ip, e)
            return ip, None

    found: dict[str, dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        for ip, system in pool.map(ask, cfg.hosts):
            if system and system.get(".1.3.6.1.2.1.1.2.0"):
                found[ip] = system
    return found


def cycle(client: SnmpClient | None, cfg: Config, state: State, scanner=netscan.scan, oui: netscan.OuiDatabase | None = None) -> dict:
    started = _now()
    known_ips = {d.get("ip") for d in state.devices.values()}
    responders = discover(client, cfg, known_ips) if client and cfg.snmp else {}
    if client and cfg.snmp:
        log.info("Sweep of %d targets: %d answered SNMP", len(cfg.hosts), len(responders))
    found = scanner(cfg.hosts, workers=min(128, cfg.workers * 2), timeout=cfg.scan_timeout) if cfg.scan else {}

    def profile(item):
        ip, system = item
        prev_key = next((k for k, d in state.devices.items() if d.get("ip") == ip), None)
        try:
            return probe(client, ip, system, state.counters.get(prev_key or f"ip:{ip}", {}))
        except Exception as e:  # noqa: BLE001
            log.warning("Profiling %s failed: %s", ip, e)
            return None

    with ThreadPoolExecutor(max_workers=max(1, cfg.workers // 4)) as pool:
        devices: list[Device] = [d for d in pool.map(profile, responders.items()) if d]

    report_devices = []
    seen_keys = set()
    now_iso = started.isoformat()
    for dev in devices:
        seen_keys.add(dev.key)
        state.counters[dev.key] = dev.counters
        record = {
            # "ip" must be a literal address (LiveTracker validates it); a hostname target goes in name instead
            "key": dev.key, "ip": dev.ip if _is_ip(dev.ip) else None, "name": dev.name or dev.ip, "type": dev.type, "vendor": dev.vendor,
            "model": dev.model, "serial": dev.serial, "firmware": dev.firmware, "os": dev.os,
            "location": dev.location, "contact": dev.contact, "health": dev.health, "detail": dev.detail or None,
            "uptime_seconds": dev.uptime_seconds, "last_seen": now_iso, "metrics": dev.metrics or None,
            "mac": found[dev.ip].mac if dev.ip in found else None, "discovery": "snmp",
        }
        state.devices[dev.key] = {**record, "last_seen": now_iso}
        report_devices.append({k: v for k, v in record.items() if v is not None})

    # Everything else the network scan found (SNMP devices keep their fuller SNMP record).
    snmp_ips = {dev.ip for dev in devices}
    oui = oui or netscan.OuiDatabase(cfg.state_dir)
    for ip, host in found.items():
        if ip in snmp_ips:
            continue
        record = {**netscan.describe(host, oui), "last_seen": now_iso}
        # the MAC-based key keeps a device one asset when DHCP gives it a new address
        if record["key"] in seen_keys:
            continue
        seen_keys.add(record["key"])
        state.devices[record["key"]] = record
        report_devices.append(record)

    # Previously-seen devices that didn't answer this time: report them as down
    # (so LiveTracker shows "Not responding") until they're 30 days gone.
    for key, saved in list(state.devices.items()):
        if key in seen_keys:
            continue
        last = datetime.fromisoformat(saved["last_seen"])
        scanned = saved.get("discovery") == "scan"
        intermittent = scanned and saved.get("presence") == "intermittent"
        forget_after = FORGET_INTERMITTENT_AFTER if intermittent else FORGET_AFTER
        if started - last > forget_after or saved.get("ip") not in cfg.hosts or (scanned and not cfg.scan):
            del state.devices[key]
            state.counters.pop(key, None)
            continue
        down = {k: v for k, v in saved.items() if v is not None and k not in ("health", "detail", "metrics", "services")}
        if intermittent:
            # switched off or gone home - not a fault
            down.update({"health": "healthy", "online": False, "detail": "Offline", "last_seen": saved["last_seen"]})
        else:
            down.update({"health": "crit", "online": False, "last_seen": saved["last_seen"],
                         "detail": "Not responding" if scanned else "Not responding to SNMP"})
        report_devices.append(down)

    state.save()
    return {
        "collector": {"version": __version__, "hostname": socket.gethostname()[:120], "interval": cfg.interval,
                      "targets": len(cfg.hosts), "snmp": bool(client and cfg.snmp), "scan": cfg.scan},
        "devices": report_devices,
    }


def send(cfg: Config, report: dict) -> bool:
    body = json.dumps(report).encode("utf-8")
    req = urllib.request.Request(cfg.report_url, data=body, method="POST", headers={
        "Authorization": f"Bearer {cfg.token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"LiveTracker-Collector/{__version__}",
    })
    context = None if cfg.verify_tls else ssl._create_unverified_context()  # noqa: S323 - opt-in for lab use only
    try:
        with urllib.request.urlopen(req, timeout=60, context=context) as resp:
            result = json.loads(resp.read() or b"{}")
            log.info("Reported %d devices (accepted %s, retired %s)", len(report["devices"]), result.get("accepted"), result.get("retired"))
            return True
    except urllib.error.HTTPError as e:
        detail = e.read()[:500].decode("utf-8", "replace")
        if e.code == 401:
            log.error("LiveTracker rejected the collector key (401) - it was revoked or rotated. Update LT_TOKEN.")
        else:
            log.error("LiveTracker returned HTTP %s: %s", e.code, detail)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.error("Could not reach LiveTracker at %s: %s", cfg.report_url, e)
    return False


def _handle_stop(signum, frame):  # noqa: ARG001
    global _stop
    _stop = True
    log.info("Stopping after this cycle")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="collector", description="LiveTracker network collector")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--dry-run", action="store_true", help="run one cycle, print the report, send nothing")
    parser.add_argument("--env-file", help="settings file (KEY=value lines); default ./collector.env if it exists")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        env_file = args.env_file or ("collector.env" if os.path.exists("collector.env") else None)
        if env_file:
            load_env_file(env_file)
        cfg = load()
    except ConfigError as e:
        log.error("Configuration error: %s", e)
        return 2

    if cfg.snmp and not shutil.which("snmpget"):
        log.warning("SNMP settings found but the net-snmp tools (snmpget) aren't installed - SNMP polling is off")
        cfg.snmp = False
    if not cfg.snmp and not cfg.scan:
        log.error("Nothing to do - SNMP is unavailable and LT_SCAN is off")
        return 2

    log.info("LiveTracker Collector %s - %d targets, every %ds, SNMP %s, network scan %s", __version__, len(cfg.hosts),
             cfg.interval, f"v{cfg.snmp_version}" if cfg.snmp else "off", "on" if cfg.scan else "off")
    client = SnmpClient(cfg) if cfg.snmp else None
    state = State(cfg.state_dir)
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    while True:
        started = time.monotonic()
        report = cycle(client, cfg, state)
        if args.dry_run:
            print(json.dumps(report, indent=2))
            return 0
        send(cfg, report)
        if args.once or _stop:
            return 0
        # sleep in short steps so docker stop is prompt
        while not _stop and time.monotonic() - started < cfg.interval:
            time.sleep(1)
        if _stop:
            return 0


if __name__ == "__main__":
    sys.exit(main())
