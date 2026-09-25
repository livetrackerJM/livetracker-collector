"""Configuration from environment variables (see example.env)."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

MAX_TARGET_HOSTS = 4096

AUTH_PROTOCOLS = {"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
PRIV_PROTOCOLS = {"DES", "AES", "AES-192", "AES-256"}


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    url: str
    token: str
    targets: list[str]
    snmp_version: str = "3"
    snmp_user: str = ""
    auth_proto: str = "SHA"
    auth_pass: str = ""
    priv_proto: str = "AES"
    priv_pass: str = ""
    community: str = ""
    interval: int = 300
    workers: int = 32
    timeout: int = 2
    retries: int = 1
    discovery_timeout: int = 1
    state_dir: str = "/data"
    verify_tls: bool = True
    snmp: bool = True
    scan: bool = True
    scan_timeout: float = 0.8
    hosts: list[str] = field(default_factory=list)

    @property
    def report_url(self) -> str:
        return self.url.rstrip("/") + "/api/collector/v1/report"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _flag(name: str, default: bool) -> bool:
    value = _env(name).lower()
    return default if value == "" else value not in ("0", "false", "no", "off")


def load_env_file(path: str) -> None:
    """KEY=value lines (Docker --env-file format) into os.environ; real environment variables win."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise ConfigError(f"Can't read settings file {path!r}: {e}") from e
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            os.environ.setdefault(key, value)


def default_state_dir() -> str:
    if os.name == "nt":
        return os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "LiveTracker", "collector")
    return "/data"


def auto_targets() -> list[str]:
    """LT_TARGETS=auto: the /24 this machine is on."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # picks the outbound interface; nothing is sent
            ip = s.getsockname()[0]
    except OSError as e:
        raise ConfigError(f"LT_TARGETS=auto couldn't work out this machine's network: {e}") from e
    return [str(ipaddress.ip_network(f"{ip}/24", strict=False))]


def expand_targets(spec: list[str]) -> list[str]:
    """Turn "10.0.0.0/24, 10.0.1.10-10.0.1.20, nas.local, 10.0.2.5" into host list."""
    hosts: list[str] = []
    for item in spec:
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError as e:
                raise ConfigError(f"Invalid subnet {item!r}: {e}") from e
            if net.version != 4:
                raise ConfigError(f"Only IPv4 subnets are supported ({item!r})")
            hosts.extend(str(h) for h in (net.hosts() if net.num_addresses > 2 else net))
        elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+", item):
            start, end = (ipaddress.IPv4Address(p) for p in item.split("-"))
            if end < start:
                raise ConfigError(f"Range {item!r} ends before it starts")
            hosts.extend(str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1))
        elif re.fullmatch(r"[A-Za-z0-9.\-]+", item):
            hosts.append(item)
        else:
            raise ConfigError(f"Invalid target {item!r}")
        if len(hosts) > MAX_TARGET_HOSTS:
            raise ConfigError(f"Targets expand to more than {MAX_TARGET_HOSTS} hosts - split them across collectors")
    # de-duplicate, keep order
    return list(dict.fromkeys(hosts))


def load() -> Config:
    url = _env("LT_URL")
    token = _env("LT_TOKEN")
    targets = [t for t in re.split(r"[,\s]+", _env("LT_TARGETS")) if t]
    if [t.lower() for t in targets] == ["auto"]:
        targets = auto_targets()

    if not url.startswith("https://") and not _env("LT_ALLOW_HTTP"):
        raise ConfigError("LT_URL must be the https:// address of LiveTracker (e.g. https://livetracker.uk)")
    if not re.fullmatch(r"ltc_\d+_[A-Za-z0-9]{48}", token):
        raise ConfigError("LT_TOKEN is missing or malformed - copy it from LiveTracker > Connectors > Network collector")
    if not targets:
        raise ConfigError("LT_TARGETS is empty - set the subnets/IPs to poll, e.g. 192.168.1.0/24 (or auto)")

    cfg = Config(
        url=url,
        token=token,
        targets=targets,
        snmp_version=_env("SNMP_VERSION", "3").lower(),
        snmp_user=_env("SNMP_USER"),
        auth_proto=_env("SNMP_AUTH_PROTO", "SHA").upper(),
        auth_pass=_env("SNMP_AUTH_PASS"),
        priv_proto=_env("SNMP_PRIV_PROTO", "AES").upper(),
        priv_pass=_env("SNMP_PRIV_PASS"),
        community=_env("SNMP_COMMUNITY"),
        interval=max(60, int(_env("LT_INTERVAL", "300"))),
        workers=min(128, max(1, int(_env("LT_WORKERS", "32")))),
        timeout=max(1, int(_env("SNMP_TIMEOUT", "2"))),
        retries=max(0, int(_env("SNMP_RETRIES", "1"))),
        discovery_timeout=max(1, int(_env("SNMP_DISCOVERY_TIMEOUT", "1"))),
        state_dir=_env("LT_STATE_DIR") or default_state_dir(),
        verify_tls=_env("LT_VERIFY_TLS", "true").lower() not in ("0", "false", "no"),
        scan=_flag("LT_SCAN", True),
        scan_timeout=min(5.0, max(0.2, float(_env("LT_SCAN_TIMEOUT", "0.8")))),
    )

    if cfg.snmp_version not in ("3", "2c", "1"):
        raise ConfigError("SNMP_VERSION must be 3, 2c or 1")
    # SNMP is optional: without credentials the collector only runs the network scan.
    cfg.snmp = _flag("LT_SNMP", True) and bool(cfg.snmp_user if cfg.snmp_version == "3" else cfg.community)
    if not cfg.snmp and not cfg.scan:
        raise ConfigError("Nothing to do - set SNMP credentials (SNMP_USER / SNMP_COMMUNITY) or leave LT_SCAN on")
    if cfg.snmp and cfg.snmp_version == "3":
        if cfg.auth_pass and cfg.auth_proto not in AUTH_PROTOCOLS:
            raise ConfigError(f"SNMP_AUTH_PROTO must be one of {sorted(AUTH_PROTOCOLS)}")
        if cfg.priv_pass and cfg.priv_proto not in PRIV_PROTOCOLS:
            raise ConfigError(f"SNMP_PRIV_PROTO must be one of {sorted(PRIV_PROTOCOLS)}")
        if cfg.priv_pass and not cfg.auth_pass:
            raise ConfigError("SNMP_PRIV_PASS needs SNMP_AUTH_PASS as well (authPriv)")
        for name in ("auth_pass", "priv_pass"):
            value = getattr(cfg, name)
            if value and len(value) < 8:
                raise ConfigError(f"SNMP_{name.upper()} must be at least 8 characters (SNMPv3 rule)")

    cfg.hosts = expand_targets(cfg.targets)
    return cfg
