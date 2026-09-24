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
    hosts: list[str] = field(default_factory=list)

    @property
    def report_url(self) -> str:
        return self.url.rstrip("/") + "/api/collector/v1/report"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


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

    if not url.startswith("https://") and not _env("LT_ALLOW_HTTP"):
        raise ConfigError("LT_URL must be the https:// address of LiveTracker (e.g. https://livetracker.uk)")
    if not re.fullmatch(r"ltc_\d+_[A-Za-z0-9]{48}", token):
        raise ConfigError("LT_TOKEN is missing or malformed - copy it from LiveTracker > Connectors > Network collector")
    if not targets:
        raise ConfigError("LT_TARGETS is empty - set the subnets/IPs to poll, e.g. 192.168.1.0/24")

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
        state_dir=_env("LT_STATE_DIR", "/data"),
        verify_tls=_env("LT_VERIFY_TLS", "true").lower() not in ("0", "false", "no"),
    )

    if cfg.snmp_version not in ("3", "2c", "1"):
        raise ConfigError("SNMP_VERSION must be 3, 2c or 1")
    if cfg.snmp_version == "3":
        if not cfg.snmp_user:
            raise ConfigError("SNMP_USER is required for SNMPv3")
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
    elif not cfg.community:
        raise ConfigError("SNMP_COMMUNITY is required for SNMP v1/v2c")

    cfg.hosts = expand_targets(cfg.targets)
    return cfg
