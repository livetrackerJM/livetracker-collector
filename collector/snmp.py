"""Thin wrapper around the net-snmp command-line tools (snmpget / snmpbulkwalk).

Why the CLI rather than a Python SNMP library: net-snmp is the reference
implementation, stable for decades, and fully supports SNMPv3 auth/priv
combinations. Credentials are written to a private snmp.conf (SNMPCONFPATH)
instead of being passed as arguments, so they never show in the process list.

Output is requested as "-On -OQ -Oe -Ot": numeric OIDs, "OID = value" without
type names, numeric enums, raw timeticks.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import Callable

from .config import Config

Runner = Callable[[list[str], dict], "subprocess.CompletedProcess[str]"]

_MISSING = ("No Such Object", "No Such Instance", "No more variables", "End of MIB")
_LINE = re.compile(r"^(\.?[0-9]+(?:\.[0-9]+)+) = (.*)$")


class SnmpTimeout(Exception):
    pass


def _default_runner(args: list[str], env: dict) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=60, errors="replace")


def parse(output: str) -> dict[str, str]:
    """Parse "-On -OQ" output into {oid: value}. Multi-line values are joined."""
    values: dict[str, str] = {}
    current: str | None = None
    for raw in output.splitlines():
        m = _LINE.match(raw)
        if m:
            oid, value = m.group(1), m.group(2)
            oid = oid if oid.startswith(".") else "." + oid
            current = oid
            values[oid] = value
        elif current is not None and raw.strip():
            values[current] += "\n" + raw
    cleaned: dict[str, str] = {}
    for oid, value in values.items():
        value = value.strip()
        if any(value.startswith(m) for m in _MISSING):
            continue
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        cleaned[oid] = value.strip()
    return cleaned


class SnmpClient:
    def __init__(self, cfg: Config, runner: Runner | None = None):
        self.cfg = cfg
        self.runner = runner or _default_runner
        self._confdir = tempfile.mkdtemp(prefix="lt-snmp-")
        os.chmod(self._confdir, 0o700)
        self._write_conf()
        self.env = {
            **os.environ,
            "SNMPCONFPATH": self._confdir,
            "MIBS": "",
            "MIBDIRS": "",
        }

    def _write_conf(self) -> None:
        c = self.cfg
        lines = []
        if c.snmp_version == "3":
            level = "authPriv" if c.priv_pass else ("authNoPriv" if c.auth_pass else "noAuthNoPriv")
            lines += ["defVersion 3", f"defSecurityName {c.snmp_user}", f"defSecurityLevel {level}"]
            if c.auth_pass:
                lines += [f"defAuthType {c.auth_proto}", f"defAuthPassphrase {c.auth_pass}"]
            if c.priv_pass:
                lines += [f"defPrivType {c.priv_proto}", f"defPrivPassphrase {c.priv_pass}"]
        else:
            lines += [f"defVersion {c.snmp_version}", f"defCommunity {c.community}"]
        path = os.path.join(self._confdir, "snmp.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def _run(self, tool: str, host: str, oids: list[str], timeout: int, retries: int, extra: list[str] | None = None) -> dict[str, str]:
        args = [tool, "-On", "-OQ", "-Oe", "-Ot", "-t", str(timeout), "-r", str(retries), *(extra or []), host, *oids]
        result = self.runner(args, self.env)
        text = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        if result.returncode != 0 and ("Timeout" in text or "No Response" in text):
            raise SnmpTimeout(host)
        if result.returncode != 0 and not result.stdout:
            # auth failures, unknown host, etc. - treat like "not an SNMP device we can read"
            raise SnmpTimeout(f"{host}: {text.strip()[:200]}")
        return parse(result.stdout or "")

    def get(self, host: str, oids: list[str], *, timeout: int | None = None, retries: int | None = None) -> dict[str, str]:
        return self._run("snmpget", host, oids,
                         timeout if timeout is not None else self.cfg.timeout,
                         retries if retries is not None else self.cfg.retries)

    def walk(self, host: str, oid: str) -> dict[str, str]:
        extra = ["-Cr25"] if self.cfg.snmp_version != "1" else []
        tool = "snmpbulkwalk" if self.cfg.snmp_version != "1" else "snmpwalk"
        try:
            return self._run(tool, host, [oid], self.cfg.timeout, self.cfg.retries, extra)
        except SnmpTimeout:
            return {}


def column(table: dict[str, str], base: str) -> dict[str, str]:
    """{index: value} for rows of a walked column, e.g. base=".1.3.6.1.2.1.2.2.1.8"."""
    prefix = base.rstrip(".") + "."
    return {oid[len(prefix):]: v for oid, v in table.items() if oid.startswith(prefix)}


def to_int(value: str | None) -> int | None:
    if value is None:
        return None
    m = re.match(r"-?\d+", value.strip())
    return int(m.group(0)) if m else None
