# LiveTracker Collector

Small collector that runs **inside your network**, finds every device on it, polls switches,
servers, NAS, printers and UPSs over **SNMP** for health detail, and reports them to
**LiveTracker IT Asset Tracker** over outbound HTTPS. Nothing needs opening on your firewall.

```
 your network                                               internet
┌────────────────────────────────────────────────┐
│ routers / Wi-Fi / PCs / phones / printers / TVs │
│ switches / servers / NAS / UPS                  │
│      ▲ network scan  ▲ SNMP (UDP 161)           │
│   ┌──┴───────────────┴──┐                       │   HTTPS (443, outbound only)
│   │ livetracker-        │───────────────────────┼──────────────► livetracker.uk
│   │ collector           │                       │
│   └─────────────────────┘                       │
└────────────────────────────────────────────────┘
```

## What it reports

**Network scan** (on by default, no setup on the devices) - everything that's on the network:

| Found by | Tells us |
|---|---|
| TCP knock on common ports + the ARP table | that a device is there (even phones that ignore connections), its MAC address and maker |
| UPnP / SSDP | make, model and name - most broadband routers, TVs, printers and media boxes announce themselves |
| mDNS / Bonjour | names and models of Apple devices, Chromecasts, printers, NAS boxes, smart speakers |
| NetBIOS, reverse DNS | Windows computer names, names your router's DHCP handed out |

Each device is classed as a router / Wi-Fi, printer, NAS, TV & media, smart device, phone or
tablet, Mac, Windows PC, Linux device or other. Devices keep one identity across IP changes
(keyed by MAC address). Phones, laptops and TVs that go offline are shown as **Offline** (not a
fault) and forgotten after 14 days; routers, NAS and servers that disappear are **Not
responding** (critical).

**SNMP** (optional - needs read-only SNMP on the devices) adds health detail:

| Device | Identity | Health |
|---|---|---|
| **Switches** (Cisco, Netgear, Aruba/HPE, Dell, Juniper, Ubiquiti, TP-Link, MikroTik…) | model, serial, firmware (ENTITY-MIB) | ports up, **input errors rising** between polls |
| **Servers** (Dell iDRAC, Windows, Linux, ESXi) | Dell service tag + model via iDRAC | iDRAC global hardware status, volumes ≥90% / ≥97% full |
| **NAS** (Synology, QNAP, Buffalo) | Synology model / serial / DSM version | system status, **failed disks**, **degraded/crashed RAID**, volumes filling |
| **Printers** | model, serial (Printer-MIB) | toner / supplies ≤10% |
| **UPS** (APC, Eaton, any RFC 1628) | model, firmware | **on battery**, battery low / depleted |
| Anything else answering SNMP | name, description, uptime | reachability |

SNMP devices that stop answering are reported as **"Not responding to SNMP"** (critical) until
they're gone for 30 days.

## Requirements

- A machine **on the network you want to see** (the scan uses ARP and multicast, which don't
  cross routers - use one collector per site/VLAN, or list other subnets for SNMP only):
  - **Linux** with Docker (VM, small PC, Raspberry Pi, or a NAS that runs containers) - the
    normal setup; or
  - **Windows** with Python 3.10+ - handy for a quick look or a small office (no SNMP on Windows).
- Outbound **HTTPS (443)** to your LiveTracker address.
- For SNMP: **SNMPv3 read-only** recommended (v2c supported), reachable on **UDP 161**.

## Install - Linux (Docker)

1. In LiveTracker: **Products → IT Asset Tracker → Connectors → Network collector** → name it
   → **Create & get setup command**. Copy the key - it is shown once.
2. On the Linux machine, either paste the `docker run` command LiveTracker shows, or use an
   env file (keeps passwords out of your shell history):

   ```bash
   curl -fsSLo collector.env https://raw.githubusercontent.com/livetrackerJM/livetracker-collector/main/example.env
   nano collector.env          # LT_TOKEN, LT_TARGETS, optional SNMP settings
   chmod 600 collector.env
   docker run -d --name livetracker-collector --restart unless-stopped --network host \
     --env-file collector.env -v livetracker-collector:/data \
     ghcr.io/livetrackerjm/livetracker-collector:latest
   ```

   `--network host` lets the scan see the real network (Docker's own network hides ARP and
   multicast). SNMP-only collectors don't need it.

3. Devices appear in LiveTracker after the first scan (a few minutes). The Connectors page
   shows the collector as **Online** with its device count.

Docker Compose:

```yaml
services:
  livetracker-collector:
    image: ghcr.io/livetrackerjm/livetracker-collector:latest
    restart: unless-stopped
    network_mode: host
    env_file: collector.env
    volumes: ["livetracker-collector:/data"]
volumes:
  livetracker-collector: {}
```

## Install - Windows (Python)

Docker Desktop on Windows can't see the local network, so run the collector with Python:

1. Install Python 3.10+ from python.org (tick *Add python.exe to PATH*).
2. Put the collector folder somewhere, e.g. `C:\LiveTracker\collector` (the folder that contains
   the `collector` package and `example.env`).
3. Copy `example.env` to `collector.env` in that folder and fill in `LT_TOKEN`. `LT_TARGETS=auto`
   scans the network the PC is on.
4. In PowerShell, in that folder:

   ```powershell
   py -m collector --dry-run      # one scan, prints what would be sent, sends nothing
   py -m collector                # keep running (every 5 minutes); Ctrl+C to stop
   ```

   Windows may ask to let Python through the firewall the first time - *Private networks* is
   enough. To keep it running in the background, create a Task Scheduler task that runs
   `py -m collector` in that folder *At startup*, whether the user is logged on or not.

State (known devices, the MAC vendor list) is kept in `%LOCALAPPDATA%\LiveTracker\collector`.

## Settings

| Variable | Default | |
|---|---|---|
| `LT_URL` | - | Your LiveTracker address (https only) |
| `LT_TOKEN` | - | Collector key from LiveTracker (`ltc_…`) |
| `LT_TARGETS` | - | Subnets / ranges / IPs / hostnames, comma-separated, or `auto` (this machine's /24). Max 4096 hosts per collector |
| `LT_SCAN` | `on` | Network scan (`off` for SNMP only) |
| `LT_SCAN_TIMEOUT` | `0.8` | Seconds per TCP knock |
| `SNMP_VERSION` | `3` | `3`, `2c` or `1` - SNMP is used when `SNMP_USER` (v3) or `SNMP_COMMUNITY` (v1/v2c) is set |
| `SNMP_USER`, `SNMP_AUTH_PROTO`, `SNMP_AUTH_PASS`, `SNMP_PRIV_PROTO`, `SNMP_PRIV_PASS` | `SHA` / `AES` | SNMPv3 (passphrases ≥ 8 chars). Leave PRIV blank for authNoPriv |
| `SNMP_COMMUNITY` | - | v1/v2c read-only community |
| `LT_INTERVAL` | `300` | Seconds between cycles (min 60) |
| `LT_WORKERS` | `32` | Parallel SNMP queries (the scan uses twice this) |
| `SNMP_TIMEOUT` / `SNMP_DISCOVERY_TIMEOUT` / `SNMP_RETRIES` | `2` / `1` / `1` | Known devices / sweep for new ones |

Settings can also come from a file: `--env-file path` (default `./collector.env` if present).
Real environment variables win over the file.

## Turning on SNMP (examples)

- **Synology DSM:** Control Panel → Terminal & SNMP → SNMP → enable SNMPv3, SHA + AES.
- **Dell iDRAC:** iDRAC Settings → Services → SNMP Agent → enable; add an SNMPv3 user
  (iDRAC Settings → Users) with SNMPv3 enabled.
- **Netgear smart switches:** System → SNMP → SNMPv3 user (read-only).
- **Cisco IOS:** `snmp-server group LT v3 priv` + `snmp-server user livetracker LT v3 auth sha … priv aes 128 …`
- **APC Network Management Card:** Configuration → Network → SNMPv3 → user profiles + access.
- **HP printers:** Embedded Web Server → Networking → SNMP → SNMPv3 (or read-only v1/v2).
- **Windows Server:** install the "SNMP Service" feature (v2c only).

## Troubleshooting

```bash
docker logs -f livetracker-collector                                  # live log
docker run --rm --network host --env-file collector.env ghcr.io/livetrackerjm/livetracker-collector:latest --dry-run
```

`--dry-run` does one cycle and prints exactly what would be sent, without sending it (the log
goes to stderr, the report to stdout). `401` in the log means the key was rotated or the
collector removed in LiveTracker - update `LT_TOKEN` and restart.

Scan finds only the collector and the router? Check the machine is on the same network (not a
guest Wi-Fi, not behind a VPN that captures local traffic), and that Docker runs with
`--network host`.

## Security

- Outbound only; the collector listens on nothing.
- The scan is read-only: TCP connections are opened and closed without sending data, one
  multicast query each for SSDP and mDNS, and a GET of each device's own UPnP description
  (plain http on that device's address only, no redirects). The MAC vendor list is downloaded
  from wireshark.org every 90 days.
- SNMP credentials are written to a private `snmp.conf` (mode 600), never passed on the
  command line.
- The LiveTracker key only allows posting this collector's device report. LiveTracker stores a
  hash of it; rotate or revoke it any time from the Connectors page.
- The container runs as a non-root user; state lives in the `/data` volume.

## Development

```bash
python -m unittest discover -s tests -v      # simulated SNMP agents and network, no network needed
```

Pushing to `main` runs the tests and publishes `ghcr.io/<owner>/livetracker-collector:latest`
(amd64 + arm64). Tag `vX.Y.Z` to publish a versioned image.
