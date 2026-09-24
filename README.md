# LiveTracker Collector

Small Docker container that runs **inside your network**, polls switches, servers, NAS,
printers and UPSs over **SNMP**, and reports them to **LiveTracker IT Asset Tracker** over
outbound HTTPS. Nothing needs opening on your firewall.

```
 your network                                         internet
┌──────────────────────────────────────────┐
│ switches / servers / NAS / printers / UPS │
│            ▲ SNMP (UDP 161)               │
│   ┌────────┴─────────┐                    │   HTTPS (443, outbound only)
│   │ livetracker-      │───────────────────┼──────────────► livetracker.uk
│   │ collector (Docker)│                   │
│   └───────────────────┘                   │
└──────────────────────────────────────────┘
```

## What it reports

| Device | Identity | Health |
|---|---|---|
| **Switches** (Cisco, Netgear, Aruba/HPE, Dell, Juniper, Ubiquiti, TP-Link, MikroTik…) | model, serial, firmware (ENTITY-MIB) | ports up, **input errors rising** between polls |
| **Servers** (Dell iDRAC, Windows, Linux, ESXi) | Dell service tag + model via iDRAC | iDRAC global hardware status, volumes ≥90% / ≥97% full |
| **NAS** (Synology, QNAP, Buffalo) | Synology model / serial / DSM version | system status, **failed disks**, **degraded/crashed RAID**, volumes filling |
| **Printers** | model, serial (Printer-MIB) | toner / supplies ≤10% |
| **UPS** (APC, Eaton, any RFC 1628) | model, firmware | **on battery**, battery low / depleted |
| Anything else answering SNMP | name, description, uptime | reachability |

Every device also gets name, location, contact and uptime. Devices that stop answering are
reported as **"Not responding to SNMP"** (critical) until they're gone for 30 days.

## Requirements

- A Linux machine (VM, small PC, Raspberry Pi, or a NAS that runs containers) with Docker,
  on a network that can reach your devices on **UDP 161**.
- Outbound **HTTPS (443)** to your LiveTracker address.
- SNMP enabled on the devices - **SNMPv3 read-only** recommended (v2c supported).

## Install

1. In LiveTracker: **Products → IT Asset Tracker → Connectors → Network collector** → name it
   → **Create & get setup command**. Copy the key - it is shown once.
2. On the Linux machine, either paste the `docker run` command LiveTracker shows, or use an
   env file (keeps passwords out of your shell history):

   ```bash
   curl -fsSLo collector.env https://raw.githubusercontent.com/livetrackerJM/livetracker-collector/main/example.env
   nano collector.env          # LT_TOKEN, LT_TARGETS, SNMP settings
   chmod 600 collector.env
   docker run -d --name livetracker-collector --restart unless-stopped \
     --env-file collector.env -v livetracker-collector:/data \
     ghcr.io/livetrackerjm/livetracker-collector:latest
   ```

3. Devices appear in LiveTracker after the first poll (a few minutes). The Connectors page
   shows the collector as **Online** with its device count.

Docker Compose:

```yaml
services:
  livetracker-collector:
    image: ghcr.io/livetrackerjm/livetracker-collector:latest
    restart: unless-stopped
    env_file: collector.env
    volumes: ["livetracker-collector:/data"]
volumes:
  livetracker-collector: {}
```

## Settings

| Variable | Default | |
|---|---|---|
| `LT_URL` | - | Your LiveTracker address (https only) |
| `LT_TOKEN` | - | Collector key from LiveTracker (`ltc_…`) |
| `LT_TARGETS` | - | Subnets / ranges / IPs / hostnames, comma-separated. Max 4096 hosts per collector |
| `SNMP_VERSION` | `3` | `3`, `2c` or `1` |
| `SNMP_USER`, `SNMP_AUTH_PROTO`, `SNMP_AUTH_PASS`, `SNMP_PRIV_PROTO`, `SNMP_PRIV_PASS` | `SHA` / `AES` | SNMPv3 (passphrases ≥ 8 chars). Leave PRIV blank for authNoPriv |
| `SNMP_COMMUNITY` | - | v1/v2c read-only community |
| `LT_INTERVAL` | `300` | Seconds between polls (min 60) |
| `LT_WORKERS` | `32` | Parallel SNMP queries |
| `SNMP_TIMEOUT` / `SNMP_DISCOVERY_TIMEOUT` / `SNMP_RETRIES` | `2` / `1` / `1` | Known devices / sweep for new ones |

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
docker run --rm --env-file collector.env ghcr.io/livetrackerjm/livetracker-collector:latest --dry-run
```

`--dry-run` does one poll and prints exactly what would be sent, without sending it.
`401` in the log means the key was rotated or the collector removed in LiveTracker - update
`LT_TOKEN` and restart.

## Security

- Outbound only; the container listens on nothing.
- SNMP credentials are written to a private `snmp.conf` inside the container (mode 600), never
  passed on the command line.
- The LiveTracker key only allows posting this collector's device report. LiveTracker stores a
  hash of it; rotate or revoke it any time from the Connectors page.
- Runs as a non-root user; state (known devices, port error counters) lives in the `/data` volume.

## Development

```bash
python -m unittest discover -s tests -v      # simulated SNMP agents, no network needed
```

Pushing to `main` runs the tests and publishes `ghcr.io/<owner>/livetracker-collector:latest`
(amd64 + arm64). Tag `vX.Y.Z` to publish a versioned image.
