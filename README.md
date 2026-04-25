# netwatch

Home network monitor: detects new devices and sends e-mail alerts.

Runs on a Raspberry Pi (or any Linux host) with no cloud dependencies.

## Features

- **Dual-stack**: detects devices via ARP scan (IPv4) and NDP cache (IPv6)
- **MAC as primary key**: stable across DHCP IP changes and IPv6 prefix rotations (Privacy Extensions / Telekom prefix delegation)
- **Vendor lookup**: via `ieee-oui.txt` from `arp-scan`
- **Fritz!Box integration**: fetches hostnames via TR-064, Fritz!Box discovered automatically via SSDP — no hardcoded host needed
- **Immediate hostname resolution**: Fritz!Box host cache is consulted at scan time, so newly detected devices get their hostname right away
- **E-mail notifications**: SMTP with STARTTLS (port 587) or SMTPS (port 465), auto-detected by port number
- **Persistent device database**: JSON file with `first_seen` / `last_seen` / hostname / IPv4 / IPv6
- **Host list mail**: full device list on demand

## Requirements

```bash
sudo apt install arp-scan
sudo chmod a+r /usr/share/arp-scan/ieee-oui.txt
```

Python 3.10+ (stdlib only, no external packages).

## Installation

```bash
sudo mkdir -p /etc/netwatch /var/lib/netwatch
sudo cp netwatch.py /usr/local/bin/netwatch.py
sudo chmod +x /usr/local/bin/netwatch.py

sudo cp netwatch.conf.example /etc/netwatch/netwatch.conf
sudo nano /etc/netwatch/netwatch.conf
sudo chmod 600 /etc/netwatch/netwatch.conf
```

## Configuration

```ini
[scan]
subnet    = 192.168.172.0/24
interface = eth0
# oui_file = /usr/share/arp-scan/ieee-oui.txt

[mail]
smtp_host      = mail.example.com
smtp_port      = 465          # 465 = SMTPS, 587 = STARTTLS (auto-detected)
smtp_user      = user@example.com
smtp_pass      = secret
mail_from      = user@example.com
mail_to        = user@example.com
subject_prefix = [netwatch]
# smtp_timeout = 15

[fritzbox]
# password = fritz-password   # only needed if TR-064 auth is enforced
```

## Initial setup

```bash
# Mark all currently visible devices as known (no mail)
sudo python3 /usr/local/bin/netwatch.py --bootstrap

# Fetch Fritz!Box hostnames and populate local cache
sudo python3 /usr/local/bin/netwatch.py --lookup

# Test run without sending mail
sudo python3 /usr/local/bin/netwatch.py --dry-run
```

## Usage

```
usage: netwatch.py [-h] [--config CONFIG] [--db DB]
                   [--dry-run] [--bootstrap] [--lookup] [--sendhosts] [-v]

options:
  --config CONFIG   Path to config file (default: /etc/netwatch/netwatch.conf)
  --db DB           Path to device database (default: /var/lib/netwatch/known_devices.json)
  --dry-run         Scan and detect, but do not send mail
  --bootstrap       Mark all current devices as known (no mail)
  --lookup          Discover Fritz!Box via SSDP, write hostnames into DB via TR-064
  --sendhosts       Send complete host list via mail (combinable with --lookup)
  -v, --verbose     Verbose output (SMTP steps, TR-064 requests)
```

## Cron

```cron
# Every 5 minutes: detect and alert on new devices
*/5 * * * * python3 /usr/local/bin/netwatch.py >> /var/log/netwatch.log 2>&1

# Daily at 7:00: refresh Fritz!Box hostnames and send host list
0 7 * * * python3 /usr/local/bin/netwatch.py --lookup --sendhosts >> /var/log/netwatch.log 2>&1
```

## Device database

Stored at `/var/lib/netwatch/known_devices.json`:

```json
{
  "ec:e3:34:ab:bc:33": {
    "ipv4": "192.168.172.33",
    "vendor": "Espressif Inc.",
    "hostname": "shellypro3em-ece334abbc33,
    "ipv6_link_local": [],
    "ipv6_global": [],
    "first_seen": "2026-04-25T13:47:31",
    "last_seen":  "2026-04-25T13:50:01"
  }
}
```

Hostnames are only written for devices already seen via ARP/NDP scan. Devices known to the Fritz!Box but currently offline are ignored.

A local Fritz!Box host cache is maintained at `/var/lib/netwatch/fritzbox_hosts.json` and consulted immediately when a new device is detected — no need to wait for the next daily `--lookup` run.

## Fritz!Box TR-064

`--lookup` discovers the Fritz!Box automatically via SSDP multicast (`239.255.255.250:1900`) — no hardcoded IP needed. Works without a password if **Home Network → Network → Home Network Sharing → Allow access for applications** is enabled.

## IPv6 notes

- **Link-Local** (`fe80::`): stable, prefix-independent, reliable identifier
- **Global Unicast**: changes on prefix delegation (Telekom DSL) and due to Privacy Extensions (RFC 4941) — logged but not used as identifier
- NDP cache may include STALE entries for devices that went offline shortly before the scan — these are not false positives; the devices will be recognized as known when they come back

## sudo

`arp-scan` requires raw socket access. Alternative to running as root:

```bash
sudo setcap cap_net_raw+ep $(which arp-scan)
```

This allows netwatch to run as an unprivileged user.


