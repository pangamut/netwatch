#!/usr/bin/env python3
"""
netwatch.py — Home network monitor: alert on new devices via e-mail.
Detects devices via ARP scan (IPv4) and NDP cache (IPv6).
MAC address is always the primary key.

IPv6 note: Global Unicast addresses change on prefix delegation changes
(e.g. Telekom) and due to Privacy Extensions (RFC 4941) — not used as key,
logged for information only. Link-Local (fe80::) is stable.
"""

import argparse
import configparser
import json
import re
import smtplib
import subprocess
import sys
import socket
import urllib.request
import urllib.error
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from xml.etree import ElementTree as ET


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(config_path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not config_path.exists():
        print(f"[ERROR] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    cfg.read(config_path)
    return cfg


# ---------------------------------------------------------------------------
# IPv4: ARP scan
# ---------------------------------------------------------------------------

def scan_ipv4(subnet: str, interface: str | None, oui_file: str = "/usr/share/arp-scan/ieee-oui.txt") -> dict[str, dict]:
    """
    Returns {mac: {"ipv4": ip, "vendor": vendor}}.
    """
    cmd = ["sudo", "arp-scan", subnet, "--ignoredups", "--ouifile", oui_file]
    if interface:
        cmd += ["--interface", interface]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        print("[ERROR] arp-scan not found. Install with: sudo apt install arp-scan", file=sys.stderr)
        sys.exit(1)
    except subprocess.timeoutExpired:
        print("[ERROR] arp-scan timed out.", file=sys.stderr)
        return {}

    devices: dict[str, dict] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip     = parts[0].strip()
            mac    = parts[1].strip().lower()
            vendor = parts[2].strip() if len(parts) >= 3 else ""
            if mac.count(":") == 5:
                devices[mac] = {"ipv4": ip, "vendor": vendor}

    return devices


# ---------------------------------------------------------------------------
# IPv6: NDP cache
# ---------------------------------------------------------------------------

def probe_ipv6_multicast(interface: str) -> None:
    """
    Sends multicast ping to ff02::1%<iface> so all IPv6 hosts
    im lokalen Segment antworten und im NDP-Cache landen.
    Fehler werden ignoriert.
    """
    try:
        subprocess.run(
            ["ping6", "-c", "3", "-i", "0.5", "-W", "1", f"ff02::1%{interface}"],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass


def scan_ipv6(interface: str) -> dict[str, dict]:
    """
    Reads the kernel NDP cache.
    Returns {mac: {"ipv6_link_local": [...], "ipv6_global": [...]}}.

    Link-Local (fe80::) is prefix-independent and stable.
    Global Unicast changes on prefix delegation and Privacy Extensions
    — logged for information only, not used as identifier.
    """
    probe_ipv6_multicast(interface)

    try:
        result = subprocess.run(
            ["ip", "-6", "neigh", "show", "dev", interface],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as e:
        print(f"[WARN] ip -6 neigh failed: {e}", file=sys.stderr)
        return {}

    # Beispielzeilen:
    #   2003:de:abc::42 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    #   fe80::1        dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
    mac_re = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})")
    devices: dict[str, dict] = {}

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        ip6   = parts[0]
        state = parts[-1]
        if state in ("FAILED", "INCOMPLETE"):
            continue

        mac_match = mac_re.search(line)
        if not mac_match:
            continue
        mac = mac_match.group(1).lower()

        entry = devices.setdefault(mac, {"ipv6_link_local": [], "ipv6_global": []})

        if ip6.startswith("fe80:"):
            if ip6 not in entry["ipv6_link_local"]:
                entry["ipv6_link_local"].append(ip6)
        else:
            if ip6 not in entry["ipv6_global"]:
                entry["ipv6_global"].append(ip6)

    return devices


# ---------------------------------------------------------------------------
# Merge results
# ---------------------------------------------------------------------------

def merge_scan_results(ipv4: dict, ipv6: dict) -> dict[str, dict]:
    """
    Merges IPv4 and IPv6 scan results by MAC address.
    Each device appears only once regardless of dual-stack or single-stack.
    """
    all_macs = set(ipv4) | set(ipv6)
    merged = {}
    for mac in all_macs:
        v4 = ipv4.get(mac, {})
        v6 = ipv6.get(mac, {})
        merged[mac] = {
            "ipv4":            v4.get("ipv4"),
            "vendor":          v4.get("vendor", ""),
            "ipv6_link_local": v6.get("ipv6_link_local", []),
            "ipv6_global":     v6.get("ipv6_global", []),
        }
    return merged


# ---------------------------------------------------------------------------
# Known devices database
# ---------------------------------------------------------------------------

def load_known(db_path: Path) -> dict:
    if db_path.exists():
        with open(db_path) as f:
            return json.load(f)
    return {}


def save_known(db_path: Path, known: dict) -> None:
    with open(db_path, "w") as f:
        json.dump(known, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Mail — shared SMTP send function
# ---------------------------------------------------------------------------

def _smtp_send(host: str, port: int, user: str, password: str,
               frm: str, to: str, msg, timeout: int, verbose: bool) -> None:
    """Shared SMTP transport with verbose logging and timeout."""
    def vprint(s: str) -> None:
        if verbose:
            print(f"  [SMTP] {s}")

    # Connection mode: port 465 → SMTPS (immediate SSL), otherwise STARTTLS
    use_ssl = (port == 465)
    try:
        vprint(f"Connecting to {host}:{port} ({'SMTPS' if use_ssl else 'STARTTLS'}, Timeout {timeout}s) ...")
        if use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            smtp_cls = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            smtp_cls = smtplib.SMTP(host, port, timeout=timeout)
        with smtp_cls as smtp:
            if verbose:
                smtp.set_debuglevel(1)
            vprint("EHLO ...")
            smtp.ehlo()
            if not use_ssl:
                vprint("STARTTLS ...")
                smtp.starttls()
                smtp.ehlo()
            vprint(f"Logging in as {user} ...")
            smtp.login(user, password)
            vprint(f"Sending to {to} ...")
            smtp.sendmail(frm, [to], msg.as_bytes())
        print(f"[OK] Mail sent to {to}")
    except TimeoutError:
        print(f"[ERROR] SMTP timeout after {timeout}s — Host {host}:{port} unreachable?", file=sys.stderr)
    except smtplib.SMTPAuthenticationError as e:
        print(f"[ERROR] SMTP authentication failed: {e}", file=sys.stderr)
    except smtplib.SMTPException as e:
        print(f"[ERROR] SMTP error: {e}", file=sys.stderr)
    except OSError as e:
        print(f"[ERROR] Network error: {e}", file=sys.stderr)


def send_mail(cfg: configparser.ConfigParser, new_devices: list[dict], verbose: bool = False) -> None:
    mc       = cfg["mail"]
    host     = mc["smtp_host"]
    port     = int(mc.get("smtp_port", "587"))
    user     = mc["smtp_user"]
    password = mc["smtp_pass"]
    frm      = mc.get("mail_from", user)
    to       = mc["mail_to"]
    prefix   = mc.get("subject_prefix", "[netwatch]")
    timeout  = int(mc.get("smtp_timeout", "15"))

    now   = datetime.now().strftime("%Y-%m-%d %H:%M")
    count = len(new_devices)
    subject = f"{prefix} {count} neues Gerät{'e' if count != 1 else ''} on home network ({now})"

    lines = [f"netwatch hat {count} neues Gerät{'e' if count != 1 else ''} entdeckt:\n"]
    for d in new_devices:
        lines.append(f"  MAC:        {d['mac']}")
        lines.append(f"  IPv4:       {d['ipv4'] or '(not seen)'}")
        lines.append(f"  Vendor:     {d['vendor'] or '(unknown)'}")
        if d.get("ipv6_link_local"):
            lines.append(f"  IPv6 LL:    {', '.join(d['ipv6_link_local'])}")
            lines.append(f"              (Link-Local — stable, prefix-independent)")
        if d.get("ipv6_global"):
            lines.append(f"  IPv6 GUA:   {', '.join(d['ipv6_global'])}")
            lines.append(f"              (changes on prefix delegation/Privacy Extensions)")
        if d.get("hostname"):
            lines.append(f"  Hostname:   {d['hostname']}")
        lines.append(f"  First seen: {d['first_seen']}")
        lines.append("")

    lines += ["---", "netwatch running on your Raspberry Pi."]
    body = "\n".join(lines)

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"]    = frm
    msg["To"]      = to

    _smtp_send(host, port, user, password, frm, to, msg, timeout, verbose)


# ---------------------------------------------------------------------------
# Fritz!Box TR-064 lookup via SSDP discovery
# ---------------------------------------------------------------------------

def fritzbox_discover(timeout: int = 3) -> str | None:
    """
    Discovers the Fritz!Box via SSDP multicast.
    Returns the TR-064 base URL, e.g. "http://192.168.178.1:49000",
    or None if no Fritz!Box is found.
    """
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    SSDP_MX   = 2
    SSDP_ST   = "urn:dslforum-org:device:InternetGatewayDevice:1"

    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {SSDP_MX}\r\n"
        f"ST: {SSDP_ST}\r\n"
        "\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                response = data.decode(errors="ignore")
                # LOCATION-Header enthält die Beschreibungs-URL
                for line in response.splitlines():
                    if line.lower().startswith("location:"):
                        location = line.split(":", 1)[1].strip()
                        # Basis-URL extrahieren: http://host:port
                        m = re.match(r"(https?://[^/]+)", location)
                        if m:
                            return m.group(1)
            except socket.timeout:
                break
    finally:
        sock.close()
    return None


def fritzbox_get_hosts(base_url: str, password: str = "", verbose: bool = False) -> dict[str, str]:
    """
    Queries all hosts from the Fritz!Box via TR-064.
    Returns {mac_lower: hostname}.
    Authentication only if password is provided; works without password
    if TR-064 access without auth is enabled in the Fritz!Box settings.
    """
    def vprint(s: str) -> None:
        if verbose:
            print(f"  [TR-064] {s}")

    CTRL_URL  = f"{base_url}/upnp/control/hosts"
    SVC       = "urn:dslforum-org:service:Hosts:1"

    def soap_call(action: str, args: str = "") -> ET.Element | None:
        body = (
            '''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action} xmlns:u="{svc}">{args}</u:{action}>
  </s:Body>
</s:Envelope>'''.format(action=action, svc=SVC, args=args)
        )
        req = urllib.request.Request(
            CTRL_URL,
            data=body.encode(),
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction":   f'"{SVC}#{action}"',
            },
        )
        if password:
            import base64
            creds = base64.b64encode(f"dslf-config:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return ET.fromstring(resp.read())
        except urllib.error.HTTPError as e:
            vprint(f"HTTP {e.code} bei {action} — auth required?")
            return None
        except Exception as e:
            vprint(f"Error on {action}: {e}")
            return None

    # number of hosts
    vprint("Querying host count ...")
    root = soap_call("GetHostNumberOfEntries")
    if root is None:
        return {}
    ns  = {"s": "http://schemas.xmlsoap.org/soap/envelope/"}
    el  = root.find(".//{*}NewHostNumberOfEntries")
    if el is None:
        vprint("NewHostNumberOfEntries missing in response")
        return {}
    count = int(el.text or "0")
    vprint(f"{count} hosts in Fritz!Box list")

    hosts: dict[str, str] = {}
    for i in range(count):
        root = soap_call("GetGenericHostEntry", f"<NewIndex>{i}</NewIndex>")
        if root is None:
            continue
        mac_el  = root.find(".//{*}NewMACAddress")
        name_el = root.find(".//{*}NewHostName")
        if mac_el is not None and name_el is not None:
            mac  = (mac_el.text or "").lower().replace("-", ":")
            name = (name_el.text or "").strip()
            if mac and name:
                hosts[mac] = name

    vprint(f"{len(hosts)} hostnames loaded")
    return hosts


def do_lookup(db_path: Path, cfg: configparser.ConfigParser, verbose: bool = False) -> None:
    """
    Discovers the Fritz!Box via SSDP, fetches all hostnames via TR-064
    and writes them into known_devices.json.
    """
    fritz_pass = ""
    if cfg.has_section("fritzbox"):
        fritz_pass = cfg["fritzbox"].get("password", "").split("#")[0].strip()

    print("Discovering Fritz!Box via SSDP ...")
    base_url = fritzbox_discover()
    if not base_url:
        print("[ERROR] No Fritz!Box found via SSDP.", file=sys.stderr)
        return
    print(f"  Found: {base_url}")

    hosts = fritzbox_get_hosts(base_url, fritz_pass, verbose)
    if not hosts:
        print("[WARN] No hostnames received from Fritz!Box.")
        return

    known   = load_known(db_path)
    updated = 0
    for mac, hostname in hosts.items():
        if mac in known:
            if known[mac].get("hostname") != hostname:
                known[mac]["hostname"] = hostname
                updated += 1
                if verbose:
                    print(f"  {mac}  →  {hostname}")
        else:
            # Device only in Fritz!Box history, never seen in scan → skip
            if verbose:
                print(f"  {mac}  →  {hostname} (nur Fritz!Box history only, skipped)")

    save_known(db_path, known)

    # Save Fritz!Box host cache for immediate lookup on new devices
    fritz_cache_path = db_path.parent / "fritzbox_hosts.json"
    with open(fritz_cache_path, "w") as f:
        json.dump(hosts, f, indent=2, ensure_ascii=False)

    print(f"[OK] {updated} hostnames updated ({len(known)} devices total)")
    print(f"[OK] Fritz!Box cache saved: {len(hosts)} entries → {fritz_cache_path}")


# ---------------------------------------------------------------------------
# Host list mail
# ---------------------------------------------------------------------------

def send_hostlist_mail(cfg: configparser.ConfigParser, known: dict, verbose: bool = False) -> None:
    """Sends the complete known device list as an e-mail."""
    mc       = cfg["mail"]
    host     = mc["smtp_host"]
    port     = int(mc.get("smtp_port", "587"))
    user     = mc["smtp_user"]
    password = mc["smtp_pass"]
    frm      = mc.get("mail_from", user)
    to       = mc["mail_to"]
    prefix   = mc.get("subject_prefix", "[netwatch]")
    timeout  = int(mc.get("smtp_timeout", "15"))

    now   = datetime.now().strftime("%Y-%m-%d %H:%M")
    count = len(known)
    subject = f"{prefix} Host list — {count} known devices ({now})"

    # Sort by IPv4 numerically, devices without IPv4 at the end
    def sort_key(item: tuple) -> tuple:
        mac, d = item
        ip = d.get("ipv4") or ""
        try:
            parts = list(map(int, ip.split(".")))
            return (0, parts)
        except Exception:
            return (1, [999, 999, 999, 999])

    lines = [f"Known devices on home network — as of {now}\n"]
    lines.append(f"{'#':>3}  {'IPv4':<16}  {'MAC':<17}  {'Vendor':<28}  {'First seen':<19}  {'Last seen'}")
    lines.append("-" * 110)

    for i, (mac, d) in enumerate(sorted(known.items(), key=sort_key), start=1):
        ipv4       = d.get("ipv4") or "(no IPv4)"
        vendor     = (d.get("vendor") or "(unknown)")[:28]
        hostname   = d.get("hostname") or ""
        first_seen = d.get("first_seen", "")[:19]
        last_seen  = d.get("last_seen",  "")[:19]
        lines.append(f"{i:>3}  {ipv4:<16}  {mac:<17}  {vendor:<28}  {first_seen:<19}  {last_seen}")
        if hostname:
            lines.append(f"       Hostname: {hostname}")

        ll  = d.get("ipv6_link_local", [])
        gua = d.get("ipv6_global", [])
        if ll:
            lines.append(f"       IPv6 LL:  {', '.join(ll)}")
        if gua:
            lines.append(f"       IPv6 GUA: {', '.join(gua)}")

    lines += ["", "---", "netwatch läuft auf deinem Raspberry Pi."]
    body = "\n".join(lines)

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"]    = frm
    msg["To"]      = to

    _smtp_send(host, port, user, password, frm, to, msg, timeout, verbose)


def load_fritz_cache(db_path: Path) -> dict[str, str]:
    """Loads the local Fritz!Box host cache {mac: hostname}."""
    cache_path = db_path.parent / "fritzbox_hosts.json"
    if cache_path.exists():
        try:
            with open(cache_path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Home network monitor: alert on new devices via e-mail"
    )
    parser.add_argument("--config",    default="/etc/netwatch/netwatch.conf",
                        help="Path to config file")
    parser.add_argument("--db",        default="/var/lib/netwatch/known_devices.json",
                        help="Path to device database")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Scan and detect, but do not send mail")
    parser.add_argument("--bootstrap", action="store_true",
                        help="Mark all current devices as known (no mail)")
    parser.add_argument("--sendhosts", action="store_true",
                        help="Send complete host list via mail after scan")
    parser.add_argument("--lookup", action="store_true",
                        help="Discover Fritz!Box via SSDP, write hostnames into DB via TR-064")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output (SMTP steps, TR-064 requests)")
    args = parser.parse_args()

    config_path = Path(args.config)
    db_path     = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    cfg    = load_config(config_path)
    subnet = cfg["scan"].get("subnet", "10.1.0.0/20").split("#")[0].strip()
    iface  = cfg["scan"].get("interface") or None
    if iface:
        iface = iface.split("#")[0].strip() or None  # Inline-Kommentare tolerieren

    # --lookup: write Fritz!Box hostnames into DB, skip scan
    if args.lookup:
        do_lookup(db_path, cfg, verbose=args.verbose)
        if args.sendhosts:
            known = load_known(db_path)
            if args.dry_run:
                print(f"[DRY-RUN] Would send host list mail ({len(known)} devices).")
            else:
                send_hostlist_mail(cfg, known, verbose=args.verbose)
        return

    fritz_cache = load_fritz_cache(db_path)

    now_str = datetime.now().isoformat(timespec="seconds")
    print(f"[{now_str}] Scanne {subnet} (IPv4) + NDP cache (IPv6) on {iface} ...")

    oui_file = cfg["scan"].get("oui_file", "/usr/share/arp-scan/ieee-oui.txt").split("#")[0].strip()
    ipv4    = scan_ipv4(subnet, iface, oui_file)
    ipv6    = scan_ipv6(iface) if iface else {}
    current = merge_scan_results(ipv4, ipv6)

    ipv6_only = len(set(ipv6) - set(ipv4))
    print(f"  {len(current)} Geräte gesamt "
          f"(IPv4: {len(ipv4)}, IPv6-only: {ipv6_only})")

    known       = load_known(db_path)
    new_devices = []

    for mac, data in current.items():
        if mac not in known:
            entry = {**data, "mac": mac, "first_seen": now_str, "last_seen": now_str}
            # Check Fritz!Box cache for hostname
            if mac in fritz_cache:
                entry["hostname"] = fritz_cache[mac]
            known[mac] = entry
            if not args.bootstrap:
                new_devices.append(entry)
                hostname_hint = f"  [{entry['hostname']}]" if entry.get("hostname") else ""
                print(f"  [NEU] {mac}  "
                      f"{(data['ipv4'] or 'kein IPv4'):16}  "
                      f"{data['vendor'] or '(unbekannt)'}{hostname_hint}")
        else:
            # Known device: update IPs, no alert
            known[mac]["last_seen"]       = now_str
            known[mac]["ipv4"]            = data["ipv4"]
            known[mac]["ipv6_link_local"] = data["ipv6_link_local"]
            known[mac]["ipv6_global"]     = data["ipv6_global"]
            if not known[mac].get("vendor") and data["vendor"]:
                known[mac]["vendor"] = data["vendor"]

    save_known(db_path, known)

    if args.bootstrap:
        print(f"[OK] Bootstrap: {len(known)} devices marked as known. No mail sent.")
        return

    # register new devices
    if new_devices:
        if args.dry_run:
            print(f"[DRY-RUN] Would send alert mail for {len(new_devices)} device(s).")
        else:
            send_mail(cfg, new_devices, verbose=args.verbose)
    else:
        print("  No new devices.")

    # send full host list
    if args.sendhosts:
        if args.dry_run:
            print(f"[DRY-RUN] Would send host list mail ({len(known)} devices).")
        else:
            send_hostlist_mail(cfg, known, verbose=args.verbose)


if __name__ == "__main__":
    main()
