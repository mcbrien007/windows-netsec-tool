"""
Threat intelligence and suspicious connection detection.

Checks connections against multiple rule categories:
  1. Known-bad ports (C2, RAT, crypto-miner, exfil patterns)
  2. Suspicious process/port mismatches (svchost on odd ports, etc.)
  3. Non-standard ports for common services
  4. High-risk country list (configurable)
  5. Tor exit node detection (via dan.me.uk/torlist — cached hourly)
  6. Known malicious IP list (abuse.ch Feodo tracker — cached hourly)
  7. Unusual outbound ports from browser/office processes
  8. Processes that should never reach the internet
  9. High data-transfer anomaly
 10. Beaconing pattern (periodic connections — detected across polls)

Each flag has:
  - code:    short identifier
  - level:   "critical" | "high" | "medium" | "low"
  - reason:  human-readable description
"""

import threading
import time
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta

# ── Flag dataclass ────────────────────────────────────────────────────────────

@dataclass
class ThreatFlag:
    code: str
    level: str       # critical | high | medium | low
    reason: str

    @property
    def icon(self) -> str:
        return {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
        }.get(self.level, "⚪")

    @property
    def color(self) -> str:
        return {
            "critical": "#f85149",
            "high":     "#e3b341",
            "medium":   "#d29922",
            "low":      "#58a6ff",
        }.get(self.level, "#8b949e")


# ── Rule tables ───────────────────────────────────────────────────────────────

# Ports associated with RATs, C2 frameworks, reverse shells, botnets
KNOWN_BAD_PORTS: dict[int, tuple[str, str]] = {
    # port: (code, reason)
    1080:  ("SOCKS",    "SOCKS proxy — common in malware C2 tunnels"),
    4444:  ("MSFRAT",   "Metasploit default reverse-shell port"),
    4445:  ("MSFRAT2",  "Metasploit secondary reverse-shell port"),
    5555:  ("RAT5555",  "Common RAT / ADB debug port"),
    6666:  ("IRC_BOT",  "IRC botnet port"),
    6667:  ("IRC",      "IRC — common botnet C2 channel"),
    6668:  ("IRC2",     "IRC alternate — common botnet port"),
    6669:  ("IRC3",     "IRC alternate — common botnet port"),
    7777:  ("RAT7777",  "Common RAT default port"),
    8888:  ("RAT8888",  "Common RAT / C2 default port"),
    9001:  ("TOR_OR",   "Tor OR port"),
    9030:  ("TOR_DIR",  "Tor directory authority port"),
    9050:  ("TOR_SOCKS","Tor SOCKS proxy port"),
    9051:  ("TOR_CTRL", "Tor control port"),
    31337: ("ELITE",    "31337 'elite' — classic backdoor/trojan port"),
    12345: ("NETBUS",   "NetBus trojan port"),
    12346: ("NETBUS2",  "NetBus trojan secondary port"),
    20034: ("NETBUS3",  "NetBus 2.x port"),
    27374: ("SUBSEVEN", "Sub7 trojan port"),
    65535: ("MAXPORT",  "Max TCP port — sometimes used to evade detection"),
    1337:  ("LEET",     "1337 — common backdoor port"),
    2222:  ("SSH_ALT",  "SSH on non-standard port — possible tunnel"),
    3333:  ("MINE",     "Common crypto-miner pool port (3333)"),
    14444: ("MINE2",    "Common crypto-miner pool port (14444)"),
    14433: ("MINE3",    "Common crypto-miner pool port (14433)"),
    45560: ("MINE4",    "Common crypto-miner pool port"),
    3389:  ("RDP",      "RDP exposed — should not be outbound from user processes"),
    5900:  ("VNC",      "VNC remote access — verify legitimacy"),
    5901:  ("VNC2",     "VNC display 1 — verify legitimacy"),
    4899:  ("RADMIN",   "Radmin remote admin — commonly abused"),
    23:    ("TELNET",   "Telnet — plaintext, rarely legitimate today"),
    135:   ("MSRPC",    "MS RPC — should not traverse internet"),
    139:   ("NETBIOS",  "NetBIOS — should not traverse internet"),
    445:   ("SMB",      "SMB — should never reach the internet; ransomware propagation"),
    1433:  ("MSSQL",    "MSSQL outbound — possible data exfil"),
    3306:  ("MYSQL",    "MySQL outbound — possible data exfil"),
    5432:  ("PSQL",     "PostgreSQL outbound — possible data exfil"),
}

# Processes that should almost never make outbound internet connections
NEVER_EXTERNAL: set[str] = {
    "lsass.exe", "lsaiso.exe", "csrss.exe", "smss.exe",
    "wininit.exe", "winlogon.exe", "services.exe",
    "spoolsv.exe", "dwm.exe", "fontdrvhost.exe",
    "sihost.exe", "taskhostw.exe",
}

# Processes expected to use only standard web ports (80/443/8080/8443)
WEB_ONLY_PROCESSES: set[str] = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe", "vivaldi.exe", "safari.exe",
    "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
}
WEB_STANDARD_PORTS: set[int] = {80, 443, 8080, 8443, 8000, 8001}

# Processes that should only bind locally, never reach the internet
LOCAL_ONLY_PROCESSES: set[str] = {
    "sqlservr.exe", "mysqld.exe", "postgres.exe", "mongod.exe",
    "redis-server.exe", "memcached.exe",
}

# High-risk country codes (connections to these get a medium flag)
HIGH_RISK_COUNTRIES: set[str] = {
    "KP",  # North Korea
    "IR",  # Iran
    "RU",  # Russia (adjust based on your threat model)
    "CN",  # China (adjust based on your threat model)
    "BY",  # Belarus
    "SY",  # Syria
    "CU",  # Cuba
    "VE",  # Venezuela
}

# Ports that should not be used for outbound connections by general software
SUSPICIOUS_HIGH_PORTS: tuple[int, int] = (49152, 65534)   # ephemeral range outbound to internet

# ── External threat feed cache ────────────────────────────────────────────────

_feed_lock   = threading.Lock()
_tor_exits:  set[str] = set()
_feodo_ips:  set[str] = set()
_feed_last_updated: datetime | None = None
_FEED_TTL = timedelta(hours=1)


def _update_feeds():
    """Fetch Tor exit list and Feodo C2 tracker. Runs in background thread."""
    global _tor_exits, _feodo_ips, _feed_last_updated

    new_tor: set[str] = set()
    new_feodo: set[str] = set()

    # Tor exit list
    try:
        r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=10)
        if r.status_code == 200:
            new_tor = {line.strip() for line in r.text.splitlines()
                       if line.strip() and not line.startswith("#")}
    except Exception:
        pass

    # Feodo tracker (Emotet, TrickBot, Dridex, QakBot C2 IPs)
    try:
        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            timeout=10
        )
        if r.status_code == 200:
            new_feodo = {line.strip() for line in r.text.splitlines()
                         if line.strip() and not line.startswith("#")}
    except Exception:
        pass

    with _feed_lock:
        if new_tor:
            _tor_exits = new_tor
        if new_feodo:
            _feodo_ips = new_feodo
        _feed_last_updated = datetime.now()


def _ensure_feeds():
    """Start feed refresh if TTL has elapsed."""
    with _feed_lock:
        if _feed_last_updated is None or datetime.now() - _feed_last_updated > _FEED_TTL:
            # Mark as updating so we don't double-spawn
            pass
        else:
            return
    threading.Thread(target=_update_feeds, daemon=True).start()


# Start initial fetch immediately at import time
threading.Thread(target=_update_feeds, daemon=True).start()


# ── Beaconing detector ────────────────────────────────────────────────────────
# Tracks first-seen timestamps per (process, remote_ip) and flags if we see
# many short-lived reconnects at regular intervals — a classic C2 beacon pattern.

@dataclass
class _BeaconRecord:
    appearances: list[datetime]
    last_flagged: datetime | None = None


_beacon_registry: dict[tuple[str, str], _BeaconRecord] = {}
_beacon_lock = threading.Lock()
_BEACON_MIN_APPEARANCES = 4      # minimum reconnects to consider
_BEACON_REGULARITY_THRESHOLD = 0.25   # coefficient of variation ≤ this = regular


def _update_beacon(process: str, remote_ip: str, first_seen: datetime):
    key = (process, remote_ip)
    with _beacon_lock:
        if key not in _beacon_registry:
            _beacon_registry[key] = _BeaconRecord(appearances=[first_seen])
        else:
            rec = _beacon_registry[key]
            if first_seen not in rec.appearances:
                rec.appearances.append(first_seen)
            # Trim old entries (> 30 min)
            cutoff = datetime.now() - timedelta(minutes=30)
            rec.appearances = [t for t in rec.appearances if t > cutoff]


def _check_beaconing(process: str, remote_ip: str) -> bool:
    """Return True if this (process, remote_ip) shows regular reconnect intervals."""
    key = (process, remote_ip)
    with _beacon_lock:
        rec = _beacon_registry.get(key)
        if not rec or len(rec.appearances) < _BEACON_MIN_APPEARANCES:
            return False
        sorted_times = sorted(rec.appearances)
        intervals = [
            (sorted_times[i+1] - sorted_times[i]).total_seconds()
            for i in range(len(sorted_times) - 1)
        ]
        if not intervals:
            return False
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            return False
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std = variance ** 0.5
        cv = std / mean   # coefficient of variation
        return cv <= _BEACON_REGULARITY_THRESHOLD


# ── Main analysis function ────────────────────────────────────────────────────

def analyze(
    local_addr: str,
    local_port: int,
    remote_addr: str,
    remote_port: int,
    protocol: str,
    process_name: str,
    pid: int,
    is_local: bool,
    status: str,
    bytes_sent: int,
    bytes_recv: int,
    rate_sent: float,
    rate_recv: float,
    first_seen: datetime,
    country_code: str = "",
) -> list[ThreatFlag]:
    """
    Run all detection rules against a single connection.
    Returns a list of ThreatFlag objects (empty = clean).
    """
    flags: list[ThreatFlag] = []
    _ensure_feeds()

    proc_lower = process_name.lower()

    # ── 1. Known-bad remote port ──
    if remote_port in KNOWN_BAD_PORTS:
        code, reason = KNOWN_BAD_PORTS[remote_port]
        level = "critical" if remote_port in (4444, 31337, 9050, 445, 12345) else "high"
        flags.append(ThreatFlag(code, level, f"Remote port {remote_port}: {reason}"))

    # ── 2. Known-bad local port (e.g. listening on 4444) ──
    if local_port in KNOWN_BAD_PORTS and status == "LISTEN":
        code, reason = KNOWN_BAD_PORTS[local_port]
        flags.append(ThreatFlag(
            f"LISTEN_{code}", "critical",
            f"Listening on {local_port}: {reason}"
        ))

    # ── 3. Tor exit node ──
    with _feed_lock:
        in_tor = remote_addr in _tor_exits

    if in_tor and not is_local:
        flags.append(ThreatFlag("TOR", "critical",
                                f"Remote IP {remote_addr} is a Tor exit node"))

    # ── 4. Feodo C2 tracker ──
    with _feed_lock:
        in_feodo = remote_addr in _feodo_ips

    if in_feodo and not is_local:
        flags.append(ThreatFlag("C2_FEODO", "critical",
                                f"Remote IP {remote_addr} is a known C2 server "
                                f"(Feodo/Emotet/TrickBot/QakBot tracker)"))

    # ── 5. Process that should never be external ──
    if not is_local and process_name in NEVER_EXTERNAL:
        flags.append(ThreatFlag("PROC_EXT", "critical",
                                f"{process_name} should never make external connections "
                                f"— possible credential theft or LSASS abuse"))

    # ── 6. Process on unexpected port ──
    if not is_local and process_name in WEB_ONLY_PROCESSES:
        if remote_port not in WEB_STANDARD_PORTS:
            flags.append(ThreatFlag("BROWSER_ODD_PORT", "high",
                                    f"{process_name} connecting on non-standard port "
                                    f"{remote_port} — possible tunnelling or malware injection"))

    # ── 7. Database process reaching internet ──
    if not is_local and process_name.lower() in {p.lower() for p in LOCAL_ONLY_PROCESSES}:
        flags.append(ThreatFlag("DB_EXTERNAL", "critical",
                                f"{process_name} should only be local — "
                                f"possible data exfiltration"))

    # ── 8. High-risk country ──
    if not is_local and country_code in HIGH_RISK_COUNTRIES and status == "ESTABLISHED":
        flags.append(ThreatFlag("RISK_COUNTRY", "medium",
                                f"Active connection to {country_code} "
                                f"(high-risk country code)"))

    # ── 9. svchost on unusual port ──
    if proc_lower == "svchost.exe" and not is_local:
        if remote_port not in {80, 443, 8080, 53, 123, 135, 137, 138, 139, 445, 5985, 5986}:
            flags.append(ThreatFlag("SVCHOST_ODD", "high",
                                    f"svchost.exe on unusual port {remote_port} "
                                    f"— possible DLL injection or hollowing"))

    # ── 10. PowerShell / cmd / wscript / cscript outbound ──
    shell_procs = {"powershell.exe", "powershell_ise.exe", "cmd.exe",
                   "wscript.exe", "cscript.exe", "mshta.exe",
                   "rundll32.exe", "regsvr32.exe", "certutil.exe",
                   "bitsadmin.exe", "msiexec.exe"}
    if proc_lower in shell_procs and not is_local:
        flags.append(ThreatFlag("SHELL_EXT", "critical",
                                f"{process_name} making external connection — "
                                f"classic LOLBin / fileless malware indicator"))

    # ── 11. Unencrypted traffic on port 80 from sensitive processes ──
    if remote_port == 80 and not is_local:
        sensitive = {"lsass.exe", "winlogon.exe", "csrss.exe"}
        if proc_lower in sensitive:
            flags.append(ThreatFlag("PLAIN_HTTP_SENSITIVE", "critical",
                                    f"{process_name} using unencrypted HTTP"))
        elif proc_lower in {p.lower() for p in WEB_ONLY_PROCESSES}:
            pass   # normal for browsers
        # Flag any process sending large data over HTTP (not HTTPS)
        elif bytes_sent > 512 * 1024:
            flags.append(ThreatFlag("HTTP_BULK", "medium",
                                    f"Large data transfer over unencrypted HTTP "
                                    f"({process_name}, {bytes_sent // 1024} KB sent)"))

    # ── 12. High-rate data exfil ──
    EXFIL_RATE_THRESHOLD = 2 * 1024 * 1024   # 2 MB/s sustained outbound
    if not is_local and rate_sent > EXFIL_RATE_THRESHOLD:
        flags.append(ThreatFlag("HIGH_EXFIL", "high",
                                f"High outbound data rate from {process_name}: "
                                f"{rate_sent / 1024:.0f} KB/s"))

    # ── 13. Beaconing pattern ──
    if not is_local and remote_addr:
        _update_beacon(process_name, remote_addr, first_seen)
        if _check_beaconing(process_name, remote_addr):
            flags.append(ThreatFlag("BEACON", "high",
                                    f"{process_name} shows regular reconnect intervals "
                                    f"to {remote_addr} — possible C2 beaconing"))

    # ── 14. Random-looking process name (entropy heuristic) ──
    import math
    base = proc_lower.replace(".exe", "").replace(".dll", "")
    if len(base) >= 6 and not is_local:
        freq = {}
        for ch in base:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = -sum((v / len(base)) * math.log2(v / len(base)) for v in freq.values())
        if entropy > 3.8:   # random-looking name threshold
            flags.append(ThreatFlag("HIGH_ENTROPY_PROC", "medium",
                                    f"Process name '{process_name}' has high character entropy "
                                    f"({entropy:.1f} bits) — possible random-named malware"))

    # ── 15. Non-ephemeral outbound local port reuse (port 0 oddity) ──
    if local_port == 0 and not is_local:
        flags.append(ThreatFlag("PORT_ZERO", "medium",
                                "Connection from local port 0 — unusual kernel behaviour"))

    # Deduplicate by code
    seen_codes: set[str] = set()
    deduped = []
    for f in flags:
        if f.code not in seen_codes:
            seen_codes.add(f.code)
            deduped.append(f)

    return deduped


def severity_score(flags: list[ThreatFlag]) -> int:
    """Return an integer 0-100 threat score from a flag list."""
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 3}
    return min(100, sum(weights.get(f.level, 0) for f in flags))


def highest_level(flags: list[ThreatFlag]) -> str | None:
    order = ["critical", "high", "medium", "low"]
    for level in order:
        if any(f.level == level for f in flags):
            return level
    return None
