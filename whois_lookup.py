"""
WHOIS / RDAP lookup for IP addresses.

Uses ARIN's RDAP API first (machine-readable JSON), then falls back to
the plain-text WHOIS port-43 socket query so we always get *something*.

Results are cached in memory per IP for the session.
"""

import socket
import threading
import requests
from datetime import datetime

_cache: dict[str, dict] = {}
_lock  = threading.Lock()

RDAP_URL = "https://rdap.arin.net/registry/ip/{ip}"
WHOIS_HOST = "whois.arin.net"
WHOIS_PORT = 43


# ── RDAP ─────────────────────────────────────────────────────────────────────

def _parse_rdap(data: dict) -> dict:
    out = {}

    out["handle"]  = data.get("handle", "")
    out["name"]    = data.get("name", "")
    out["type"]    = data.get("type", "")

    # CIDR / IP range
    cidr_blocks = data.get("cidr0_cidrs", [])
    if cidr_blocks:
        out["cidr"] = ", ".join(
            f"{b.get('v4prefix') or b.get('v6prefix', '')}/{b.get('length', '')}"
            for b in cidr_blocks
        )
    else:
        start = data.get("startAddress", "")
        end   = data.get("endAddress", "")
        out["cidr"] = f"{start} – {end}" if start else ""

    # Country
    out["country"] = data.get("country", "")

    # Registration dates
    events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
    out["registered"]   = _fmt_date(events.get("registration", ""))
    out["last_changed"] = _fmt_date(events.get("last changed", ""))

    # Entities (org, abuse, tech contacts)
    contacts = []
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [])
        name = _extract_vcard_name(vcard)
        email = _extract_vcard_email(vcard)
        phone = _extract_vcard_tel(vcard)
        addr  = _extract_vcard_addr(vcard)
        contacts.append({
            "roles":  ", ".join(roles),
            "name":   name,
            "email":  email,
            "phone":  phone,
            "address":addr,
        })
    out["contacts"] = contacts

    # Remarks / description
    remarks = []
    for r in data.get("remarks", []):
        title = r.get("title", "")
        desc  = " ".join(r.get("description", []))
        if desc:
            remarks.append(f"{title}: {desc}" if title else desc)
    out["remarks"] = remarks

    # Links
    out["links"] = [l.get("href", "") for l in data.get("links", []) if l.get("rel") == "self"]

    # Port 43
    out["port43"] = data.get("port43", "")

    return out


def _fmt_date(s: str) -> str:
    if not s:
        return ""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return s


def _vcard_get(vcard, field: str) -> list:
    if not vcard or len(vcard) < 2:
        return []
    entries = vcard[1] if isinstance(vcard[1], list) else []
    return [e for e in entries if isinstance(e, list) and len(e) >= 4 and e[0] == field]


def _extract_vcard_name(vcard) -> str:
    rows = _vcard_get(vcard, "fn")
    if rows:
        val = rows[0][3]
        return val if isinstance(val, str) else ""
    return ""


def _extract_vcard_email(vcard) -> str:
    rows = _vcard_get(vcard, "email")
    if rows:
        val = rows[0][3]
        return val if isinstance(val, str) else ""
    return ""


def _extract_vcard_tel(vcard) -> str:
    rows = _vcard_get(vcard, "tel")
    if rows:
        val = rows[0][3]
        if isinstance(val, str):
            return val.replace("tel:", "")
    return ""


def _extract_vcard_addr(vcard) -> str:
    rows = _vcard_get(vcard, "adr")
    if rows:
        val = rows[0][3]
        if isinstance(val, list):
            return ", ".join(p for p in val if p)
        return str(val)
    return ""


# ── Plain WHOIS fallback ──────────────────────────────────────────────────────

def _whois_raw(ip: str) -> str:
    try:
        s = socket.create_connection((WHOIS_HOST, WHOIS_PORT), timeout=6)
        s.sendall(f"n {ip}\r\n".encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        return resp.decode("utf-8", errors="replace")
    except Exception as e:
        return f"WHOIS lookup failed: {e}"


# ── Public API ────────────────────────────────────────────────────────────────

def lookup(ip: str) -> dict:
    """
    Full RDAP+WHOIS lookup for an IP. Returns a dict with all available fields.
    Cached per session.
    """
    with _lock:
        if ip in _cache:
            return _cache[ip]

    result = {"ip": ip, "rdap": None, "whois_raw": "", "error": ""}

    # 1. Try RDAP
    try:
        resp = requests.get(RDAP_URL.format(ip=ip), timeout=8,
                            headers={"Accept": "application/json"})
        if resp.status_code == 200:
            result["rdap"] = _parse_rdap(resp.json())
        else:
            result["error"] = f"RDAP returned HTTP {resp.status_code}"
    except Exception as e:
        result["error"] = f"RDAP error: {e}"

    # 2. Always fetch raw WHOIS as supplementary data
    result["whois_raw"] = _whois_raw(ip)

    with _lock:
        _cache[ip] = result
    return result


def invalidate(ip: str):
    with _lock:
        _cache.pop(ip, None)
