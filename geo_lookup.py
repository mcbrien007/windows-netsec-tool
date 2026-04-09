"""
IP Geolocation — uses ip-api.com (free, no key required, 45 req/min limit).
Results are cached in memory to avoid hammering the API.
Private/local IPs are resolved without any HTTP call.
"""

import threading
import requests
from functools import lru_cache

# ip-api.com batch endpoint (up to 100 IPs per call)
BATCH_URL = "http://ip-api.com/batch"
SINGLE_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,query"

_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()

PRIVATE_LABEL = {
    "country": "Local / Private",
    "countryCode": "LO",
    "city": "",
    "isp": "",
    "org": "",
}

LOOPBACK_LABEL = {
    "country": "Loopback",
    "countryCode": "LB",
    "city": "",
    "isp": "",
    "org": "",
}

EMPTY_LABEL = {
    "country": "—",
    "countryCode": "—",
    "city": "",
    "isp": "",
    "org": "",
}

# Country code → flag emoji (subset, extended via unicode logic below)
def flag_emoji(code: str) -> str:
    """Convert ISO 3166-1 alpha-2 country code to flag emoji."""
    if not code or len(code) != 2 or not code.isalpha():
        return ""
    # Regional indicator symbols: A=0x1F1E6, Z=0x1F1FF
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def _is_private_ip(ip: str) -> bool:
    from network_monitor import is_private
    return is_private(ip)


def _classify(ip: str) -> dict | None:
    """Return static geo for special IPs, None for public IPs."""
    if not ip or ip in ("", "0.0.0.0", "::", "*", "—"):
        return EMPTY_LABEL
    if ip == "127.0.0.1" or ip == "::1":
        return LOOPBACK_LABEL
    if _is_private_ip(ip):
        return PRIVATE_LABEL
    return None


def lookup(ip: str) -> dict:
    """Return geo dict for a single IP. Cached."""
    static = _classify(ip)
    if static is not None:
        return static

    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    try:
        resp = requests.get(SINGLE_URL.format(ip=ip), timeout=4)
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "countryCode": data.get("countryCode", "??"),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
            }
        else:
            result = {"country": "Unknown", "countryCode": "??", "city": "", "isp": "", "org": ""}
    except Exception:
        result = {"country": "Lookup failed", "countryCode": "??", "city": "", "isp": "", "org": ""}

    with _cache_lock:
        _cache[ip] = result
    return result


def batch_lookup(ips: list[str]) -> dict[str, dict]:
    """
    Look up a list of IPs. Returns {ip: geo_dict}.
    Already-cached and private IPs are resolved immediately;
    remaining are fetched in a single batch HTTP call.
    """
    results = {}
    to_fetch = []

    for ip in ips:
        static = _classify(ip)
        if static is not None:
            results[ip] = static
            continue
        with _cache_lock:
            if ip in _cache:
                results[ip] = _cache[ip]
            else:
                to_fetch.append(ip)

    if not to_fetch:
        return results

    # ip-api batch: max 100 per request
    for chunk_start in range(0, len(to_fetch), 100):
        chunk = to_fetch[chunk_start:chunk_start + 100]
        payload = [{"query": ip, "fields": "status,country,countryCode,city,isp,org,query"}
                   for ip in chunk]
        try:
            resp = requests.post(BATCH_URL, json=payload, timeout=8)
            for entry in resp.json():
                ip = entry.get("query", "")
                if entry.get("status") == "success":
                    geo = {
                        "country": entry.get("country", "Unknown"),
                        "countryCode": entry.get("countryCode", "??"),
                        "city": entry.get("city", ""),
                        "isp": entry.get("isp", ""),
                        "org": entry.get("org", ""),
                    }
                else:
                    geo = {"country": "Unknown", "countryCode": "??", "city": "", "isp": "", "org": ""}
                results[ip] = geo
                with _cache_lock:
                    _cache[ip] = geo
        except Exception:
            for ip in chunk:
                geo = {"country": "Lookup failed", "countryCode": "??", "city": "", "isp": "", "org": ""}
                results[ip] = geo

    return results


def invalidate_cache():
    with _cache_lock:
        _cache.clear()
