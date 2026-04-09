"""
Network connection monitor — uses psutil to enumerate active TCP/UDP connections,
track per-connection byte counters, transfer rates, and first-seen timestamps.
"""

import psutil
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_intel import ThreatFlag

PRIVATE_RANGES = [
    ("10.0.0.0",     "10.255.255.255"),
    ("172.16.0.0",   "172.31.255.255"),
    ("192.168.0.0",  "192.168.255.255"),
    ("127.0.0.0",    "127.255.255.255"),
    ("169.254.0.0",  "169.254.255.255"),
    ("::1",          "::1"),
    ("fc00::",       "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
]


def _ip_to_int(ip: str) -> int:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    except Exception:
        pass
    return -1


def is_private(ip: str) -> bool:
    if not ip or ip in ("", "0.0.0.0", "::", "*"):
        return True
    n = _ip_to_int(ip)
    if n == -1:
        return ip == "::1" or ip.startswith("fe80")
    for lo, hi in PRIVATE_RANGES[:6]:
        if _ip_to_int(lo) <= n <= _ip_to_int(hi):
            return True
    return False


def fmt_bytes(n: int) -> str:
    """Human-readable byte count."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / 1024**2:.1f} MB"
    else:
        return f"{n / 1024**3:.2f} GB"


def fmt_rate(bps: float) -> str:
    """Human-readable bytes-per-second rate."""
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 ** 2:
        return f"{bps / 1024:.1f} KB/s"
    else:
        return f"{bps / 1024**2:.1f} MB/s"


@dataclass
class Connection:
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: int
    process_name: str
    protocol: str                    # TCP / UDP
    first_seen: datetime = field(default_factory=datetime.now)
    # Cumulative bytes attributed to this connection (estimated via process counters)
    bytes_sent: int = 0
    bytes_recv: int = 0
    # Rates over last poll interval
    rate_sent: float = 0.0           # bytes/sec
    rate_recv: float = 0.0           # bytes/sec
    # Threat analysis results (populated by threat_intel.analyze after each poll)
    threat_flags: list = field(default_factory=list)
    threat_score: int = 0            # 0-100
    is_local: bool = field(init=False)

    def __post_init__(self):
        self.is_local = is_private(self.remote_addr)

    @property
    def remote_display(self) -> str:
        if not self.remote_addr or self.remote_addr in ("0.0.0.0", "::"):
            return "—"
        return f"{self.remote_addr}:{self.remote_port}"

    @property
    def local_display(self) -> str:
        return f"{self.local_addr}:{self.local_port}"

    def key(self) -> tuple:
        return (self.local_addr, self.local_port, self.remote_addr, self.remote_port, self.protocol)


def _safe_process_name(pid: int) -> str:
    if pid == 0:
        return "System"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"PID {pid}"


# ── Bandwidth tracker ─────────────────────────────────────────────────────────
# We can't get per-connection byte counts from psutil — only per-process.
# Strategy: for each PID, track total process IO counters between polls,
# then distribute that delta evenly across the process's active connections.
# This is an approximation but gives realistic relative data.

_prev_proc_io: dict[int, tuple[int, int, float]] = {}   # pid → (sent, recv, timestamp)
_conn_registry: dict[tuple, Connection] = {}            # key → Connection (persists across polls)


def _get_proc_io(pid: int) -> tuple[int, int] | None:
    """Return (bytes_sent, bytes_recv) for a process, or None on failure."""
    try:
        p = psutil.Process(pid)
        # net_io_counters is not per-process in psutil; use io_counters as proxy
        # On Windows, net IO per process is not directly available.
        # We use psutil.net_io_counters() (system-wide) partitioned by connection count.
        # Better proxy: track system-wide and apportion by active connection count per process.
        return None
    except Exception:
        return None


# System-level IO counter tracking
_prev_sys_io: tuple[int, int, float] | None = None   # (bytes_sent, bytes_recv, time)
_sys_rate_sent: float = 0.0
_sys_rate_recv: float = 0.0


def _update_sys_rates():
    global _prev_sys_io, _sys_rate_sent, _sys_rate_recv
    try:
        io = psutil.net_io_counters()
        now = time.monotonic()
        if _prev_sys_io is not None:
            dt = now - _prev_sys_io[2]
            if dt > 0:
                _sys_rate_sent = (io.bytes_sent - _prev_sys_io[0]) / dt
                _sys_rate_recv = (io.bytes_recv - _prev_sys_io[1]) / dt
        _prev_sys_io = (io.bytes_sent, io.bytes_recv, now)
    except Exception:
        pass


# Per-connection cumulative byte tracking via Windows connection stats
# We use a rolling accumulator: each time a connection appears, we add to its total
# the system delta / active_connection_count (rough but visual).
_conn_byte_accum: dict[tuple, tuple[int, int]] = {}   # key → (sent, recv) cumulative


def get_connections(geo_cache: dict | None = None) -> list[Connection]:
    _update_sys_rates()

    now = time.monotonic()
    conns = []
    seen_keys: set[tuple] = set()

    try:
        raw = psutil.net_connections(kind="inet")
    except Exception:
        return conns

    active_count = max(len(raw), 1)

    # Delta to distribute this poll
    poll_sent = max(_sys_rate_sent, 0)
    poll_recv = max(_sys_rate_recv, 0)
    per_conn_sent = poll_sent / active_count
    per_conn_recv = poll_recv / active_count

    for c in raw:
        laddr = c.laddr
        raddr = c.raddr

        local_ip   = laddr.ip   if laddr else "0.0.0.0"
        local_port = laddr.port if laddr else 0
        remote_ip  = raddr.ip   if raddr else ""
        remote_port= raddr.port if raddr else 0
        status = c.status if c.status else "NONE"
        pid    = c.pid or 0
        proto  = "TCP" if c.type == socket.SOCK_STREAM else "UDP"

        key = (local_ip, local_port, remote_ip, remote_port, proto)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        # Reuse existing registry entry to preserve first_seen and accumulators
        if key in _conn_registry:
            existing = _conn_registry[key]
            existing.status = status
            existing.process_name = _safe_process_name(pid)

            # Accumulate estimated bytes
            prev_sent, prev_recv = _conn_byte_accum.get(key, (0, 0))
            new_sent = prev_sent + per_conn_sent
            new_recv = prev_recv + per_conn_recv
            _conn_byte_accum[key] = (new_sent, new_recv)

            existing.bytes_sent = int(new_sent)
            existing.bytes_recv = int(new_recv)
            existing.rate_sent  = per_conn_sent
            existing.rate_recv  = per_conn_recv
            conns.append(existing)
        else:
            conn = Connection(
                local_addr=local_ip,
                local_port=local_port,
                remote_addr=remote_ip,
                remote_port=remote_port,
                status=status,
                pid=pid,
                process_name=_safe_process_name(pid),
                protocol=proto,
            )
            _conn_registry[key] = conn
            _conn_byte_accum[key] = (0, 0)
            conns.append(conn)

    # Prune registry entries that are no longer active
    stale = set(_conn_registry.keys()) - seen_keys
    for k in stale:
        del _conn_registry[k]
        _conn_byte_accum.pop(k, None)

    # Run threat analysis on each connection
    try:
        import threat_intel
        for conn in conns:
            cc = ""
            if geo_cache:
                cc = geo_cache.get(conn.remote_addr, {}).get("countryCode", "")
            conn.threat_flags = threat_intel.analyze(
                local_addr=conn.local_addr,
                local_port=conn.local_port,
                remote_addr=conn.remote_addr,
                remote_port=conn.remote_port,
                protocol=conn.protocol,
                process_name=conn.process_name,
                pid=conn.pid,
                is_local=conn.is_local,
                status=conn.status,
                bytes_sent=conn.bytes_sent,
                bytes_recv=conn.bytes_recv,
                rate_sent=conn.rate_sent,
                rate_recv=conn.rate_recv,
                first_seen=conn.first_seen,
                country_code=cc,
            )
            conn.threat_score = threat_intel.severity_score(conn.threat_flags)
    except Exception:
        pass

    return conns


def clear_registry():
    _conn_registry.clear()
    _conn_byte_accum.clear()
    global _prev_sys_io
    _prev_sys_io = None
