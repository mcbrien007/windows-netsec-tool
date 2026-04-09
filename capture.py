"""
Per-connection packet capture using Scapy.

Opens a raw socket sniff filtered to a specific (local_ip, local_port,
remote_ip, remote_port) tuple and streams decoded packet summaries
back via a callback.

Requires:
  - Scapy installed  (pip install scapy)
  - Npcap installed  (https://npcap.com/#download) — needed on Windows
    for raw socket capture.  Npcap is free for personal use.
"""

import threading
import time
from datetime import datetime
from dataclasses import dataclass

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw, conf
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
    conf.verb = 0          # Silence Scapy warnings
except ImportError:
    SCAPY_AVAILABLE = False


NPCAP_HELP = (
    "Npcap is not installed or Scapy is unavailable.\n\n"
    "To enable packet capture:\n"
    "  1. Install Scapy:  pip install scapy\n"
    "  2. Download and install Npcap from https://npcap.com/#download\n"
    "     (select 'WinPcap API-compatible Mode' during install)\n\n"
    "Re-launch the app after installing."
)


@dataclass
class PacketEntry:
    timestamp: str
    direction: str      # "→ OUT" or "← IN "
    proto: str
    size: int
    summary: str
    raw_hex: str = ""


class ConnectionCapture:
    """
    Captures packets matching a specific connection 5-tuple.
    Runs on a background thread; pushes PacketEntry objects via on_packet callback.
    """

    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        protocol: str,
        on_packet,          # callable(PacketEntry)
        on_error,           # callable(str)
        max_packets: int = 2000,
    ):
        self.local_ip    = local_ip
        self.local_port  = local_port
        self.remote_ip   = remote_ip
        self.remote_port = remote_port
        self.protocol    = protocol.upper()
        self.on_packet   = on_packet
        self.on_error    = on_error
        self.max_packets = max_packets

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._count = 0

    def start(self):
        if not SCAPY_AVAILABLE:
            self.on_error(NPCAP_HELP)
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _build_bpf(self) -> str:
        """Build a BPF filter string for this connection."""
        proto = "tcp" if self.protocol == "TCP" else "udp"
        parts = [f"proto {proto}"]

        if self.remote_ip and self.remote_ip not in ("", "0.0.0.0", "::"):
            parts.append(f"host {self.remote_ip}")

        if self.local_port:
            parts.append(f"port {self.local_port}")
        elif self.remote_port:
            parts.append(f"port {self.remote_port}")

        return " and ".join(parts)

    def _decode_packet(self, pkt) -> PacketEntry | None:
        try:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # Layer detection
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if not ip_layer:
                return None

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if self.protocol == "TCP":
                transport = pkt.getlayer(TCP)
            else:
                transport = pkt.getlayer(UDP)

            if not transport:
                return None

            src_port = transport.sport
            dst_port = transport.dport
            size = len(pkt)

            # Direction
            if src_ip == self.local_ip and src_port == self.local_port:
                direction = "→ OUT"
            elif dst_ip == self.local_ip and dst_port == self.local_port:
                direction = "← IN "
            else:
                direction = "  ↔  "

            # Build summary
            proto_str = self.protocol
            flags_str = ""
            if self.protocol == "TCP":
                flag_map = {
                    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
                    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
                }
                flags = transport.flags
                active = [v for k, v in flag_map.items() if flags & k]
                flags_str = f" [{','.join(active)}]" if active else ""

            # HTTP detection
            http_info = ""
            if pkt.haslayer(HTTPRequest):
                req = pkt.getlayer(HTTPRequest)
                method  = req.Method.decode(errors="replace") if req.Method else ""
                path    = req.Path.decode(errors="replace")   if req.Path   else ""
                host    = req.Host.decode(errors="replace")   if req.Host   else ""
                http_info = f"  HTTP {method} {host}{path}"
            elif pkt.haslayer(HTTPResponse):
                resp = pkt.getlayer(HTTPResponse)
                code = resp.Status_Code.decode(errors="replace") if resp.Status_Code else ""
                http_info = f"  HTTP {code}"

            # Raw payload snippet
            raw_snippet = ""
            if pkt.haslayer(Raw):
                raw_bytes = bytes(pkt[Raw])[:64]
                try:
                    text = raw_bytes.decode("utf-8", errors="replace")
                    printable = "".join(c if c.isprintable() else "." for c in text)
                    raw_snippet = f"  │ {printable}"
                except Exception:
                    pass

            summary = (
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
                f"  {proto_str}{flags_str}  {size}B"
                f"{http_info}{raw_snippet}"
            )

            # Hex dump of first 32 bytes
            raw_hex = " ".join(f"{b:02x}" for b in bytes(pkt)[:32])

            return PacketEntry(
                timestamp=ts,
                direction=direction,
                proto=proto_str + flags_str,
                size=size,
                summary=summary,
                raw_hex=raw_hex,
            )
        except Exception as e:
            return None

    def _run(self):
        bpf = self._build_bpf()

        def handle(pkt):
            if self._stop_event.is_set():
                return True   # tells sniff to stop
            entry = self._decode_packet(pkt)
            if entry:
                self._count += 1
                self.on_packet(entry)
                if self._count >= self.max_packets:
                    self._stop_event.set()
                    return True

        try:
            sniff(
                filter=bpf,
                prn=handle,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception as e:
            self.on_error(
                f"Capture error: {e}\n\n"
                "Make sure Npcap is installed (https://npcap.com/#download)\n"
                "and the app is running as Administrator."
            )
