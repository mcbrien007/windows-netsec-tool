"""
Main GUI window — live network connection tracker with geo info,
bandwidth counters, first-seen timestamps, and click-to-capture panel.
"""

import tkinter as tk
from tkinter import ttk
import threading
import time
from datetime import datetime

from network_monitor import get_connections, Connection, fmt_bytes, fmt_rate
from geo_lookup import batch_lookup, flag_emoji
from capture import ConnectionCapture, PacketEntry, SCAPY_AVAILABLE, NPCAP_HELP
import whois_lookup

# ── Colour palette ────────────────────────────────────────────────────────────
BG          = "#0d1117"
BG_ALT      = "#161b22"
HEADER_BG   = "#21262d"
FG          = "#c9d1d9"
FG_DIM      = "#8b949e"
ACCENT      = "#58a6ff"
GREEN       = "#3fb950"
YELLOW      = "#d29922"
RED         = "#f85149"
ORANGE      = "#e3b341"
PURPLE      = "#bc8cff"
TEAL        = "#39d353"
BORDER      = "#30363d"

REFRESH_INTERVAL = 3   # seconds

COLUMNS = [
    ("threat",    "⚠",               28),
    ("flag",      "  ",              36),
    ("country",   "Country",        130),
    ("remote",    "Remote IP:Port", 178),
    ("local",     "Local IP:Port",  168),
    ("proto",     "Proto",           52),
    ("status",    "Status",         100),
    ("process",   "Process",        138),
    ("pid",       "PID",             52),
    ("first_seen","First Seen",      76),
    ("duration",  "Duration",        68),
    ("sent",      "Sent",            72),
    ("recv",      "Recv",            72),
    ("rate",      "Rate ↕",          88),
    ("city",      "City",            106),
    ("org",       "Org / ISP",       190),
]

# Column index of "org" (0-based) — used for click detection
ORG_COL_INDEX = [c[0] for c in COLUMNS].index("org")

STATUS_COLORS = {
    "ESTABLISHED": GREEN,
    "LISTEN":      ACCENT,
    "TIME_WAIT":   YELLOW,
    "CLOSE_WAIT":  ORANGE,
    "SYN_SENT":    PURPLE,
    "SYN_RECV":    PURPLE,
    "FIN_WAIT1":   FG_DIM,
    "FIN_WAIT2":   FG_DIM,
    "CLOSING":     FG_DIM,
    "LAST_ACK":    FG_DIM,
    "NONE":        FG_DIM,
}

THREAT_ROW_COLORS = {
    "critical": "#3d0000",   # dark red background
    "high":     "#2d1a00",   # dark orange background
    "medium":   "#2a2000",   # dark yellow background
    "low":      "#001a2d",   # dark blue background
}

THREAT_FG_COLORS = {
    "critical": "#f85149",
    "high":     "#e3b341",
    "medium":   "#d29922",
    "low":      "#58a6ff",
}

DIRECTION_COLORS = {
    "→ OUT": "#58a6ff",
    "← IN ": "#3fb950",
    "  ↔  ": FG_DIM,
}


class CapturePanel(tk.Toplevel):
    """
    Floating window that shows live packet capture for one connection.
    """

    def __init__(self, parent, conn: Connection, geo: dict):
        super().__init__(parent)
        self.title(
            f"Capture — {conn.process_name}  "
            f"{conn.local_display} ↔ {conn.remote_display}"
        )
        self.configure(bg=BG)
        self.geometry("1000x520")
        self.minsize(700, 300)

        self._conn = conn
        self._capture: ConnectionCapture | None = None
        self._packet_count = 0
        self._byte_count = 0
        self._running = False

        self._build_ui(conn, geo)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self, conn: Connection, geo: dict):
        # ── Header ──
        hdr = tk.Frame(self, bg=HEADER_BG, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(
            hdr, text=f"  Packet Capture", bg=HEADER_BG, fg=ACCENT,
            font=("Segoe UI", 11, "bold")
        ).pack(side="left", pady=8)

        country = geo.get("country", "")
        city    = geo.get("city", "")
        org     = geo.get("org", "")
        cc      = geo.get("countryCode", "")
        flag    = flag_emoji(cc) if cc and len(cc) == 2 else ""
        loc_str = ", ".join(filter(None, [flag + " " + country if flag else country, city, org]))

        tk.Label(
            hdr, text=f"  {conn.process_name} (PID {conn.pid})  │  "
                      f"{conn.local_display} ↔ {conn.remote_display}  │  {loc_str}",
            bg=HEADER_BG, fg=FG_DIM, font=("Segoe UI", 8)
        ).pack(side="left", pady=8, padx=8)

        btn_frame = tk.Frame(hdr, bg=HEADER_BG)
        btn_frame.pack(side="right", padx=10)

        self._start_btn = tk.Button(
            btn_frame, text="▶ Start Capture", bg=GREEN, fg="#000000",
            relief="flat", font=("Segoe UI", 9, "bold"), padx=10, pady=3,
            activebackground="#2ea043", activeforeground="#000000",
            command=self._toggle_capture
        )
        self._start_btn.pack(side="left", padx=(0, 6))

        tk.Button(
            btn_frame, text="⊘ Clear", bg=BG_ALT, fg=FG, relief="flat",
            font=("Segoe UI", 9), padx=8, pady=3,
            activebackground=BORDER, activeforeground=FG,
            command=self._clear
        ).pack(side="left")

        # ── Stats row ──
        stats_row = tk.Frame(self, bg=BG_ALT, height=24)
        stats_row.pack(fill="x")
        stats_row.pack_propagate(False)
        self._cap_stats = tk.Label(
            stats_row, text="  Ready — press Start Capture",
            bg=BG_ALT, fg=FG_DIM, font=("Segoe UI", 8)
        )
        self._cap_stats.pack(side="left", padx=8)

        # ── Packet list ──
        list_frame = tk.Frame(self, bg=BG)
        list_frame.pack(fill="both", expand=True)

        cap_cols = [
            ("time",  "Time",       80),
            ("dir",   "Dir",        58),
            ("proto", "Flags",      90),
            ("size",  "Size",       60),
            ("info",  "Info",      999),
        ]

        style = ttk.Style()
        style.configure("Cap.Treeview",
                         background=BG, foreground=FG, fieldbackground=BG,
                         borderwidth=0, rowheight=20, font=("Consolas", 8))
        style.configure("Cap.Treeview.Heading",
                         background=HEADER_BG, foreground=FG_DIM,
                         borderwidth=0, relief="flat", font=("Segoe UI", 8, "bold"))
        style.map("Cap.Treeview", background=[("selected", "#1f6feb")],
                  foreground=[("selected", "#ffffff")])
        style.layout("Cap.Treeview", [("Cap.Treeview.treearea", {"sticky": "nswe"})])

        self._cap_tree = ttk.Treeview(
            list_frame,
            columns=[c[0] for c in cap_cols],
            show="headings",
            style="Cap.Treeview",
            selectmode="browse",
        )
        for cid, clabel, cw in cap_cols:
            stretch = cid == "info"
            self._cap_tree.heading(cid, text=clabel)
            self._cap_tree.column(cid, width=cw, minwidth=30,
                                  anchor="w", stretch=stretch)

        # Direction colour tags
        for direction, color in DIRECTION_COLORS.items():
            self._cap_tree.tag_configure(direction.strip(), foreground=color)
        self._cap_tree.tag_configure("SYN",   foreground=PURPLE)
        self._cap_tree.tag_configure("RST",   foreground=RED)
        self._cap_tree.tag_configure("FIN",   foreground=YELLOW)
        self._cap_tree.tag_configure("PSH",   foreground=TEAL)

        vsb = ttk.Scrollbar(list_frame, orient="vertical",   command=self._cap_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self._cap_tree.xview)
        self._cap_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._cap_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # ── Hex detail panel ──
        detail_frame = tk.Frame(self, bg=BG_ALT, height=70)
        detail_frame.pack(fill="x", side="bottom")
        detail_frame.pack_propagate(False)

        tk.Label(detail_frame, text="  First 32 bytes (hex):",
                 bg=BG_ALT, fg=FG_DIM, font=("Segoe UI", 7)).pack(anchor="w", padx=8, pady=(4, 0))
        self._hex_lbl = tk.Label(
            detail_frame, text="", bg=BG_ALT, fg=TEAL,
            font=("Consolas", 8), anchor="w", justify="left"
        )
        self._hex_lbl.pack(fill="x", padx=12, pady=(0, 4))

        self._cap_tree.bind("<<TreeviewSelect>>", self._on_select_packet)

        # Npcap warning if not available
        if not SCAPY_AVAILABLE:
            self._start_btn.config(state="disabled", text="Scapy/Npcap not installed")
            self._show_npcap_warning()

    def _show_npcap_warning(self):
        warn = tk.Label(
            self, text=NPCAP_HELP, bg=BG, fg=YELLOW,
            font=("Segoe UI", 9), justify="left", wraplength=700
        )
        warn.place(relx=0.5, rely=0.5, anchor="center")

    def _toggle_capture(self):
        if self._running:
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self):
        self._running = True
        self._start_btn.config(text="⏹ Stop Capture", bg=RED, activebackground="#b91c1c",
                                activeforeground="#ffffff", fg="#ffffff")
        self._cap_stats.config(text="  Capturing…  (packets will appear below)")

        c = self._conn
        self._capture = ConnectionCapture(
            local_ip=c.local_addr,
            local_port=c.local_port,
            remote_ip=c.remote_addr,
            remote_port=c.remote_port,
            protocol=c.protocol,
            on_packet=self._on_packet,
            on_error=self._on_error,
        )
        self._capture.start()

    def _stop_capture(self):
        self._running = False
        if self._capture:
            self._capture.stop()
            self._capture = None
        self._start_btn.config(text="▶ Start Capture", bg=GREEN,
                                activebackground="#2ea043", fg="#000000",
                                activeforeground="#000000")
        self._cap_stats.config(
            text=f"  Stopped — {self._packet_count} packets  {fmt_bytes(self._byte_count)} captured"
        )

    def _on_packet(self, entry: PacketEntry):
        """Called from capture thread — schedule UI update on main thread."""
        self.after(0, lambda e=entry: self._insert_packet(e))

    def _insert_packet(self, entry: PacketEntry):
        self._packet_count += 1
        self._byte_count += entry.size

        # Pick tag
        tag = entry.direction.strip()
        if "SYN" in entry.proto and "ACK" not in entry.proto:
            tag = "SYN"
        elif "RST" in entry.proto:
            tag = "RST"
        elif "FIN" in entry.proto:
            tag = "FIN"

        iid = self._cap_tree.insert(
            "", "end",
            values=(entry.timestamp, entry.direction, entry.proto,
                    f"{entry.size} B", entry.summary),
            tags=(tag,),
        )
        # Store hex in item metadata via iid mapping
        self._cap_tree.item(iid, tags=(tag, f"hex:{entry.raw_hex}"))

        # Auto-scroll
        self._cap_tree.see(iid)

        # Update stats
        self._cap_stats.config(
            text=f"  {self._packet_count} packets  │  {fmt_bytes(self._byte_count)} captured  │  "
                 f"Last: {entry.timestamp}"
        )

    def _on_select_packet(self, _event):
        sel = self._cap_tree.selection()
        if not sel:
            return
        tags = self._cap_tree.item(sel[0], "tags")
        hex_str = ""
        for t in tags:
            if t.startswith("hex:"):
                hex_str = t[4:]
                break
        self._hex_lbl.config(text=hex_str or "—")

    def _on_error(self, msg: str):
        self.after(0, lambda: self._cap_stats.config(text=f"  Error: {msg[:120]}"))

    def _clear(self):
        self._cap_tree.delete(*self._cap_tree.get_children())
        self._packet_count = 0
        self._byte_count = 0
        self._hex_lbl.config(text="")
        self._cap_stats.config(text="  Cleared")

    def _on_close(self):
        self._stop_capture()
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────

class AlertsPanel(tk.Toplevel):
    """
    Floating panel listing all threat alerts fired this session.
    """

    def __init__(self, parent, existing_log: list, on_clear=None):
        super().__init__(parent)
        self.title("NetSec — Threat Alerts")
        self.configure(bg=BG)
        self.geometry("920x480")
        self.minsize(700, 300)
        self._on_clear_cb = on_clear
        self._build_ui()
        # Populate with existing alerts
        for entry in existing_log:
            self.add_entry(entry)

    def _build_ui(self):
        hdr = tk.Frame(self, bg=HEADER_BG, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="  Threat Alerts", bg=HEADER_BG, fg=RED,
                 font=("Segoe UI", 11, "bold")).pack(side="left", pady=8, padx=10)
        tk.Label(hdr,
                 text="  🔴 Critical  🟠 High  🟡 Medium  🔵 Low",
                 bg=HEADER_BG, fg=FG_DIM, font=("Segoe UI", 8)).pack(side="left", padx=8)

        tk.Button(hdr, text="🗑 Clear all", bg=BG_ALT, fg=FG, relief="flat",
                  font=("Segoe UI", 9), padx=8, pady=2,
                  activebackground=BORDER, command=self._clear
                  ).pack(side="right", padx=10, pady=8)

        cols = [
            ("time",    "Time",     72),
            ("level",   "Severity", 72),
            ("score",   "Score",    50),
            ("process", "Process", 130),
            ("remote",  "Remote",  160),
            ("flags",   "Flags / Reasons", 999),
        ]

        style = ttk.Style()
        style.configure("Alert.Treeview",
                         background=BG, foreground=FG, fieldbackground=BG,
                         borderwidth=0, rowheight=22, font=("Segoe UI", 9))
        style.configure("Alert.Treeview.Heading",
                         background=HEADER_BG, foreground=FG_DIM,
                         borderwidth=0, relief="flat", font=("Segoe UI", 8, "bold"))
        style.map("Alert.Treeview",
                  background=[("selected", "#1f6feb")],
                  foreground=[("selected", "#ffffff")])
        style.layout("Alert.Treeview", [("Alert.Treeview.treearea", {"sticky": "nswe"})])

        list_frame = tk.Frame(self, bg=BG)
        list_frame.pack(fill="both", expand=True)

        self._tree = ttk.Treeview(
            list_frame, columns=[c[0] for c in cols],
            show="headings", style="Alert.Treeview", selectmode="browse"
        )
        for cid, clabel, cw in cols:
            self._tree.heading(cid, text=clabel)
            self._tree.column(cid, width=cw, minwidth=30,
                              anchor="w", stretch=(cid == "flags"))

        # Level colour tags
        for level, color in THREAT_FG_COLORS.items():
            self._tree.tag_configure(level, foreground=color,
                                     background=THREAT_ROW_COLORS[level])

        vsb = ttk.Scrollbar(list_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # Detail pane at bottom
        detail = tk.Frame(self, bg=BG_ALT, height=80)
        detail.pack(fill="x", side="bottom")
        detail.pack_propagate(False)
        tk.Label(detail, text="  Flag details:", bg=BG_ALT, fg=FG_DIM,
                 font=("Segoe UI", 7)).pack(anchor="w", padx=8, pady=(4, 0))
        self._detail_lbl = tk.Label(
            detail, text="", bg=BG_ALT, fg=FG,
            font=("Segoe UI", 8), anchor="w", justify="left", wraplength=880
        )
        self._detail_lbl.pack(fill="x", padx=12, pady=(0, 4))
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Keep reference to entries for detail lookup
        self._entries: dict[str, list] = {}   # iid → flags list

    def add_entry(self, entry: dict):
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
            entry["level"], "⚪")
        flags_str = "  │  ".join(
            f"{f.icon} [{f.code}] {f.reason}" for f in entry["flags"]
        )
        iid = self._tree.insert(
            "", 0,   # newest at top
            values=(
                entry["time"],
                f"{icon} {entry['level'].upper()}",
                entry["score"],
                entry["process"],
                entry["remote"],
                flags_str,
            ),
            tags=(entry["level"],),
        )
        self._entries[iid] = entry["flags"]
        self._tree.see(iid)

    def _on_select(self, _):
        sel = self._tree.selection()
        if not sel:
            return
        flags = self._entries.get(sel[0], [])
        lines = [f"{f.icon} [{f.code}] {f.level.upper()}: {f.reason}" for f in flags]
        self._detail_lbl.config(text="\n".join(lines) if lines else "—")

    def _clear(self):
        self._tree.delete(*self._tree.get_children())
        self._entries.clear()
        self._detail_lbl.config(text="")
        if self._on_clear_cb:
            self._on_clear_cb()


# ─────────────────────────────────────────────────────────────────────────────

class OrgDetailPanel(tk.Toplevel):
    """
    Popup showing full RDAP + raw WHOIS data for a remote IP's owning entity.
    Opens on single-click of the Org/ISP cell.
    """

    def __init__(self, parent, ip: str, display_org: str):
        super().__init__(parent)
        self.title(f"Org / ISP Detail — {ip}")
        self.configure(bg=BG)
        self.geometry("780x620")
        self.minsize(600, 400)

        self._ip = ip
        self._build_ui(display_org)
        self._fetch(ip)

    def _build_ui(self, display_org: str):
        # Header
        hdr = tk.Frame(self, bg=HEADER_BG, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  {self._ip}  —  {display_org}",
                 bg=HEADER_BG, fg=ACCENT, font=("Segoe UI", 11, "bold")).pack(
                 side="left", pady=10, padx=10)
        tk.Button(hdr, text="⟳ Refresh", bg=BG_ALT, fg=FG, relief="flat",
                  font=("Segoe UI", 9), padx=8, pady=2,
                  activebackground=BORDER, activeforeground=FG,
                  command=lambda: (whois_lookup.invalidate(self._ip), self._fetch(self._ip))
                  ).pack(side="right", padx=10, pady=8)

        # Notebook: Summary | Contacts | Raw WHOIS
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        style = ttk.Style()
        style.configure("TNotebook",        background=BG,        borderwidth=0)
        style.configure("TNotebook.Tab",    background=HEADER_BG, foreground=FG_DIM,
                        font=("Segoe UI", 9), padding=(10, 4))
        style.map("TNotebook.Tab",
                  background=[("selected", BG_ALT)],
                  foreground=[("selected", FG)])

        self._summary_frame   = tk.Frame(nb, bg=BG)
        self._contacts_frame  = tk.Frame(nb, bg=BG)
        self._whois_frame     = tk.Frame(nb, bg=BG)

        nb.add(self._summary_frame,  text="  Summary  ")
        nb.add(self._contacts_frame, text="  Contacts  ")
        nb.add(self._whois_frame,    text="  Raw WHOIS  ")

        # Loading label (replaced once data arrives)
        self._loading_lbl = tk.Label(
            self._summary_frame, text="Loading…", bg=BG, fg=FG_DIM,
            font=("Segoe UI", 10)
        )
        self._loading_lbl.pack(expand=True)

    def _fetch(self, ip: str):
        """Run lookup in background thread, then populate UI on main thread."""
        self._loading_lbl.config(text="Loading RDAP + WHOIS data…")
        threading.Thread(target=self._do_fetch, args=(ip,), daemon=True).start()

    def _do_fetch(self, ip: str):
        result = whois_lookup.lookup(ip)
        self.after(0, lambda r=result: self._populate(r))

    def _populate(self, result: dict):
        rdap = result.get("rdap")
        whois_raw = result.get("whois_raw", "")
        error = result.get("error", "")

        # ── Summary tab ──
        for w in self._summary_frame.winfo_children():
            w.destroy()

        canvas = tk.Canvas(self._summary_frame, bg=BG, highlightthickness=0)
        vsb = ttk.Scrollbar(self._summary_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _resize(e):
            canvas.itemconfig(win_id, width=e.width)
        canvas.bind("<Configure>", _resize)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        def row(label: str, value: str, value_color=FG):
            if not value:
                return
            f = tk.Frame(inner, bg=BG)
            f.pack(fill="x", padx=16, pady=1)
            tk.Label(f, text=f"{label}:", bg=BG, fg=FG_DIM,
                     font=("Segoe UI", 9), width=18, anchor="w").pack(side="left")
            tk.Label(f, text=value, bg=BG, fg=value_color,
                     font=("Segoe UI", 9), anchor="w", wraplength=560, justify="left"
                     ).pack(side="left", fill="x", expand=True)

        tk.Label(inner, text="", bg=BG, height=1).pack()  # top padding

        if error and not rdap:
            tk.Label(inner, text=f"  {error}", bg=BG, fg=YELLOW,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=16)
        elif rdap:
            row("Handle",       rdap.get("handle", ""))
            row("Name",         rdap.get("name",   ""),  ACCENT)
            row("Type",         rdap.get("type",   ""))
            row("IP / CIDR",    rdap.get("cidr",   ""),  TEAL)
            row("Country",      rdap.get("country",""))
            row("Registered",   rdap.get("registered", ""))
            row("Last changed", rdap.get("last_changed",""))
            for remark in rdap.get("remarks", []):
                row("Remark", remark)
            for link in rdap.get("links", []):
                row("RDAP link", link, FG_DIM)
            if error:
                row("Note", error, YELLOW)

        # ── Contacts tab ──
        for w in self._contacts_frame.winfo_children():
            w.destroy()

        if rdap and rdap.get("contacts"):
            cv = tk.Canvas(self._contacts_frame, bg=BG, highlightthickness=0)
            csb = ttk.Scrollbar(self._contacts_frame, orient="vertical", command=cv.yview)
            cv.configure(yscrollcommand=csb.set)
            csb.pack(side="right", fill="y")
            cv.pack(side="left", fill="both", expand=True)
            cin = tk.Frame(cv, bg=BG)
            cwin = cv.create_window((0, 0), window=cin, anchor="nw")
            cv.bind("<Configure>", lambda e: cv.itemconfig(cwin, width=e.width))
            cin.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))

            for contact in rdap["contacts"]:
                sep = tk.Frame(cin, bg=BORDER, height=1)
                sep.pack(fill="x", padx=12, pady=6)
                role_lbl = tk.Label(cin, text=f"  {contact['roles'].upper()}",
                                    bg=BG, fg=ORANGE, font=("Segoe UI", 9, "bold"))
                role_lbl.pack(anchor="w")

                def crow(lbl, val, col=FG):
                    if not val: return
                    f = tk.Frame(cin, bg=BG)
                    f.pack(fill="x", padx=24, pady=1)
                    tk.Label(f, text=f"{lbl}:", bg=BG, fg=FG_DIM,
                             font=("Segoe UI", 9), width=12, anchor="w").pack(side="left")
                    tk.Label(f, text=val, bg=BG, fg=col,
                             font=("Segoe UI", 9), anchor="w").pack(side="left")

                crow("Name",    contact.get("name",""),    ACCENT)
                crow("Email",   contact.get("email",""),   TEAL)
                crow("Phone",   contact.get("phone",""))
                crow("Address", contact.get("address",""))
        else:
            tk.Label(self._contacts_frame,
                     text="No contact data available from RDAP.",
                     bg=BG, fg=FG_DIM, font=("Segoe UI", 9)).pack(expand=True)

        # ── Raw WHOIS tab ──
        for w in self._whois_frame.winfo_children():
            w.destroy()

        txt_frame = tk.Frame(self._whois_frame, bg=BG)
        txt_frame.pack(fill="both", expand=True)
        txt = tk.Text(
            txt_frame, bg=BG, fg=FG, font=("Consolas", 8),
            insertbackground=FG, relief="flat", wrap="none",
            highlightthickness=0
        )
        wsb_v = ttk.Scrollbar(txt_frame, orient="vertical",   command=txt.yview)
        wsb_h = ttk.Scrollbar(txt_frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=wsb_v.set, xscrollcommand=wsb_h.set)
        wsb_v.pack(side="right",  fill="y")
        wsb_h.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True, padx=4, pady=4)

        content = whois_raw if whois_raw else "(no WHOIS data)"
        txt.insert("1.0", content)
        txt.config(state="disabled")


# ─────────────────────────────────────────────────────────────────────────────

class NetSecWindow:
    def __init__(self, root: tk.Tk, tray=None):
        self.root = root
        self._tray = tray
        self.root.title("NetSec Monitor")
        self.root.configure(bg=BG)
        self.root.geometry("1440x760")
        self.root.minsize(1000, 450)
        self.root.protocol("WM_DELETE_WINDOW", self.hide)

        self._geo_cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = True
        self._paused = False
        self._filter_text = tk.StringVar()
        self._filter_text.trace_add("write", self._on_filter_change)
        self._show_listeners = tk.BooleanVar(value=False)
        self._last_connections: list[Connection] = []
        self._row_ids: dict[str, str] = {}       # conn_key_str → iid
        self._iid_to_conn: dict[str, Connection] = {}   # iid → Connection
        self._open_captures: dict[str, CapturePanel] = {}  # key → window

        # Alert state
        self._alert_log: list[dict] = []          # list of alert dicts
        self._alerts_panel: tk.Toplevel | None = None
        self._alert_seen_keys: set[str] = set()   # keys already alerted
        # Traffic spike detection
        self._spike_notified: set[str] = set()    # process names already notified
        SPIKE_RATE_THRESHOLD_MBPS = 5.0           # MB/s per-connection spike
        self._SPIKE_THRESHOLD = SPIKE_RATE_THRESHOLD_MBPS * 1024 * 1024

        self._sort_col = "first_seen"
        self._sort_rev = True          # newest first by default

        self._build_ui()
        self._start_threads()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        topbar = tk.Frame(self.root, bg=HEADER_BG, height=52)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        tk.Label(
            topbar, text="  NetSec Monitor", bg=HEADER_BG, fg=ACCENT,
            font=("Segoe UI", 14, "bold")
        ).pack(side="left", padx=(8, 0), pady=10)

        self._live_dot = tk.Label(topbar, text="●", bg=HEADER_BG, fg=GREEN, font=("Segoe UI", 11))
        self._live_dot.pack(side="left", padx=(8, 2), pady=10)
        self._live_lbl = tk.Label(topbar, text="LIVE", bg=HEADER_BG, fg=GREEN,
                                  font=("Segoe UI", 9, "bold"))
        self._live_lbl.pack(side="left", pady=10)

        ctrl = tk.Frame(topbar, bg=HEADER_BG)
        ctrl.pack(side="right", padx=12, pady=8)

        tk.Label(ctrl, text="Filter:", bg=HEADER_BG, fg=FG_DIM,
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        tk.Entry(
            ctrl, textvariable=self._filter_text,
            bg=BG_ALT, fg=FG, insertbackground=FG,
            relief="flat", font=("Segoe UI", 9), width=22,
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT
        ).pack(side="left", padx=(0, 12), ipady=3)

        tk.Checkbutton(
            ctrl, text="Show listeners", variable=self._show_listeners,
            bg=HEADER_BG, fg=FG_DIM, selectcolor=BG, activebackground=HEADER_BG,
            activeforeground=FG, font=("Segoe UI", 9), command=self._refresh_display
        ).pack(side="left", padx=(0, 12))

        self._pause_btn = tk.Button(
            ctrl, text="⏸ Pause", bg=BG_ALT, fg=FG, relief="flat",
            font=("Segoe UI", 9), padx=8, pady=3,
            activebackground=BORDER, activeforeground=FG,
            command=self._toggle_pause
        )
        self._pause_btn.pack(side="left", padx=(0, 6))

        tk.Button(
            ctrl, text="⟳ Clear cache", bg=BG_ALT, fg=FG, relief="flat",
            font=("Segoe UI", 9), padx=8, pady=3,
            activebackground=BORDER, activeforeground=FG,
            command=self._clear_cache
        ).pack(side="left", padx=(0, 6))

        self._alerts_btn = tk.Button(
            ctrl, text="⚠ Alerts  0", bg=BG_ALT, fg=FG_DIM, relief="flat",
            font=("Segoe UI", 9, "bold"), padx=8, pady=3,
            activebackground=BORDER, activeforeground=FG,
            command=self._open_alerts_panel
        )
        self._alerts_btn.pack(side="left")

        # Stats bar
        stats_bar = tk.Frame(self.root, bg=BG_ALT, height=26)
        stats_bar.pack(fill="x", side="top")
        stats_bar.pack_propagate(False)
        self._stats_lbl = tk.Label(stats_bar, text="", bg=BG_ALT, fg=FG_DIM,
                                    font=("Segoe UI", 8))
        self._stats_lbl.pack(side="left", padx=12)
        self._time_lbl = tk.Label(stats_bar, text="", bg=BG_ALT, fg=FG_DIM,
                                   font=("Segoe UI", 8))
        self._time_lbl.pack(side="right", padx=12)

        # Click hint
        tk.Label(
            stats_bar, text="Double-click a row to open packet capture  │",
            bg=BG_ALT, fg=FG_DIM, font=("Segoe UI", 7, "italic")
        ).pack(side="right", padx=(0, 6))

        # Table
        table_frame = tk.Frame(self.root, bg=BG)
        table_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Net.Treeview",
                         background=BG, foreground=FG, fieldbackground=BG,
                         borderwidth=0, rowheight=24, font=("Segoe UI", 9))
        style.configure("Net.Treeview.Heading",
                         background=HEADER_BG, foreground=FG_DIM,
                         borderwidth=0, relief="flat", font=("Segoe UI", 8, "bold"))
        style.map("Net.Treeview",
                  background=[("selected", "#1f6feb")],
                  foreground=[("selected", "#ffffff")])
        style.layout("Net.Treeview", [("Net.Treeview.treearea", {"sticky": "nswe"})])

        col_ids = [c[0] for c in COLUMNS]
        self.tree = ttk.Treeview(
            table_frame, columns=col_ids, show="headings",
            style="Net.Treeview", selectmode="browse"
        )

        center_cols = {"flag", "proto", "pid", "status", "sent", "recv", "rate",
                       "first_seen", "duration"}
        for col_id, col_label, col_width in COLUMNS:
            anchor = "center" if col_id in center_cols else "w"
            self.tree.heading(col_id, text=col_label,
                              command=lambda c=col_id: self._sort_by(c))
            self.tree.column(col_id, width=col_width, minwidth=28,
                             anchor=anchor, stretch=(col_id == "org"))

        for status, color in STATUS_COLORS.items():
            self.tree.tag_configure(f"status_{status}", foreground=color)
        self.tree.tag_configure("local_row", foreground=FG_DIM)
        self.tree.tag_configure("alt_row",   background=BG_ALT)

        # Threat-level row highlights
        for level, bg in THREAT_ROW_COLORS.items():
            self.tree.tag_configure(
                f"threat_{level}",
                background=bg,
                foreground=THREAT_FG_COLORS[level],
            )

        vsb = ttk.Scrollbar(table_frame, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Double-click → capture; single-click on org column → detail
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<ButtonRelease-1>", self._on_single_click)

        # Hover tooltip
        self._tooltip = tk.Toplevel(self.root)
        self._tooltip.withdraw()
        self._tooltip.overrideredirect(True)
        self._tooltip.configure(bg=HEADER_BG)
        self._tooltip_lbl = tk.Label(
            self._tooltip, bg=HEADER_BG, fg=FG,
            font=("Segoe UI", 8), padx=8, pady=4,
            justify="left", highlightthickness=1, highlightbackground=BORDER
        )
        self._tooltip_lbl.pack()
        self.tree.bind("<Motion>", self._on_hover)
        self.tree.bind("<Leave>",  lambda e: self._tooltip.withdraw())

    # ── Threading ─────────────────────────────────────────────────────────────

    def _start_threads(self):
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def _poll_loop(self):
        while self._running:
            if not self._paused:
                with self._lock:
                    geo_snapshot = dict(self._geo_cache)
                conns = get_connections(geo_cache=geo_snapshot)
                self._last_connections = conns

                public_ips = {
                    c.remote_addr for c in conns
                    if c.remote_addr and not c.is_local
                    and c.remote_addr not in ("", "0.0.0.0", "::")
                }
                missing = public_ips - set(self._geo_cache.keys())
                if missing:
                    geo = batch_lookup(list(missing))
                    with self._lock:
                        self._geo_cache.update(geo)

                self._check_traffic_spike(conns)
                self.root.after(0, self._refresh_display)
            time.sleep(REFRESH_INTERVAL)

    # ── Display ───────────────────────────────────────────────────────────────

    def _format_duration(self, first_seen: datetime) -> str:
        secs = int((datetime.now() - first_seen).total_seconds())
        if secs < 60:
            return f"{secs}s"
        elif secs < 3600:
            return f"{secs//60}m{secs%60:02d}s"
        else:
            h = secs // 3600
            m = (secs % 3600) // 60
            return f"{h}h{m:02d}m"

    def _refresh_display(self, *_):
        conns = self._last_connections
        ftext = self._filter_text.get().lower().strip()
        show_listeners = self._show_listeners.get()

        filtered = []
        for c in conns:
            if not show_listeners and (not c.remote_addr or c.remote_addr in ("", "0.0.0.0", "::")):
                continue
            if ftext:
                hay = " ".join([
                    c.remote_addr, c.local_addr, c.process_name,
                    c.status, c.protocol, str(c.pid),
                    self._geo_cache.get(c.remote_addr, {}).get("country", ""),
                    self._geo_cache.get(c.remote_addr, {}).get("org", ""),
                ]).lower()
                if ftext not in hay:
                    continue
            filtered.append(c)

        # Sort
        def sort_key(c: Connection):
            col = self._sort_col
            geo = self._geo_cache.get(c.remote_addr, {})
            if   col == "threat":     return c.threat_score
            elif col == "flag":       return geo.get("countryCode", "ZZ")
            elif col == "country":    return geo.get("country", "ZZ").lower()
            elif col == "remote":     return c.remote_addr
            elif col == "local":      return c.local_addr
            elif col == "proto":      return c.protocol
            elif col == "status":     return c.status
            elif col == "process":    return c.process_name.lower()
            elif col == "pid":        return c.pid
            elif col == "first_seen": return c.first_seen
            elif col == "duration":   return c.first_seen   # same axis, rev order
            elif col == "sent":       return c.bytes_sent
            elif col == "recv":       return c.bytes_recv
            elif col == "rate":       return c.rate_sent + c.rate_recv
            elif col == "city":       return geo.get("city", "").lower()
            elif col == "org":        return geo.get("org", "").lower()
            return ""

        filtered.sort(key=sort_key, reverse=self._sort_rev)

        existing = set(self.tree.get_children())
        new_keys: set[str] = set()
        new_iid_map: dict[str, Connection] = {}

        now = datetime.now()

        for i, c in enumerate(filtered):
            geo = self._geo_cache.get(c.remote_addr, {})
            if c.is_local or not c.remote_addr:
                if c.remote_addr in ("127.0.0.1", "::1"):
                    country, cc = "Loopback", "LB"
                else:
                    country, cc = "Local / Private", "LO"
            else:
                country = geo.get("country", "…")
                cc      = geo.get("countryCode", "")

            flag = (
                flag_emoji(cc) if cc not in ("LO", "LB", "", "??", "—")
                else ("🔁" if cc == "LB" else "🏠")
            )
            city  = geo.get("city", "")
            org   = geo.get("org", "") or geo.get("isp", "")

            fs    = c.first_seen.strftime("%H:%M:%S")
            dur   = self._format_duration(c.first_seen)
            sent  = fmt_bytes(c.bytes_sent)
            recv  = fmt_bytes(c.bytes_recv)
            rate  = fmt_rate(c.rate_sent + c.rate_recv) if (c.rate_sent + c.rate_recv) > 0 else "—"

            # Threat icon
            from threat_intel import highest_level
            top_level = highest_level(c.threat_flags) if c.threat_flags else None
            threat_icon = {
                "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"
            }.get(top_level, "")

            values = (
                threat_icon,
                flag, country,
                c.remote_display, c.local_display,
                c.protocol, c.status,
                c.process_name, c.pid if c.pid else "",
                fs, dur,
                sent, recv, rate,
                city, org,
            )

            key_str = "|".join(str(v) for v in c.key())
            new_keys.add(key_str)

            # Tags: threat level overrides alt-row background
            tags = [f"status_{c.status}"]
            if top_level:
                tags.append(f"threat_{top_level}")
            elif i % 2 == 1:
                tags.append("alt_row")
            if c.is_local and not top_level:
                tags.append("local_row")

            # Fire alerts for newly-flagged connections
            if c.threat_flags and key_str not in self._alert_seen_keys:
                self._alert_seen_keys.add(key_str)
                self._fire_alert(c)
            elif not c.threat_flags:
                self._alert_seen_keys.discard(key_str)

            if key_str in self._row_ids and self._row_ids[key_str] in existing:
                iid = self._row_ids[key_str]
                self.tree.item(iid, values=values, tags=tags)
                self.tree.move(iid, "", i)
            else:
                iid = self.tree.insert("", i, values=values, tags=tags)
                self._row_ids[key_str] = iid

            new_iid_map[self._row_ids[key_str]] = c

        # Prune stale rows
        for key_str, iid in list(self._row_ids.items()):
            if key_str not in new_keys and iid in self.tree.get_children():
                self.tree.delete(iid)
                del self._row_ids[key_str]

        self._iid_to_conn = new_iid_map

        # Stats
        total       = len(filtered)
        established = sum(1 for c in filtered if c.status == "ESTABLISHED")
        external    = sum(1 for c in filtered if not c.is_local and c.remote_addr)
        countries   = len({
            self._geo_cache.get(c.remote_addr, {}).get("countryCode", "??")
            for c in filtered if not c.is_local and c.remote_addr
        } - {"??", "", "—"})
        total_sent  = sum(c.bytes_sent for c in filtered)
        total_recv  = sum(c.bytes_recv for c in filtered)
        total_rate  = sum(c.rate_sent + c.rate_recv for c in filtered)

        self._stats_lbl.config(
            text=(
                f"  {total} connections  │  {established} established  │  "
                f"{external} external  │  {countries} countries  │  "
                f"↑ {fmt_bytes(total_sent)}  ↓ {fmt_bytes(total_recv)}  "
                f"@ {fmt_rate(total_rate)}"
            )
        )
        self._time_lbl.config(text=f"Updated {datetime.now().strftime('%H:%M:%S')}  ")

    def _on_filter_change(self, *_):
        self._refresh_display()

    def _sort_by(self, col: str):
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = col in ("sent", "recv", "rate", "first_seen")
        self._refresh_display()

    # ── Traffic spike detection ───────────────────────────────────────────────

    def _check_traffic_spike(self, conns: list[Connection]):
        """Notify tray if any single connection exceeds the spike threshold."""
        if not self._tray:
            return
        for c in conns:
            total_rate = c.rate_sent + c.rate_recv
            if total_rate < self._SPIKE_THRESHOLD:
                # Reset notification gate once traffic drops
                self._spike_notified.discard(c.process_name)
                continue
            if c.process_name in self._spike_notified:
                continue
            self._spike_notified.add(c.process_name)
            mbps = total_rate / (1024 * 1024)
            self._tray.notify(
                title="NetSec — High Traffic Spike",
                message=(
                    f"{c.process_name} (PID {c.pid})\n"
                    f"→ {c.remote_display}\n"
                    f"Rate: {mbps:.1f} MB/s  "
                    f"(↑{fmt_rate(c.rate_sent)}  ↓{fmt_rate(c.rate_recv)})"
                ),
                alert=True,
            )
            # Also log it as a medium alert
            self._alert_log.append({
                "time":    datetime.now().strftime("%H:%M:%S"),
                "level":   "high",
                "process": c.process_name,
                "remote":  c.remote_display,
                "pid":     c.pid,
                "flags":   [type("F", (), {
                    "code": "TRAFFIC_SPIKE",
                    "level": "high",
                    "reason": f"Traffic spike: {mbps:.1f} MB/s on {c.remote_display}",
                    "icon": "🟠",
                    "color": THREAT_FG_COLORS["high"],
                })()],
                "score":   60,
            })
            self.root.after(0, self._update_alerts_btn)

    def _update_alerts_btn(self):
        count = len(self._alert_log)
        if count == 0:
            return
        top_levels = [e["level"] for e in self._alert_log]
        top = "critical" if "critical" in top_levels else (
              "high" if "high" in top_levels else "medium")
        self._alerts_btn.config(
            text=f"⚠ Alerts  {count}",
            fg=THREAT_FG_COLORS.get(top, FG_DIM),
            bg="#2d1a00" if top in ("critical", "high") else BG_ALT,
        )

    # ── Threat alerts ─────────────────────────────────────────────────────────

    def _fire_alert(self, conn: Connection):
        """Record a new alert and update the Alerts button."""
        from threat_intel import highest_level
        top = highest_level(conn.threat_flags)
        entry = {
            "time":     datetime.now().strftime("%H:%M:%S"),
            "level":    top or "low",
            "process":  conn.process_name,
            "remote":   conn.remote_display,
            "pid":      conn.pid,
            "flags":    conn.threat_flags,
            "score":    conn.threat_score,
        }
        self._alert_log.append(entry)

        # Update Alerts button
        count = len(self._alert_log)
        btn_color = THREAT_FG_COLORS.get(top, FG_DIM)
        self._alerts_btn.config(
            text=f"⚠ Alerts  {count}",
            fg=btn_color,
            bg="#2d1a00" if top in ("critical", "high") else BG_ALT,
        )

        # Tray balloon for critical/high
        if top in ("critical", "high") and self._tray:
            flags_summary = "  |  ".join(f"[{f.code}] {f.reason[:60]}" for f in conn.threat_flags[:2])
            self._tray.notify(
                title=f"⚠ NetSec Alert — {top.upper()}",
                message=f"{conn.process_name} → {conn.remote_display}\n{flags_summary}",
                alert=True,
            )

        # Refresh alerts panel if open
        if self._alerts_panel and self._alerts_panel.winfo_exists():
            self._alerts_panel.add_entry(entry)

    def _open_alerts_panel(self):
        if self._alerts_panel and self._alerts_panel.winfo_exists():
            self._alerts_panel.lift()
            self._alerts_panel.focus_force()
            return
        self._alerts_panel = AlertsPanel(self.root, self._alert_log,
                                          on_clear=self._clear_alerts)

    def _clear_alerts(self):
        self._alert_log.clear()
        self._alert_seen_keys.clear()
        self._spike_notified.clear()
        self._alerts_btn.config(text="⚠ Alerts  0", fg=FG_DIM, bg=BG_ALT)
        if self._tray:
            self._tray.clear_alert()

    # ── Double-click → Capture ────────────────────────────────────────────────

    def _on_double_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        conn = self._iid_to_conn.get(iid)
        if not conn:
            return

        key_str = "|".join(str(v) for v in conn.key())

        # If already open, just focus it
        if key_str in self._open_captures:
            win = self._open_captures[key_str]
            try:
                win.lift()
                win.focus_force()
                return
            except tk.TclError:
                pass  # window was closed

        geo = self._geo_cache.get(conn.remote_addr, {})
        panel = CapturePanel(self.root, conn, geo)
        self._open_captures[key_str] = panel

        def on_close(k=key_str):
            self._open_captures.pop(k, None)
        panel.protocol("WM_DELETE_WINDOW", lambda: (on_close(), panel._on_close()))

    # ── Single-click → Org/ISP detail ────────────────────────────────────────

    def _on_single_click(self, event):
        """Open Org/ISP detail panel when the user clicks the org column."""
        col = self.tree.identify_column(event.x)   # '#1', '#2', … '#N'
        iid = self.tree.identify_row(event.y)
        if not iid or not col:
            return

        # Map column id string '#N' to column name
        col_names = [c[0] for c in COLUMNS]
        try:
            col_index = int(col.lstrip("#")) - 1
            col_name  = col_names[col_index]
        except (ValueError, IndexError):
            return

        if col_name != "org":
            return

        conn = self._iid_to_conn.get(iid)
        if not conn or not conn.remote_addr or conn.is_local:
            return

        values = self.tree.item(iid, "values")
        display_org = values[14] if values and len(values) > 14 else ""
        if not display_org or display_org in ("—", ""):
            display_org = conn.remote_addr

        self._open_org_detail(conn.remote_addr, display_org)

    def _open_org_detail(self, ip: str, display_org: str):
        """Raise existing org panel or create a new one."""
        key = f"org:{ip}"
        if key in self._open_captures:
            win = self._open_captures[key]
            try:
                win.lift()
                win.focus_force()
                return
            except tk.TclError:
                pass

        panel = OrgDetailPanel(self.root, ip, display_org)
        self._open_captures[key] = panel

        def on_close(k=key):
            self._open_captures.pop(k, None)
        panel.protocol("WM_DELETE_WINDOW", lambda: (on_close(), panel.destroy()))

    # ── Tooltip ───────────────────────────────────────────────────────────────

    def _on_hover(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            self._tooltip.withdraw()
            return
        conn = self._iid_to_conn.get(iid)
        values = self.tree.item(iid, "values")
        if not values:
            self._tooltip.withdraw()
            return

        country, remote, local, proto, status = values[1], values[2], values[3], values[4], values[5]
        process, pid, fs, dur = values[6], values[7], values[8], values[9]
        sent, recv, rate = values[10], values[11], values[12]
        city, org = values[13], values[14]

        lines = [
            f"Process : {process}  (PID {pid})",
            f"Protocol: {proto}  │  Status: {status}",
            f"Local   : {local}",
            f"Remote  : {remote}",
            f"Country : {country}" + (f", {city}" if city else ""),
            f"First seen: {fs}  │  Duration: {dur}",
            f"Sent: {sent}  │  Recv: {recv}  │  Rate: {rate}",
        ]
        if org:
            lines.append(f"Org/ISP : {org}")
        lines.append("")
        lines.append("Double-click → open packet capture")
        lines.append("Click Org/ISP cell → WHOIS / RDAP detail")

        self._tooltip_lbl.config(text="\n".join(lines))
        self._tooltip.geometry(f"+{event.x_root + 14}+{event.y_root + 14}")
        self._tooltip.deiconify()
        self._tooltip.lift()

    # ── Controls ──────────────────────────────────────────────────────────────

    def _toggle_pause(self):
        self._paused = not self._paused
        if self._paused:
            self._pause_btn.config(text="▶ Resume")
            self._live_dot.config(fg=YELLOW)
            self._live_lbl.config(text="PAUSED", fg=YELLOW)
        else:
            self._pause_btn.config(text="⏸ Pause")
            self._live_dot.config(fg=GREEN)
            self._live_lbl.config(text="LIVE", fg=GREEN)

    def _clear_cache(self):
        from geo_lookup import invalidate_cache
        invalidate_cache()
        from network_monitor import clear_registry
        clear_registry()
        with self._lock:
            self._geo_cache.clear()

    def hide(self):
        self.root.withdraw()

    def show(self):
        self.root.deiconify()
        self.root.lift()

    def destroy(self):
        self._running = False
        for panel in list(self._open_captures.values()):
            try:
                panel._on_close()
            except Exception:
                pass
        self.root.destroy()
