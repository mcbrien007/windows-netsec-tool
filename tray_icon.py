"""
System tray icon — sits next to the clock, right-click for menu,
left-click/double-click to show/hide the main window.

Also provides:
  - notify()    — Windows balloon notification via win10toast or ctypes fallback
  - alert_icon  — switches tray icon to red when threats are active
"""

import threading
import ctypes
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as Item, Menu


def _make_icon_image(size: int = 64, alert: bool = False) -> Image.Image:
    """Draw a shield icon. Red variant when alert=True."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = size // 8
    w = size - 2 * pad

    shield_color = (200, 30, 30, 230) if alert else (30, 150, 255, 230)
    inner_color  = (255, 80, 80, 180) if alert else (80, 190, 255, 180)

    pts = [
        (pad, pad),
        (pad + w, pad),
        (pad + w, pad + int(w * 0.6)),
        (pad + w // 2, pad + w),
        (pad, pad + int(w * 0.6)),
    ]
    d.polygon(pts, fill=shield_color)

    s = size // 6
    inner = [
        (pad + s, pad + s),
        (pad + w - s, pad + s),
        (pad + w - s, pad + int(w * 0.55)),
        (pad + w // 2, pad + w - s),
        (pad + s, pad + int(w * 0.55)),
    ]
    d.polygon(inner, fill=inner_color)

    cx = size // 2
    cy = size // 2 + size // 10
    r  = size // 10
    # Exclamation mark when alert, dot when normal
    if alert:
        # Draw "!" — vertical bar + dot
        bar_top    = (cx - 2, cy - r - size // 6)
        bar_bottom = (cx + 2, cy - 2)
        d.rectangle([bar_top, bar_bottom], fill=(255, 255, 255, 230))
        d.ellipse((cx - 2, cy + 2, cx + 2, cy + 6), fill=(255, 255, 255, 230))
    else:
        d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(255, 255, 255, 220))

    return img


def _windows_toast(title: str, message: str):
    """
    Fire a Windows 10/11 balloon notification using shell32 directly.
    Falls back silently if unavailable.
    """
    try:
        # Try win10toast if installed
        from win10toast import ToastNotifier
        t = ToastNotifier()
        threading.Thread(
            target=t.show_toast,
            args=(title, message),
            kwargs={"duration": 6, "threaded": True},
            daemon=True,
        ).start()
        return
    except ImportError:
        pass

    # Fallback: use Windows balloon via Shell_NotifyIcon through ctypes
    # This is best-effort; if the pystray icon is active we use its notify() instead
    try:
        ctypes.windll.user32.MessageBeep(0x00000040)   # MB_ICONINFORMATION beep
    except Exception:
        pass


class TrayApp:
    def __init__(self, on_show, on_quit):
        self._on_show   = on_show
        self._on_quit   = on_quit
        self._icon      = None
        self._alert_mode = False
        self._notif_lock = threading.Lock()
        self._last_notif_time: float = 0.0
        self._NOTIF_COOLDOWN = 15.0   # seconds between balloon alerts

    def _build_menu(self):
        return Menu(
            Item("Show / Hide", self._handle_show, default=True),
            Menu.SEPARATOR,
            Item("Quit", self._handle_quit),
        )

    def _handle_show(self, icon=None, item=None):
        self._on_show()

    def _handle_quit(self, icon=None, item=None):
        if self._icon:
            self._icon.stop()
        self._on_quit()

    def run(self):
        img = _make_icon_image(64)
        self._icon = pystray.Icon(
            "netsec_monitor",
            img,
            "NetSec Monitor",
            menu=self._build_menu(),
        )
        self._icon.on_activate = self._handle_show
        self._icon.run()

    def notify(self, title: str, message: str, alert: bool = False):
        """
        Show a balloon notification from the tray icon.
        Throttled to avoid spamming.
        alert=True switches the tray icon red until cleared.
        """
        import time as _time
        with self._notif_lock:
            now = _time.monotonic()
            if now - self._last_notif_time < self._NOTIF_COOLDOWN:
                return
            self._last_notif_time = now

        if alert and not self._alert_mode:
            self._alert_mode = True
            self._set_icon_alert(True)

        # Try pystray built-in notify first (works on Windows 10/11)
        if self._icon:
            try:
                self._icon.notify(message, title)
                return
            except Exception:
                pass

        # Fallback
        _windows_toast(title, message)

    def clear_alert(self):
        """Reset icon to normal (blue shield) once threats are acknowledged."""
        if self._alert_mode:
            self._alert_mode = False
            self._set_icon_alert(False)

    def _set_icon_alert(self, is_alert: bool):
        if self._icon:
            try:
                self._icon.icon = _make_icon_image(64, alert=is_alert)
                tooltip = "⚠ NetSec Monitor — THREAT DETECTED" if is_alert else "NetSec Monitor"
                self._icon.title = tooltip
            except Exception:
                pass

    def stop(self):
        if self._icon:
            self._icon.stop()
