"""
NetSec Monitor — entry point.

Launches:
  • A system tray icon next to the Windows clock
  • A dark-themed GUI window showing live network connections with geo-IP info

Run with:
    python main.py

Requires Python 3.10+ and packages in requirements.txt.
For best results, run as Administrator (to see all process names).
"""

import sys
import threading
import tkinter as tk
import ctypes

from gui import NetSecWindow
from tray_icon import TrayApp


def request_admin_elevation():
    """Re-launch as admin if not already elevated (Windows only)."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        # Re-launch with UAC prompt
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(f'"{a}"' for a in sys.argv), None, 1
            )
            sys.exit(0)
        except Exception:
            pass  # User declined elevation — continue without admin


def main():
    # Request elevation for full process visibility
    request_admin_elevation()

    # ── Tkinter root (hidden — we manage visibility ourselves) ──
    root = tk.Tk()
    root.withdraw()  # Start hidden; tray click will show it

    # High-DPI awareness
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    # ── Tray icon — must be created before NetSecWindow so we can pass it in ──
    tray = TrayApp(on_show=lambda: None, on_quit=lambda: None)

    app = NetSecWindow(root, tray=tray)

    def on_show():
        """Toggle window visibility from tray."""
        if root.state() == "withdrawn":
            app.show()
        else:
            app.hide()

    def on_quit():
        """Clean shutdown."""
        app.destroy()

    tray._on_show = on_show
    tray._on_quit = on_quit

    tray_thread = threading.Thread(target=tray.run, daemon=True)
    tray_thread.start()

    # Show window on first launch
    root.after(200, app.show)

    # ── Tkinter main loop ──
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        tray.stop()


if __name__ == "__main__":
    main()
