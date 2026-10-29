"""Interactive customer UI. It has no private-key or owner-token access."""
import ctypes
import getpass
import json
import locale
import io
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from urllib.parse import urlsplit
from urllib.request import build_opener

from consent_client import display
from windows_host import input_desktop_unlocked, ipc

VERSION = "1.0.2"


def remote_image(url):
    from PIL import Image
    from windows_host import NoRedirect
    import warnings
    if not isinstance(url, str) or len(url) > 2048:
        return None
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    try:
        started = time.monotonic()
        with build_opener(NoRedirect()).open(url, timeout=2) as response:
            chunks, size = [], 0
            while True:
                if time.monotonic() - started > 2:
                    return None
                chunk = response.read1(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 1024 * 1024:
                    return None
                chunks.append(chunk)
            content = b"".join(chunks)
        if len(content) > 1024 * 1024:
            return None
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            image = Image.open(io.BytesIO(content))
            if image.width * image.height > 2000000 or image.format not in ("PNG", "JPEG", "WEBP"):
                return None
            image.load()
            image.thumbnail((40, 40))
            return image.convert("RGB")
    except Exception:
        return None
HE = {
    "powered": "מופעל על ידי Remote Consent Agent", "support": "תמיכה מרחוק", "tech": "טכנאי",
    "desktop": "מסך", "terminal": "מסוף", "files": "קבצים",
    "ask_desktop": "מבקש לראות את המסך שלך", "ask_terminal": "מבקש לפתוח מסוף פקודות במחשב שלך",
    "ask_files": "מבקש גישה לקבצים במחשב שלך",
    "explain_desktop": "🖥️ הטכנאי יראה את כל מה שמופיע במסך.",
    "explain_terminal": "⌨️ הטכנאי יוכל להריץ פקודות במחשב. הוא לא יראה את המסך שלך.",
    "explain_files": "📁 הטכנאי יוכל לראות, להעתיק ולהעלות קבצים.",
    "ticket": "קריאה", "computer": "מחשב", "approve": "אשר", "deny": "דחה",
    "repeat": "אשר אוטומטית בקשות נוספות מטכנאי זה ל-5 דקות",
    "countdown": "הבקשה תידחה אוטומטית בעוד {time} אם לא תענה",
    "timeout": "הבקשה נדחתה",
    "timeout_detail": "לא התקבלה תשובה תוך 60 שניות, ולכן הטכנאי לא חובר. אם צריך, אפשר לבקש ממנו לנסות שוב.",
    "close": "סגור", "connected": "מחובר", "disconnect": "נתק", "disconnect_all": "נתק הכל",
    "multiple": "{n} טכנאים מחוברים", "ending": "מנתק…", "ended": "החיבור הסתיים",
    "ended_detail": "{tech} התנתק {time}. משך: {minutes} דק'. סיכום הטיפול יופיע בקריאה.",
    "standing": "{org} מבקש להתחבר למחשב הזה בלי לשאול אותך כל פעם",
    "standing_explain": "כך הטכנאים של {org} יוכלו לטפל גם כשאתה לא ליד המחשב.",
    "scopes": "מה יהיה מותר:", "duration": "לכמה זמן:", "30days": "30 יום", "forever": "עד שאבטל",
    "standing_detail": 'בכל חיבור תראה סרגל עם שם הטכנאי וכפתור "נתק". אפשר לבטל את האישור בכל רגע מהאייקון במגש.',
    "standing_yes": "מאשר חיבור אוטומטי", "standing_no": "לא, תמיד לשאול אותי",
    "customer": "שם המאשר", "online": "מחובר לשרת התמיכה", "offline": "אין חיבור לשרת התמיכה",
    "grant": "🔓 חיבור אוטומטי פעיל עד {date} · {scopes}", "revoke": "בטל חיבור אוטומטי",
    "version": "גרסה {version} · מתעדכן אוטומטית", "tray": "מגש המערכת",
    "not_enrolled": "הרכיב ממתין לרישום על ידי בעל הארגון", "clock": "שעון המחשב לא מסונכרן",
}
EN = {
    "powered": "Powered by Remote Consent Agent", "support": "Remote support", "tech": "Technician",
    "desktop": "Screen", "terminal": "Terminal", "files": "Files",
    "ask_desktop": "Requests to see your screen", "ask_terminal": "Requests to open a command terminal on your computer",
    "ask_files": "Requests access to files on your computer",
    "explain_desktop": "🖥️ The technician will see everything on your screen.",
    "explain_terminal": "⌨️ The technician will be able to run commands on your computer. They will not see your screen.",
    "explain_files": "📁 The technician will be able to view, copy and upload files.",
    "ticket": "Ticket", "computer": "Computer", "approve": "Approve", "deny": "Deny",
    "repeat": "Automatically approve more requests from this technician for 5 minutes",
    "countdown": "The request will be denied automatically in {time} if you do not respond",
    "timeout": "Request denied",
    "timeout_detail": "No response was received within 60 seconds, so the technician was not connected. You can ask them to try again if needed.",
    "close": "Close", "connected": "connected", "disconnect": "Disconnect", "disconnect_all": "Disconnect all",
    "multiple": "{n} technicians connected", "ending": "Disconnecting…", "ended": "Connection ended",
    "ended_detail": "{tech} disconnected at {time}. Duration: {minutes} min. A summary will appear in the ticket.",
    "standing": "{org} requests to connect to this computer without asking each time",
    "standing_explain": "This lets technicians from {org} help even when you are away from the computer.",
    "scopes": "Allow:", "duration": "For how long:", "30days": "30 days", "forever": "Until I revoke",
    "standing_detail": 'Every connection shows a bar with the technician’s name and a "Disconnect" button. You can revoke approval from the tray icon at any time.',
    "standing_yes": "Approve automatic connection", "standing_no": "No, always ask me",
    "customer": "Approved by", "online": "Connected to the support server", "offline": "Support server unavailable",
    "grant": "🔓 Automatic connection active until {date} · {scopes}", "revoke": "Revoke automatic connection",
    "version": "Version {version} · Updates automatically", "tray": "System tray",
    "not_enrolled": "Waiting for the organization owner to enroll this component", "clock": "Computer clock is not synchronized",
}


def language():
    return "he" if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3ff == 0x0d else "en"


def user_name():
    result = queue.Queue(maxsize=1)
    def lookup():
        size = ctypes.c_ulong(256)
        buffer = ctypes.create_unicode_buffer(256)
        try:
            if ctypes.windll.secur32.GetUserNameExW(3, buffer, ctypes.byref(size)):
                result.put(display(buffer.value, 100))
        except Exception:
            pass
    # Domain-backed display-name lookup can block on an unavailable directory.
    # Never block a consent window on that network-dependent Windows API.
    threading.Thread(target=lookup, daemon=True).start()
    try:
        name = result.get(timeout=.25)
        if name:
            return name
    except queue.Empty:
        pass
    import win32api
    return display(win32api.GetUserName(), 100)


class CustomerUI:
    def __init__(self, lang=None, gallery=False):
        self.lang = lang or language()
        self.words = HE if self.lang == "he" else EN
        self.rtl = self.lang == "he"
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title("Remote Consent Agent")
        self.root.option_add("*Font", "{Segoe UI} 11")
        self.events = queue.Queue()
        self.snapshot = dict(online=False, requests=[], connections=[], grants=[])
        self.window = self.bar = self.tray = None
        self.request = None
        self.dismissed = set()
        self.previous = {}
        self.last_shape = None
        self.gallery = gallery
        self.sent = []
        self.restart = None
        if not gallery:
            threading.Thread(target=self.worker, daemon=True).start()
            threading.Thread(target=self.native_tray, daemon=True).start()
        self.root.after(100, self.tick)

    def text(self, key, **fields):
        return self.words[key].format(**fields)

    def label(self, parent, text, bold=False, color="#1f2937", background="white"):
        label = tk.Label(parent, text=("\u200f" if self.rtl else "") + text, bg=background, fg=color,
                         font=("Segoe UI", 11, "bold" if bold else "normal"),
                         anchor="e" if self.rtl else "w", justify="right" if self.rtl else "left",
                         wraplength=430)
        label.pack(fill="x", pady=4)
        return label

    def new_window(self, title="Remote Consent Agent"):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.configure(bg="white")
        window.attributes("-topmost", True)
        window.resizable(False, False)
        window.geometry("480x570+180+110")
        container = tk.Frame(window, bg="white", padx=22, pady=16)
        container.pack(fill="both", expand=True)
        return window, container

    def identity(self, parent, name, url=None, initials=None):
        row = tk.Frame(parent, bg="white")
        row.pack(fill="x", pady=5)
        initials = initials or "".join(part[0] for part in name.split() if part[0].isalnum())[:2] or "?"
        badge = tk.Label(row, text=initials, bg="#dbeafe", fg="#1e40af", width=3, height=2,
                         font=("Segoe UI", 12, "bold"))
        badge.pack(side="right" if self.rtl else "left", padx=6)
        self.label(row, name, True)
        if url and not self.gallery:
            def load():
                image = remote_image(url)
                if image:
                    self.events.put(("image", (badge, image)))
            threading.Thread(target=load, daemon=True).start()

    def dispatch(self, command):
        if self.gallery:
            self.sent.append(command)
            return
        def send():
            try:
                ipc(command)
            except Exception:
                self.events.put(("offline", None))
        threading.Thread(target=send, daemon=True).start()

    def decide(self, approved):
        if not self.request:
            return
        request = self.request
        if approved and (not self.snapshot["online"] or not input_desktop_unlocked()
                         or request["expires_at"] <= time.time()):
            return
        command = dict(action="decision", request_id=request["request_id"], approved=approved,
                       repeat=bool(self.repeat.get()))
        if request["purpose"] == "standing":
            name = display(self.customer.get(), 100)
            selected = [scope for scope, variable in self.scopes.items() if variable.get()]
            if approved and (not name or not selected):
                return
            command.update(scopes=selected, customer_name=name,
                           duration=2592000 if self.duration.get() == "30" else None)
        self.dismissed.add(request["request_id"])
        self.dispatch(command)
        self.close_request()

    def close_request(self):
        if self.window:
            self.window.destroy()
        self.window = None
        self.request = None

    def request_window(self, request):
        self.close_request()
        self.request = request
        window, body = self.new_window()
        self.window = window
        org = display(request.get("organization_name"))
        tech = display(request.get("technician_name"))
        self.identity(body, org + " · " + self.text("support"), request.get("organization_logo_url"), org[:1])
        self.label(body, self.text("powered"), color="#64748b")
        if request["purpose"] == "connect":
            self.identity(body, tech, request.get("technician_photo_url"))
            self.label(body, f"{self.text('tech')} · {org}", color="#64748b")
            self.label(body, self.text("ask_" + request["transport"]), True)
            self.label(body, self.text("explain_" + request["transport"]), color="#64748b")
            ticket = request.get("ticket")
            if ticket:
                self.label(body, f"{self.text('ticket')}: {display(ticket.get('title'))} · {display(ticket.get('reference'), 12)} · {self.text('computer')}: {display(request.get('computer_name'))}", color="#64748b")
        else:
            self.label(body, self.text("standing", org=org), True)
            self.label(body, self.text("standing_explain", org=org), color="#64748b")
        self.repeat = tk.BooleanVar(value=False)
        if request["purpose"] == "connect":
            tk.Checkbutton(body, text=self.text("repeat"), variable=self.repeat, bg="white",
                           wraplength=420, anchor="e" if self.rtl else "w").pack(fill="x", pady=8)
        else:
            self.label(body, self.text("scopes"))
            self.scopes = {}
            for scope in request.get("scopes", [request["transport"]]):
                self.scopes[scope] = tk.BooleanVar(value=True)
                tk.Checkbutton(body, text=self.text(scope), variable=self.scopes[scope], bg="white").pack(anchor="e" if self.rtl else "w")
            self.duration = tk.StringVar(value="30")
            self.label(body, self.text("duration"))
            radios = tk.Frame(body, bg="white")
            radios.pack(fill="x")
            for value, key in (("30", "30days"), ("forever", "forever")):
                tk.Radiobutton(radios, text=self.text(key), variable=self.duration, value=value,
                               bg="white").pack(side="right" if self.rtl else "left")
            self.label(body, self.text("customer"))
            self.customer = tk.StringVar(value=user_name())
            tk.Entry(body, textvariable=self.customer, justify="right" if self.rtl else "left").pack(fill="x")
            self.label(body, self.text("standing_detail"), color="#64748b")
        remaining = max(0, int(request["expires_at"] - time.time()))
        self.countdown = self.label(body, self.text("countdown", time=f"{remaining // 60}:{remaining % 60:02}"), color="#64748b")
        buttons = tk.Frame(body, bg="white")
        buttons.pack(side="bottom", fill="x", pady=8)
        standing = request["purpose"] == "standing"
        approve = tk.Button(buttons, text=self.text("standing_yes" if standing else "approve"),
                            bg="#2563eb", fg="white", padx=14, pady=9, takefocus=False,
                            command=lambda: self.decide(True))
        approve.pack(side="right" if self.rtl else "left", expand=True, fill="x", padx=3)
        approve.bind("<Key>", lambda event: "break")
        deny = tk.Button(buttons, text=self.text("standing_no" if standing else "deny"), padx=14,
                         pady=9, command=lambda: self.decide(False))
        deny.pack(side="right" if self.rtl else "left", expand=True, fill="x", padx=3)
        window.protocol("WM_DELETE_WINDOW", lambda: self.decide(False))
        if standing:
            # Size from the translated copy and all requested scope controls,
            # including the countdown, before placing the action row.
            window.update_idletasks()
            window.geometry(f"480x{max(570, body.winfo_reqheight() + 8)}+180+40")
        # Initial focus is the window, never the approval button. No global
        # Return/Space accelerator exists. Approval is a mouse click only.
        window.focus_set()

    def notice(self, kind, connection=None):
        self.close_request()
        self.window, body = self.new_window()
        self.label(body, "⏱️" if kind == "timeout" else "✅", True)
        self.label(body, self.text(kind), True)
        if kind == "timeout":
            detail = self.text("timeout_detail")
        else:
            detail = self.text("ended_detail", tech=display((connection or {}).get("technician_name")),
                               time=datetime.fromtimestamp((connection or {}).get("ended_at") or time.time()).strftime("%H:%M"),
                               minutes=int((connection or {}).get("duration_seconds") or 0) // 60)
        self.label(body, detail, color="#64748b")
        tk.Button(body, text=self.text("close"), command=self.close_request).pack(pady=16)

    def privacy(self):
        active = [c for c in self.snapshot["connections"] if c["state"] in ("active", "revoking")]
        shape = json.dumps([active, self.snapshot.get("ending", [])], sort_keys=True)
        if shape == self.last_shape:
            return
        self.last_shape = shape
        if self.bar:
            self.bar.destroy()
            self.bar = None
        if not active:
            return
        self.bar = tk.Toplevel(self.root)
        self.bar.overrideredirect(True)
        self.bar.attributes("-topmost", True)
        self.bar.configure(bg="#0f172a")
        self.bar.geometry("760x48+100+12")
        transports = ", ".join(self.text(t) for t in sorted(set(c["transport"] for c in active)))
        technicians = set(c["technician_auth_id"] for c in active)
        description = (self.text("multiple", n=len(technicians)) if len(technicians) > 1
                       else f"{display(active[0].get('technician_name'))} ({display(active[0].get('organization_name'))}) {self.text('connected')}")
        description_label = tk.Label(self.bar, text=("\u200f" if self.rtl else "") + f"● {description} · {transports}",
                 bg="#0f172a", fg="white", anchor="e" if self.rtl else "w", font=("Segoe UI", 11))
        ending = any(c["state"] == "revoking" or c["id"] in self.snapshot.get("ending", []) for c in active)
        button = tk.Button(self.bar, text=self.text("ending" if ending else "disconnect_all" if len(active) > 1 else "disconnect"),
                           bg="#dc2626", fg="white", command=lambda: self.end_all(active))
        button.pack(side="left" if self.rtl else "right", padx=8, pady=6)
        # Reserve the disconnect action before laying out untrusted names.
        description_label.pack(side="right" if self.rtl else "left", padx=12, fill="x", expand=True)

    def end_all(self, connections):
        self.snapshot["ending"] = [c["id"] for c in connections]
        self.privacy()
        for connection in connections:
            self.dispatch(dict(action="end", session_id=connection["id"]))

    def tray_window(self):
        if self.tray:
            self.tray.destroy()
        self.tray, body = self.new_window(self.text("tray"))
        self.tray.geometry("480x330+180+110")
        self.label(body, "🛟 Remote Consent Agent", True)
        org = display(self.snapshot.get("organization_name"))
        self.label(body, "● " + self.text("online" if self.snapshot["online"] else "offline") + (" · " + org if org else ""))
        if self.snapshot.get("error") == "not_enrolled":
            self.label(body, self.text("not_enrolled"))
        if self.snapshot.get("error") == "clock_not_synchronized":
            self.label(body, self.text("clock"))
        for grant in self.snapshot["grants"]:
            until = datetime.fromtimestamp(grant["expires_at"]).strftime("%d.%m") if grant["expires_at"] else self.text("forever")
            self.label(body, self.text("grant", date=until, scopes=", ".join(self.text(s) for s in grant["scopes"])))
            tk.Button(body, text=self.text("revoke"), fg="#b91c1c",
                      command=lambda g=grant: self.dispatch(dict(action="revoke", grant_id=g["id"]))).pack(pady=4)
        # Portal entry points are hidden: this package has no verified existing
        # organization-bound portal route. Never redirect customers to the Hub.
        self.label(body, self.text("version", version=VERSION), color="#64748b")

    def native_tray(self):
        import win32api
        import win32con
        import win32gui
        message = win32con.WM_USER + 20
        def handler(hwnd, msg, wparam, lparam):
            if msg == message and lparam in (win32con.WM_RBUTTONUP, win32con.WM_LBUTTONUP):
                self.events.put(("tray", None))
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
        wc = win32gui.WNDCLASS()
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpszClassName = "RemoteConsentAgentTray"
        wc.lpfnWndProc = handler
        atom = win32gui.RegisterClass(wc)
        hwnd = win32gui.CreateWindow(atom, "", 0, 0, 0, 0, 0, 0, 0, wc.hInstance, None)
        icon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
        win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, (hwnd, 1, win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP,
                                                  message, icon, "Remote Consent Agent"))
        win32gui.PumpMessages()

    def worker(self):
        while True:
            try:
                snapshot = ipc({"action": "snapshot", "unlocked": input_desktop_unlocked()})
                self.events.put(("exit" if snapshot.get("exit") else "snapshot", snapshot))
            except Exception:
                from windows_host import installed_ui_after_update
                replacement = installed_ui_after_update()
                if replacement:
                    self.events.put(("restart", replacement))
                    return
                self.events.put(("offline", None))
            time.sleep(1)

    def tick(self):
        while not self.events.empty():
            kind, value = self.events.get_nowait()
            if kind == "tray":
                self.tray_window()
            elif kind == "exit":
                self.root.destroy()
                return
            elif kind == "restart":
                self.restart = value
                self.root.destroy()
                return
            elif kind == "image":
                from PIL import ImageTk
                badge, image = value
                if badge.winfo_exists():
                    badge.image = ImageTk.PhotoImage(image)
                    badge.configure(image=badge.image, text="", width=40, height=40)
            elif kind == "snapshot":
                ended = next((c for c in value["connections"] if c["state"] == "ended"
                              and self.previous.get(c["id"]) in ("active", "revoking")), None)
                self.previous = {c["id"]: c["state"] for c in value["connections"]}
                self.snapshot = value
                if ended and not self.request:
                    self.notice("ended", ended)
            elif kind == "offline":
                self.snapshot["online"] = False
                self.snapshot["requests"] = []
        self.privacy()
        if self.request:
            remaining = max(0, int(self.request["expires_at"] - time.time()))
            self.countdown.configure(text=self.text("countdown", time=f"{remaining // 60}:{remaining % 60:02d}"))
            if not remaining:
                self.dismissed.add(self.request["request_id"])
                self.notice("timeout")
            elif not self.snapshot["online"] and not self.gallery:
                self.close_request()
        if not self.window and input_desktop_unlocked():
            pending = next((r for r in self.snapshot["requests"] if r["request_id"] not in self.dismissed
                            and r["expires_at"] > time.time()), None)
            if pending:
                self.request_window(pending)
        self.root.after(200, self.tick)


def gallery(directory):
    """Exercise the real UI with deterministic, synthetic harness fields."""
    from PIL import ImageGrab
    import uuid
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for lang in ("he", "en"):
        ui = CustomerUI(lang, gallery=True)
        base = dict(request_id=str(uuid.uuid4()), org_id=str(uuid.uuid4()), device_id=str(uuid.uuid4()),
                    technician_auth_id=str(uuid.uuid4()), purpose="connect", expires_at=int(time.time()) + 60,
                    organization_name="ארגון לדוגמה" if lang == "he" else "Example Organization",
                    technician_name="טכנאי לדוגמה" if lang == "he" else "Example Technician", computer_name="Test computer",
                    ticket=dict(title="אין צליל במחשב" if lang == "he" else "No sound on computer", reference="#3F9A21"))
        ui.snapshot["online"] = True
        ui.snapshot["organization_name"] = base["organization_name"]
        def capture(name, window):
            window.update()
            time.sleep(.2)
            window.update()
            def check_actions(widget):
                if isinstance(widget, tk.Button):
                    assert widget.winfo_height() >= widget.winfo_reqheight(), "clipped action height"
                    assert widget.winfo_width() >= widget.winfo_reqwidth(), "clipped action width"
                    assert widget.winfo_rooty() + widget.winfo_height() <= window.winfo_rooty() + window.winfo_height(), "action below window"
                for child in widget.winfo_children():
                    check_actions(child)
            check_actions(window)
            x, y = window.winfo_rootx(), window.winfo_rooty()
            ImageGrab.grab(bbox=(x, y, x + window.winfo_width(), y + window.winfo_height())).save(directory / f"{lang}-{name}.png")
        for transport in ("desktop", "terminal", "files"):
            ui.request_window(dict(base, transport=transport, expires_at=int(time.time()) + 60))
            capture(transport, ui.window)
            # Keyboard safety exercises the actual built widget tree.
            ui.window.event_generate("<Return>")
            ui.window.event_generate("<space>")
            ui.window.update()
            assert not ui.sent
            assert not ui.repeat.get()
            assert ui.window.attributes("-topmost")
        ui.request_window(dict(base, transport="desktop", ticket=None, expires_at=int(time.time()) + 60))
        capture("no-assets-no-ticket", ui.window)
        ui.request_window(dict(base, transport="desktop", ticket=None, expires_at=int(time.time()) + 60,
                               technician_name="<script>alert(1)</script>\u202e" + "A" * 10000))
        capture("hostile-no-assets-no-ticket", ui.window)
        ui.notice("timeout")
        capture("timeout", ui.window)
        ui.notice("ended", dict(technician_name=base["technician_name"], duration_seconds=840))
        capture("ended", ui.window)
        ui.request_window(dict(base, transport="desktop", purpose="standing", scopes=["desktop", "terminal", "files"],
                               expires_at=int(time.time()) + 60))
        assert all(scope.get() for scope in ui.scopes.values())
        ui.scopes["files"].set(False)
        capture("standing", ui.window)
        ui.close_request()
        connection = dict(base, id=base["request_id"], transport="files", state="active")
        ui.snapshot["connections"] = [connection]
        ui.privacy()
        capture("bar-single", ui.bar)
        ui.snapshot["connections"].append(dict(connection, id=str(uuid.uuid4()), technician_auth_id=str(uuid.uuid4()), transport="terminal"))
        ui.privacy()
        capture("bar-multiple", ui.bar)
        ui.snapshot["ending"] = [connection["id"]]
        ui.privacy()
        capture("bar-disconnecting", ui.bar)
        ui.snapshot["connections"] = [dict(connection, technician_name="Long technician " + "A" * 10000)]
        ui.snapshot["ending"] = []
        ui.privacy()
        capture("bar-hostile-name", ui.bar)
        ui.tray_window()
        capture("tray-no-grant", ui.tray)
        ui.snapshot["grants"] = [dict(id=str(uuid.uuid4()), scopes=["desktop", "terminal"], expires_at=int(time.time()) + 2592000)]
        ui.tray_window()
        capture("tray-grant", ui.tray)
        for timer in ui.root.tk.call("after", "info"):
            ui.root.after_cancel(timer)
        ui.root.destroy()
