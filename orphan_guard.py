"""
OrphanGuard - Detect and clean up orphaned Windows processes.

System tray app that monitors for application processes left behind
after their parent application has been closed. Configurable profiles
map each application to its indicator process and cleanup targets.

Run on Windows with: pythonw orphan_guard.py
"""

import ctypes
import ctypes.wintypes
import json
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

import psutil
import pystray
from PIL import Image, ImageDraw


if sys.platform != "win32":
    print("OrphanGuard requires Windows.")
    sys.exit(1)

# Prevent multiple instances
_mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "OrphanGuard_Mutex")
if ctypes.windll.kernel32.GetLastError() == 183:
    ctypes.windll.user32.MessageBoxW(
        0, "OrphanGuard is already running.", "OrphanGuard", 0x40
    )
    sys.exit(0)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = SCRIPT_DIR / "config.json"

DEFAULT_CONFIG = {
    "scan_interval_seconds": 15,
    "profiles": [
        {
            "name": "Microsoft Edge",
            "enabled": False,
            "indicator": {"process": "msedge.exe", "mode": "window"},
            "targets": ["msedge.exe", "msedgewebview2.exe"],
        },
        {
            "name": "Citrix Workspace",
            "enabled": False,
            "indicator": {"process": "SelfService.exe", "mode": "process"},
            "targets": [
                "wfcrun32.exe",
                "Receiver.exe",
                "redirector.exe",
                "ssonsvr.exe",
                "concentr.exe",
                "wfica32.exe",
                "AuthManSvr.exe",
                "SelfServicePlugin.exe",
            ],
        },
        {
            "name": "Microsoft Teams",
            "enabled": False,
            "indicator": {"process": "ms-teams.exe", "mode": "window"},
            "targets": ["ms-teams.exe"],
        },
        {
            "name": "Zoom",
            "enabled": False,
            "indicator": {"process": "Zoom.exe", "mode": "window"},
            "targets": ["Zoom.exe", "ZoomWebHost.exe", "CptHost.exe"],
        },
        # --- Bloatware blocklist (mode=blocklist: always unwanted) ---
        {
            "name": "Xbox Game Bar",
            "enabled": False,
            "indicator": {"process": "", "mode": "blocklist"},
            "targets": ["GameBar.exe", "GameBarPresenceWriter.exe", "GameBarFTServer.exe"],
            "auto_kill": False,
        },
        {
            "name": "Widgets",
            "enabled": False,
            "indicator": {"process": "", "mode": "blocklist"},
            "targets": ["Widgets.exe", "WidgetService.exe"],
            "auto_kill": False,
        },
        {
            "name": "Phone Link",
            "enabled": False,
            "indicator": {"process": "", "mode": "blocklist"},
            "targets": ["PhoneExperienceHost.exe", "YourPhone.exe"],
            "auto_kill": False,
        },
        {
            "name": "Cortana",
            "enabled": False,
            "indicator": {"process": "", "mode": "blocklist"},
            "targets": ["Cortana.exe"],
            "auto_kill": False,
        },
        {
            "name": "OneDrive",
            "enabled": False,
            "indicator": {"process": "", "mode": "blocklist"},
            "targets": ["OneDrive.exe"],
            "auto_kill": False,
        },
    ],
}


def load_config():
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE) as f:
                return validate_config(json.load(f))
    except (json.JSONDecodeError, OSError):
        pass
    save_config(DEFAULT_CONFIG)
    return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


PROTECTED_PROCESSES = frozenset({
    "csrss.exe", "dwm.exe", "explorer.exe", "lsass.exe", "ntoskrnl.exe",
    "services.exe", "smss.exe", "svchost.exe", "system", "conhost.exe",
    "taskmgr.exe", "wininit.exe", "winlogon.exe", "registry",
})


def validate_config(config):
    """Validate and sanitize loaded config; discard malformed entries."""
    if not isinstance(config, dict):
        return json.loads(json.dumps(DEFAULT_CONFIG))

    interval = config.get("scan_interval_seconds", 15)
    if not isinstance(interval, (int, float)) or not (5 <= interval <= 300):
        interval = 15

    raw = config.get("profiles", [])
    if not isinstance(raw, list):
        raw = []

    profiles = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if not isinstance(name, str) or not name.strip():
            continue

        indicator = p.get("indicator", {})
        if not isinstance(indicator, dict):
            indicator = {}
        mode = indicator.get("mode", "process")
        if mode not in ("window", "process", "blocklist"):
            mode = "process"
        proc = indicator.get("process", "")
        if not isinstance(proc, str):
            proc = ""

        targets = p.get("targets", [])
        if not isinstance(targets, list):
            targets = []
        targets = [t for t in targets if isinstance(t, str) and t.strip()]

        profiles.append({
            "name": name.strip(),
            "enabled": bool(p.get("enabled", True)),
            "indicator": {"process": proc, "mode": mode},
            "targets": targets,
            "auto_kill": bool(p.get("auto_kill", False)),
        })

    return {"scan_interval_seconds": int(interval), "profiles": profiles}


# ---------------------------------------------------------------------------
# Win32 helpers
# ---------------------------------------------------------------------------

def get_pids_with_visible_windows():
    """Return PIDs that own at least one visible, titled window."""
    pids = set()

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
    def _cb(hwnd, _):
        if ctypes.windll.user32.IsWindowVisible(hwnd):
            if ctypes.windll.user32.GetWindowTextLengthW(hwnd) > 0:
                pid = ctypes.wintypes.DWORD()
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                pids.add(pid.value)
        return True

    ctypes.windll.user32.EnumWindows(_cb, 0)
    return pids


def get_file_description(exe_path):
    """Extract FileDescription from an executable's version resource."""
    try:
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(exe_path, None)
        if not size:
            return ""
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(exe_path, 0, size, buf):
            return ""
        lp_trans = ctypes.c_void_p()
        cb_trans = ctypes.c_uint()
        if not ver.VerQueryValueW(buf, r"\VarFileInfo\Translation",
                                  ctypes.byref(lp_trans), ctypes.byref(cb_trans)):
            return ""
        lang = ctypes.cast(lp_trans, ctypes.POINTER(ctypes.c_uint16))
        sub = f"\\StringFileInfo\\{lang[0]:04x}{lang[1]:04x}\\FileDescription"
        lp_desc = ctypes.c_void_p()
        cb_desc = ctypes.c_uint()
        if ver.VerQueryValueW(buf, sub, ctypes.byref(lp_desc), ctypes.byref(cb_desc)):
            if cb_desc.value > 0:
                return ctypes.wstring_at(lp_desc.value, cb_desc.value - 1)
        return ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Startup with Windows (registry)
# ---------------------------------------------------------------------------

_STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_APP_NAME = "OrphanGuard"


def get_startup_enabled():
    import winreg

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_KEY, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, _APP_NAME)
        winreg.CloseKey(key)
        return True
    except (FileNotFoundError, OSError):
        return False


def set_startup_enabled(enable):
    import winreg

    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _STARTUP_KEY, 0, winreg.KEY_SET_VALUE
        )
        if enable:
            exe = sys.executable
            if exe.endswith("python.exe"):
                exe = exe.replace("python.exe", "pythonw.exe")
            script = str(Path(__file__).resolve())
            winreg.SetValueEx(key, _APP_NAME, 0, winreg.REG_SZ, f'"{exe}" "{script}"')
        else:
            try:
                winreg.DeleteValue(key, _APP_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Icon generation
# ---------------------------------------------------------------------------

def create_icon(alert=False, size=64):
    """Draw a shield-shaped tray icon: green (clear) or red (orphans)."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    fill = (220, 60, 60) if alert else (60, 170, 80)
    m = 2
    cx = size // 2
    shield = [
        (m, m),
        (size - m, m),
        (size - m, size * 2 // 3),
        (cx, size - m),
        (m, size * 2 // 3),
    ]
    draw.polygon(shield, fill=fill, outline="white")
    return img


# ---------------------------------------------------------------------------
# Process monitor
# ---------------------------------------------------------------------------

class ProfileState(Enum):
    IDLE = auto()
    RUNNING = auto()
    ORPHANED = auto()


@dataclass
class OrphanProcess:
    pid: int
    name: str
    memory_mb: float
    create_time: float = 0.0


@dataclass
class ProfileStatus:
    state: ProfileState = ProfileState.IDLE
    orphans: list[OrphanProcess] = field(default_factory=list)
    notified: bool = False


class ProcessMonitor:
    def __init__(self, config):
        self.config = config
        self.statuses: dict[str, ProfileStatus] = {}
        self._sync_statuses()

    def _sync_statuses(self):
        active = {p["name"] for p in self.config.get("profiles", [])}
        enabled = {p["name"] for p in self.config.get("profiles", []) if p.get("enabled", True)}
        for name in active:
            self.statuses.setdefault(name, ProfileStatus())
        for stale in set(self.statuses) - active:
            del self.statuses[stale]
        for name in active - enabled:
            self.statuses[name] = ProfileStatus()

    def reload(self, config):
        self.config = config
        self._sync_statuses()

    def scan(self):
        """Scan all profiles. Returns (newly_orphaned, auto_killed).

        newly_orphaned: profile names with new detections awaiting user action.
        auto_killed: list of (name, count) for profiles that were auto-killed.
        """
        newly_orphaned = []
        auto_killed = []
        visible_pids = None
        psutil.process_iter.cache_clear()

        for profile in self.config.get("profiles", []):
            if not profile.get("enabled", True):
                continue

            name = profile["name"]
            indicator = profile.get("indicator", {})
            targets = [t.lower() for t in profile.get("targets", [])]
            mode = indicator.get("mode", "process")
            proc_name = indicator.get("process", "")

            if mode == "blocklist":
                app_running = False
            elif mode == "window":
                if visible_pids is None:
                    visible_pids = get_pids_with_visible_windows()
                app_running = self._has_windowed_process(proc_name, visible_pids)
            else:
                app_running = self._process_exists(proc_name)

            orphans = self._find_processes(targets)
            status = self.statuses.setdefault(name, ProfileStatus())

            if app_running:
                status.state = ProfileState.RUNNING
                status.orphans = []
                status.notified = False
            elif orphans:
                status.state = ProfileState.ORPHANED
                status.orphans = orphans
                if profile.get("auto_kill"):
                    k, _d = self.kill_profile(name)
                    if k:
                        auto_killed.append((name, k))
                elif not status.notified:
                    newly_orphaned.append(name)
                    status.notified = True
            else:
                status.state = ProfileState.IDLE
                status.orphans = []
                status.notified = False

        return newly_orphaned, auto_killed

    # --- helpers ----

    def _has_windowed_process(self, name, visible_pids):
        if not name:
            return False
        low = name.lower()
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if p.info["name"] and p.info["name"].lower() == low and p.info["pid"] in visible_pids:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False

    def _process_exists(self, name):
        if not name:
            return False
        low = name.lower()
        for p in psutil.process_iter(["name"]):
            try:
                if p.info["name"] and p.info["name"].lower() == low:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False

    def _find_processes(self, target_names):
        found = []
        for p in psutil.process_iter(["pid", "name", "memory_info", "create_time"]):
            try:
                pname = p.info["name"]
                if not pname or pname.lower() not in target_names:
                    continue
                if pname.lower() in PROTECTED_PROCESSES:
                    continue
                mem = p.info.get("memory_info")
                found.append(
                    OrphanProcess(
                        pid=p.info["pid"],
                        name=pname,
                        memory_mb=round(mem.rss / 1_048_576, 1) if mem else 0,
                        create_time=p.info.get("create_time") or 0.0,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return found

    # --- actions ---

    def kill_profile(self, profile_name):
        """Kill orphans for a profile. Returns (killed, denied) counts."""
        status = self.statuses.get(profile_name)
        if not status or status.state != ProfileState.ORPHANED:
            return 0, 0
        killed = 0
        denied = 0
        for orphan in list(status.orphans):
            try:
                proc = psutil.Process(orphan.pid)
                if proc.name().lower() != orphan.name.lower():
                    continue
                if orphan.create_time and abs(proc.create_time() - orphan.create_time) > 1.0:
                    continue
                proc.kill()
                killed += 1
            except psutil.AccessDenied:
                if self._taskkill(orphan.pid):
                    killed += 1
                else:
                    denied += 1
            except psutil.NoSuchProcess:
                pass
        status.orphans = []
        status.state = ProfileState.IDLE
        status.notified = False
        return killed, denied

    @staticmethod
    def _taskkill(pid):
        """Fallback kill via taskkill /F (may succeed where psutil can't)."""
        try:
            r = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, timeout=5,
            )
            return r.returncode == 0
        except Exception:
            return False

    def kill_all(self):
        """Returns (total_killed, total_denied)."""
        killed = denied = 0
        for n in list(self.statuses):
            k, d = self.kill_profile(n)
            killed += k
            denied += d
        return killed, denied

    def has_any_orphans(self):
        return any(s.state == ProfileState.ORPHANED for s in self.statuses.values())

    def total_orphan_count(self):
        return sum(len(s.orphans) for s in self.statuses.values() if s.state == ProfileState.ORPHANED)

    def orphaned_profiles(self):
        return [(n, s) for n, s in self.statuses.items() if s.state == ProfileState.ORPHANED]


# ---------------------------------------------------------------------------
# Settings UI (tkinter)
# ---------------------------------------------------------------------------

class ProcessBrowser:
    """Dialog to browse running processes and select targets."""

    def __init__(self, parent):
        self.selected = []
        self.all_procs = self._snapshot()

        dlg = tk.Toplevel(parent)
        dlg.title("Browse Running Processes")
        dlg.geometry("720x460")
        dlg.resizable(True, True)
        dlg.transient(parent)
        dlg.grab_set()

        f = ttk.Frame(dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)

        ff = ttk.Frame(f)
        ff.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(ff, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._populate())
        filter_entry = ttk.Entry(ff, textvariable=self.filter_var)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        self.count_label = ttk.Label(ff, text="")
        self.count_label.pack(side=tk.RIGHT)

        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("name", "desc", "count", "memory", "path")
        self.tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings",
            selectmode="extended", height=15,
        )
        self.tree.heading("name", text="Process", command=lambda: self._sort("name"))
        self.tree.heading("desc", text="Description", command=lambda: self._sort("desc"))
        self.tree.heading("count", text="#", command=lambda: self._sort("count"))
        self.tree.heading("memory", text="MB", command=lambda: self._sort("memory"))
        self.tree.heading("path", text="Path", command=lambda: self._sort("path"))
        self.tree.column("name", width=140)
        self.tree.column("desc", width=180)
        self.tree.column("count", width=30)
        self.tree.column("memory", width=55)
        self.tree.column("path", width=200)

        sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(bf, text="Add Selected", command=lambda: self._add(dlg)).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text="Refresh", command=self._refresh).pack(side=tk.LEFT, padx=2)

        self._sort_key = "name"
        self._sort_reverse = False
        self._populate()
        filter_entry.focus_set()
        dlg.wait_window()

    def _snapshot(self):
        psutil.process_iter.cache_clear()
        procs = {}
        for p in psutil.process_iter(["name", "memory_info", "exe"]):
            try:
                name = p.info["name"]
                if not name or name.lower() in PROTECTED_PROCESSES:
                    continue
                if name not in procs:
                    procs[name] = {"count": 0, "memory": 0, "path": "", "desc": ""}
                procs[name]["count"] += 1
                mem = p.info.get("memory_info")
                if mem:
                    procs[name]["memory"] += mem.rss
                if not procs[name]["path"]:
                    exe = p.info.get("exe")
                    if exe:
                        procs[name]["path"] = exe
                        procs[name]["desc"] = get_file_description(exe)
            except Exception:
                pass
        return procs

    def _populate(self):
        self.tree.delete(*self.tree.get_children())
        filt = self.filter_var.get().lower()
        items = []
        for name, info in self.all_procs.items():
            searchable = f"{name} {info['desc']} {info['path']}".lower()
            if filt and filt not in searchable:
                continue
            mem_mb = round(info["memory"] / 1_048_576, 1)
            items.append((name, info["desc"], info["count"], mem_mb, info["path"]))

        key_idx = {"name": 0, "desc": 1, "count": 2, "memory": 3, "path": 4}[self._sort_key]
        items.sort(key=lambda r: r[key_idx], reverse=self._sort_reverse)

        for row in items:
            self.tree.insert("", tk.END, iid=row[0], values=row)
        self.count_label.configure(text=f"{len(items)} of {len(self.all_procs)}")

    def _sort(self, col):
        if self._sort_key == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = col
            self._sort_reverse = False
        self._populate()

    def _refresh(self):
        self.all_procs = self._snapshot()
        self._populate()

    def _add(self, dlg):
        self.selected = list(self.tree.selection())
        dlg.destroy()


class ProfileDialog:
    """Modal dialog to add or edit a single profile."""

    def __init__(self, parent, profile):
        self.result = None
        self.dlg = dlg = tk.Toplevel(parent)
        dlg.title("Edit Profile" if profile.get("name") else "New Profile")
        dlg.geometry("460x480")
        dlg.resizable(False, False)
        dlg.transient(parent)
        dlg.grab_set()

        f = ttk.Frame(dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text="Profile Name:").pack(anchor=tk.W)
        self.name_var = tk.StringVar(value=profile.get("name", ""))
        ttk.Entry(f, textvariable=self.name_var).pack(fill=tk.X, pady=(0, 8))

        chk_frame = ttk.Frame(f)
        chk_frame.pack(fill=tk.X, pady=(0, 8))
        self.enabled_var = tk.BooleanVar(value=profile.get("enabled", True))
        ttk.Checkbutton(chk_frame, text="Enabled", variable=self.enabled_var).pack(side=tk.LEFT)
        self.auto_kill_var = tk.BooleanVar(value=profile.get("auto_kill", False))
        ttk.Checkbutton(chk_frame, text="Auto-kill on detection", variable=self.auto_kill_var).pack(side=tk.LEFT, padx=(20, 0))

        indicator = profile.get("indicator", {})
        self.mode_var = tk.StringVar(value=indicator.get("mode", "process"))

        mode_frame = ttk.LabelFrame(f, text="Detection mode", padding=5)
        mode_frame.pack(fill=tk.X, pady=(0, 8))
        for text, val in [("Window (app has a visible window)", "window"),
                          ("Process (indicator process is running)", "process"),
                          ("Blocklist (always unwanted / bloatware)", "blocklist")]:
            ttk.Radiobutton(mode_frame, text=text, variable=self.mode_var, value=val,
                            command=self._on_mode_change).pack(anchor=tk.W)

        self.ind_frame = ttk.LabelFrame(f, text="Indicator (main app process)", padding=5)
        self.ind_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(self.ind_frame, text="Process name:").pack(anchor=tk.W)
        self.ind_proc = tk.StringVar(value=indicator.get("process", ""))
        ttk.Entry(self.ind_frame, textvariable=self.ind_proc).pack(fill=tk.X)

        th = ttk.Frame(f)
        th.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(th, text="Processes to clean up (one per line):").pack(side=tk.LEFT)
        ttk.Button(th, text="Browse…", command=self._browse_processes).pack(side=tk.RIGHT)
        self.targets_text = tk.Text(f, height=5, width=40)
        self.targets_text.pack(fill=tk.BOTH, expand=True)
        self.targets_text.insert("1.0", "\n".join(profile.get("targets", [])))

        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(bf, text="OK", command=lambda: self._ok(dlg)).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT, padx=2)

        self._on_mode_change()
        dlg.wait_window()

    def _on_mode_change(self):
        if self.mode_var.get() == "blocklist":
            for child in self.ind_frame.winfo_children():
                child.configure(state="disabled")
        else:
            for child in self.ind_frame.winfo_children():
                child.configure(state="normal")

    def _browse_processes(self):
        browser = ProcessBrowser(self.dlg)
        if not browser.selected:
            return
        existing = self.targets_text.get("1.0", tk.END).strip()
        already = {t.strip().lower() for t in existing.splitlines() if t.strip()}
        new = [name for name in browser.selected if name.lower() not in already]
        if new:
            if existing:
                self.targets_text.insert(tk.END, "\n")
            self.targets_text.insert(tk.END, "\n".join(new))

    def _ok(self, dlg):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Validation", "Profile name is required.", parent=dlg)
            return
        raw = self.targets_text.get("1.0", tk.END).strip()
        targets = [t.strip() for t in raw.splitlines() if t.strip()]
        blocked = [t for t in targets if t.lower() in PROTECTED_PROCESSES]
        if blocked:
            messagebox.showwarning(
                "Validation",
                f"Protected system processes cannot be targeted:\n{', '.join(blocked)}",
                parent=dlg,
            )
            return
        mode = self.mode_var.get()
        self.result = {
            "name": name,
            "enabled": self.enabled_var.get(),
            "indicator": {
                "process": "" if mode == "blocklist" else self.ind_proc.get().strip(),
                "mode": mode,
            },
            "targets": targets,
            "auto_kill": self.auto_kill_var.get(),
        }
        dlg.destroy()


class SettingsWindow:
    """Main settings window for managing profiles."""

    def __init__(self, config, on_save):
        self.config = json.loads(json.dumps(config))
        self.on_save = on_save

        self.root = tk.Tk()
        self.root.title("OrphanGuard Settings")
        self.root.geometry("620x480")
        self.root.resizable(False, False)
        self._build()
        self.root.mainloop()

    def _build(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        gf = ttk.LabelFrame(main, text="General", padding=5)
        gf.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(gf, text="Scan interval (seconds):").pack(side=tk.LEFT, padx=5)
        self.interval = tk.IntVar(value=self.config.get("scan_interval_seconds", 15))
        ttk.Spinbox(gf, from_=5, to=300, textvariable=self.interval, width=6).pack(side=tk.LEFT)

        pf = ttk.LabelFrame(main, text="Application Profiles", padding=5)
        pf.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        cols = ("name", "mode", "indicator", "targets", "auto", "on")
        self.tree = ttk.Treeview(pf, columns=cols, show="headings", height=10)
        for col, hdr, w in [("name", "Name", 130), ("mode", "Mode", 70),
                             ("indicator", "Indicator", 110), ("targets", "Targets", 140),
                             ("auto", "Auto-Kill", 60), ("on", "On", 35)]:
            self.tree.heading(col, text=hdr)
            self.tree.column(col, width=w)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", lambda _: self._edit())
        self._refresh()

        bf = ttk.Frame(pf)
        bf.pack(fill=tk.X, pady=(5, 0))
        for text, cmd in [("Add", self._add), ("Edit", self._edit), ("Remove", self._remove)]:
            ttk.Button(bf, text=text, command=cmd).pack(side=tk.LEFT, padx=2)

        bot = ttk.Frame(main)
        bot.pack(fill=tk.X)
        ttk.Button(bot, text="Save", command=self._save).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bot, text="Close", command=self.root.destroy).pack(side=tk.RIGHT, padx=2)

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        for p in self.config.get("profiles", []):
            ind = p.get("indicator", {})
            mode = ind.get("mode", "process")
            self.tree.insert("", tk.END, values=(
                p.get("name", ""),
                mode,
                ind.get("process", "") if mode != "blocklist" else "",
                ", ".join(p.get("targets", [])[:4]),
                "Yes" if p.get("auto_kill") else "",
                "Yes" if p.get("enabled", True) else "",
            ))

    def _sel(self):
        s = self.tree.selection()
        return self.tree.index(s[0]) if s else None

    def _add(self):
        r = ProfileDialog(self.root, {"name": "", "enabled": True, "indicator": {"process": "", "mode": "process"}, "targets": []}).result
        if r:
            self.config.setdefault("profiles", []).append(r)
            self._refresh()

    def _edit(self):
        i = self._sel()
        if i is None:
            return
        r = ProfileDialog(self.root, self.config["profiles"][i]).result
        if r:
            self.config["profiles"][i] = r
            self._refresh()

    def _remove(self):
        i = self._sel()
        if i is None:
            return
        name = self.config["profiles"][i]["name"]
        if messagebox.askyesno("Remove", f'Remove "{name}"?', parent=self.root):
            del self.config["profiles"][i]
            self._refresh()

    def _save(self):
        self.config["scan_interval_seconds"] = self.interval.get()
        save_config(self.config)
        if self.on_save:
            self.on_save(self.config)


# ---------------------------------------------------------------------------
# Status / details window
# ---------------------------------------------------------------------------

class StatusWindow:
    def __init__(self, monitor: ProcessMonitor):
        self.monitor = monitor
        self.root = tk.Tk()
        self.root.title("OrphanGuard Status")
        self.root.geometry("540x340")
        self.root.resizable(True, True)
        self._build()
        self.root.mainloop()

    def _build(self):
        f = ttk.Frame(self.root, padding=10)
        f.pack(fill=tk.BOTH, expand=True)

        orphaned = self.monitor.orphaned_profiles()
        if not orphaned:
            ttk.Label(f, text="No orphaned processes detected.", font=("Segoe UI", 12)).pack(pady=20)
            return

        total = self.monitor.total_orphan_count()
        ttk.Label(f, text=f"{total} orphaned process(es)", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0, 8))

        cols = ("profile", "process", "pid", "memory")
        tree = ttk.Treeview(f, columns=cols, show="headings", height=10)
        for col, hdr, w in [("profile", "Application", 140), ("process", "Process", 150), ("pid", "PID", 70), ("memory", "Memory (MB)", 90)]:
            tree.heading(col, text=hdr)
            tree.column(col, width=w)

        for name, status in orphaned:
            for o in status.orphans:
                tree.insert("", tk.END, values=(name, o.name, o.pid, o.memory_mb))

        sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        bf = ttk.Frame(self.root, padding=10)
        bf.pack(fill=tk.X)
        ttk.Button(bf, text="Kill All", command=self._kill_and_close).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text="Close", command=self.root.destroy).pack(side=tk.RIGHT, padx=2)

    def _kill_and_close(self):
        killed, denied = self.monitor.kill_all()
        if denied:
            messagebox.showwarning(
                "Access Denied",
                f"Killed {killed} process(es), but {denied} require admin privileges.\n"
                "Run OrphanGuard as Administrator to kill protected processes.",
                parent=self.root,
            )
        self.root.destroy()


# ---------------------------------------------------------------------------
# Main application (tray icon + monitoring)
# ---------------------------------------------------------------------------

class OrphanGuard:
    def __init__(self):
        self.config = load_config()
        self.monitor = ProcessMonitor(self.config)
        self.stop_event = threading.Event()
        self.icon = None

    def _status_text(self):
        n = self.monitor.total_orphan_count()
        return f"OrphanGuard — {n} orphan(s) detected" if n else "OrphanGuard — All clear"

    def _profile_label(self, name):
        s = self.monitor.statuses.get(name)
        if s and s.orphans:
            return f"⚠ Kill: {name} ({len(s.orphans)})"
        return name

    def _profile_has_orphans(self, name):
        s = self.monitor.statuses.get(name)
        return s is not None and s.state == ProfileState.ORPHANED

    def _build_menu(self):
        items = [
            pystray.MenuItem(lambda _: self._status_text(), None, enabled=False),
            pystray.Menu.SEPARATOR,
        ]

        for profile in self.config.get("profiles", []):
            if not profile.get("enabled", True):
                continue
            n = profile["name"]
            items.append(pystray.MenuItem(
                lambda _, n=n: self._profile_label(n),
                (lambda name: lambda icon, item: self._do_kill_profile(name))(n),
                visible=lambda _, n=n: self._profile_has_orphans(n),
            ))

        items.append(pystray.MenuItem(
            lambda _: f"Kill All ({self.monitor.total_orphan_count()})",
            self._do_kill_all,
            visible=lambda _: self.monitor.has_any_orphans(),
        ))

        items += [
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("View Details…", self._do_details, default=True),
            pystray.MenuItem("Scan Now", self._do_scan),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Settings…", self._do_settings),
            pystray.MenuItem("Start with Windows", self._do_toggle_startup, checked=lambda _: get_startup_enabled()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._do_exit),
        ]
        return pystray.Menu(*items)

    # --- menu actions ---

    def _do_kill_profile(self, name):
        killed, denied = self.monitor.kill_profile(name)
        self._refresh_icon()
        if self.icon:
            self.icon.notify(self._kill_summary(killed, denied, name), "OrphanGuard")

    def _do_kill_all(self, icon=None, item=None):
        killed, denied = self.monitor.kill_all()
        self._refresh_icon()
        if self.icon:
            self.icon.notify(self._kill_summary(killed, denied), "OrphanGuard")

    @staticmethod
    def _kill_summary(killed, denied, profile=None):
        parts = []
        label = f" for {profile}" if profile else ""
        if killed:
            parts.append(f"Killed {killed} process(es){label}.")
        if denied:
            parts.append(f"{denied} process(es) require admin privileges — run as Administrator.")
        if not parts:
            parts.append(f"No processes to kill{label}.")
        return "\n".join(parts)

    def _do_scan(self, icon=None, item=None):
        newly, auto_killed = self.monitor.scan()
        self._refresh_icon()
        if newly:
            self._notify_new(newly)
        if auto_killed:
            self._notify_auto_killed(auto_killed)
        if not newly and not auto_killed and not self.monitor.has_any_orphans():
            if self.icon:
                self.icon.notify("Scan complete — no orphans found.", "OrphanGuard")

    def _do_details(self, icon=None, item=None):
        threading.Thread(target=lambda: StatusWindow(self.monitor), daemon=True).start()

    def _do_settings(self, icon=None, item=None):
        threading.Thread(target=lambda: SettingsWindow(self.config, self._on_config_saved), daemon=True).start()

    def _on_config_saved(self, new_config):
        self.config = new_config
        self.monitor.reload(new_config)
        if self.icon:
            self.icon.menu = self._build_menu()
            self.icon.update_menu()

    def _do_toggle_startup(self, icon=None, item=None):
        set_startup_enabled(not get_startup_enabled())

    def _do_exit(self, icon=None, item=None):
        self.stop_event.set()
        if self.icon:
            self.icon.stop()

    # --- icon & notifications ---

    def _refresh_icon(self):
        if not self.icon:
            return
        self.icon.icon = create_icon(alert=self.monitor.has_any_orphans())
        self.icon.title = self._status_text()
        self.icon.update_menu()

    def _notify_new(self, profile_names):
        if not self.icon:
            return
        n = self.monitor.total_orphan_count()
        names = ", ".join(profile_names)
        self.icon.notify(
            f"{n} orphaned process(es) from: {names}\nRight-click to clean up.",
            "OrphanGuard",
        )

    def _notify_auto_killed(self, auto_killed):
        if not self.icon:
            return
        total = sum(c for _, c in auto_killed)
        names = ", ".join(n for n, _ in auto_killed)
        self.icon.notify(
            f"Auto-killed {total} process(es): {names}",
            "OrphanGuard",
        )

    # --- main loop ---

    def _monitor_loop(self):
        while not self.stop_event.is_set():
            try:
                newly, auto_killed = self.monitor.scan()
                if newly:
                    self._notify_new(newly)
                if auto_killed:
                    self._notify_auto_killed(auto_killed)
                self._refresh_icon()
                self.stop_event.wait(self.config.get("scan_interval_seconds", 15))
            except Exception:
                self.stop_event.wait(15)

    def run(self):
        self.icon = pystray.Icon(
            "OrphanGuard",
            create_icon(alert=False),
            "OrphanGuard",
            menu=self._build_menu(),
        )
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        self.icon.run()


if __name__ == "__main__":
    OrphanGuard().run()
