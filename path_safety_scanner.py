#!/usr/bin/env python3
"""
macOS Path Safety Scanner
Scans a selected folder and flags files/directories whose names, paths,
permissions, symlinks, or encoding characteristics may cause problems
with copying, archives, NAS/SMB, Windows, scripts, or web uploads.

Python 3.10+
No third-party packages required.
"""

import csv
import os
import subprocess
import sys
import stat
import unicodedata
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
import threading

APP_TITLE = "Path Safety Scanner"

# Conservative interoperability limits, not macOS hard limits.
WARN_COMPONENT_BYTES = 240
WARN_PATH_BYTES = 900

# Characters that often cause trouble across Windows, shells, URLs,
# archive tools, SMB/NAS software, or manual scripting.
WINDOWS_FORBIDDEN = set('<>:"/\\|?*')
SHELL_META = set('\'"`$&;|<>*?()[]{}!#~')
INVISIBLE_CODEPOINTS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE/BOM",
    "\u00a0": "NO-BREAK SPACE",
}

WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

def filesystem_bytes(s: str) -> bytes:
    return os.fsencode(s)

def has_surrogateescape(s: str) -> bool:
    # Invalid filesystem bytes decoded by Python often land in U+DC80..U+DCFF.
    return any(0xDC80 <= ord(ch) <= 0xDCFF for ch in s)

def control_chars(s: str):
    found = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat.startswith("C") and ch not in ("\t",):
            found.append(f"U+{ord(ch):04X} {unicodedata.name(ch, cat)}")
    return found

def invisible_chars(s: str):
    return [name for ch, name in INVISIBLE_CODEPOINTS.items() if ch in s]

def windows_reserved_name(name: str) -> bool:
    # Windows checks basename before first dot.
    stem = name.split(".", 1)[0].rstrip(" .").upper()
    return stem in WINDOWS_RESERVED

def analyze_component(name: str):
    issues = []

    if not name:
        return issues

    if has_surrogateescape(name):
        issues.append(("CRITICAL", "Invalid/non-UTF-8 filename bytes"))

    try:
        name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        issues.append(("CRITICAL", "Filename cannot be encoded as strict UTF-8"))

    ctrl = control_chars(name)
    if ctrl:
        issues.append(("CRITICAL", "Control/special Unicode character: " + ", ".join(ctrl[:3])))

    inv = invisible_chars(name)
    if inv:
        issues.append(("WARNING", "Invisible/special spacing character: " + ", ".join(inv)))

    # macOS commonly stores decomposed Unicode (NFD). This is valid, but can
    # collide or display differently on Linux/Windows/NAS systems.
    nfc = unicodedata.normalize("NFC", name)
    nfd = unicodedata.normalize("NFD", name)
    if name != nfc:
        issues.append(("INFO", "Filename is not NFC-normalized (macOS Unicode normalization risk)"))
    if nfc != nfd and name == nfd:
        issues.append(("INFO", "Decomposed Unicode filename (common on macOS; interoperability risk)"))

    if name.endswith((" ", ".")):
        issues.append(("CRITICAL", "Filename ends with space or dot (unsafe on Windows/SMB)"))

    if name.startswith(" ") or name.endswith(" "):
        issues.append(("WARNING", "Leading/trailing space in filename"))

    if windows_reserved_name(name):
        issues.append(("CRITICAL", "Windows reserved filename"))

    win_bad = sorted(set(name) & WINDOWS_FORBIDDEN)
    # "/" cannot occur within a POSIX component, but retained for completeness.
    if win_bad:
        issues.append(("WARNING", "Windows/SMB-problematic character(s): " + " ".join(win_bad)))

    shell_bad = sorted(set(name) & SHELL_META)
    if shell_bad:
        issues.append(("INFO", "Shell/script-sensitive character(s): " + " ".join(shell_bad)))

    if "\n" in name or "\r" in name:
        issues.append(("CRITICAL", "Filename contains newline/carriage return"))

    b_len = len(filesystem_bytes(name))
    if b_len > WARN_COMPONENT_BYTES:
        issues.append(("WARNING", f"Very long filename component: {b_len} bytes"))

    return issues

def analyze_path(path: Path, root: Path):
    results = []
    s = str(path)
    rel = str(path.relative_to(root)) if path != root else "."

    # Every component can be problematic.
    for part in path.parts:
        for severity, reason in analyze_component(part):
            results.append((severity, reason))

    path_bytes = len(filesystem_bytes(s))
    if path_bytes > WARN_PATH_BYTES:
        results.append(("WARNING", f"Very long full path: {path_bytes} bytes"))

    try:
        st = path.lstat()
    except (OSError, UnicodeError) as e:
        results.append(("CRITICAL", f"Cannot stat path: {type(e).__name__}: {e}"))
        return rel, "unknown", results

    if stat.S_ISLNK(st.st_mode):
        typ = "symlink"
        try:
            target = path.resolve(strict=True)
        except Exception as e:
            results.append(("CRITICAL", f"Broken/unresolvable symlink: {e}"))
    elif stat.S_ISDIR(st.st_mode):
        typ = "directory"
        if not os.access(path, os.R_OK | os.X_OK):
            results.append(("CRITICAL", "Directory is not readable/searchable"))
    elif stat.S_ISREG(st.st_mode):
        typ = "file"
        if not os.access(path, os.R_OK):
            results.append(("CRITICAL", "File is not readable"))

        # Confirm opening actually works. Read only one byte.
        try:
            with open(path, "rb") as f:
                f.read(1)
        except PermissionError as e:
            results.append(("CRITICAL", f"Permission denied while opening file: {e}"))
        except OSError as e:
            results.append(("CRITICAL", f"Cannot open/read file: {type(e).__name__}: {e}"))
    else:
        typ = "special"
        results.append(("WARNING", "Special filesystem object (not normal file/directory/symlink)"))

    return rel, typ, results

def severity_rank(s):
    return {"CRITICAL": 0, "WARNING": 1, "INFO": 2}.get(s, 9)

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x720")
        self.minsize(900, 560)

        self.root_path = tk.StringVar()
        self.status = tk.StringVar(value="Choose a folder to scan.")
        self.include_info = tk.BooleanVar(value=True)
        self.only_problematic = tk.BooleanVar(value=True)
        self.follow_hidden = tk.BooleanVar(value=True)

        self._stop = threading.Event()
        self._queue = Queue()
        self._rows = []

        self._build_ui()
        self.after(100, self._poll_queue)

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Folder:").pack(side="left")
        ttk.Entry(top, textvariable=self.root_path).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(top, text="Choose…", command=self.choose_folder).pack(side="left")
        self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(8, 0))
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(6, 0))

        opts = ttk.Frame(self, padding=(10, 0, 10, 8))
        opts.pack(fill="x")
        ttk.Checkbutton(opts, text="Show INFO-level interoperability warnings",
                        variable=self.include_info, command=self.refresh_view).pack(side="left")
        ttk.Checkbutton(opts, text="Only show paths with issues",
                        variable=self.only_problematic, command=self.refresh_view).pack(side="left", padx=15)

        summary = ttk.Frame(self, padding=(10, 0, 10, 8))
        summary.pack(fill="x")
        self.count_label = ttk.Label(summary, text="0 flagged paths")
        self.count_label.pack(side="left")
        ttk.Button(summary, text="Export CSV…", command=self.export_csv).pack(side="right")
        ttk.Button(summary, text="Copy selected path", command=self.copy_selected_path).pack(side="right", padx=6)
        ttk.Button(summary, text="Reveal in Finder", command=self.reveal_selected).pack(side="right")

        columns = ("severity", "type", "path", "reason")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("type", text="Type")
        self.tree.heading("path", text="Relative path")
        self.tree.heading("reason", text="Reason")
        self.tree.column("severity", width=90, stretch=False)
        self.tree.column("type", width=85, stretch=False)
        self.tree.column("path", width=500, minwidth=220)
        self.tree.column("reason", width=450, minwidth=220)

        y = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        x = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)

        self.tree.pack(fill="both", expand=True, padx=(10, 0), pady=(0, 0))
        y.place(relx=1.0, rely=0.17, relheight=0.73, anchor="ne")
        x.pack(fill="x", padx=10)

        statusbar = ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w", padding=(8, 4))
        statusbar.pack(fill="x", side="bottom")

        self.tree.bind("<Double-1>", lambda e: self.reveal_selected())

    def choose_folder(self):
        folder = filedialog.askdirectory(title="Choose folder to scan")
        if folder:
            self.root_path.set(folder)

    def start_scan(self):
        folder = self.root_path.get().strip()
        if not folder:
            self.choose_folder()
            folder = self.root_path.get().strip()
        if not folder:
            return

        root = Path(folder)
        if not root.exists() or not root.is_dir():
            messagebox.showerror(APP_TITLE, "Please choose an existing folder.")
            return

        self._rows.clear()
        self._stop.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status.set("Scanning…")
        self.count_label.config(text="0 flagged paths")

        threading.Thread(target=self._scan_worker, args=(root,), daemon=True).start()

    def stop_scan(self):
        self._stop.set()
        self.status.set("Stopping after current files…")

    def _scan_worker(self, root):
        paths = []
        errors = []

        def onerror(e):
            errors.append(e)
            self._queue.put(("walk_error", str(e)))

        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
                if self._stop.is_set():
                    break
                d = Path(dirpath)
                paths.append(d)
                for name in filenames:
                    paths.append(d / name)
                # os.walk will include symlink dirs in dirnames but not recurse if followlinks=False.
                for name in dirnames:
                    p = d / name
                    if p.is_symlink():
                        paths.append(p)
        except Exception as e:
            self._queue.put(("fatal", f"Could not enumerate folder: {e}"))
            return

        total = len(paths)
        self._queue.put(("total", total))

        # Filesystem access is mostly I/O bound; modest concurrency keeps UI responsive.
        max_workers = min(8, (os.cpu_count() or 4) + 2)
        completed = 0

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(analyze_path, p, root): p for p in paths}
            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                completed += 1
                try:
                    rel, typ, issues = fut.result()
                except Exception as e:
                    rel = str(futures[fut])
                    typ = "unknown"
                    issues = [("CRITICAL", f"Scanner error: {e}")]

                if issues:
                    for sev, reason in issues:
                        self._queue.put(("row", (sev, typ, rel, reason)))
                self._queue.put(("progress", (completed, total)))

        self._queue.put(("done", completed))

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "row":
                    self._rows.append(payload)
                elif kind == "progress":
                    done, total = payload
                    self.status.set(f"Scanning… {done:,} / {total:,}")
                elif kind == "walk_error":
                    # Enumeration errors are relevant enough to show.
                    self._rows.append(("CRITICAL", "directory", "(enumeration)", payload))
                elif kind == "fatal":
                    messagebox.showerror(APP_TITLE, payload)
                    self.scan_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                elif kind == "done":
                    self.scan_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    if self._stop.is_set():
                        self.status.set(f"Stopped. Inspected {payload:,} paths.")
                    else:
                        self.status.set(f"Finished. Inspected {payload:,} paths.")
                    self.refresh_view()
        except Empty:
            pass

        # Refresh incrementally if rows accumulated.
        if len(self._rows) and not self.scan_btn["state"] == "normal":
            self.refresh_view()
        self.after(150, self._poll_queue)

    def refresh_view(self):
        selected_values = None
        selected = self.tree.selection()
        if selected:
            selected_values = tuple(self.tree.item(selected[0], "values"))

        existing = self.tree.get_children()
        if existing:
            self.tree.delete(*existing)

        rows = sorted(self._rows, key=lambda r: (severity_rank(r[0]), r[2].lower(), r[3].lower()))

        shown_paths = set()
        selected_item = None
        for sev, typ, rel, reason in rows:
            if sev == "INFO" and not self.include_info.get():
                continue
            item = self.tree.insert("", "end", values=(sev, typ, rel, reason))
            if selected_values == (sev, typ, rel, reason):
                selected_item = item
            shown_paths.add(rel)

        if selected_item is not None:
            self.tree.selection_set(selected_item)
            self.tree.focus(selected_item)

        crit = len({r[2] for r in rows if r[0] == "CRITICAL"})
        warn = len({r[2] for r in rows if r[0] == "WARNING"})
        info = len({r[2] for r in rows if r[0] == "INFO"})
        self.count_label.config(
            text=f"{len(shown_paths):,} flagged paths — critical {crit:,}, warning {warn:,}, info {info:,}"
        )

    def selected_abs_path(self):
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0], "values")
        rel = vals[2]
        if rel == "(enumeration)":
            return None
        return Path(self.root_path.get()) / rel

    def reveal_selected(self):
        p = self.selected_abs_path()
        if not p:
            return
        # Ask Finder to reveal and select the exact item.
        finder_path = str(p).replace("\\", "\\\\").replace('"', '\\"')
        subprocess.run(
            [
                "/usr/bin/osascript",
                "-e", f'tell application "Finder" to reveal POSIX file "{finder_path}"',
                "-e", 'tell application "Finder" to activate',
            ],
            check=False,
        )

    def copy_selected_path(self):
        p = self.selected_abs_path()
        if not p:
            return
        self.clipboard_clear()
        self.clipboard_append(str(p))
        self.status.set("Path copied to clipboard.")

    def export_csv(self):
        if not self._rows:
            messagebox.showinfo(APP_TITLE, "Nothing to export yet.")
            return
        dest = filedialog.asksaveasfilename(
            title="Export scan results",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            initialfile="path-safety-scan.csv",
        )
        if not dest:
            return

        with open(dest, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["severity", "type", "relative_path", "reason", "absolute_path"])
            root = Path(self.root_path.get())
            for row in sorted(self._rows, key=lambda r: (severity_rank(r[0]), r[2].lower())):
                sev, typ, rel, reason = row
                w.writerow([sev, typ, rel, reason, str(root / rel) if rel != "(enumeration)" else ""])
        self.status.set(f"Exported: {dest}")

if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()
