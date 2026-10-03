#!/usr/bin/env python3
"""Storage device watcher: shows storage devices as they connect/disconnect and
drives udev (triggers, rule management, permissions, properties)."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import logging.handlers
import os
import queue
import shutil
import subprocess
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import hook
import libvirt_vm as lv
import udev_control as ctl
import udev_monitor as ud

LOG_PATH = os.environ.get("UDEV_GUI_LOG", "/tmp/opencode/udev_gui.log")


def setup_logging(path: str = LOG_PATH) -> logging.Logger:
    """Everything the dialogs show also goes to a file, so it can be inspected."""
    logger = logging.getLogger("storage-watcher")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
    except OSError as exc:  # never let logging take the app down
        print(f"cannot open log file {path}: {exc}")
        return logger
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(threadName)-14s %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    logger.info("=== storage watcher starting (pid %d) ===", os.getpid())
    return logger


log = setup_logging()


def log_files() -> list:
    """Every log file the app is writing to, newest content last."""
    return [h.baseFilename for h in log.handlers if getattr(h, "baseFilename", None)]


def tail_file(path: str, limit: int = 8000) -> str:
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read()[-limit:]
    except OSError as exc:
        return f"(cannot read {path}: {exc})"


class StorageWatcherApp:
    COLUMNS = ("time", "action", "device", "type", "size", "filesystem", "vendor", "model", "serial", "detail")

    def __init__(self, root_dir: str = "/", preference: str = "auto", interval: float = 1.0,
                 profile: str = "storage", include_partitions: bool = False):
        self.subsystems = ud.subsystems_for(profile)
        self.profile = profile
        self.include_partitions = include_partitions
        self.monitor = ud.create_monitor(
            preference, root=root_dir, subsystems=self.subsystems, interval=interval,
            include_partitions=include_partitions,
        )
        self.control = ctl.UdevControl()
        self.vms = lv.LibvirtVms(self.control)
        self.root_dir = root_dir
        self.interval = interval
        self._falling_back = False
        self.rows: dict[str, ud.DeviceEvent] = {}
        self.order: list[str] = []
        self.paused = False
        self.pending: queue.Queue = queue.Queue()
        self.ui_queue: queue.Queue = queue.Queue()
        self.added = self.removed = 0
        self.filter_vars: dict[str, tk.BooleanVar] = {}

        self.root = tk.Tk()
        self.root.title("storage watcher")
        self.root.geometry("1220x700")
        self.root.minsize(860, 460)
        self.show_existing = tk.BooleanVar(master=self.root, value=False)
        self.removable_only = tk.BooleanVar(master=self.root, value=False)
        self.status = tk.StringVar(master=self.root, value="starting")
        self.tally = tk.StringVar(master=self.root, value="")
        self.backend_text = tk.StringVar(master=self.root, value=self.monitor.backend)
        self.selected_text = tk.StringVar(master=self.root, value="no device selected")
        self.priv_text = tk.StringVar(master=self.root, value=f"privileges: {self.control.elevation}")
        self.mode_var = tk.StringVar(master=self.root, value="0660")
        self.group_var = tk.StringVar(master=self.root, value="plugdev")
        self.prop_key = tk.StringVar(master=self.root, value="MY_STORAGE_FLAG")
        self.prop_val = tk.StringVar(master=self.root, value="1")
        self.rule_name = tk.StringVar(master=self.root, value="99-storage-watcher.rules")
        self.hook_enabled = tk.BooleanVar(master=self.root, value=False)
        self.hook_command = tk.StringVar(
            master=self.root,
            value="TINY_WINDOW=1 " + os.path.join(os.path.dirname(os.path.abspath(__file__)), "boot-tiny-linux.sh"),
        )
        self.hook_delay = tk.StringVar(master=self.root, value="3")
        self.hook_status = tk.StringVar(master=self.root, value="hook disabled")
        self.hook_confirm = tk.BooleanVar(master=self.root, value=True)
        self.hook_notify = tk.BooleanVar(master=self.root, value=True)
        self.noauto_unmount = tk.BooleanVar(master=self.root, value=True)
        self.noauto_rule = tk.StringVar(master=self.root, value="98-no-host-automount.rules")
        self.vm_backend = tk.StringVar(master=self.root, value="libvirt")
        self.vm_memory = tk.StringVar(master=self.root, value="256")
        self.vm_writable = tk.BooleanVar(master=self.root, value=False)
        self.vm_list_text = tk.StringVar(master=self.root, value="(no libvirt domains yet)")

        self._build_style()
        self._build_events_tab()
        self._build_control_tab()
        self._build_hook_tab()
        self._build_vm_tab()
        self._bind_keys()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._seed_existing()
        log.info("backend=%s%s", self.monitor.backend,
                 f" ({self.monitor.note})" if self.monitor.note else "")
        log.info("profile=%s subsystems=%s partitions=%s uid=%d elevation=%s",
                 self.profile, ",".join(self.subsystems), self.include_partitions,
                 os.geteuid(), self.control.elevation)
        if self.monitor.note:
            self.status.set(f"{self.monitor.backend} fallback - unavailable: {self.monitor.note}")
        threading.Thread(target=self._watch, name="gui-queue", daemon=True).start()
        self.root.after(120, self._pump)

    def _build_style(self) -> None:
        style = ttk.Style()
        for theme in ("clam", "alt", "default"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Treeview", rowheight=24)
        style.configure("Toolbar.TFrame", background="#e8e8e8")
        style.configure("Hint.TLabel", foreground="#555555")
        style.configure("Mono.TLabel", font=("TkFixedFont",))

    def _build_events_tab(self) -> None:
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(side="top", fill="both", expand=True, padx=8, pady=8)
        events = ttk.Frame(self.tabs)
        self.tabs.add(events, text="Storage events")

        toolbar = ttk.Frame(events, style="Toolbar.TFrame", padding=(8, 6))
        toolbar.pack(side="top", fill="x")
        self.pause_btn = ttk.Button(toolbar, text="Pause", width=9, command=self.toggle_pause)
        self.pause_btn.pack(side="left")
        ttk.Button(toolbar, text="Clear", width=9, command=self.clear).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Save log…", width=11, command=self.save_log).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="App log…", width=11, command=self.save_app_log).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Dedicate to VM →", width=17,
                   command=self.dedicate_to_vm).pack(side="left", padx=16)
        ttk.Button(toolbar, text="udev control →", width=15,
                   command=lambda: self.tabs.select(self.control_tab)).pack(side="left")
        ttk.Label(toolbar, textvariable=self.tally).pack(side="left")
        ttk.Label(toolbar, textvariable=self.backend_text).pack(side="right")

        filters = ttk.LabelFrame(events, text="Show", padding=(8, 4))
        filters.pack(side="top", fill="x", pady=(8, 4))
        for label, members in ud.SUBSYSTEM_GROUPS.items():
            if not set(members) & set(self.subsystems):
                continue
            var = tk.BooleanVar(master=self.root, value=True)
            self.filter_vars[label] = var
            ttk.Checkbutton(filters, text=label, variable=var, command=self.apply_filter).pack(side="left", padx=2)
        if "block" in self.subsystems:
            ttk.Separator(filters, orient="vertical").pack(side="left", fill="y", padx=10)
            ttk.Checkbutton(filters, text="removable only", variable=self.removable_only,
                            command=self.apply_filter).pack(side="left")
        ttk.Separator(filters, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Checkbutton(filters, text="list devices present at startup", variable=self.show_existing,
                        command=self._seed_existing).pack(side="left")

        self.tree = ttk.Treeview(events, columns=self.COLUMNS, show="headings", selectmode="browse")
        headings = {
            "time": ("Time", 80), "action": ("Action", 80), "device": ("Device", 100),
            "type": ("Type", 90), "size": ("Size", 90), "filesystem": ("Filesystem", 130),
            "vendor": ("Vendor", 110), "model": ("Model", 160), "serial": ("Serial", 140),
            "detail": ("Location", 260),
        }
        for key, (text, width) in headings.items():
            self.tree.heading(key, text=text)
            self.tree.column(key, width=width, anchor="e" if key == "size" else "w", stretch=(key == "detail"))
        self.tree.tag_configure("add", foreground="#0b6e2f")
        self.tree.tag_configure("remove", foreground="#a3121b")
        self.tree.tag_configure("gone", foreground="#808080", font=("", 10, "italic"))
        vsb = ttk.Scrollbar(events, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="top", fill="both", expand=True, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy line", command=self.copy_line)
        menu.add_command(label="Copy details (JSON)", command=self.copy_details)
        menu.add_separator()
        menu.add_command(label="Show details", command=self.show_details)
        menu.add_command(label="Save log…", command=self.save_log)
        self.tree.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))
        self.tree.bind("<Double-1>", lambda e: self.show_details())

        self.status_bar = ttk.Label(self.root, textvariable=self.status, anchor="w", padding=(10, 4))
        self.status_bar.pack(side="bottom", fill="x")

    def _build_control_tab(self) -> None:
        self.control_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.control_tab, text="udev control")
        left = ttk.Frame(self.control_tab, padding=10)
        left.pack(side="left", fill="y")

        ttk.Label(left, textvariable=self.selected_text, style="Mono.TLabel").pack(anchor="w")
        ttk.Label(left, textvariable=self.priv_text, style="Hint.TLabel").pack(anchor="w", pady=(2, 10))

        def section(text):
            ttk.Label(left, text=text, font=("", 10, "bold")).pack(anchor="w", pady=(8, 3))

        def button(text, cmd, row=None):
            b = ttk.Button(left, text=text, command=cmd)
            b.pack(fill="x", pady=2)
            return b

        section("Selected device")
        button("Trigger change (re-evaluate rules)", lambda: self.act_trigger("change"))
        button("Trigger add", lambda: self.act_trigger("add"))
        button("Trigger remove", lambda: self.act_trigger("remove"))
        button("Test rules against device", self.act_test)
        button("Trigger all block devices (change)", lambda: self.control_bg(self.control.trigger_block("change")))

        section("Access")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=(2, 2))
        ttk.Label(row, text="mode").pack(side="left")
        ttk.Entry(row, textvariable=self.mode_var, width=7).pack(side="left", padx=6)
        ttk.Label(row, text="group").pack(side="left")
        ttk.Entry(row, textvariable=self.group_var, width=12).pack(side="left", padx=6)
        button("Apply permissions to device node", self.act_chmod)

        section("Properties")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=(2, 2))
        ttk.Label(row, text="key").pack(side="left")
        ttk.Entry(row, textvariable=self.prop_key, width=20).pack(side="left", padx=6)
        ttk.Label(row, text="value").pack(side="left")
        ttk.Entry(row, textvariable=self.prop_val, width=14).pack(side="left", padx=6)
        button("Set property for udev events", self.act_property)

        section("Host automount")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=(2, 2))
        ttk.Checkbutton(row, text="also unmount now", variable=self.noauto_unmount).pack(side="left")
        button("Stop host automount for this device", self.act_block_automount)
        button("Unmount on host now", self.act_unmount)
        button("Allow host automount again", self.act_allow_automount)
        button("Show automount state", self.act_automount_state)

        section("Rules & daemon")
        button("Reload rules", lambda: self.control_bg(self.control.reload_rules()))
        button("Restart systemd-udevd", lambda: self.confirm_restart())
        row = ttk.Frame(left)
        row.pack(fill="x", pady=(6, 2))
        ttk.Label(row, text="file").pack(side="left")
        ttk.Entry(row, textvariable=self.rule_name, width=24).pack(side="left", padx=6)
        row2 = ttk.Frame(left)
        row2.pack(fill="x", pady=(2, 2))
        self.rule_dir = tk.StringVar(master=self.root, value="/etc/udev/rules.d")
        ttk.Combobox(row2, textvariable=self.rule_dir, values=list(ctl.RULE_DIRS), width=26,
                     state="readonly").pack(side="left")
        button("Write rule for selected device…", self.act_write_rule)
        button("Delete rule file", self.act_delete_rule)
        button("List installed rule files", lambda: self.control_now(self.control.list_rules()))

        ttk.Separator(left).pack(fill="x", pady=10)
        ttk.Label(left, text=f"running as uid {os.geteuid()} - privileged actions use "
                             f"{self.control.elevation}", style="Hint.TLabel",
                  wraplength=380, justify="left").pack(anchor="w")

    def _build_hook_tab(self) -> None:
        self.hook_runner = hook.HookRunner(self.hook_command.get(), 3.0,
                                           self.hook_enabled.get())
        self.hook_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.hook_tab, text="On connect")

        ttk.Label(self.hook_tab, textvariable=self.hook_status, style="Mono.TLabel").pack(anchor="w")
        ttk.Label(
            self.hook_tab,
            text="Runs the command below every time a storage device is connected. The device is "
                 "passed in environment variables (DEV_NODE, DEV_MODEL, DEV_SERIAL, DEV_SIZE, "
                 "DEV_ID_PATH, DEV_FILESYSTEM, ...).",
            style="Hint.TLabel", wraplength=780, justify="left",
        ).pack(anchor="w", pady=(4, 12))

        row = ttk.Frame(self.hook_tab)
        row.pack(fill="x")
        ttk.Label(row, text="command").pack(side="left")
        ttk.Entry(row, textvariable=self.hook_command).pack(side="left", fill="x", expand=True, padx=8)
        row2 = ttk.Frame(self.hook_tab)
        row2.pack(fill="x", pady=8)
        ttk.Label(row2, text="delay (s)").pack(side="left")
        ttk.Spinbox(row2, from_=0, to=120, textvariable=self.hook_delay, width=6).pack(side="left", padx=8)
        ttk.Checkbutton(row2, text="run on connect", variable=self.hook_enabled,
                        command=self._apply_hook).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(row2, text="ask me first", variable=self.hook_confirm,
                        command=self._apply_hook).pack(side="left", padx=8)
        ttk.Checkbutton(row2, text="confirm the launch", variable=self.hook_notify,
                        command=self._apply_hook).pack(side="left", padx=8)
        ttk.Button(row2, text="Save setting", command=self._apply_hook).pack(side="left", padx=8)

        buttons = ttk.Frame(self.hook_tab)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Boot a dedicated VM for selected device",
                   command=self.dedicate_to_vm).pack(side="left")
        ttk.Button(buttons, text="Show what it would run", command=self.hook_preview).pack(side="left", padx=8)
        ttk.Button(buttons, text="Last result", command=self.hook_last).pack(side="left")

        ttk.Label(
            self.hook_tab,
            text="The bundled boot-tiny-linux.sh boots a throwaway busybox Linux with that disk "
                 "attached read-only and refuses to touch the disk holding your running OS.\n"
                 "Prefix the command with environment variables to change that, e.g.\n"
                 "    TINY_WINDOW=1 ./boot-tiny-linux.sh        (show the VM in a window, serial console)\n"
                 "    TINY_WRITABLE=1 TINY_TIMEOUT=60 ./boot-tiny-linux.sh",
            style="Hint.TLabel", wraplength=780, justify="left",
        ).pack(anchor="w", pady=(16, 0))

    def _build_vm_tab(self) -> None:
        self.vm_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.vm_tab, text="Virtual machines")

        ttk.Label(self.vm_tab, text="Dedicated VMs (libvirt)", font=("", 11, "bold")).pack(anchor="w")
        ttk.Label(
            self.vm_tab,
            text="Each disk gets its own persistent libvirt domain named tiny-<device>, so it shows up "
                 "in 'virsh list --all'. The host is told not to automount the same disk.",
            style="Hint.TLabel", wraplength=780, justify="left",
        ).pack(anchor="w", pady=(2, 10))

        opts = ttk.Frame(self.vm_tab)
        opts.pack(fill="x")
        ttk.Label(opts, text="launcher").pack(side="left")
        ttk.Radiobutton(opts, text="libvirt (visible in virsh)", variable=self.vm_backend,
                        value="libvirt").pack(side="left", padx=6)
        ttk.Radiobutton(opts, text="bare qemu (no virsh entry)", variable=self.vm_backend,
                        value="qemu").pack(side="left", padx=6)
        ttk.Label(opts, text="memory (MiB)").pack(side="left", padx=(16, 0))
        ttk.Entry(opts, textvariable=self.vm_memory, width=7).pack(side="left", padx=6)
        ttk.Checkbutton(opts, text="writable disk", variable=self.vm_writable).pack(side="left", padx=6)

        buttons = ttk.Frame(self.vm_tab)
        buttons.pack(fill="x", pady=10)
        ttk.Button(buttons, text="Dedicate selected device to a new VM",
                   command=self.dedicate_to_vm).pack(side="left")
        ttk.Button(buttons, text="Open CLI (virsh console)", command=self.vm_console).pack(side="left", padx=8)
        ttk.Button(buttons, text="How do I get a shell?", command=self.console_help).pack(side="left", padx=8)
        ttk.Button(buttons, text="Stop & delete VM for selected device",
                   command=self.vm_stop_selected).pack(side="left")
        ttk.Button(buttons, text="Refresh list", command=self.refresh_vm_list).pack(side="left", padx=8)
        ttk.Button(buttons, text="Save diagnostics…", command=self.save_diagnostics).pack(side="left", padx=8)
        ttk.Button(buttons, text="Save app log…", command=self.save_app_log).pack(side="left", padx=8)
        ttk.Button(buttons, text="Fix libvirt access", command=self.fix_libvirt_access).pack(side="left", padx=8)
        ttk.Button(buttons, text="Fix QEMU file access", command=self.fix_qemu_access).pack(side="left", padx=8)

        listing = ttk.LabelFrame(self.vm_tab, text="virsh list --all (tiny-* only)", padding=8)
        listing.pack(fill="both", expand=True, pady=(4, 0))
        ttk.Label(listing, textvariable=self.vm_list_text, style="Mono.TLabel",
                  justify="left", anchor="nw").pack(fill="both", expand=True)

        ttk.Label(
            self.vm_tab,
            text="After starting a VM:  virsh list --all  ·  virsh console tiny-<device>  ·  "
                 "virsh destroy tiny-<device>",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(10, 0))
        self.root.after(600, self.refresh_vm_list)

    def _apply_hook(self) -> None:
        try:
            delay = float(self.hook_delay.get() or 0)
        except ValueError:
            delay = 0.0
            self.hook_delay.set("0")
        self.hook_runner.configure(self.hook_command.get(), delay, self.hook_enabled.get())
        state = "armed" if self.hook_enabled.get() else "disabled"
        self.hook_status.set(f"hook {state} (delay {delay:g}s): {self.hook_command.get() or '(empty)'}")

    def hook_preview(self) -> None:
        dev = self.selected()
        if dev is None:
            messagebox.showinfo("No device", "Select a device in the Storage events tab first.")
            self.tabs.select(0)
            return
        self._apply_hook()
        result = self.hook_runner.dry_run(dev)
        if not result.launched:
            messagebox.showerror("Hook not usable", result.stderr)
            return
        env = hook.device_env(dev)
        body = "\n".join(f"{k:<16} {v}" for k, v in env.items() if v)
        messagebox.showinfo("Hook preview", f"command:\n{' '.join(result.command)}\n\nenvironment:\n{body}")

    def hook_test(self) -> None:
        dev = self.selected()  # kept for the "Last result"/preview helpers
        if dev is None:
            messagebox.showinfo("No device", "Select a device in the Storage events tab first.")
            self.tabs.select(0)
            return
        self._apply_hook()
        previous, self.hook_runner.enabled = self.hook_runner.enabled, True
        try:
            result = self.hook_runner.submit(dev)
        finally:
            self.hook_runner.enabled = previous
        if result is None:
            return
        self.hook_status.set(f"test run: {result.summary}")
        messagebox.showinfo("Hook test", f"{' '.join(result.command)}\n\n{result.summary}")

    def hook_last(self) -> None:
        if not self.hook_runner.log:
            messagebox.showinfo("Hook history", "no hook runs yet")
            return
        lines = []
        for entry in self.hook_runner.log[-10:]:
            body = (entry.stderr or entry.stdout or "").strip()
            lines.append(f"{' '.join(entry.command) or '(none)'}\n  {entry.summary}")
            if body:
                lines.append("  " + body.splitlines()[-1])
        messagebox.showinfo("Hook history", "\n".join(lines))

    def _bind_keys(self) -> None:
        self.root.bind("<space>", lambda e: self.toggle_pause())
        self.root.bind("<Delete>", lambda e: self.clear())
        self.root.bind("<Control-s>", lambda e: self.save_log())

    def _post(self, callback, *args) -> None:
        self.ui_queue.put((callback, args))

    def _pump(self) -> None:
        try:
            while True:
                self._handle(self.pending.get_nowait())
        except queue.Empty:
            pass
        try:
            while True:
                callback, args = self.ui_queue.get_nowait()
                try:
                    callback(*args)
                except Exception as exc:
                    log.exception("ui callback failed: %s", callback)
                    self.status.set(f"ui error: {type(exc).__name__}: {exc}")
        except queue.Empty:
            pass
        self._check_backend()
        if self.root.winfo_exists():
            self.root.after(120, self._pump)

    def _check_backend(self) -> None:
        if self.monitor.alive() or self._falling_back:
            return
        self._falling_back = True
        reason = self.monitor.error or "backend thread stopped"
        self.monitor.stop()
        self.monitor = ud.PollingMonitor(self.root_dir, self.subsystems, self.interval,
                                         include_partitions=self.include_partitions)
        self.monitor.start()
        self.backend_text.set(f"{self.monitor.backend} (after {reason})")
        self.status.set(f"{reason}; switched to sysfs polling")

    def _watch(self) -> None:
        while True:
            event = self.monitor.events.get()
            if event is None:
                return
            self.pending.put(event)

    def selected(self):
        selection = self.tree.selection()
        return self.rows.get(selection[0]) if selection else None

    def _on_select(self, _event=None) -> None:
        dev = self.selected()
        self.selected_text.set(
            "no device selected" if dev is None
            else f"{dev.device}  {dev.vendor} {dev.model}".rstrip()
        )

    def _seed_existing(self) -> None:
        if not self.show_existing.get():
            for key in [k for k in self.order if self.rows[k].action == "present"]:
                self.tree.delete(key)
                self.order.remove(key)
                del self.rows[key]
            self.status.set(f"monitoring via {self.monitor.backend} - waiting for storage events")
            return
        have = {(e.subsystem, e.name) for e in self.rows.values() if e.action in ("present", "add")}
        count = 0
        for key, info in self.monitor.snapshot().items():
            subsystem, _, name = key.partition("/")
            if (subsystem, name) in have:
                continue
            event = self._event_from_info("present", subsystem, name, info)
            if self._visible(event):
                self._insert(event)
                count += 1
        self.status.set(f"listed {count} storage devices already attached")

    def _visible(self, event: ud.DeviceEvent) -> bool:
        if event.subsystem not in self.subsystems:
            return False
        if self.removable_only.get() and not event.removable:
            return False
        return any(
            var.get() and event.subsystem in ud.SUBSYSTEM_GROUPS[label]
            for label, var in self.filter_vars.items()
        )

    def _event_from_info(self, action: str, subsystem: str, name: str, info: dict) -> ud.DeviceEvent:
        return ud.DeviceEvent(
            action=action, subsystem=subsystem, name=name,
            syspath=info.get("syspath", ""), bus=info.get("bus", ""),
            vendor=info.get("vendor", ""), model=info.get("model", ""), serial=info.get("serial", ""),
            devtype=info.get("devtype", ""), devnode=info.get("devnode", ""),
            devpath=info.get("devpath", ""), detail=info.get("detail", ""), size=info.get("size", ""),
            fstype=info.get("fstype", ""), fslabel=info.get("fslabel", ""), fsuuid=info.get("fsuuid", ""),
            removable=info.get("removable", False), readonly=info.get("readonly", False),
            rotational=info.get("rotational", False), is_partition=info.get("is_partition", False),
            properties=info.get("properties", {}),
        )

    def _tag(self, event: ud.DeviceEvent) -> str:
        return "add" if event.action == "add" else "remove" if event.action == "remove" else "gone"

    def _values(self, event: ud.DeviceEvent) -> tuple:
        filesystem = event.fstype
        if event.fslabel:
            filesystem = f"{filesystem} '{event.fslabel}'" if filesystem else f"'{event.fslabel}'"
        details = " ".join(b for b in (event.devpath, event.detail) if b)
        return (
            dt.datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S"),
            event.action,
            event.device,
            event.devtype or event.bus,
            event.size,
            filesystem,
            event.vendor,
            event.model,
            event.serial,
            details,
        )

    def _insert(self, event: ud.DeviceEvent) -> None:
        key = f"{event.action}:{event.subsystem}/{event.name}:{event.timestamp}"
        self.rows[key] = event
        self.order.append(key)
        self.tree.insert("", "end", iid=key, values=self._values(event), tags=(self._tag(event),))
        if not self.paused:
            self.tree.see(key)
        self._restyle()

    def _restyle(self) -> None:
        alive = {e.name for e in self.rows.values() if e.action == "add"}
        for key, event in self.rows.items():
            if event.action == "remove" and event.name in alive:
                self.tree.item(key, tags=("gone",))

    def _handle(self, event: ud.DeviceEvent) -> None:
        log.info("event %-6s %-14s %-10s %-12s %s", event.action, event.device, event.size,
                 event.fstype or "-", event.label or "")
        if self._visible(event):
            self._insert(event)
        if event.action == "add":
            self.added += 1
        elif event.action == "remove":
            self.removed += 1
        self.tally.set(f"{self.added} added · {self.removed} removed · {len(self.order)} shown")
        if not self.paused:
            self.status.set(f"{event.action.upper()}  {event.device}  —  {event.label}  {event.size}")
        if event.action == "add" and self.hook_runner.enabled:
            log.info("connect hook armed for %s -> %s", event.device, self.hook_runner.command)
            self._post(self._start_hook, event)

    def _start_hook(self, event: ud.DeviceEvent) -> None:
        """Runs on the main thread so every widget access is legal."""
        if not self.hook_runner.enabled:
            return
        detail = f"{event.device}\n{event.label}   {event.size}"
        if event.serial:
            detail += f"\nserial {event.serial}"
        if self.hook_confirm.get():
            if not messagebox.askyesno("Launch VM for this device?",
                                       detail + "\n\nStart the tiny Linux VM with that disk?",
                                       default="no"):
                self.hook_status.set(f"skipped - declined for {event.device}")
                self.tabs.select(self.hook_tab)
                return
        notify = self.hook_notify.get()
        self.hook_status.set(f"launching for {event.device} in {self.hook_runner.delay:g}s ...")
        threading.Thread(target=self._run_hook, args=(event, notify), daemon=True).start()

    def _run_hook(self, event: ud.DeviceEvent, notify: bool) -> None:
        try:
            result = self.hook_runner.submit(event)
        except Exception as exc:
            log.exception("hook raised for %s", event.device)
            self._post(self.hook_status.set, f"hook failed: {type(exc).__name__}: {exc}")
            return
        if result is None:
            self._post(self.hook_status.set, f"hook skipped: {event.device}")
            return
        log.log(logging.INFO if result.ok else logging.ERROR,
                "hook %s for %s: cmd=%s env=%s\n  %s", result.summary, event.device,
                " ".join(result.command), result.env_overrides or {},
                (result.stderr or result.stdout or "")[:1500])
        self._post(self.hook_status.set, f"hook fired for {event.device}: {result.summary}")
        if notify:
            self._post(self._announce, event, result)

    def _announce(self, event: ud.DeviceEvent, result: hook.HookResult) -> None:
        body = (f"device    {event.device}\n"
                f"name      {event.label}\n"
                f"size      {event.size}\n"
                f"command   {' '.join(result.command)}\n"
                f"status    {result.summary}\n")
        if result.env_overrides:
            body += "env       " + " ".join(f"{k}={v}" for k, v in result.env_overrides.items()) + "\n"
        if not result.launched:
            body += f"\n{result.stderr}"
        else:
            body += "\nThe VM runs on its own; it stops by itself after the timeout."
        messagebox.showinfo("Tiny Linux VM launched", body)

    def toggle_pause(self) -> None:
        self.paused = not self.paused
        self.pause_btn.configure(text="Resume" if self.paused else "Pause")
        self.status.set("paused - events are still recorded" if self.paused else "resumed")

    def clear(self) -> None:
        for key in self.order:
            self.tree.delete(key)
        self.order.clear()
        self.rows.clear()
        self.added = self.removed = 0
        self.tally.set("0 added · 0 removed · 0 shown")

    def apply_filter(self) -> None:
        shown = set()
        for key, event in self.rows.items():
            if self._visible(event):
                if key in self.tree.get_children(""):
                    self.tree.item(key, values=self._values(event), tags=(self._tag(event),))
                else:
                    self.tree.insert("", "end", iid=key, values=self._values(event), tags=(self._tag(event),))
                if key not in self.order:
                    self.order.append(key)
                shown.add(key)
        for key in set(self.rows) - shown:
            if key in self.tree.get_children(""):
                self.tree.detach(key)
            self.order.remove(key)
        self.tally.set(f"{self.added} added · {self.removed} removed · {len(shown)} shown")

    def show_details(self) -> None:
        dev = self.selected()
        if dev is None:
            return
        rows = [
            ("action", dev.action), ("device", dev.device), ("type", dev.devtype or "-"),
            ("size", dev.size or "-"),
            ("filesystem", " ".join(b for b in (dev.fstype, f"label={dev.fslabel}" if dev.fslabel else "") if b) or "-"),
            ("fs uuid", dev.fsuuid or "-"), ("vendor", dev.vendor or "-"), ("model", dev.model or "-"),
            ("serial", dev.serial or "-"), ("bus", dev.bus or "-"),
            ("removable", "yes" if dev.removable else "no"), ("read-only", "yes" if dev.readonly else "no"),
            ("id_path", dev.devpath or "-"), ("syspath", dev.syspath),
        ]
        messagebox.showinfo("Storage device", "\n".join(f"{k:<11}: {v}" for k, v in rows))

    def copy_line(self) -> None:
        selection = self.tree.selection()
        if selection:
            self.root.clipboard_clear()
            self.root.clipboard_append("\t".join(str(v) for v in self.tree.item(selection[0], "values")))

    def copy_details(self) -> None:
        dev = self.selected()
        if dev is None:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(json.dumps({
            "action": dev.action, "device": dev.device, "type": dev.devtype, "size": dev.size,
            "filesystem": dev.fstype, "fslabel": dev.fslabel, "fsuuid": dev.fsuuid,
            "removable": dev.removable, "read_only": dev.readonly, "rotational": dev.rotational,
            "bus": dev.bus, "vendor": dev.vendor, "model": dev.model, "serial": dev.serial,
            "syspath": dev.syspath, "id_path": dev.devpath, "properties": dev.properties,
            "timestamp": dev.timestamp,
        }, indent=2))

    def save_log(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".log", title="Save device log",
            filetypes=(("Text log", "*.log"), ("JSON lines", "*.jsonl"), ("All files", "*.*")),
        )
        if not path:
            return
        as_json = path.endswith(".jsonl")
        try:
            with open(path, "w") as fh:
                for key in self.order:
                    dev = self.rows[key]
                    stamp = dt.datetime.fromtimestamp(dev.timestamp).isoformat(timespec="milliseconds")
                    if as_json:
                        fh.write(json.dumps({
                            "time": stamp, "action": dev.action, "device": dev.device, "type": dev.devtype,
                            "size": dev.size, "filesystem": dev.fstype, "fslabel": dev.fslabel,
                            "removable": dev.removable, "vendor": dev.vendor, "model": dev.model,
                            "serial": dev.serial, "id_path": dev.devpath,
                        }) + "\n")
                    else:
                        fh.write(f"{stamp} {dev.action:<7} {dev.device:<8} {dev.size:>10}  "
                                 f"{dev.fstype or '-':<8} {dev.vendor} {dev.model} {dev.serial} {dev.devpath}\n")
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.status.set(f"wrote {len(self.order)} records to {path}")

    def control_bg(self, factory, show_output: bool = False) -> None:
        log.info("udev action requested (privileged=%s, elevate=%s)", self.control.is_root,
                 self.control.elevation)
        if self.control.is_root:
            self.report(factory(), show_output)
            return
        self.status.set("waiting for polkit authorisation…")
        threading.Thread(target=self._run_control, args=(factory, show_output), daemon=True).start()

    def control_now(self, factory, show_output: bool = True) -> None:
        try:
            self.report(factory(), show_output)
        except ctl.ControlError as exc:
            self.fail(exc)
        except Exception as exc:
            self.fail(f"{type(exc).__name__}: {exc}")

    def _run_control(self, factory, show_output: bool) -> None:
        try:
            result = factory()
        except ctl.ControlError as exc:
            self._post(self.fail, exc)
            return
        except Exception as exc:
            self._post(self.fail, f"{type(exc).__name__}: {exc}")
            return
        self._post(self.report, result, show_output)

    def report(self, result: ctl.ControlResult, show_output: bool = False) -> None:
        command = " ".join(str(part) for part in result.command)
        log.log(logging.INFO if result.ok else logging.ERROR, "udev %s exit=%d\n  $ %s\n  %s",
                "ok" if result.ok else "FAILED", result.code, command,
                (result.output or "(no output)")[:1500])
        self.status.set(f"{command} → exit {result.code}")
        if result.ok and not show_output:
            return
        body = result.output or "(no output)"
        box = messagebox.showinfo if result.ok else messagebox.showerror
        box(f"udev: {'done' if result.ok else 'failed'} (exit {result.code})",
            f"$ {command}\n\n{body}")

    def fail(self, exc) -> None:
        log.error("udev action failed: %s: %s", type(exc).__name__, exc)
        messagebox.showerror("udev control failed", str(exc))
        self.status.set(f"failed: {exc}")

    def need_device(self) -> ud.DeviceEvent | None:
        dev = self.selected()
        if dev is None:
            messagebox.showinfo("No device", "Select a device in the Storage events tab first.")
            self.tabs.select(0)
        return dev

    def act_trigger(self, action: str) -> None:
        dev = self.need_device()
        if dev:
            self.control_bg(lambda: self.control.trigger(dev.syspath, action))

    def act_test(self) -> None:
        dev = self.need_device()
        if dev:
            self.control_now(lambda: self.control.test_rules(dev.syspath))

    def act_chmod(self) -> None:
        dev = self.need_device()
        if not dev:
            return
        mode, group = self.mode_var.get().strip(), self.group_var.get().strip()

        def run():
            return self.control.change_access(dev.devnode or dev.name, mode, group=group or None)

        self.control_bg(run)

    def act_property(self) -> None:
        key, value = self.prop_key.get().strip(), self.prop_val.get()
        self.control_bg(lambda: self.control.set_property(key, value))

    def confirm_restart(self) -> None:
        if not messagebox.askyesno(
            "Restart udevd",
            "Restart systemd-udevd?\n\nDevices may briefly disappear. "
            "Stop USB storage first if you are running from one.",
        ):
            return
        self.control_bg(self.control.restart_udevd)

    def act_write_rule(self) -> None:
        dev = self.need_device()
        if not dev:
            return
        path = filedialog.asksaveasfilename(
            title="Save udev rule", initialdir=self.rule_dir.get(),
            initialfile=ctl.validate_rule_name(self.rule_name.get()),
            defaultextension=".rules", filetypes=(("udev rules", "*.rules"),),
        )
        if not path:
            return
        name = self.rule_name.get()
        text = ctl.DEFAULT_RULE_TEMPLATE.format(name=name, kernel=dev.name)
        directory = os.path.dirname(path)
        self.control_bg(lambda: self.control.install_rule(name, text, directory))

    def act_delete_rule(self) -> None:
        name = self.rule_name.get().strip()
        if not messagebox.askyesno("Delete rule", f"Delete {name} from {self.rule_dir.get()}?"):
            return
        directory = self.rule_dir.get()
        self.control_bg(lambda: self.control.remove_rule(name, directory))

    def dedicate_to_vm(self) -> None:
        """Hands the selected device to its own VM - nothing else, no automatic mount."""
        dev = self.need_device()
        if not dev:
            return
        self._apply_hook()
        result = self.hook_runner.dry_run(dev)
        if not result.command:
            messagebox.showerror("VM command not usable", result.stderr)
            return
        detail = f"{dev.device}\n{dev.label}   {dev.size}"
        if dev.serial:
            detail += f"\nserial {dev.serial}"
        if self.vm_backend.get() == "libvirt":
            name = lv.domain_name(dev.devnode or dev.name)
            detail += f"\n\nlibvirt domain   {name}"
            detail += "\nvisible in      virsh list --all"
            detail += f"\nconsole        virsh console {name}"
            detail += "\n\nStart a dedicated VM for this device?"
            if not messagebox.askyesno("Dedicate this disk to a VM?", detail, default="yes"):
                self.status.set(f"skipped - not dedicating {dev.device}")
                return
            self.status.set(f"defining libvirt domain {name} ...")
            threading.Thread(target=self._start_domain, args=(dev,), daemon=True).start()
            return
        detail += f"\n\ncommand   {' '.join(result.command)}"
        detail += "\n\nStart a dedicated VM for this device?"
        if not messagebox.askyesno("Dedicate this disk to a VM?", detail, default="yes"):
            self.status.set(f"skipped - not dedicating {dev.device}")
            return
        self.status.set(f"starting dedicated VM for {dev.device} ...")
        threading.Thread(target=self._run_hook, args=(dev, True), daemon=True).start()

    def _start_domain(self, dev: ud.DeviceEvent) -> None:
        """Runs on a worker; every widget write goes back through _post."""
        devnode = dev.devnode or ""
        if not devnode.startswith("/dev/"):
            self._post(self.status.set, f"cannot launch: {devnode!r} is not a device node")
            return
        log.info("dedicate %s -> libvirt domain (writable=%s)", devnode, self.vm_writable.get())
        try:
            name, xml, report = self.vms.define_and_start(
                devnode, memory=int(self.vm_memory.get() or 256), writable=self.vm_writable.get())
        except (ctl.ControlError, ValueError) as exc:
            log.error("cannot build domain for %s: %s", devnode, exc)
            self._post(messagebox.showerror, "Could not start the VM", str(exc))
            return
        except Exception as exc:
            log.exception("unexpected failure starting %s", devnode)
            self._post(messagebox.showerror, "Could not start the VM", f"{type(exc).__name__}: {exc}")
            return
        log.log(logging.INFO if report.ok else logging.ERROR,
                "domain %s: exit=%d\n  $ %s\n  %s", name, report.code,
                " ".join(report.command), (report.output or report.stderr or "")[:2000])
        if not report.ok and self.vms.denied(report):
            self._post(lambda: self._denied_dialog(report))
            return
        if not report.ok and "error reading initrd" in (report.output or ""):
            log.error("qemu could not read the initramfs; offer the file-access fix")
            self._post(lambda: (messagebox.showerror("QEMU cannot read the VM files",
                                                      report.output or report.stderr),
                                self.fix_qemu_access()))
        port = self.vms.vnc_port(name) if report.ok else ""
        if report.ok:
            self.hook_status.set(f"libvirt domain {name} running")
            body = (f"{report.output}\n\nname      {name}"
                    f"\nconsole   virsh console {name}"
                    f"\nvnc       127.0.0.1:{port or '?'}")
            self._post(messagebox.showinfo, "Dedicated VM started", body)
        else:
            self.hook_status.set(f"libvirt domain {name} failed")
            self._post(messagebox.showerror, "virsh failed", report.output or report.stderr)
        self._post(self.refresh_vm_list)

    def refresh_vm_list(self) -> None:
        try:
            probe = self.vms.virsh("list", "--all")
            if self.vms.denied(probe):
                self.vm_list_text.set("libvirt refused the request - press 'Fix libvirt access'")
                self._post(messagebox.showwarning, "libvirt access denied",
                           self.vms.access_help())
                return
            domains = self.vms.domains()
        except Exception as exc:
            log.exception("listing libvirt domains failed")
            self.vm_list_text.set(f"(virsh failed: {exc})")
            return
        if not domains:
            self.vm_list_text.set("(no tiny-* domains defined)")
            return
        rows = []
        for info in domains:
            mark = "running" if info.running else info.state
            address = self.vms.vnc_address(info.name) if info.running else "-"
            rows.append(f"{info.name:<18} {mark:<10} vnc {address:<18} "
                        f"console  virsh console {info.name}")
        self.vm_list_text.set("\n".join(rows))

    def fix_libvirt_access(self) -> None:
        """virsh keeps getting refused by polkit - install a rule for this desktop user."""
        result = self.vms.virsh("list", "--all")
        if result.ok and not self.vms.denied(result):
            messagebox.showinfo("libvirt access is fine",
                                "virsh is already allowed - nothing to do.")
            return
        log.warning("libvirt access denied: %s", (result.stderr or result.stdout).strip())
        if not messagebox.askyesno(
            "Let virsh manage VMs for you",
            self.vms.access_help() +
            "\n\nInstall the polkit rule now? (one password prompt)"
            "\nIt still needs one authentication, but not one per action afterwards.",
            default="yes",
        ):
            return

        def run():
            return self.vms.install_access_rule()

        self.control_bg(run, show_output=True)

    def fix_qemu_access(self) -> None:
        """QEMU (user libvirt-qemu) has to be able to read the kernel and initramfs."""
        kernel = self.vms.kernel_path()
        problems = lv.access_problems(kernel, lv.DEFAULT_INITRD)
        log.info("qemu file access check: kernel=%s problems=%s", kernel, problems or "none")
        if not problems:
            messagebox.showinfo("File access is fine",
                                f"QEMU can read everything:\n  {kernel}\n  {lv.DEFAULT_INITRD}")
            return
        staged = self.vms.staged_initrd()
        body = "QEMU cannot read:\n  " + "\n  ".join(problems) + "\n"
        if staged:
            body += f"\nA copy is already staged at {staged} - it will be used automatically."
            messagebox.showinfo("File access", body)
            return
        body += ("\nQEMU runs as the user libvirt-qemu, not as you, so it cannot read "
                 "files inside a private home directory.\n\nFix it by copying the initramfs to "
                 f"{lv.STAGE_PATHS[0]}, which is world-readable and needs no password. "
                 "Nothing about your home directory permissions changes.")
        if not messagebox.askyesno("Fix QEMU file access", body + "\n\nDo it now?", default="yes"):
            return
        self.control_bg(lambda: self.vms.stage_initrd(), show_output=True)

    def _denied_dialog(self, result: ctl.ControlResult) -> bool:
        """Shows the polkit help when libvirt refused us; True if it was that."""
        if not self.vms.denied(result):
            return False
        log.error("libvirt refused the request: %s", (result.stderr or result.stdout).strip())
        if messagebox.askyesno("libvirt refused the request",
                               self.vms.access_help() + "\n\nInstall the rule now?",
                               default="yes"):
            self.fix_libvirt_access()
        return True

    def save_diagnostics(self) -> None:
        """Dumps everything readable to one file, plus the root-only commands to run."""
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(os.path.dirname(LOG_PATH) or ".", f"diagnostics-{stamp}.txt")
        dev = self.selected()
        nodes = [n for n in ("sda", "sdb", "sdc", "sdd", "nvme0n1") if os.path.exists(f"/dev/{n}")]

        def run(cmd: list, limit: int = 4000) -> str:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return f"$ {' '.join(cmd)}\n  failed: {exc}\n"
            out = (proc.stdout + proc.stderr).strip()
            return f"$ {' '.join(cmd)}\n{out[:limit]}\n"

        parts = [
            f"storage watcher diagnostics - {dt.datetime.now().isoformat(timespec='seconds')}",
            f"uid={os.geteuid()} elevation={self.control.elevation} "
            f"backend={self.monitor.backend}",
            f"log files: {', '.join(log_files())}",
            "",
            "== app log ==",
        ]
        for candidate in log_files() or [LOG_PATH]:
            parts += [f"-- {candidate} --", tail_file(candidate)]
        parts += [
            "",
            "== virsh ==",
            run(["virsh", "-c", lv.SYSTEM_URI, "list", "--all"]),
            run(["virsh", "-c", lv.SYSTEM_URI, "version"]),
        ]
        for domain in self.vms.domains():
            parts += ["", f"== domain {domain.name} ==",
                      run(["virsh", "-c", lv.SYSTEM_URI, "domstate", domain.name]),
                      run(["virsh", "-c", lv.SYSTEM_URI, "dumpxml", "--inactive", domain.name]),
                      run(["virsh", "-c", lv.SYSTEM_URI, "vncdisplay", domain.name])]
        parts += ["", "== block devices ==", run(["lsblk", "-o",
                    "NAME,SIZE,TRAN,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL"])]
        for node in nodes:
            parts += ["", f"== udev /dev/{node} ==",
                      run(["udevadm", "info", "--query=property", f"--name=/dev/{node}"]),
                      run(["udevadm", "test", f"/sys/class/block/{node}"])]
        parts += ["", "== mounts ==", tail_file("/proc/mounts", 3000),
                  "", "== rules ==", run(["ls", "-la", "/etc/udev/rules.d"]),
                  "", "== NEEDS ROOT ==",
                  "The VM serial console and libvirt log are root-only, so read them with:\n"
                  "  sudo cat /var/log/libvirt/qemu/tiny-*.log\n"
                  "  sudo journalctl -u libvirtd --since '-30 min' --no-pager | tail -60\n"
                  "  sudo virsh -c qemu:///system start tiny-sdb      # watch it fail live\n"]
        body = "\n".join(parts)
        try:
            with open(path, "w") as handle:
                handle.write(body)
        except OSError as exc:
            messagebox.showerror("Could not save diagnostics", str(exc))
            return
        log.info("diagnostics written to %s (%d bytes)", path, len(body))
        messagebox.showinfo("Diagnostics saved", f"{path}\n\n"
                            "It also lists the root-only commands to run for the VM console log.")

    def save_app_log(self) -> None:
        """Saves the app log wherever the user wants, for reading or sharing."""
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        default = os.path.join(os.path.expanduser("~"), f"udev_gui-{stamp}.log")
        path = filedialog.asksaveasfilename(
            title="Save app log", initialdir=os.path.dirname(default),
            initialfile=os.path.basename(default), defaultextension=".log",
            filetypes=(("log files", "*.log"), ("text files", "*.txt"), ("all files", "*")),
        )
        if not path:
            return
        chunks = [f"# storage watcher log saved {dt.datetime.now().isoformat(timespec='seconds')}",
                  f"# host {os.uname().nodename}  uid {os.geteuid()}  backend {self.monitor.backend}"]
        for candidate in log_files() or [LOG_PATH]:
            chunks += ["", f"===== {candidate} =====", tail_file(candidate, 400_000)]
        try:
            with open(path, "w") as handle:
                handle.write("\n".join(chunks))
        except OSError as exc:
            messagebox.showerror("Could not save the log", str(exc))
            return
        log.info("app log saved to %s", path)
        self.status.set(f"log saved: {path}")
        messagebox.showinfo("App log saved", path)

    def vm_console(self) -> None:
        """Opens a shell in the VM: a terminal running virsh console."""
        name = self.selected_domain_name()
        if not name:
            return
        info = next((d for d in self.vms.domains() if d.name == name), None)
        if info is None:
            messagebox.showinfo("No VM yet", f"libvirt domain {name} does not exist.\n\n"
                                 "Use 'Dedicate selected device to a new VM' first.")
            return
        if not info.running:
            if not messagebox.askyesno("VM is not running",
                                       f"{name} is {info.state}. Start it and open a console?"):
                return
            self.status.set(f"starting {name} ...")
            threading.Thread(target=self._start_named_domain, args=(name,), daemon=True).start()
            return
        cmd = self._terminal_command(["virsh", "-c", lv.SYSTEM_URI, "console", name])
        if cmd is None:
            messagebox.showinfo("Open a console yourself", self.vms.console_help(
                name, self.vms.console_pty(name)))
            return
        try:
            subprocess.Popen(cmd, start_new_session=True)
        except OSError as exc:
            messagebox.showerror("Could not open a terminal", str(exc))
            return
        self.status.set(f"console for {name}: press Ctrl-] in the terminal to detach")
        log.info("opened console for %s via %s", name, " ".join(cmd))

    def console_help(self) -> None:
        name = self.selected_domain_name()
        if not name:
            return
        messagebox.showinfo("Getting a shell in the VM",
                            self.vms.console_help(name, self.vms.console_pty(name)))

    def _start_named_domain(self, name: str) -> None:
        try:
            result = self.vms.start(name)
        except Exception as exc:
            log.exception("starting %s failed", name)
            self._post(messagebox.showerror, "Could not start the VM", f"{type(exc).__name__}: {exc}")
            return
        log.log(logging.INFO if result.ok else logging.ERROR,
                "start %s: exit=%d %s", name, result.code, (result.stderr or result.stdout)[:800])
        if not result.ok and self.vms.denied(result):
            self._post(lambda: self._denied_dialog(result))
            return
        if not result.ok:
            self._post(messagebox.showerror, "Could not start the VM", result.stderr or result.stdout)
            return
        self._post(self.refresh_vm_list)
        self._post(lambda: self.status.set(f"{name} running - use 'Open console' for a shell"))

    @staticmethod
    def _terminal_command(argv: list) -> list | None:
        for terminal in ("x-terminal-emulator", "konsole", "gnome-terminal", "xterm", "alacritty"):
            path = shutil.which(terminal)
            if not path:
                continue
            if terminal == "konsole":
                return [path, "-e", *argv]
            if terminal == "gnome-terminal":
                return [path, "--", *argv]
            if terminal == "alacritty":
                return [path, "-e", *argv]
            return [path, "-e", *argv]
        return None

    def selected_domain_name(self) -> str | None:
        dev = self.selected()
        if dev and dev.devnode:
            return lv.domain_name(dev.devnode)
        for info in self.vms.domains():
            return info.name
        messagebox.showinfo("No device", "Select a device in the Storage events tab first.")
        self.tabs.select(0)
        return None

    def vm_stop_selected(self) -> None:
        dev = self.selected()
        if not dev or not dev.devnode:
            messagebox.showinfo("No device", "Select a device in the Storage events tab first.")
            self.tabs.select(0)
            return
        name = lv.domain_name(dev.devnode)
        if not messagebox.askyesno("Remove the VM", f"Stop and delete libvirt domain {name}?"):
            return
        self.control_bg(lambda: self.vms.remove(name), show_output=True)

    def act_block_automount(self) -> None:
        dev = self.need_device()
        if not dev:
            return
        name = ctl.validate_rule_name(self.noauto_rule.get())
        if not messagebox.askyesno(
            "Stop host automount",
            f"Keep {dev.device} from being mounted by the desktop?\n\n"
            "A udev rule will set UDISKS_IGNORE=1 and ID_AUTOMOUNT=0 for"
            f"\n{dev.serial or dev.name}, so only the VM uses it."
            + ("\n\nIt will also be unmounted right now." if self.noauto_unmount.get() else ""),
            default="yes",
        ):
            return
        rule_name, unmount = name, self.noauto_unmount.get()

        def run():
            return self.control.block_automount(
                rule_name, serial=dev.serial or None, kernel=dev.name,
                devnode=dev.devnode or None, syspath=dev.syspath or None)

        self.control_bg(run, show_output=True)

    def act_allow_automount(self) -> None:
        dev = self.need_device()
        if not dev:
            return
        name = ctl.validate_rule_name(self.noauto_rule.get())
        if not messagebox.askyesno("Allow host automount", f"Remove {name} and re-enable automount?"):
            return

        def run():
            return self.control.allow_automount(name, syspath=dev.syspath or None)

        self.control_bg(run, show_output=True)

    def act_unmount(self) -> None:
        dev = self.need_device()
        if not dev:
            return
        self.control_bg(lambda: self.control.unmount_device(dev.devnode or dev.name), show_output=True)

    def act_automount_state(self) -> None:
        dev = self.need_device()
        if not dev:
            return
        self.control_now(lambda: self.control.automount_state(
            dev.devnode or dev.name, syspath=dev.syspath or None), show_output=True)

    def on_close(self) -> None:
        self.monitor.stop()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Watches storage devices and drives udev")
    parser.add_argument("--profile", default="storage", choices=tuple(ud.PROFILES),
                        help="storage (default): disks only · all: every device class")
    parser.add_argument("--partitions", action="store_true", help="also report partitions")
    parser.add_argument("--backend", default="auto", choices=("auto", "netlink", "pyudev", "poll"))
    parser.add_argument("--interval", type=float, default=1.0, help="poll interval in seconds")
    parser.add_argument("--root", default="/", help="treat this path as / (useful for testing)")
    parser.add_argument("--no-gui", action="store_true", help="log events to stdout instead")
    args = parser.parse_args()
    subsystems = ud.subsystems_for(args.profile)

    if args.no_gui:
        monitor = ud.create_monitor(args.backend, root=args.root, subsystems=subsystems,
                                    interval=args.interval, include_partitions=args.partitions)
        print(f"monitoring {', '.join(subsystems)} via {monitor.backend}")
        try:
            while True:
                ev = monitor.events.get()
                print(dt.datetime.fromtimestamp(ev.timestamp).strftime("%H:%M:%S"),
                      f"{ev.action:<6}", f"{ev.device:<8}", f"{ev.size:>10}",
                      ev.fstype or "-", ev.vendor, ev.model, ev.serial)
        except KeyboardInterrupt:
            monitor.stop()
        return

    StorageWatcherApp(root_dir=args.root, preference=args.backend, interval=args.interval,
                      profile=args.profile, include_partitions=args.partitions).run()


if __name__ == "__main__":
    main()