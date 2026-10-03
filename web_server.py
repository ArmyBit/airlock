#!/usr/bin/env python3
"""Web front end for the triage app.

Binds to 127.0.0.1 only. This process can start VMs and hand disks to them, so it
must not be reachable from the network, and every state-changing request must carry
the session token the page was served with - otherwise any website you happen to
have open could POST to localhost and drive your machine.
"""

from __future__ import annotations

import json
import mimetypes
import secrets
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import collections
import csv
import io
import live_feed
import triage_state as ts
import virustotal
from triage_state import TriageState

WEBUI = Path(__file__).resolve().parent / "webui"
DOCS = Path(__file__).resolve().parent / "docs"
# the user's sign-off that this machine is ready to triage: a timestamp, kept
# next to the VirusTotal key and out of the repository
CONFIGURED_FILE = Path.home() / ".config" / "triage" / "configured"
# environment checks touch libvirt, so they are cached, not recomputed per poll
ENV_CACHE_SECONDS = 30.0
DEFAULT_PORT = 8765
MAX_BODY = 1 << 20

# how long the collector gets before the app stops waiting. A big disk with big
# files is genuinely slow, so this is generous; it is not a safety limit, the
# stop_vm button is.
SCAN_TIMEOUT = 3600
# must match guest_collector.MARKER, which is the line the collector prints on
# stdout when it is finished; a test keeps the two honest
COLLECTOR_MARKER = "TRIAGE_COMPLETE"
# a disk showing up is a request to work on it, so the guest is booted for you
# instead of making it a second click
AUTO_START = True
# how many rows the table draws: the biggest first, so the interesting files are
# the ones that survive the cut. Every file is still scanned, hashed and checked -
# this only decides what the table shows.
REPORT_ROWS = 500


def parse_report(text: str) -> dict:
    """Turns the collector's JSON Lines into what the UI shows.

    The collector is deliberately verbose - one line per file, plus errors and
    mount records - so this picks the counters out of it rather than passing the
    whole stream to a browser that would have to hold every path in memory.
    """
    entries, errors, summary, notes = [], 0, {}, []
    hidden_files = dot_files = hashed = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        kind = record.get("type")
        if kind == "entry":
            entries.append(record)
            if record.get("kind") == "file":
                if record.get("hidden_attr"):
                    hidden_files += 1
                if record.get("hidden_dot"):
                    dot_files += 1
                if record.get("sha256"):
                    hashed += 1
        elif kind == "error":
            errors += 1
        elif kind == "done":
            summary = record
        elif kind in ("fs", "mount", "meta"):
            notes.append(record)
    files = [row for row in entries if row.get("kind") == "file"]
    files.sort(key=lambda row: row.get("size") or 0, reverse=True)
    counted = {key: summary.get(key, 0) for key in
               ("entries", "files", "dirs", "others", "errors", "skipped",
                "hashed_bytes", "seconds")}
    counted["hidden"] = hidden_files
    counted["hidden_dot"] = dot_files
    counted["hashed"] = hashed
    counted["total_records"] = len(entries) + errors
    counted["rows_shown"] = min(len(files), REPORT_ROWS)
    counted["truncated"] = max(0, len(files) - REPORT_ROWS)
    counted["filesystems"] = [
        {"node": note.get("node", ""), "fstype": note.get("fstype") or "unknown",
         "offset": note.get("offset", 0)}
        for note in notes if note.get("type") == "fs"]
    return {
        "summary": counted,
        "filesystems": counted["filesystems"],
        "rows": [{"path": row.get("path", ""), "size": row.get("size", 0),
                  "hidden": bool(row.get("hidden_attr")),
                  "hidden_dot": bool(row.get("hidden_dot")),
                  "sha256": row.get("sha256") or ""}
                 for row in files],
    }


def report_csv(report: dict, device: dict | None = None) -> str:
    """The whole result as one file: what was scanned, then every file's verdict.

    Metadata comes first as `# key, value` lines so a spreadsheet shows the context
    above the table instead of the file being just a list of hashes.
    """
    summary = report.get("summary") or {}
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    if device:
        # the snapshot form of a device, so this works on anything the UI could
        # have sent and nothing depends on a live object here
        for label, value in (("device", device.get("devnode", "")),
                             ("size", device.get("size_human") or device.get("size", "")),
                             ("model", " ".join(filter(None, [device.get("vendor", ""),
                                                              device.get("model", "")]))),
                             ("serial", device.get("serial", "")),
                             ("filesystem", device.get("fstype", "")),
                             ("label", device.get("label", "")),
                             ("in the guest", device.get("guest_node", "")),
                             ("exported", time.strftime("%Y-%m-%d %H:%M %Z"))):
            writer.writerow([f"# {label}", value])
    for key in ("entries", "files", "dirs", "others", "hidden", "hashed",
                "unhashed", "errors", "skipped", "seconds", "virustotal",
                "vt_not_checked"):
        if key in summary:
            writer.writerow([f"# {key}", summary[key]])
    for disk in report.get("filesystems") or []:
        writer.writerow(["# filesystem", disk.get("fstype", ""),
                         disk.get("node", ""), disk.get("offset", 0)])
    writer.writerow([])
    writer.writerow(["verdict", "detections", "scanned", "size", "hidden",
                     "sha256", "path", "virustotal_name", "virustotal_link"])
    for row in report.get("rows") or []:
        writer.writerow([
            row.get("virustotal") or "not checked",
            row.get("detections", ""),
            row.get("scanned", ""),
            row.get("size", 0),
            "attr" if row.get("hidden") else ("dot" if row.get("hidden_dot") else ""),
            row.get("sha256", ""),
            row.get("path", ""),
            row.get("vt_name", ""),
            row.get("vt_link", ""),
        ])
    return out.getvalue()


def _pdf_text(value) -> str:
    """reportlab's Helvetica only speaks latin-1; a filename from another
    alphabet must degrade to question marks, not crash the whole report."""
    return str(value or "").encode("latin-1", "replace").decode("latin-1")


def report_pdf(report: dict, device: dict | None = None) -> bytes:
    """The whole result as a printable PDF: what was scanned, the verdict,
    the flagged files with their engines, then every file's verdict."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import landscape, A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle)

    summary = report.get("summary") or {}
    rows = report.get("rows") or []
    flagged = [row for row in rows if row.get("virustotal") == "malicious"]
    clean = sum(1 for row in rows if row.get("virustotal") == "clean")
    unknown = len(rows) - len(flagged) - clean

    ink = colors.HexColor("#1d212b")
    soft = colors.HexColor("#565c68")
    faint = colors.HexColor("#8a8f9a")
    line = colors.HexColor("#ddd8cc")
    red = colors.HexColor("#b3261e")
    green = colors.HexColor("#1e7e34")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4),
                            leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm,
                            title="Airlock forensic report")
    title = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20,
                           leading=24, textColor=ink)
    heading = ParagraphStyle("heading", fontName="Helvetica-Bold", fontSize=11,
                             leading=14, textColor=ink, spaceBefore=14,
                             spaceAfter=6)
    body = ParagraphStyle("body", fontName="Helvetica", fontSize=9,
                          leading=12, textColor=soft)
    verdict_style = ParagraphStyle("verdict", parent=body, fontSize=13,
                                   leading=16, fontName="Helvetica-Bold",
                                   textColor=red if flagged else green)
    cell = ParagraphStyle("cell", fontName="Helvetica", fontSize=7,
                          leading=8, textColor=ink)
    cell_small = ParagraphStyle("cell_small", parent=cell,
                                fontName="Courier", fontSize=6.5)
    head_cell = ParagraphStyle("head", parent=cell, fontName="Helvetica-Bold",
                               textColor=soft)

    story = [Paragraph("Airlock — forensic report", title)]
    if device:
        bits = [device.get("devnode", ""),
                device.get("size_human") or device.get("size", ""),
                " ".join(filter(None, [device.get("vendor", ""),
                                       device.get("model", "")]))]
        story.append(Paragraph(_pdf_text("  ·  ".join(b for b in bits if b)
                                        + f"  ·  exported "
                                        f"{time.strftime('%Y-%m-%d %H:%M')}"),
                               body))
    story.append(Spacer(1, 6))
    if flagged:
        story.append(Paragraph(
            _pdf_text(f"{len(flagged)} of {len(rows)} files flagged as malicious"),
            verdict_style))
    elif unknown:
        story.append(Paragraph(
            _pdf_text(f"nothing flagged · {unknown} hashes never seen by "
                      "VirusTotal"), verdict_style))
    else:
        story.append(Paragraph(
            _pdf_text(f"nothing flagged in {len(rows)} files"), verdict_style))

    stats = [["files", "flagged", "clean", "unknown", "hashed", "errors",
              "seconds"],
             [str(summary.get("files", len(rows))), str(len(flagged)),
              str(clean), str(unknown), str(summary.get("hashed", "")),
              str(summary.get("errors", "")), str(summary.get("seconds", ""))]]
    stats_table = Table(stats, colWidths=[30 * mm] * 7)
    stats_table.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (-1, 0), faint),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 1), (-1, 1), ink),
        ("LINEABOVE", (0, 1), (-1, 1), 1, line),
        ("LINEBELOW", (0, 1), (-1, 1), 1, line),
    ]))
    story += [Spacer(1, 8), stats_table]

    if flagged:
        story.append(Paragraph("Flagged files", heading))
        for row in flagged:
            engines = ", ".join(
                f"{engine.get('engine')}: {engine.get('result')}"
                for engine in (row.get("engines") or [])[:5])
            detail = (f"{row.get('detections', 0)}/{row.get('scanned', 0)} engines"
                      + (f" · {engines}" if engines else "")
                      + (f" · {row.get('vt_name', '')}" if row.get("vt_name") else ""))
            story.append(Paragraph(
                f"<b>{_pdf_text(row.get('path', '-'))}</b> — {_pdf_text(detail)}",
                body))

    story.append(Paragraph("Every file", heading))
    table_rows = [[Paragraph(f"<b>{head}</b>", head_cell)
                   for head in ("verdict", "det", "size", "hidden",
                                "path", "sha256", "note")]]
    for row in rows:
        name = row.get("virustotal") or "not checked"
        table_rows.append([
            Paragraph(_pdf_text(name), cell),
            Paragraph(_pdf_text(f"{row.get('detections', 0)}/"
                                f"{row.get('scanned', 0)}"
                                if row.get("scanned") else "-"), cell),
            Paragraph(_pdf_text(row.get("size", "")), cell),
            Paragraph("attr" if row.get("hidden")
                      else ("dot" if row.get("hidden_dot") else ""), cell),
            Paragraph(_pdf_text(row.get("path", "")), cell),
            Paragraph(_pdf_text((row.get("sha256") or "")[:20]), cell_small),
            Paragraph(_pdf_text(row.get("vt_error")
                                or (row.get("vt_name")
                                    if name == "malicious" else name)), cell),
        ])
    widths = [28 * mm, 16 * mm, 20 * mm, 14 * mm, 105 * mm, 32 * mm, 55 * mm]
    table = Table(table_rows, colWidths=widths, repeatRows=1)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.4, line),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1),
              [colors.white, colors.HexColor("#f6f4ee")])]
    for index, row in enumerate(rows, start=1):
        if row.get("virustotal") == "malicious":
            style.append(("BACKGROUND", (0, index), (-1, index),
                          colors.HexColor("#fbe9e7")))
    table.setStyle(TableStyle(style))
    story.append(table)
    doc.build(story)
    return buffer.getvalue()


class Actions:
    """The privileged half of the app.

    Everything here is deliberately slow-moving: each call reports progress into
    the event log so the UI can show what is happening while libvirt works.
    """

    def __init__(self, state: TriageState):
        self.state = state
        self._vm = None
        self._listener = None
        self._scan_thread = None
        self._boot_thread = None
        self._build_thread = None
        self._build_log: collections.deque = collections.deque(maxlen=200)
        self._build_error: str = ""
        self._env_checks: list = []
        self._env_at: float = 0.0
        self._reconcile_lock = threading.Lock()

    @property
    def vm(self):
        # imported late so the state machine can be used without libvirt present
        if self._vm is None:
            import triage_vm
            self._vm = triage_vm.TriageVM()
        return self._vm

    @property
    def listener(self):
        if self._listener is None:
            import device_listener
            self._listener = device_listener.StorageListener(
                on_device=self.device_arrived,
                on_remove=self.device_removed,
                on_note=lambda text, level="info": self.state.say(text, level=level))
        return self._listener

    def start_listener(self) -> None:
        """Begins watching for storage. Devices already here are ignored."""
        self.listener.start()

    # -- the device listener ------------------------------------------------

    def device_arrived(self, device) -> None:
        """A new disk showed up. Never interrupts work in progress."""
        if self.state.state in ts.TERMINAL_BUSY:
            self.state.say(
                f"{device.devnode} arrived while {self.state.state}: "
                f"ignored until this investigation is closed", "warn")
            return
        current = self.state.device
        if current and current.devnode != device.devnode:
            self.state.say(
                f"{device.devnode} arrived while {current.devnode} is the subject; "
                f"forget it first", "warn")
            return
        self.state.set_device(device)
        self.state.move(ts.DEVICE_FOUND,
                        f"{device.devnode} arrived", force=True)
        self.state.say(
            f"{device.devnode} {device.info.get('size_human', '')} "
            f"{device.bus} {device.model}".strip(), "info")
        self.auto_start_vm()

    def auto_start_vm(self) -> None:
        """Boots the guest in the background because storage was detected.

        Off the listener thread on purpose: a boot takes tens of seconds and the
        listener has to keep watching for the disk being pulled back out. If the
        VM is already up there is nothing to do, and if a boot is already in
        flight this returns rather than starting a second one.
        """
        if not AUTO_START or self.state.state != ts.DEVICE_FOUND:
            return
        if self.state.vm.get("running"):
            self.state.say("the VM is already running", "info")
            return
        if self._boot_thread is not None and self._boot_thread.is_alive():
            return
        self._boot_thread = threading.Thread(target=self._boot_worker,
                                             name="auto-boot", daemon=True)
        self._boot_thread.start()

    def _boot_worker(self) -> None:
        """The auto-start body, so a slow boot cannot block a request thread."""
        node = self.state.device.devnode if self.state.device else "the device"
        self.state.say(f"starting the VM automatically for {node}", "info")
        code, message = self.start_vm()
        if code != 200:
            self.state.say(f"the automatic start failed: {message}", "error")
        else:
            self.state.move(ts.DEVICE_FOUND,
                            f"{node} is ready to send to the VM", force=True)

    def forget_device(self, device: str = "") -> tuple:
        current = self.state.device
        if current is not None:
            # a disk still inside the guest has to come back out before the app
            # can honestly say the host is not sharing it any more
            self.detach_device(current.devnode)
            self.state.set_device(None)
            if self.listener is not None:
                self.listener.devices.pop(current.devnode, None)
        self.state.move(ts.READY if self.state.vm.get("running") else ts.IDLE,
                        "device forgotten", force=True)
        return 200, "the device was forgotten"

    # -- environment setup ----------------------------------------------------

    def environment_status(self) -> dict:
        """What the settings page shows: one check per prerequisite, the build
        state, and whether the user has flagged this machine as configured."""
        now = time.monotonic()
        if now - self._env_at > ENV_CACHE_SECONDS or not self._env_checks:
            self._env_checks = self._environment_checks()
            self._env_at = now
        try:
            stamp = CONFIGURED_FILE.read_text().strip()
        except OSError:
            stamp = ""
        build_thread = self._build_thread
        return {
            "checks": self._env_checks,
            "ready": all(check["ok"] for check in self._env_checks),
            "configured": bool(stamp),
            "configured_at": stamp,
            "build": {
                "running": bool(build_thread is not None and build_thread.is_alive()),
                "error": self._build_error,
                "log": list(self._build_log)[-40:],
            },
        }

    def _environment_checks(self) -> list:
        """Each prerequisite on its own, so one red line says exactly what to
        fix. Nothing here may raise: a check that cannot even run is a failed
        check, not a crashed settings page."""
        import os
        checks = []

        def check(id: str, label: str, func):
            try:
                ok, detail = func()
            except Exception as exc:                  # noqa: BLE001
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            checks.append({"id": id, "label": label, "ok": bool(ok),
                           "detail": detail or ""})

        def files():
            import triage_vm
            missing = [str(target) for target in
                       (triage_vm.GOLDEN, triage_vm.INITRAMFS, triage_vm.KEY)
                       if not target.exists()]
            if missing:
                return False, "missing: " + ", ".join(missing)
            return True, "golden image, initramfs and ssh key are staged"

        def libvirt():
            import triage_vm
            import libvirt_vm as lv
            problems = lv.access_problems(lv.default_kernel(),
                                          str(triage_vm.INITRAMFS))
            if problems:
                return False, "; ".join(problems)
            return True, "libvirt can read the boot files"

        def vt_key():
            if virustotal.read_key():
                return True, "a key is stored outside the repository"
            return False, ("no key: put one in ~/.config/triage/virustotal "
                           "(mode 600) or set TRIAGE_VT_KEY")

        def buildable():
            import shutil
            if os.geteuid() == 0:
                return True, "running as root, so it builds directly"
            if shutil.which("fakeroot"):
                return True, ("fakeroot stands in for root: ownership in "
                               "the image is still correct")
            return False, ("neither root nor fakeroot: install fakeroot "
                           "or run the app as root to build (scanning "
                           "needs neither)")

        check("files", "Guest image staged", files)
        check("libvirt", "Libvirt can boot it", libvirt)
        check("virustotal", "VirusTotal key present", vt_key)
        check("build", "Can build the image", buildable)
        return checks

    def start_build(self) -> tuple:
        """Rebuilds the golden image in the background. Refused while anything
        runs off the current image, and while a build is already going."""
        thread = self._build_thread
        if thread is not None and thread.is_alive():
            return 409, "a build is already running"
        if self.state.vm.get("running") or self.state.snapshot()["busy"]:
            return 409, ("stop the VM and finish or forget the device first: "
                         "rebuilding under a running guest is not safe")
        self._build_error = ""
        self._build_log.clear()
        self._build_thread = threading.Thread(target=self._build_worker,
                                              name="build-image", daemon=True)
        self._build_thread.start()
        return 202, "building the golden image in the background"

    def _build_worker(self) -> None:
        import triage_vm
        self.state.say("building the golden image; this takes minutes", "info")
        try:
            triage_vm.build_image(progress=self._build_log.append)
        except Exception as exc:                      # noqa: BLE001
            self._build_error = str(exc)[:300]
            self.state.say(f"the build failed: {exc}", "error")
            return
        self._env_at = 0.0               # the file checks are stale now
        self.state.say("the golden image is built", "info")

    def set_configured(self, configured: bool) -> tuple:
        """The user's sign-off that this machine is ready. A timestamp, so a
        stale flag from a previous install is at least visibly old."""
        try:
            if configured:
                CONFIGURED_FILE.parent.mkdir(parents=True, exist_ok=True)
                CONFIGURED_FILE.write_text(time.strftime("%Y-%m-%d %H:%M %Z"))
            elif CONFIGURED_FILE.exists():
                CONFIGURED_FILE.unlink()
        except OSError as exc:
            return 500, f"could not write the flag: {exc}"
        return 200, ("environment flagged as configured"
                     if configured else "configuration flag cleared")

    def device_removed(self, devnode: str) -> None:
        """The subject disk was unplugged: stop everything and start over.

        Runs on the listener thread, so it must never raise. The VM is
        destroyed (its disk is physically gone, so there is nothing to detach
        gracefully), the device, report and scan progress are cleared, and the
        UI falls back to waiting for the next device.
        """
        try:
            current = self.state.device
            if current is None or current.devnode != devnode:
                return                    # some other disk; the note already said so
            self.state.say(f"{devnode} was unplugged; stopping the VM and "
                           "starting over", "warn")
            try:
                info = self.vm.stop(detach_first=True)
                self.state.set_vm(**info)
            except Exception as exc:      # noqa: BLE001
                # the domain may already be gone; the reset below matters more
                self.state.say(f"the VM did not stop cleanly: {exc}", "error")
                self.state.set_vm(running=False, ssh_ok=False)
            self.state.set_report(None)   # also clears the scan progress
            self.state.set_device(None)
            self.state.move(ts.IDLE, "waiting for a device", force=True)
        except Exception as exc:          # noqa: BLE001
            # a reset that crashes the listener thread would blind the app to
            # every future device, which is worse than a dirty state
            try:
                self.state.say(f"reset after unplug failed: {exc}", "error")
            except Exception:             # noqa: BLE001
                pass

    # -- keeping the state honest -------------------------------------------

    def reconcile(self) -> None:
        """Corrects the state machine when the VM changed outside the app.

        Without this the UI can claim a VM is running after someone destroyed it
        at the shell, which is the kind of lie that loses trust in a tool whose
        whole job is telling you what is really attached.
        """
        if not self._reconcile_lock.acquire(blocking=False):
            return
        try:
            current = self.state.state
            if current in (ts.BOOTING_VM, ts.TEARING_DOWN, ts.ATTACHING, ts.SCANNING):
                return
            if current == ts.ATTACHED and not self.vm.guest_has_disk():
                # the disk was pulled out of the guest, or the guest is gone
                self.state.set_device(None)
                self.state.move(ts.READY,
                                "the disk is no longer in the VM", force=True,
                                level="warn")
                return
            claimed = bool(self.state.vm.get("running"))
            try:
                actual = self.vm.is_running()
            except Exception:                          # noqa: BLE001
                return
            if claimed and not actual:
                self.state.set_vm(running=False, ssh_ok=False)
                # destroying the guest closed its side of the disk, so the host is
                # no longer sharing it and there is nothing left to investigate
                self.state.set_device(None)
                self.state.move(ts.ERROR,
                                "the VM stopped outside the app; nothing is attached "
                                "any more", force=True, level="error")
            elif actual and not claimed:
                import triage_vm
                # start() on a running domain only runs the ssh gate, so this
                # adopts the VM and proves it is really reachable
                self.state.say("a VM is already running; checking ssh", "warn")
                try:
                    info = self.vm.start(progress=lambda message: None)
                    message = "adopted the VM that was already running"
                except Exception as exc:                 # noqa: BLE001
                    info = {"name": triage_vm.DOMAIN, "running": True, "ssh_ok": False,
                            "host": triage_vm.GUEST_IP, "port": triage_vm.SSH_PORT}
                    message = f"adopted the VM but could not verify ssh: {exc}"
                self.state.set_vm(**info)
                self.state.move(ts.READY, message, force=True, level="warn")
        finally:
            self._reconcile_lock.release()

    def start_vm(self, device: str = "") -> tuple:
        self.state.move(ts.BOOTING_VM, "starting the VM with no storage attached")

        def progress(message):
            self.state.say(message)

        try:
            info = self.vm.start(progress=progress)
        except Exception as exc:                        # noqa: BLE001
            self.state.set_vm(running=self.vm.is_running(), ssh_ok=False)
            self.state.move(ts.ERROR, str(exc), force=True, level="error")
            return 500, str(exc)
        self.state.set_vm(**info)
        self.state.move(ts.READY, "VM ready - plug in a storage device", force=True)
        return 200, "the VM is up and ssh answered"

    def stop_vm(self, device: str = "") -> tuple:
        self.state.move(ts.TEARING_DOWN, "destroying the VM")
        try:
            info = self.vm.stop()
        except Exception as exc:                        # noqa: BLE001
            if self.state.state == ts.TEARING_DOWN:
                self.state.move(ts.ERROR, str(exc), force=True, level="error")
            return 500, str(exc)
        self.state.set_vm(**info)
        self.state.set_device(None)
        self.state.move(ts.IDLE, "VM stopped", force=True)
        return 200, "the VM was destroyed"

    def send_to_vm(self, device: str = "") -> tuple:
        """Hands the subject disk to the guest, read-only, and verifies it landed."""
        current = self.state.device
        if current is None:
            return 409, "there is no device to send"
        if device and device != current.devnode:
            return 409, f"the subject is {current.devnode}, not {device}"
        node = current.devnode
        if not self.state.vm.get("ssh_ok"):
            # the ssh gate in front of every disk handoff, checked again here
            return 409, "the VM must be up with ssh before anything is attached"
        self.state.move(ts.ATTACHING, f"handing {node} to the VM, read-only")

        def progress(message):
            self.state.say(message)

        try:
            result = self.vm.attach(node, progress=progress)
        except Exception as exc:                        # noqa: BLE001
            if self.state.state == ts.ATTACHING:        # unless it was stopped
                self.state.move(ts.ERROR, str(exc), force=True, level="error")
            return 500, str(exc)
        self.state.note_attachment(result["guest_node"])
        self.state.move(ts.ATTACHED,
                        f"{node} is in the VM as {result['guest_node']}, read-only")
        return 200, f"{node} is in the VM as {result['guest_node']}, read-only"

    def detach_device(self, device: str = "", progress=None) -> None:
        """Takes the disk back out of the guest, so the host stops sharing it."""
        try:
            result = self.vm.detach(device, progress=progress)
        except Exception as exc:                        # noqa: BLE001
            self.state.say(f"could not detach the disk from the VM: {exc}", "error")
            return
        self.state.say(result.get("detail", "the disk is back with the host"))

    def scan_device(self, device: str = "") -> tuple:
        """Runs the collector in the guest and brings the report back."""
        current = self.state.device
        if current is None or not current.guest_node:
            return 409, "send the device to the VM first"
        if self._scan_thread is not None and self._scan_thread.is_alive():
            return 409, "a scan is already running"
        self.state.set_report(None)
        self.state.set_scan(node=current.guest_node, entries=0, running=True)
        self.state.move(ts.SCANNING,
                        f"scanning {current.guest_node} inside the guest")
        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(current.guest_node,),
            name="scan", daemon=True)
        self._scan_thread.start()
        return 200, f"scanning {current.guest_node} inside the guest"

    def _scan_worker(self, node: str) -> None:
        """The long part, off the request thread so the UI keeps polling."""
        try:
            report = self._collect(node)
        except Exception as exc:                        # noqa: BLE001
            self.state.set_scan(running=False)
            if self.state.state == ts.SCANNING:         # the VM may have gone
                self.state.move(ts.ERROR, f"the scan failed: {exc}",
                                force=True, level="error")
            return
        if self.state.state != ts.SCANNING:
            # the disk was unplugged mid-scan and the app already reset: no
            # VirusTotal quota on a disk that is gone, and no report for it
            return
        self._enrich(report)
        if self.state.state != ts.SCANNING:
            return                     # removed while the hashes were checked
        self.state.set_report(report)
        summary = report["summary"]
        self.state.move(ts.RESULTS,
                        f"scan of {node} finished: {summary['entries']} entries, "
                        f"{summary['files']} files, {summary['errors']} errors",
                        force=True)

    def _collector_gone(self) -> bool:
        """True when the collector process is no longer there but never printed
        its completion marker, which means it died rather than finished."""
        probe = self._guest(
            "if pgrep -f guest_collector.py > /dev/null 2>&1; "
            "then echo RUNNING; else echo GONE; fi", timeout=30)
        return "GONE" in (probe.stdout or "")

    def _enrich(self, report: dict) -> None:
        """Looks up each file hash on VirusTotal, from the host.

        The hashes go out, not the files. Rows that share a hash share an
        answer, and nothing here can change the state the scan ended in - a
        lookup failure is shown in the report, not raised.
        """
        key = virustotal.read_key()
        if not key:
            report["summary"]["virustotal"] = "not configured"
            return
        rows = report["rows"]
        hashes = [row["sha256"] for row in rows if row["sha256"]]
        unhashed = sum(1 for row in rows if not row["sha256"])
        self.state.set_scan(vt_total=len(hashes))
        self.state.say(
            f"checking {len(hashes)} file hashes on VirusTotal from the host "
            "(hashes only, no file content leaves this machine)", "info")
        client = virustotal.VirusTotal(key)

        def progress(done: int, counters: dict) -> None:
            self.state.set_scan(vt_done=done, vt_flagged=counters["malicious"])

        limit = virustotal.VT_LIMIT or None
        try:
            results, counters = client.lookup_many(hashes, cap=limit,
                                                   progress=progress)
        except Exception as exc:                        # noqa: BLE001
            report["summary"]["virustotal"] = f"failed: {exc}"[:200]
            return
        for row in rows:
            found = results.get(row["sha256"])
            if found is None:
                # a hash with no verdict is shown as one, never as clean
                row["virustotal"] = ("skipped" if row["sha256"] else "no hash")
            else:
                row["virustotal"] = found.get("status", "error")
                row["detections"] = found.get("detections", 0)
                row["scanned"] = found.get("scanned", 0)
                row["engines"] = found.get("engines", [])
                row["vt_name"] = found.get("meaningful_name", "")
                row["vt_link"] = found.get("permalink", "")
                row["vt_error"] = found.get("error")
        report["summary"]["virustotal"] = virustotal.counters_label(counters)
        if unhashed:
            report["summary"]["unhashed"] = unhashed
        if counters.get("skipped"):
            report["summary"]["vt_not_checked"] = counters["skipped"]
        self.state.set_scan(vt_done=counters["checked"], vt_flagged=counters["malicious"],
                            running=True)
        self.state.say(f"VirusTotal: {report['summary']['virustotal']}",
                       "warn" if counters["malicious"] or counters["errors"] else "info")

    def _guest(self, command: str, timeout: int = 60):
        import triage_vm                       # late, like Actions.vm, so the
        return self.vm.vms.ssh_run(triage_vm.DOMAIN, command,
                                   port=triage_vm.SSH_PORT, key=str(triage_vm.KEY),
                                   host=triage_vm.GUEST_IP, timeout=timeout)

    def _collect(self, node: str, poll: float = 3.0) -> dict:
        """Starts the collector in the guest, watches it, reads the report back.

        The collector is started detached inside the guest so one dropped ssh
        connection does not lose a scan that has already been running for an
        hour, and so its progress can be counted while it works.
        """
        start = self._guest(
            "mkdir -p /var/lib/triage && rm -f /var/lib/triage/report.jsonl "
            "/var/lib/triage/scan.out && "
            "setsid python3 /usr/local/bin/guest_collector.py "
            f"--report=/var/lib/triage/report.jsonl {node} "
            ">/var/lib/triage/scan.out 2>&1 </dev/null & "
            "sleep 2; echo STARTED", timeout=30)
        if not start.ok or "STARTED" not in (start.stdout or ""):
            raise RuntimeError(
                "the collector did not start in the guest:\n"
                f"{start.output or 'no answer over ssh'}")
        self.state.say("the collector is running in the guest", "info")

        deadline = time.monotonic() + SCAN_TIMEOUT
        last_report = 0
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"the collector was still running after {SCAN_TIMEOUT // 60} "
                    "minutes; stop the VM to end it")
            probe = self._guest(
                f"if [ -f /var/lib/triage/scan.out ] && "
                f"grep -q {COLLECTOR_MARKER} /var/lib/triage/scan.out; "
                "then echo FINISHED; fi; "
                f"wc -l < /var/lib/triage/report.jsonl 2>/dev/null || echo 0",
                timeout=30)
            output = (probe.stdout or "").split()
            if probe.ok and output and output[-1].isdigit():
                lines = int(output[-1])
                if lines != last_report:
                    last_report = lines
                    self.state.set_scan(entries=lines)
            elif not probe.ok:
                # a broken probe used to look exactly like a slow scan, and the
                # wait then ran out an hour later with nothing to show
                raise RuntimeError(
                    f"lost sight of the collector while it ran:\n{probe.output}")
            if "FINISHED" in output:
                break
            if self._collector_gone():
                tail = self._guest(f"tail -n 8 /var/lib/triage/scan.out",
                                   timeout=30)
                raise RuntimeError(
                    "the collector stopped without finishing:\n"
                    f"{(tail.stdout or tail.output or '').strip()}")
            time.sleep(poll)

        raw = self._guest("cat /var/lib/triage/report.jsonl", timeout=300)
        if not raw.ok:
            raise RuntimeError(f"could not read the report back:\n{raw.output}")
        tail = self._guest("tail -n 5 /var/lib/triage/scan.out", timeout=30)
        self.state.say((tail.stdout or "").strip(), "info")
        return parse_report(raw.stdout)

    def close_results(self, device: str = "") -> tuple:
        self.state.set_report(None)
        self.state.move(ts.ATTACHED, "results closed", force=True)
        return 200, "results closed"


class Handler(BaseHTTPRequestHandler):
    server_version = "airlock/1.0"
    protocol_version = "HTTP/1.1"

    # set by serve()
    state: TriageState
    actions: Actions
    token: str

    # -- helpers ------------------------------------------------------------

    def log_message(self, fmt, *args):  # quieter than the default stderr spam
        pass

    def handle_one_request(self):
        # a browser that closes the connection mid-request is normal traffic,
        # not something worth a traceback in the log
        try:
            super().handle_one_request()
        except (ConnectionError, TimeoutError):
            self.close_connection = True

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass                    # the browser navigated away; not an error

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def _authorised(self) -> bool:
        if self.headers.get("X-Triage-Token") != self.token:
            self._json(403, {"error": "bad or missing session token"})
            return False
        return True

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode() or "{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    # -- routes -------------------------------------------------------------

    def do_GET(self):
        route = urlparse(self.path)
        if route.path == "/live":
            return self._websocket(route)
        if route.path in ("/", "/index.html"):
            return self._static("index.html")
        if route.path.startswith("/static/"):
            return self._static(route.path[len("/static/"):])
        if route.path.startswith("/docs/"):
            return self._docs(route.path[len("/docs/"):])
        if route.path == "/api/report.pdf":
            return self._report_pdf(parse_qs(route.query))
        if route.path == "/api/settings":
            return self._settings(parse_qs(route.query))
        if route.path == "/api/settings/build":
            return self._settings_build(parse_qs(route.query))
        if route.path == "/api/settings/configured":
            return self._settings_configured(parse_qs(route.query))
        if route.path == "/api/state":
            snapshot = self.state.snapshot()
            try:
                environment = self.actions.environment_status()
                snapshot["environment"] = {
                    "configured": environment["configured"],
                    "ready": environment["ready"]}
            except Exception:                         # noqa: BLE001
                snapshot["environment"] = {"configured": False,
                                           "ready": False}
            listener = self.actions._listener
            snapshot["listener"] = (listener.status() if listener is not None
                                   else {"listening": False, "baseline": [],
                                         "seen": [], "devices": [],
                                         "started_at": 0, "error": ""})
            return self._json(200, snapshot)
        if route.path == "/api/events":
            query = parse_qs(route.query)
            since = int((query.get("since") or ["0"])[0] or 0)
            return self._json(200, {"events": self.state.events_since(since)})
        if route.path == "/api/health":
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "no such page"})

    def do_POST(self):
        route = urlparse(self.path).path
        # settings are outside the state machine: no allowed-actions gating,
        # just the session token
        if route == "/api/settings/build":
            return self._settings_build(parse_qs(urlparse(self.path).query))
        if route == "/api/settings/configured":
            return self._settings_configured(parse_qs(urlparse(self.path).query))
        if not self._authorised():
            return None
        body = self._body()
        action = route.rsplit("/", 1)[-1]
        if not hasattr(self.actions, action):
            return self._json(404, {"error": f"unknown action {action!r}"})
        if action not in self.state.snapshot()["allowed_actions"]:
            self.state.reject(f"{action} is not available while "
                              f"{self.state.snapshot()['state']}")
            return self._json(409, {"error": f"{action} is not allowed right now",
                                    "state": self.state.snapshot()})
        try:
            code, message = getattr(self.actions, action)(body.get("device", ""))
        except Exception as exc:                      # noqa: BLE001
            self.state.move("error", str(exc), force=True, level="error")
            return self._json(500, {"error": str(exc)})
        return self._json(code, {"message": message, "state": self.state.snapshot()})

    def _settings_token(self, query: dict):
        provided = self.headers.get("X-Triage-Token") or \
            (query.get("token") or [None])[0]
        if not live_feed.token_ok(provided, self.token):
            self._json(403, {"error": "bad or missing session token"})
            return None
        return True

    def _settings(self, query: dict) -> None:
        if not self._settings_token(query):
            return None
        return self._json(200, self.actions.environment_status())

    def _settings_build(self, query: dict) -> None:
        if not self._settings_token(query):
            return None
        if self.command != "POST":
            return self._json(405, {"error": "build with POST"})
        code, message = self.actions.start_build()
        status = self.actions.environment_status()
        if code == 202:
            return self._json(202, {"message": message, "build": status["build"]})
        return self._json(code, {"error": message})

    def _settings_configured(self, query: dict) -> None:
        if not self._settings_token(query):
            return None
        if self.command != "POST":
            return self._json(405, {"error": "flag with POST"})
        try:
            configured = bool(self._body().get("configured", True))
        except (ValueError, AttributeError):
            configured = True
        code, message = self.actions.set_configured(configured)
        status = self.actions.environment_status()
        key = "message" if code == 200 else "error"
        payload = {key: message, "configured": status["configured"],
                   "configured_at": status["configured_at"]}
        return self._json(code, payload)

    def _report_pdf(self, query: dict) -> None:
        """The download. The token can ride in a header or the query string,
        because a plain link cannot carry a header."""
        provided = self.headers.get("X-Triage-Token") or \
            (query.get("token") or [None])[0]
        if not live_feed.token_ok(provided, self.token):
            return self._json(403, {"error": "bad or missing session token"})
        report = self.state.snapshot()["report"]
        if not report:
            return self._json(404, {"error": "there is no report to export yet"})
        device = self.state.snapshot()["device"]
        body = report_pdf(report, device)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        slug = (device.get("devnode") or "device").replace("/", "-") if device else "device"
        name = f"airlock-{slug}-{stamp}.pdf"
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _websocket(self, route) -> None:
        """Upgrades to a websocket and hands the socket to the live feed.

        The token is required here for the same reason it is required on POST:
        this connection can drive the whole UI, so an unauthenticated one would
        be a way to start VMs and attach disks from any page in a browser.
        """
        key = self.headers.get("Sec-WebSocket-Key")
        if (self.headers.get("Upgrade", "").lower() != "websocket" or not key
                or self.headers.get("Sec-WebSocket-Version") != "13"):
            return self._json(400, {"error": "this endpoint expects a websocket"})
        provided = (parse_qs(route.query).get("token") or [None])[0]
        if not live_feed.token_ok(provided, self.token):
            return self._json(403, {"error": "bad or missing session token"})
        self.close_connection = True
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", live_feed.accept_key(key))
        self.end_headers()
        self.wfile.flush()
        try:
            live_feed.serve(self.server.feed, self.connection, self.token)
        except (ConnectionError, OSError):
            pass

    def _static(self, name: str):
        return self._serve_file(WEBUI, name, tokenize=True)

    def _docs(self, name: str):
        return self._serve_file(DOCS, name)

    def _serve_file(self, base: Path, name: str, tokenize: bool = False):
        # keep requests inside base/ no matter what the path contains
        target = (base / name).resolve()
        if not str(target).startswith(str(base.resolve())) or not target.is_file():
            return self._json(404, {"error": "no such file"})
        kind = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        body = target.read_bytes()
        if tokenize and target.name == "index.html":
            body = body.replace(b"__TOKEN__", self.token.encode())
            # the UI is cached by the browser, and a stale app.js against a new
            # page is a frozen UI: it throws on the first render and never
            # updates again. Versioning by mtime makes every deploy land whole.
            for asset in ("app.js", "style.css"):
                try:
                    version = int((WEBUI / asset).stat().st_mtime)
                except OSError:
                    continue
                body = body.replace(f"/static/{asset}".encode(),
                                    f"/static/{asset}?v={version}".encode())
        return self._send(200, body, kind)


def serve(state: TriageState | None = None, actions: Actions | None = None,
          port: int = DEFAULT_PORT, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    """Builds the server without starting it, so it can be tested or embedded."""
    state = state if state is not None else TriageState()
    handler = type("BoundHandler", (Handler,), {
        "state": state,
        "actions": actions if actions is not None else Actions(state),
        "token": secrets.token_urlsafe(24),
    })
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.state = state
    server.actions = server.RequestHandlerClass.actions
    server.feed = live_feed.LiveFeed(state.snapshot)
    state.attach_feed(server.feed)
    return server


def background_loop(actions: Actions, interval: float = 5.0) -> threading.Thread:
    """Keeps the state machine honest about what is really running.

    Nothing else in the app can notice a VM that was destroyed at the shell, and
    a status display that lies about what is attached is worse than no display.
    """

    def run() -> None:
        reported = ""
        while True:
            try:
                actions.reconcile()
            except Exception as exc:                   # noqa: BLE001
                # never die quietly: a reconcile that stops working means the
                # status display starts lying again
                detail = f"{type(exc).__name__}: {exc}"
                if detail != reported:
                    reported = detail
                    actions.state.say(f"reconcile failed: {detail}", "error")
                    print(f"reconcile failed: {detail}", file=sys.stderr, flush=True)
            time.sleep(interval)

    thread = threading.Thread(target=run, name="reconcile", daemon=True)
    thread.start()
    return thread


def stop_vm_on_exit(actions) -> None:
    """Best effort: never leave the guest running behind a stopped app.

    The guest is disposable and the disk is read-only, but a VM left running
    with a case disk attached is exactly the thing this app exists to prevent,
    so the exit path destroys it even if the stop button was never pressed.
    """
    try:
        if not actions.vm.is_running():
            return
        actions.state.move(ts.TEARING_DOWN, "stopping the VM: the app is exiting",
                           force=True)
        info = actions.vm.stop()
        actions.state.set_vm(**info)
        actions.state.set_device(None)
        actions.state.move(ts.IDLE, "VM stopped because the app exited",
                           force=True)
        print("triage web ui: stopped the VM on exit")
    except Exception as exc:                            # noqa: BLE001
        # say it loudly: a half-torn-down VM is the one thing here worth a
        # visible failure, and there is no state left to record it in
        print(f"triage web ui: FAILED to stop the VM on exit: {exc}")


def main() -> int:
    state = TriageState()
    actions = Actions(state)
    server = serve(state, actions)
    host, port = server.server_address[:2]
    state.say(f"web ui on http://{host}:{port}")
    print(f"triage web ui: http://{host}:{port}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actions.start_listener()
    background_loop(actions)
    # SIGTERM is what `kill` sends, and it does not raise KeyboardInterrupt, so
    # without this the app would exit on the default disposition and skip the
    # cleanup below - leaving the VM running
    def on_signal(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, on_signal)
    try:
        while thread.is_alive():
            thread.join(0.5)
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.shutdown()
        actions.listener.stop()
        stop_vm_on_exit(actions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())