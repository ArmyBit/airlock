#!/usr/bin/env python3
"""The single state machine behind the whole application.

One VM, one investigation at a time. Every part of the app - the web UI, the
device listener, the libvirt actions - reads and writes this one object, so
there is a single answer to "what is happening right now" and no way for two
parts of the app to disagree about it.

The states deliberately say what the *user* is allowed to do next, not what the
code is doing internally.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

# --- states ---------------------------------------------------------------

IDLE = "idle"                    # app just started
BOOTING_VM = "booting_vm"        # starting the VM, no storage attached
READY = "ready"                  # VM up, ssh proven, waiting for a device
DEVICE_FOUND = "device_found"    # device info shown, waiting for a choice
ATTACHING = "attaching"          # handing the disk to the VM
ATTACHED = "attached"            # the disk is in the guest, read-only
SCANNING = "scanning"            # collector running in the guest
RESULTS = "results"              # report available
TEARING_DOWN = "tearing_down"    # destroying the VM before the next case
ERROR = "error"                  # something failed; message explains what

# There is no host-mounted state: an evidence disk is never mounted on the host,
# only ever handed to the disposable guest read-only.
STATES = (IDLE, BOOTING_VM, READY, DEVICE_FOUND, ATTACHING, ATTACHED,
          SCANNING, RESULTS, TEARING_DOWN, ERROR)

# What the UI should enable in each state. Keeping this in one table means the
# buttons can never offer an action the machine cannot honour.
ALLOWED_ACTIONS = {
    IDLE: {"start_vm"},
    BOOTING_VM: set(),
    READY: {"stop_vm"},
    # a device can arrive before or after the VM boots, so both offers are here
    DEVICE_FOUND: {"start_vm", "stop_vm", "send_to_vm", "forget_device"},
    ATTACHING: set(),
    ATTACHED: {"scan_device", "stop_vm", "forget_device"},
    # stop_vm stays available so a wedged scan can always be ended
    SCANNING: {"stop_vm"},
    RESULTS: {"close_results", "stop_vm"},
    TEARING_DOWN: set(),
    ERROR: {"stop_vm", "forget_device"},
}

# Which transitions the machine allows. Anything not listed here is a bug and is
# refused, so a stale button click cannot push the app into an impossible state.
TRANSITIONS = {
    IDLE: {BOOTING_VM, DEVICE_FOUND, ERROR},
    BOOTING_VM: {READY, DEVICE_FOUND, ERROR},
    READY: {DEVICE_FOUND, TEARING_DOWN, ERROR},
    # tearing_down is allowed here because stop_vm is offered in this state
    DEVICE_FOUND: {ATTACHING, READY, BOOTING_VM, TEARING_DOWN, ERROR},
    ATTACHING: {ATTACHED, SCANNING, TEARING_DOWN, ERROR},
    ATTACHED: {SCANNING, DEVICE_FOUND, TEARING_DOWN, ERROR},
    SCANNING: {RESULTS, ERROR},
    RESULTS: {ATTACHED, TEARING_DOWN, ERROR, READY},
    TEARING_DOWN: {BOOTING_VM, IDLE, ERROR},
    ERROR: {BOOTING_VM, READY, IDLE, TEARING_DOWN},
}

TERMINAL_BUSY = (ATTACHING, ATTACHED, SCANNING, RESULTS, TEARING_DOWN)

# the event log is shown in the browser and streamed over the websocket, so it is
# bounded: a long-running case must not grow it without limit
MAX_EVENTS = 500
LOG_TAIL = 60


class StateError(Exception):
    """Raised when something asks for a transition the machine forbids."""


@dataclass
class Device:
    """A storage device that arrived after the app started."""

    devnode: str
    added: float = field(default_factory=time.time)
    model: str = ""
    serial: str = ""
    vendor: str = ""
    size: int = 0
    bus: str = ""
    fstype: str = ""
    label: str = ""
    guest_node: str = ""          # /dev/vdb once it is in the guest
    info: dict = field(default_factory=dict)

    @property
    def mountpoint(self) -> str:
        """Where the host has this disk mounted, if anywhere. Evidence must be
        unmounted on the host before it is handed over, so this is read-only
        information, never something the app sets."""
        return str(self.info.get("mountpoint", "") or "")

    def as_dict(self) -> dict:
        data = dict(self.__dict__)
        data["size_human"] = human_size(self.size)
        data["added_human"] = time.strftime("%H:%M:%S", time.localtime(self.added))
        return data


def human_size(num: int) -> str:
    step = 1024.0
    value = float(max(0, int(num or 0)))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < step or unit == "PiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= step
    return f"{value:.1f} PiB"


class TriageState:
    """Thread-safe holder for the current state, device and event log."""

    def __init__(self, log_size: int = 300):
        self._lock = threading.RLock()
        self._events = deque(maxlen=log_size)
        self._seq = 0
        self.state = IDLE
        self.message = "starting up"
        self.device: Device | None = None
        self.vm: dict = {"name": None, "running": False, "ssh_ok": False, "port": None}
        self.report: dict | None = None
        self.scan: dict = {}
        self.last_error: str = ""

    # -- reading ------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "state": self.state,
                "message": self.message,
                "allowed_actions": sorted(ALLOWED_ACTIONS.get(self.state, set())),
                "device": self.device.as_dict() if self.device else None,
                "vm": dict(self.vm),
                "report": self.report,
                "scan": dict(self.scan),
                "last_error": self.last_error,
                "busy": self.state in TERMINAL_BUSY,
                "seq": self._seq,
                # the tail of the log, so a page opened mid-scan starts with the
                # history instead of an empty box
                "events": list(self._events)[-LOG_TAIL:],
                "feed": getattr(self, "_feed", None) is not None,
            }

    def attach_feed(self, feed) -> None:
        """A live feed to push every change to. Attached after construction
        because the feed needs the snapshot function this object provides."""
        self._feed = feed

    def _notify(self, kind: str = "state", **fields) -> None:
        feed = getattr(self, "_feed", None)
        if feed is None:
            return
        try:
            if kind == "state":
                feed.publish_state()
            else:
                feed.publish(kind, **fields)
        except Exception:                # noqa: BLE001
            pass                        # a broken socket must never break the app

    def events_since(self, seq: int) -> list:
        with self._lock:
            return [e for e in self._events if e["seq"] > seq]

    # -- writing ------------------------------------------------------------

    def _log(self, text: str, level: str = "info") -> dict:
        self._seq += 1
        event = {
            "seq": self._seq,
            "ts": time.time(),
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "text": str(text),
        }
        self._events.append(event)
        while len(self._events) > MAX_EVENTS:
            self._events.popleft()
        return event

    def move(self, new_state: str, message: str = "", *, force: bool = False,
             level: str = "info") -> None:
        """Moves to ``new_state``, refusing transitions the machine disallows."""
        if new_state not in STATES:
            raise StateError(f"unknown state {new_state!r}")
        with self._lock:
            if new_state != self.state:
                allowed = TRANSITIONS.get(self.state, set())
                if new_state not in allowed and not force:
                    raise StateError(
                        f"cannot go from {self.state} to {new_state}; "
                        f"only {sorted(allowed)} are allowed")
                self.state = new_state
            if message:
                self.message = message
            if level == "error":
                self.last_error = message
            event = self._log(f"{new_state}: {message or self.message}", level)
        self._notify("state")
        self._notify("log", event=event)
        return self.snapshot()

    def say(self, text: str, level: str = "info") -> None:
        with self._lock:
            self.message = text
            event = self._log(text, level)
        self._notify("state")
        self._notify("log", event=event)

    def set_vm(self, **fields) -> None:
        with self._lock:
            self.vm.update(fields)
        self._notify()

    def set_device(self, device: Device | None) -> None:
        with self._lock:
            self.device = device
            if device is None:
                self.report = None
        self._notify()

    def note_attachment(self, guest_node: str) -> None:
        """Records where the subject disk turned up inside the guest."""
        with self._lock:
            if self.device is not None:
                self.device.guest_node = guest_node
        self._notify()

    def set_report(self, report: dict | None) -> None:
        with self._lock:
            self.report = report
            self.scan = {}
        self._notify()

    def set_scan(self, **fields) -> None:
        """Live progress while the collector runs, so a long scan is not a blank
        screen."""
        with self._lock:
            self.scan.update(fields)
        self._notify()

    def reject(self, reason: str) -> None:
        """Records a refused action without changing state."""
        with self._lock:
            event = self._log(reason, "warn")
        self._notify("log", event=event)