#!/usr/bin/env python3
"""Device hotplug monitoring backends: kernel uevents (netlink), pyudev, and a
privilege-free sysfs/udev-database poller.  All backends emit DeviceEvent
objects through a thread-safe queue so a GUI can consume them safely."""

from __future__ import annotations

import os
import queue
import socket
import threading
import time
from dataclasses import dataclass, field

NETLINK_KOBJECT_UEVENT = 1
KERNEL_EVENT_GROUP = 1

DEFAULT_SUBSYSTEMS = (
    "usb",
    "block",
    "net",
    "scsi",
    "tty",
    "input",
    "hidraw",
    "ieee80211",
    "sound",
    "media",
    "video4linux",
    "drm",
    "nvme",
    "pci",
    "usbmon",
)

SUBSYSTEM_GROUPS = {
    "USB": ("usb",),
    "Storage": ("block", "scsi", "nvme"),
    "Network": ("net", "ieee80211"),
    "Input/HID": ("input", "hidraw"),
    "Audio/Video": ("sound", "media", "video4linux", "drm"),
    "Serial": ("tty",),
    "PCI": ("pci",),
}

STORAGE_SUBSYSTEMS = ("block",)

PROFILES = {
    "storage": STORAGE_SUBSYSTEMS,
    "storage+usb": ("block", "usb"),
    "usb": ("usb",),
    "all": DEFAULT_SUBSYSTEMS,
}


def subsystems_for(profile: str):
    try:
        return PROFILES[profile]
    except KeyError:
        raise ValueError(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}") from None


@dataclass
class DeviceEvent:
    action: str
    subsystem: str
    name: str
    syspath: str
    bus: str = ""
    vendor: str = ""
    model: str = ""
    serial: str = ""
    devtype: str = ""
    devnode: str = ""
    devpath: str = ""
    detail: str = ""
    size: str = ""
    fstype: str = ""
    fslabel: str = ""
    fsuuid: str = ""
    removable: bool = False
    readonly: bool = False
    rotational: bool = False
    is_partition: bool = False
    properties: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def label(self) -> str:
        bits = [b for b in (self.vendor, self.model) if b]
        name = " ".join(bits) if bits else (self.devnode or self.name)
        return " ".join(b for b in (self.devtype, name) if b)

    @property
    def device(self) -> str:
        return self.devnode or self.name

    @property
    def is_storage(self) -> bool:
        return self.subsystem == "block"

    @property
    def location(self) -> str:
        return self.devpath or self.syspath

    @property
    def age(self) -> str:
        d = time.time() - self.timestamp
        if d < 60:
            return f"{d:.1f}s ago"
        if d < 3600:
            return f"{d / 60:.0f}m ago"
        return f"{d / 3600:.1f}h ago"


def parse_kv(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


def read_text(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def first_attr(syspath: str, *relatives: str) -> str:
    for rel in relatives:
        value = read_text(os.path.join(syspath, rel)).strip()
        if value:
            return value
    return ""


def udev_db_properties(root: str, subsystem: str, name: str, uevent: dict) -> dict:
    candidates = [os.path.join(root, "run", "udev", "data", subsystem, name)]
    major, minor = uevent.get("MAJOR"), uevent.get("MINOR")
    if major and minor and major.isdigit() and minor.isdigit():
        base = os.path.join(root, "run", "udev", "data")
        candidates.append(os.path.join(base, f"c{major}:{minor}"))
        candidates.append(os.path.join(base, f"b{major}:{minor}"))
    props = {}
    for path in candidates:
        raw = read_text(path)
        if raw:
            for line in raw.splitlines():
                if line.startswith("E:"):
                    key, sep, value = line[2:].partition("=")
                    if sep:
                        props[key] = value
            break
    return props


def describe(root: str, subsystem: str, name: str, syspath: str) -> dict:
    uevent = parse_kv(read_text(os.path.join(syspath, "uevent")))
    udev = udev_db_properties(root, subsystem, name, uevent)
    info = {
        "syspath": syspath,
        "vendor": first_attr(syspath, "vendor", "device/vendor") or udev.get("ID_VENDOR", ""),
        "model": first_attr(syspath, "model", "device/model") or udev.get("ID_MODEL", ""),
        "serial": (
            first_attr(syspath, "serial", "device/serial")
            or udev.get("ID_SERIAL_SHORT", "")
            or udev.get("ID_SERIAL", "")
        ),
        "bus": udev.get("ID_BUS", ""),
        "devtype": udev.get("ID_TYPE", ""),
        "devnode": uevent.get("DEVNAME") or udev.get("DEVNAME", ""),
        "devpath": udev.get("ID_PATH", "") or udev.get("ID_PATH_TAG", ""),
        "size": "",
        "fstype": udev.get("ID_FS_TYPE", ""),
        "fslabel": udev.get("ID_FS_LABEL", ""),
        "fsuuid": udev.get("ID_FS_UUID_ENC", "") or udev.get("ID_FS_UUID", ""),
        "removable": first_attr(syspath, "removable") == "1",
        "readonly": first_attr(syspath, "ro") == "1",
        "rotational": first_attr(syspath, "queue/rotational") == "1",
        "is_partition": first_attr(syspath, "partition").isdigit(),
        "detail": "",
        "properties": uevent,
        "udev": udev,
    }
    if subsystem == "block":
        devnode = info["devnode"]
        if devnode and not devnode.startswith("/"):
            info["devnode"] = f"/dev/{devnode}"
        sectors = first_attr(syspath, "size")
        if sectors.isdigit():
            info["size"] = _human_size(int(sectors) * 512)
        info["devtype"] = info["devtype"] or ("partition" if info["is_partition"] else "disk")
        bits = [b for b in (info["fstype"], f"label={info['fslabel']}" if info["fslabel"] else "") if b]
        if info["removable"]:
            bits.append("removable")
        if info["readonly"]:
            bits.append("read-only")
        info["detail"] = ", ".join(bits)
    elif subsystem == "net":
        mac = first_attr(syspath, "address")
        info["detail"] = f"iface={first_attr(syspath, 'ifindex') or '?'} mac={mac}"
    elif subsystem == "usb":
        product = uevent.get("PRODUCT", "")
        if ":" in product:
            info["detail"] = f"vid:pid={product}"
        if uevent.get("TYPE"):
            info["detail"] = f"type={uevent['TYPE']} {info['detail']}".strip()
    return info


def _human_size(num: int) -> str:
    step = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if step < 1024 or unit == "TiB":
            return f"{step:.0f} {unit}" if unit == "B" else f"{step:.1f} {unit}"
        step /= 1024
    return f"{step:.1f} TiB"


def _is_partition(root: str, name: str) -> bool:
    return bool(first_attr(os.path.join(root, "sys", "class", "block", name), "partition").isdigit())


def scan(root: str = "/", subsystems=DEFAULT_SUBSYSTEMS, include_partitions: bool = False) -> dict:
    snapshot = {}
    for subsystem in subsystems:
        base = os.path.join(root, "sys", "class", subsystem)
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for name in sorted(names):
            if subsystem == "block" and not include_partitions and _is_partition(root, name):
                continue
            try:
                syspath = os.path.realpath(os.path.join(base, name))
            except OSError:
                continue
            snapshot[f"{subsystem}/{name}"] = describe(root, subsystem, name, syspath)
    return snapshot


class Monitor:
    backend = "none"

    def __init__(self, root: str = "/", subsystems=DEFAULT_SUBSYSTEMS, include_partitions: bool = False):
        self.root = root
        self.subsystems = tuple(subsystems)
        self.include_partitions = include_partitions
        self.events: queue.Queue = queue.Queue()
        self.error: BaseException | None = None
        self.note: str = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        def target() -> None:
            try:
                self._run()
            except Exception as exc:
                self.error = exc

        self._thread = threading.Thread(target=target, name=f"udev-{self.backend}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> dict:
        return scan(self.root, self.subsystems, self.include_partitions)

    def _run(self) -> None:
        raise NotImplementedError

    def _emit(self, event: DeviceEvent) -> None:
        if event.subsystem == "block" and event.is_partition and not self.include_partitions:
            return
        self.events.put(event)

    def _event_from(self, action: str, subsystem: str, name: str, syspath: str, info: dict | None = None) -> DeviceEvent:
        info = info if info is not None else describe(self.root, subsystem, name, syspath)
        return DeviceEvent(
            action=action,
            subsystem=subsystem,
            name=name,
            syspath=syspath,
            bus=info["bus"],
            vendor=info["vendor"],
            model=info["model"],
            serial=info["serial"],
            devtype=info["devtype"],
            devnode=info["devnode"],
            devpath=info["devpath"],
            detail=info["detail"],
            size=info["size"],
            fstype=info["fstype"],
            fslabel=info["fslabel"],
            fsuuid=info["fsuuid"],
            removable=info["removable"],
            readonly=info["readonly"],
            rotational=info["rotational"],
            is_partition=info["is_partition"],
            properties=info["properties"],
        )


class NetlinkMonitor(Monitor):
    backend = "netlink (kernel uevent)"

    def _run(self) -> None:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
            sock.bind((0, 0))
            try:
                sock.bind((0, KERNEL_EVENT_GROUP))
            except PermissionError:
                sock.bind((0, 1))
            sock.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    data = sock.recv(1 << 17)
                except socket.timeout:
                    continue
                except OSError:
                    break
                for event in self._parse(data):
                    self._emit(event)
        finally:
            sock.close()

    def _parse(self, data: bytes):
        fields = parse_kv(data.decode("utf-8", "replace").replace("\x00", "\n"))
        action = fields.get("ACTION", "")
        subsystem = fields.get("SUBSYSTEM", "")
        devpath = fields.get("DEVPATH", "")
        if not action or not devpath or subsystem not in self.subsystems:
            return
        name = fields.get("DEVNAME") or fields.get("INTERFACE") or devpath.rsplit("/", 1)[-1]
        syspath = os.path.join(self.root, devpath.lstrip("/"))
        if not os.path.exists(syspath) and action == "remove":
            syspath = devpath
        event = self._event_from(action, subsystem, name, syspath)
        for key, value in fields.items():
            event.properties.setdefault(key, value)
        if "PRODUCT" in fields and ":" in fields["PRODUCT"]:
            vid, pid = fields["PRODUCT"].split(":", 1)[:2]
            event.detail = event.detail or f"vid:pid={vid}:{pid}"
        yield event


class PyudevMonitor(Monitor):
    backend = "pyudev"

    def __init__(self, root: str = "/", subsystems=DEFAULT_SUBSYSTEMS, include_partitions: bool = False):
        super().__init__(root, subsystems, include_partitions)
        self._observer = None
        self._context = None

    def _run(self) -> None:
        import pyudev

        self._context = pyudev.Context()
        self._observer = pyudev.MonitorObserver(self._handle, self._context)
        monitor = pyudev.Monitor.from_netlink(self._context)
        monitor.filter_by("block", "net", "usb")
        monitor.start()
        try:
            while not self._stop.is_set():
                device = monitor.poll(timeout=500)
                if device is not None:
                    self._handle(device)
        finally:
            try:
                monitor.stop()
            except Exception:
                pass

    def _handle(self, device) -> None:
        subsystem = device.subsystem
        if not subsystem or subsystem not in self.subsystems:
            return
        syspath = device.sys_path
        if not self.root.endswith("/"):
            syspath = os.path.join(self.root, syspath.lstrip("/"))
        self._emit(self._event_from(device.action, subsystem, device.device, syspath))


class PollingMonitor(Monitor):
    backend = "sysfs polling"

    def __init__(self, root: str = "/", subsystems=DEFAULT_SUBSYSTEMS, interval: float = 1.0,
                 settle: float = 2.0, include_partitions: bool = False):
        super().__init__(root, subsystems, include_partitions)
        self.interval = max(0.1, float(interval))
        self.settle = settle
        self.known: dict[str, dict] = {}

    def _event_with_props(self, action: str, subsystem: str, name: str, syspath: str) -> DeviceEvent:
        event = self._event_from(action, subsystem, name, syspath)
        if action == "add" and not event.bus and self.settle > 0:
            deadline = time.time() + self.settle
            while time.time() < deadline and not self._stop.is_set():
                time.sleep(0.1)
                event = self._event_from(action, subsystem, name, syspath)
                if event.bus or event.fstype:
                    break
        return event

    def _run(self) -> None:
        previous = self.snapshot()
        self.known = dict(previous)
        while not self._stop.wait(self.interval):
            current = self.snapshot()
            for key in sorted(current.keys() - previous.keys()):
                subsystem, _, name = key.partition("/")
                event = self._event_with_props("add", subsystem, name, current[key]["syspath"])
                self.known[key] = current[key]
                self._emit(event)
            for key in sorted(previous.keys() - current.keys()):
                subsystem, _, name = key.partition("/")
                last = self.known.get(key)
                syspath = last.get("syspath", name) if last else name
                self._emit(self._event_from("remove", subsystem, name, syspath, last))
                self.known.pop(key, None)
            previous = current


def create_monitor(preference: str = "auto", root: str = "/", subsystems=DEFAULT_SUBSYSTEMS,
                   interval: float = 1.0, include_partitions: bool = False):
    attempts = []
    if preference in ("auto", "netlink"):
        attempts.append(("netlink", lambda: NetlinkMonitor(root, subsystems, include_partitions)))
    if preference in ("auto", "pyudev"):
        attempts.append(("pyudev", lambda: PyudevMonitor(root, subsystems, include_partitions)))
    if preference in ("auto", "poll"):
        attempts.append(("poll", lambda: PollingMonitor(root, subsystems, interval, include_partitions=include_partitions)))
    errors = []
    for label, factory in attempts:
        monitor = factory()
        try:
            monitor.start()
            time.sleep(0.2)
            if monitor.alive():
                return monitor
            errors.append(f"{label}: {monitor.error or 'thread died'}")
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    if errors and preference != "poll":
        monitor = PollingMonitor(root, subsystems, interval, include_partitions=include_partitions)
        monitor.start()
        monitor.note = "; ".join(errors)
        return monitor
    raise RuntimeError("no usable backend: " + "; ".join(errors))