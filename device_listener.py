#!/usr/bin/env python3
"""Watches for storage that arrives after the app started.

Three rules, in this order, because each one is a safety rule:

1. **Only new devices.** The snapshot taken at ``start()`` is the baseline, so
   anything already plugged in when the app started is ignored forever. This is
   deliberate: an investigation is about the device you plug in now, not the
   disks the host happens to be running on.
2. **Whole disks only.** Partitions are skipped; the collector walks them inside
   the guest, where a hostile filesystem cannot reach the host.
3. **Never the host's own disks.** ``libvirt_vm.refuse_host_disk`` runs on every
   candidate, so the host root disk and its siblings are refused even if they
   somehow show up as new.

Discovery is by polling /sys/class/block rather than by listening on the kernel
netlink uevent socket. Binding to the kernel's event group succeeds without
privileges but delivers nothing - only a privileged process (which is why
udevd runs as root) actually receives kernel uevents - so a netlink listener
would sit there silently forever. sysfs is updated synchronously when a device
appears, so polling finds arrivals just as reliably and needs no privileges.

Descriptions come from udev_monitor.describe(), so the fields are the same ones
the old Tkinter UI showed.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time

import udev_monitor
from libvirt_vm import refuse_host_disk
from triage_state import Device, human_size

# loop/ram/zram/dm/md/sr/fd are not removable storage we could triage
NOT_REAL = re.compile(r"^(loop|ram|zram|dm|md|sr|fd|nbd|zd)\d*$")

# a disk is only interesting if it has a size and a transport
TRANSPORTS = ("usb", "ata", "scsi", "nvme", "mmc", "virtio")


def sysfs_key(name: str) -> str:
    """scan() keys are 'block/sda'; the event name is 'sda'. One spelling only."""
    return f"block/{name}"


def sysfs_attr(name: str, attr: str) -> str:
    try:
        with open(os.path.join("/sys/class/block", name, attr), encoding="ascii") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def size_bytes(name: str) -> int:
    """Disk size in bytes. sysfs counts 512-byte sectors; udev's describe() only
    gives a rounded human string like '29.3G', which is no use for a filter."""
    sectors = sysfs_attr(name, "size")
    return int(sectors) * 512 if sectors.isdigit() else 0


def partitions_of(name: str) -> list:
    """Partition names under a whole disk, e.g. sdb -> sdb1, sdb2."""
    base = os.path.join("/sys/class/block", name)
    try:
        return sorted(child for child in os.listdir(base)
                      if child.startswith(name) and child != name)
    except OSError:
        return []


def blkid_probe(nodes: list) -> dict:
    """Read-only probe: filesystem type, label and uuid. Never mounts."""
    if not nodes:
        return {}
    try:
        done = subprocess.run(["blkid", "-p", "-o", "export", *nodes],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=15)
    except (OSError, subprocess.SubprocessError):
        return {}
    found, current = {}, {}
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            current[key] = value
        elif current:
            found[current.get("DEVNAME", "")] = current
            current = {}
    if current:
        found[current.get("DEVNAME", "")] = current
    return found


def is_real_disk(event: udev_monitor.DeviceEvent) -> tuple:
    """(accept, reason) - reason is why not, for the event log."""
    name = event.name
    if event.subsystem != "block":
        return False, "not a block device"
    # read it from sysfs rather than believing the event: a partition's number is
    # right there, and a partition must never be offered as a whole disk
    if event.is_partition or sysfs_attr(name, "partition").isdigit():
        return False, "partition, the whole disk is triaged instead"
    if NOT_REAL.match(name):
        return False, "virtual device"
    if event.readonly:
        return False, "reported read-only"
    if size_bytes(name) == 0:
        return False, "no media (zero size)"
    syspath = os.path.realpath(event.syspath or "")
    if "/devices/virtual/block/" in syspath:
        return False, "virtual block device"
    if "/virtio" in syspath:
        # the VM's own disks; we attach those, we never triage them
        return False, "belongs to the VM"
    if not any(f"/{bus}" in syspath or f"/{bus}:" in syspath for bus in TRANSPORTS):
        return False, "no known transport"
    return True, ""


class StorageListener:
    """Feeds newly arrived disks to a callback, one investigation at a time."""

    # how often to look, and how long a new disk must stay put before we report
    # it: partitions and partition tables appear a moment after the disk does
    POLL_SECONDS = 0.7
    SETTLE_SECONDS = 2.0

    def __init__(self, on_device=None, on_note=None, on_remove=None):
        self.on_device = on_device or (lambda device: None)
        self.on_note = on_note or (lambda text, level="info": None)
        self.on_remove = on_remove or (lambda devnode: None)
        self.seen: set = set()
        self.devices: dict = {}
        self.started_at = time.time()
        self.baseline: dict = {}
        self.error: str = ""
        self.pending: dict = {}
        self.ignored: dict = {}
        self._thread = None
        self._stop = threading.Event()

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Records the baseline first, then listens - so nothing pre-existing counts."""
        self.baseline = udev_monitor.scan(subsystems=("block",))
        self.seen = set(self.baseline)
        names = sorted(key.rsplit("/", 1)[-1] for key in self.baseline
                       if not key.rsplit("/", 1)[-1][-1].isdigit())
        self.on_note(
            f"watching for storage; already present and ignored: "
            f"{', '.join(names) or 'none'} - unplug and replug one to use it", "info")
        self._thread = threading.Thread(target=self._run, name="storage-listener",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.5)

    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        return {
            "listening": self.alive(),
            "baseline": sorted(self.baseline),
            "seen": sorted(self.seen),
            "devices": [d.as_dict() for d in self.devices.values()],
            "ignored": dict(self.ignored),
            "started_at": self.started_at,
            "error": self.error,
        }

    # -- work ---------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:                # never kill the listener
                self.error = f"{type(exc).__name__}: {exc}"
                self.on_note(f"device listener error: {exc}", "error")
            self._stop.wait(self.POLL_SECONDS)

    def _poll(self) -> None:
        current = udev_monitor.scan(subsystems=("block",))
        gone = self.seen - set(current)
        for key in gone:
            # unplugged: forget it, so plugging it in again is a new arrival
            self.seen.discard(key)
            self.pending.pop(key, None)
            name = key.rsplit("/", 1)[-1]
            device = self.devices.pop(f"/dev/{name}", None)
            if device is not None:
                self.on_note(f"{device.devnode} was removed", "warn")
                self.on_remove(device.devnode)
        for key in set(current) - self.seen:
            if key not in self.pending:
                self.pending[key] = time.time()
        now = time.time()
        for key, first_seen in list(self.pending.items()):
            if now - first_seen < self.SETTLE_SECONDS:
                continue
            self.pending.pop(key, None)
            name = key.rsplit("/", 1)[-1]
            if key not in current:                  # vanished again while settling
                continue
            self._handle(self.event_from(name, current[key]))

    @staticmethod
    def event_from(name: str, info: dict) -> udev_monitor.DeviceEvent:
        """Turns one describe() result into the same shape a uevent would give."""
        syspath = os.path.realpath(os.path.join("/sys/class/block", name))
        return udev_monitor.DeviceEvent(
            action="add", subsystem="block", name=name, syspath=syspath,
            bus=info.get("bus", ""), vendor=info.get("vendor", ""),
            model=info.get("model", ""), serial=info.get("serial", ""),
            devtype=info.get("devtype", ""), devnode=info.get("devnode", ""),
            devpath=info.get("devpath", ""), detail=info.get("detail", ""),
            size=info.get("size", ""), fstype=info.get("fstype", ""),
            fslabel=info.get("fslabel", ""), fsuuid=info.get("fsuuid", ""),
            removable=info.get("removable", False), readonly=info.get("readonly", False),
            rotational=info.get("rotational", False),
            is_partition=info.get("is_partition", False),
            properties=info.get("properties", {}))

    def _handle(self, event: udev_monitor.DeviceEvent) -> None:
        if event.action != "add":
            if event.action == "remove" and event.devnode in self.devices:
                gone = self.devices.pop(event.devnode)
                self.on_note(f"{gone.devnode} was removed", "warn")
                self.on_remove(gone.devnode)
            return
        accept, reason = is_real_disk(event)
        if not accept:
            # a card reader with no card in it reports zero size, and a disk with
            # media later would change its mind - so keep watching it, but only
            # say it once per distinct reason
            if self.ignored.get(event.name) != reason:
                self.ignored[event.name] = reason
                self.on_note(f"ignored {event.name}: {reason}")
            return
        self.ignored.pop(event.name, None)
        key = sysfs_key(event.name)
        if key in self.seen:
            return
        self.seen.add(key)

        devnode = event.devnode or f"/dev/{event.name}"
        # last line of defence: never the disk the host is running from
        try:
            refuse_host_disk(devnode)
        except Exception as exc:
            self.on_note(f"refused {devnode}: {exc}", "error")
            self.devices.pop(devnode, None)
            return
        if self._is_mounted(devnode):
            self.on_note(f"refused {devnode}: it is mounted on the host", "error")
            return

        self.record(event)

    def record(self, event: udev_monitor.DeviceEvent) -> Device:
        """Turns an accepted arrival into the app's Device and hands it over.

        Split out from _handle so the filters above stay in one place and the
        device that reaches the state machine is built the same way every time.
        """
        name = event.name
        devnode = event.devnode or f"/dev/{name}"
        parts = partitions_of(name)
        probed = blkid_probe([devnode] + [f"/dev/{p}" for p in parts])
        whole = probed.get(devnode, {})
        device = Device(
            devnode=devnode,
            added=time.time(),
            model=" ".join(x for x in (event.vendor, event.model) if x),
            serial=event.serial,
            vendor=event.vendor,
            size=size_bytes(name),
            bus=event.bus or self._transport(event.syspath),
            fstype=whole.get("TYPE", event.fstype),
            label=whole.get("LABEL", event.fslabel) or "",
            info={
                "syspath": event.syspath,
                "mountpoint": self._mountpoint(devnode),
                "devpath": event.devpath,
                "removable": event.removable,
                "rotational": event.rotational,
                "partitions": [
                    {"name": p, "devnode": f"/dev/{p}",
                     "fstype": probed.get(f"/dev/{p}", {}).get("TYPE", ""),
                     "label": probed.get(f"/dev/{p}", {}).get("LABEL", "")}
                    for p in parts
                ],
                "size_human": human_size(size_bytes(name)),
            },
        )
        self.devices[devnode] = device
        self.on_device(device)
        return device

    # -- small helpers ------------------------------------------------------

    @staticmethod
    def _transport(syspath: str) -> str:
        real = os.path.realpath(syspath or "")
        for bus in TRANSPORTS:
            if f"/{bus}" in real:
                return bus
        return ""

    @staticmethod
    def _is_mounted(devnode: str) -> bool:
        try:
            with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) > 1 and os.path.realpath(parts[1]) == os.path.realpath(devnode):
                        return True
        except OSError:
            pass
        return False

    @staticmethod
    def _mountpoint(devnode: str) -> str:
        try:
            with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) > 1 and os.path.realpath(parts[1]) == os.path.realpath(devnode):
                        return parts[1]
        except OSError:
            pass
        return ""


if __name__ == "__main__":
    def show(device):
        print(f"NEW DEVICE {device.devnode} {device.size_human} "
              f"{device.bus} {device.model} {device.fstype} {device.label}", flush=True)

    listener = StorageListener(on_device=show, on_note=lambda t, l="info": print(f"  {t}"))
    listener.start()
    print("plug a storage device in now; ctrl-c to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        listener.stop()