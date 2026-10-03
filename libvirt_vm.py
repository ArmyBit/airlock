#!/usr/bin/env python3
"""Dedicated throwaway VMs for storage devices, managed by libvirt.

A bare ``qemu-system-x86_64`` process is invisible to ``virsh``; anything here
goes through libvirt instead, so the domains show up in ``virsh list --all``,
can be inspected, started, stopped and thrown away again.

Every device gets its own domain name, so two disks never share a VM.
"""

from __future__ import annotations

import getpass
import glob
import os
import re
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from xml.sax.saxutils import escape

from udev_control import ControlError, ControlResult, UdevControl

VIRSH = "/usr/bin/virsh"
VIRT_XML_VALIDATE = "/usr/bin/virt-xml-validate"
SYSTEM_URI = "qemu:///system"
POLKIT_RULE_PATH = "/etc/polkit-1/rules.d/49-libvirt-user.rules"
POLKIT_RULE = """// installed by the storage watcher app
// lets the logged-in desktop user manage libvirt VMs without a prompt each time.
// security note: this is equivalent to libvirt group membership - any process
// running as this user can control VMs while logged in at the machine.
polkit.addRule(function (action, subject) {
    const managed = [
        "org.libvirt.unix.manage",
        "org.libvirt.unix.manage-domains",
        "org.libvirt.unix.monitor",
        "org.libvirt.unix.console",
    ];
    if (managed.indexOf(action.id) === -1) {
        return;
    }
    if (subject.user === "%(user)s" && subject.local && subject.active) {
        return polkit.Result.YES;
    }
});
""" % {"user": os.environ.get("USER") or getpass.getuser()}
ACCESS_ERRORS = ("access denied by policy", "authentication failed",
                 "failed to connect to the hypervisor")
QEMU_USER_HINT = "the qemu process (user libvirt-qemu) cannot read it"
# World-readable places for the initramfs. The first one is writable without any
# privilege; the second is libvirt's own image directory and needs root.
USER_STAGE_DIR = "/var/tmp/storage-watcher"
ROOT_STAGE_DIR = "/var/lib/libvirt/images/tiny-linux"
STAGE_PATHS = (os.path.join(USER_STAGE_DIR, "initramfs.cpio.gz"),
               os.path.join(ROOT_STAGE_DIR, "initramfs.cpio.gz"))
SHARED_INITRD = STAGE_PATHS[0]


def _other_can_read(path: str) -> bool:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & stat.S_IROTH)


def _other_can_traverse(path: str) -> bool:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & stat.S_IXOTH)


def access_problems(kernel: str, initrd: str) -> list:
    """Files QEMU needs, that the qemu user cannot read.

    QEMU runs as ``libvirt-qemu``, not as you, so a kernel or initramfs under a
    private home directory (``drwx------``) is unreadable and the domain dies
    with "error reading initrd ... Permission denied".
    """
    problems = []
    for target in (kernel, initrd):
        if not os.path.exists(target):
            problems.append(f"{target}: missing")
            continue
        if not _other_can_read(target):
            problems.append(f"{target}: mode does not let others read it - {QEMU_USER_HINT}")
        parts = os.path.dirname(target).split(os.sep)[:-1]
        for depth in range(1, len(parts) + 1):
            path = os.sep + os.sep.join(part for part in parts[1:depth] if part)
            if path and not _other_can_traverse(path):
                problems.append(f"{path}: not traversable by others (chmod o+x) - {QEMU_USER_HINT}")
    return sorted(set(problems))
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INITRD = os.path.join(PROJECT_DIR, "tiny-linux", "initramfs.cpio.gz")
DEFAULT_ID_KEY = os.path.join(PROJECT_DIR, "tiny-linux", "keys", "host_id_ed25519")
SSH_PORT = 2222
DEFAULT_KERNEL = None  # resolved by default_kernel()
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
DEVPATH_RE = re.compile(r"^/dev/[A-Za-z0-9][A-Za-z0-9_./-]*$")
MAX_XML_BYTES = 128 * 1024


def default_kernel() -> str:
    """Prefers the kernel the tiny initramfs was built for, else the newest one."""
    kver_file = os.path.join(PROJECT_DIR, "tiny-linux", "kver")
    try:
        with open(kver_file) as handle:
            candidate = f"/boot/vmlinuz-{handle.read().strip()}"
        if os.path.exists(candidate):
            return candidate
    except OSError:
        pass
    if os.path.exists("/boot/vmlinuz"):
        return "/boot/vmlinuz"
    found = sorted(glob.glob("/boot/vmlinuz-*"))
    if found:
        return found[-1]
    raise ControlError("no kernel found in /boot - install one or pass kernel=...")


def domain_name(device: str) -> str:
    """``/dev/sdb`` -> ``tiny-sdb`` (libvirt names are lowercase alnum + dash)."""
    base = os.path.basename(str(device or "")).strip().lower()
    base = re.sub(r"[^a-z0-9]+", "-", base).strip("-")
    if not base:
        raise ControlError(f"cannot derive a domain name from {device!r}")
    return f"tiny-{base}"[:63].strip("-")


def _require(path: str) -> str:
    if not os.path.exists(path):
        raise ControlError(f"missing: {path}")
    return path


SYS_BLOCK = "/sys/dev/block"
PROC_MOUNTS = "/proc/mounts"


def _maj_min(path: str) -> str | None:
    """``/dev/sda2`` -> ``8:2``, or None when it is not a block device."""
    try:
        info = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISBLK(info.st_mode):
        return None
    return f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"


def _sys_dev_file(path: str) -> str | None:
    """``.../block/sda/sda2`` -> ``8:2`` by reading its sysfs ``dev`` file.

    sysfs entries are directories, so ``os.stat`` cannot be used on them.
    """
    try:
        with open(os.path.join(path, "dev")) as handle:
            value = handle.read().strip()
    except OSError:
        return None
    return value if ":" in value else None


def _sys_children(mm: str, kind: str) -> list:
    """``(name, maj:min)`` pairs under ``/sys/dev/block/<mm>/<kind>/``.

    ``kind='slaves'`` gives the devices one is built on top of, which is how
    LUKS, LVM and mdraid stacks are followed down to the physical disks.
    """
    found = []
    base = os.path.join(SYS_BLOCK, mm, kind)
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return found
    for entry in entries:
        value = _sys_dev_file(os.path.join(base, entry))
        if value:
            found.append((entry, value))
    return found


def _sys_partitions(mm: str) -> list:
    """``(name, maj:min)`` for every partition of disk ``mm``.

    A disk's partitions are direct children of its sysfs directory, so anything
    that has no ``dev`` file (``queue``, ``holders``, ``mq`` ...) is skipped
    rather than listed.
    """
    found = []
    try:
        base = os.path.realpath(os.path.join(SYS_BLOCK, mm))
        entries = sorted(os.listdir(base))
    except OSError:
        return found
    disk = os.path.basename(base)
    for entry in entries:
        if entry == disk or entry.startswith("."):
            continue
        value = _sys_dev_file(os.path.join(base, entry))
        if value:
            found.append((entry, value))
    return found


def _sys_parent_disk(mm: str) -> tuple | None:
    """The disk a partition lives on: ``8:2`` -> ``("sda", "8:0")``.

    sysfs nests partitions under ``.../block/<disk>/<partition>``, and there is
    no ``block/`` subdirectory inside a device directory, so the containing
    disk is the parent directory - but only when that parent's own parent is
    really named ``block``, otherwise this is some other kind of device.
    """
    try:
        here = os.path.realpath(os.path.join(SYS_BLOCK, mm))
    except OSError:
        return None
    parent = os.path.dirname(here)
    if os.path.basename(os.path.dirname(parent)) != "block":
        return None
    value = _sys_dev_file(parent)
    return (os.path.basename(parent), value) if value else None


def host_root_devices(mounts_path: str = PROC_MOUNTS) -> tuple:
    """Everything the running system is made of, as ``{maj:min: label}``.

    Walking down ``slaves`` and up ``block/`` means a plain LUKS root resolves
    to both the encrypted partition and its disk, and an LVM-on-LUKS-on-RAID
    stack is followed all the way down to the physical disks. Siblings of the
    root partition are included too: LUKS swap on the same disk is the same
    evidence, handed over just as completely.
    """
    labels = {}
    chain = []
    try:
        with open(mounts_path) as handle:
            mounts = handle.read().splitlines()
    except OSError:
        return labels, chain

    wanted = []
    for line in mounts:
        fields = line.split()
        if len(fields) >= 2 and fields[1] in ("/", "/home"):
            wanted.append(fields[0])
    seen_stack = set()
    for source in wanted:
        node = source.split("[")[0]
        if not node.startswith("/dev/"):
            continue
        start = _maj_min(os.path.realpath(node))
        if not start:
            continue
        chain.append(source)
        queue = [start]
        while queue:
            mm = queue.pop(0)
            if mm in seen_stack:
                continue
            seen_stack.add(mm)
            labels[mm] = source
            for _, slave in _sys_children(mm, "slaves"):
                queue.append(slave)
            parent = _sys_parent_disk(mm)
            if parent:
                disk, disk_mm = parent
                labels[disk_mm] = f"{disk} (holds {source})"
                labels.setdefault(disk_mm + ":disk", source)
                for part, part_mm in _sys_partitions(disk_mm):
                    labels[part_mm] = f"{part} on {disk} (same disk as {source})"
                    labels.setdefault(part_mm + ":disk", source)
    return labels, chain


def refuse_host_disk(device: str, mounts_path: str = PROC_MOUNTS) -> None:
    """Raises when ``device`` is, or shares a disk with, the running system.

    This is the guard that stops the tool taking the machine down with it: a
    guest with raw access to the root disk can read everything the logged-in
    user can, and rewrite it if the disk was attached writable.
    """
    labels, chain = host_root_devices(mounts_path)
    if not labels:
        return
    candidate = _maj_min(device) or _maj_min(os.path.realpath(device))
    where = " -> ".join(chain)
    if candidate and candidate in labels:
        raise ControlError(
            f"REFUSING: {device} is the running system ({labels[candidate]}).\n"
            f"  root chain: {where}\n"
            "  Attaching it would hand the guest read/write access to your OS.")
    if candidate and candidate + ":disk" in labels:
        raise ControlError(
            f"REFUSING: {device} is the disk holding the running system "
            f"({labels[candidate + ':disk']}).\n"
            f"  root chain: {where}\n"
            "  Booting a guest with your OS disk attached is not a good idea.")
    if not candidate:
        raise ControlError(f"REFUSING: {device} is not a block device.")


def domain_xml(device: str = "", kernel: str | None = DEFAULT_KERNEL, initrd: str = DEFAULT_INITRD,
               memory: int = 256, vcpu: int = 1, name: str | None = None,
               writable: bool = False, vnc: bool = True, ssh_port: int = 2222) -> str:
    """Builds the domain XML.

    With ``device=""`` the VM boots with no storage at all, which is how the
    ssh handshake is verified before a disk is ever handed over.
    """
    if device and not DEVPATH_RE.match(device):
        raise ControlError(f"not a valid device node: {device!r}")
    kernel = kernel or default_kernel()
    _require(kernel)
    _require(initrd)
    name = name or (domain_name(device) if device else "tiny-linux")
    if not NAME_RE.match(name):
        raise ControlError(f"invalid domain name: {name!r}")
    memory, vcpu = int(memory), int(vcpu)
    if not 32 <= memory <= 32768:
        raise ControlError("memory must be between 32 and 32768 MiB")
    if not 1 <= vcpu <= 8:
        raise ControlError("vcpu must be between 1 and 8")

    cmdline = "console=tty0 console=ttyS0,115200 panic=-1 rootwait=0"
    if not vnc:
        cmdline += " quiet"
    if device == "":
        # no disk yet: bring networking up so ssh can be verified before any
        # storage is handed over
        cmdline += " ip=10.0.2.15::10.0.2.2:255.255.255.0:tiny-ssh::off"
    network = (
        "    <interface type='user'>\n"
        "      <mac address='52:54:00:7b:1c:01'/>\n"
        "      <model type='virtio'/>\n"
        "      <backend type='passt'/>\n"
        f"      <portForward proto='tcp' address='127.0.0.1'>\n"
        f"        <range start='{ssh_port}' to='22'/>\n"
        "      </portForward>\n"
        "    </interface>\n"
    ) if ssh_port else ""
    graphics = (
        "    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'>\n"
        "      <listen type='address' address='127.0.0.1'/>\n"
        "    </graphics>\n"
    ) if vnc else ""

    disk = ""
    if device:
        disk = (
            "    <disk type='block' device='disk'>\n"
            "      <driver name='qemu' type='raw' cache='none' io='native'/>\n"
            f"      <source dev='{escape(device)}'/>\n"
            "      <target dev='vda' bus='virtio'/>\n"
        )
        disk += "    </disk>\n" if writable else "      <readonly/>\n    </disk>\n"

    return f"""<domain type='qemu'>
  <name>{escape(name)}</name>
  <title>dedicated to {escape(device)}</title>
  <description>tiny busybox Linux, single disk {escape(device)}, throwaway</description>
  <memory unit='MiB'>{memory}</memory>
  <currentMemory unit='MiB'>{memory}</currentMemory>
  <vcpu placement='static'>{vcpu}</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <kernel>{escape(kernel)}</kernel>
    <initrd>{escape(initrd)}</initrd>
    <cmdline>{escape(cmdline)}</cmdline>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='custom' match='exact' check='none'>
    <model fallback='allow'>qemu64</model>
  </cpu>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
{graphics}    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <memballoon model='none'/>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
{network}{disk}</devices>
</domain>
"""


@dataclass
class DomainInfo:
    name: str
    id: str = "-"
    state: str = "unknown"
    autostart: bool = False
    xml: str = ""

    @property
    def running(self) -> bool:
        return self.state.lower().startswith("running")


class LibvirtVms:
    """Thin, validated wrapper around virsh for these per-disk domains."""

    def __init__(self, control: UdevControl | None = None, uri: str = SYSTEM_URI):
        self.control = control or UdevControl()
        self.uri = uri

    # -- low level -----------------------------------------------------
    def virsh(self, *args: str, elevate: bool = False) -> ControlResult:
        return self.control.run_raw([VIRSH, "-c", self.uri, *args], elevate=elevate)

    @staticmethod
    def validate_xml(xml: str) -> ControlResult:
        if len(xml.encode()) > MAX_XML_BYTES:
            raise ControlError("domain XML is too large")
        if "<domain" not in xml or "</domain>" not in xml:
            raise ControlError("that does not look like libvirt domain XML")
        if not os.path.exists(VIRT_XML_VALIDATE):
            return ControlResult(True, ["virt-xml-validate", "(skipped)"], "validator not installed", "", 0)
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
            handle.write(xml)
            path = handle.name
        try:
            proc = subprocess.run([VIRT_XML_VALIDATE, path], capture_output=True, text=True)
            return ControlResult(proc.returncode == 0, [VIRT_XML_VALIDATE, path],
                                 proc.stdout, proc.stderr, proc.returncode)
        finally:
            os.unlink(path)

    # -- reporting -----------------------------------------------------
    def _retry(self, call, *args, tries: int = 4, pause: float = 2.0):
        """Polkit refuses virsh at random, so a denial is worth retrying."""
        result = call(*args)
        for attempt in range(1, tries):
            if result.ok or not self.denied(result):
                return result
            time.sleep(pause)
            result = call(*args)
        return result

    def denied(self, result: ControlResult) -> bool:
        """True when libvirt refused us over polkit rather than failing at the VM."""
        blob = f"{result.stdout}\n{result.stderr}".lower()
        return any(marker in blob for marker in ACCESS_ERRORS)

    def access_help(self) -> str:
        return (
            "libvirt refused the request:\n\n"
            f"  {' '.join(self.access_fix_command())}\n\n"
            "either that, or:\n\n"
            f"  sudo usermod -aG libvirt {os.environ.get('USER', 'your-user')}   "
            "(then log out and back in)\n\n"
            f"polkit rule currently installed: "
            f"{'yes' if os.path.exists(POLKIT_RULE_PATH) else 'no'}"
        )

    @staticmethod
    def access_fix_command() -> list:
        return ["install", "-m", "0644", "/dev/stdin", POLKIT_RULE_PATH]

    def staged_initrd(self) -> str | None:
        """The initramfs already copied somewhere QEMU can read, if any."""
        for candidate in STAGE_PATHS:
            if os.path.exists(candidate) and _other_can_read(candidate):
                return candidate
        return None

    def stage_to_user_dir(self, initrd: str = DEFAULT_INITRD) -> ControlResult:
        """Copies the initramfs somewhere QEMU can read, without needing root.

        This is the fix for a mode 700 home directory: instead of loosening the
        permissions on your files, the image is copied to a world-readable path.
        """
        if not os.path.exists(initrd):
            raise ControlError(f"nothing to copy: {initrd}")
        target = STAGE_PATHS[0]
        try:
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            with open(initrd, "rb") as source, open(target, "wb") as sink:
                sink.write(source.read())
            os.chmod(os.path.dirname(target), 0o755)
            os.chmod(target, 0o644)
        except OSError as exc:
            return ControlResult(False, ["copy", initrd, target], "", str(exc), 1)
        problems = access_problems(self.kernel_path(), target)
        if problems:
            return ControlResult(False, ["copy", initrd, target],
                                 f"copied to {target} but QEMU still cannot read it:\n"
                                 + "\n".join(f"  {p}" for p in problems), "", 1)
        return ControlResult(True, ["copy", initrd, target],
                             f"initramfs copied to {target}\n"
                             f"mode 644, directories 755 - QEMU can read it now.\n\n"
                             "Launch the VM for that device again; it will use this copy "
                             "automatically.", "", 0)

    def best_initrd(self, initrd: str = DEFAULT_INITRD) -> str:
        """Prefers a staged copy over one under a private home directory."""
        try:
            kernel = default_kernel()
        except ControlError:
            kernel = "/boot/vmlinuz"
        if not access_problems(kernel, initrd):
            return initrd
        return self.staged_initrd() or initrd

    def stage_initrd(self, initrd: str = DEFAULT_INITRD) -> ControlResult:
        """Tries the no-privilege location first, then libvirt's image directory."""
        user_copy = self.stage_to_user_dir(initrd)
        if user_copy.ok:
            return user_copy
        steps = [
            ("copy initramfs to " + STAGE_PATHS[1], self.control.run_raw(
                ["install", "-D", "-m", "0644", initrd, STAGE_PATHS[1]], elevate=True)),
        ]
        from udev_control import _chain
        report = _chain(steps)
        if report.ok:
            return ControlResult(True, report.command,
                                 f"initramfs available to QEMU at {STAGE_PATHS[1]}\n\n"
                                 "Now launch the VM again for that device.", "", 0)
        return ControlResult(False, report.command,
                             f"{user_copy.stderr or user_copy.stdout}\n"
                             f"privileged fallback:\n{report.output}", "", 1)

    @staticmethod
    def kernel_path() -> str:
        try:
            return default_kernel()
        except ControlError:
            return "/boot/vmlinuz"

    def install_access_rule(self) -> ControlResult:
        """Lets virsh manage VMs as this desktop user (still one password prompt)."""
        result = self.control.run_raw(["tee", POLKIT_RULE_PATH], elevate=True, stdin=POLKIT_RULE)
        if result.ok:
            return ControlResult(True, result.command,
                                 f"wrote {POLKIT_RULE_PATH}\n\n"
                                 "Retry now, or log out and back in if it still asks.\n"
                                 "virsh will then work without repeating the prompt.", "", 0)
        return result

    def list_domains(self, prefix: str = "tiny-") -> ControlResult:
        """``virsh list --all`` restricted to our own domains."""
        result = self._retry(self.virsh, "list", "--all")
        if not result.ok:
            return result
        keep = [line for line in result.stdout.splitlines()
                if prefix in line or line.startswith(" Id ")]
        listing = "\n".join(line.rstrip() for line in keep if line.strip())
        return ControlResult(True, ["virsh", "list", "--all"], listing or "(no domains defined)", "", 0)

    def domains(self, prefix: str = "tiny-") -> list:
        """Structured view of the tiny- domains, for the GUI table.

        Uses ``--name`` instead of parsing the table columns, so the ids and
        state text cannot break it.
        """
        result = self._retry(self.virsh, "list", "--all", "--name")
        if not result.ok:
            return []
        found = []
        for name in result.stdout.split("\n"):
            name = name.strip()
            if not name or not name.startswith(prefix):
                continue
            state = self.virsh("domstate", name)
            text = state.stdout.strip().splitlines()[0].strip() if state.ok else "unknown"
            found.append(DomainInfo(name, "-", text.lower()))
        return found

    def console_pty(self, name: str) -> str:
        """The pty behind the serial console, e.g. /dev/pts/3."""
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        result = self._retry(self.virsh, "ttyconsole", name)
        return result.stdout.strip() if result.ok else ""

    def console_command(self, name: str) -> str:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        return f"virsh -c {SYSTEM_URI} console {name}"

    def console_help(self, name: str, pty: str = "") -> str:
        pty_note = (f"\nThe pty is {pty} but it belongs to libvirt-qemu with mode 600, so opening it "
                    "yourself needs root:\n    sudo socat -,raw,echo=0 " + pty) if pty else ""
        return ("Get a shell in the VM:\n\n"
                f"    {self.console_command(name)}\n\n"
                "Press Ctrl-] to leave the console. That needs polkit permission for"
                " org.libvirt.unix.console - press 'Fix libvirt access' once to grant it."
                + pty_note + "\n\nOr use the graphical console: the VM serves VNC on"
                f" {self.vnc_port(name) or '127.0.0.1:5900'} (needs a VNC viewer such as"
                " virt-viewer).")

    def vnc_port(self, name: str) -> str:
        """The TCP port the VNC console listens on (vncdisplay reports a display)."""
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        result = self._retry(self.virsh, "vncdisplay", name)
        if not result.ok:
            return ""
        value = result.stdout.strip().split(":")[-1]
        try:
            return str(5900 + int(value))
        except ValueError:
            return ""

    def vnc_address(self, name: str) -> str:
        port = self.vnc_port(name)
        return f"127.0.0.1:{port}" if port else ""

    # -- lifecycle -----------------------------------------------------
    def define(self, xml: str, elevate: bool = False) -> ControlResult:
        """``virsh define`` - makes a persistent domain, so it shows in list --all."""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
            handle.write(xml)
            path = handle.name
        try:
            return self._retry(self.virsh, "define", path)
        finally:
            os.unlink(path)

    def start(self, name: str, elevate: bool = False) -> ControlResult:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        return self._retry(self.virsh, "start", name)

    def shutdown(self, name: str) -> ControlResult:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        return self._retry(self.virsh, "shutdown", name)

    def destroy(self, name: str) -> ControlResult:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        return self._retry(self.virsh, "destroy", name)

    def undefine(self, name: str) -> ControlResult:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        return self._retry(self.virsh, "undefine", name)

    def autostart(self, name: str, enable: bool = True) -> ControlResult:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        return self.virsh("autostart", name, "--enable" if enable else "--disable", elevate=True)

    def set_memory(self, name: str, memory: int) -> ControlResult:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        if not 32 <= int(memory) <= 32768:
            raise ControlError("memory must be between 32 and 32768 MiB")
        return self.virsh("setmaxmem", name, f"{int(memory)}M", "--config", elevate=True)

    def domain_exists(self, name: str) -> bool:
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        return any(d.name == name for d in self.domains())

    def replace_domain(self, name: str, prefix: str = "tiny-") -> ControlResult:
        """Clears a stale definition so the same disk can get a fresh VM.

        ``virsh define`` refuses with "domain 'x' already exists" when the file
        carries a new UUID, which is exactly what happens on the second launch
        of the same device.
        """
        notes = []
        for info in self.domains(prefix=prefix):
            if info.name != name:
                continue
            if info.running:
                notes.append(("stop running " + name, self.destroy(name)))
            notes.append(("remove old definition", self.undefine(name)))
        if not notes:
            return ControlResult(True, ["virsh", "list", "--all", "--name"],
                                 "no previous domain to replace", "", 0)
        from udev_control import _chain
        return _chain(notes)

    def ssh_check(self, name: str, port: int = 2222, timeout: int = 60,
                  key: str = DEFAULT_ID_KEY, host: str = "127.0.0.1") -> ControlResult:
        """Logs in over ssh and asks the guest to prove it is alive.

        This is the gate in front of every disk handoff: nothing is attached
        until this returns ok.
        """
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        if not os.path.exists(key):
            return ControlResult(False, ["ssh", "-i", key, "..."], "", f"no ssh key at {key}", 1)
        marker = "TINY_SSH_OK"
        argv = ["ssh", "-i", key, "-p", str(port),
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                f"root@{host}", f"echo {marker}"]
        deadline = time.monotonic() + max(5, int(timeout))
        last = ControlResult(False, argv, "", "ssh was not attempted", 1)
        while time.monotonic() < deadline:
            last = self.control.run_raw(argv, elevate=False)
            if last.ok and marker in (last.stdout or ""):
                return ControlResult(
                    True, argv,
                    f"ssh login on port {port} succeeded, guest answered {marker}",
                    "", 0)
            time.sleep(2)
        detail = (last.stderr or last.stdout or "no answer").strip().splitlines()
        return ControlResult(
            False, argv,
            f"ssh on port {port} did not answer within {timeout}s\n"
            f"  last reply: {detail[-1] if detail else 'none'}",
            "", last.code or 1)

    def ssh_run(self, name: str, command: str, port: int = 2222,
                key: str = DEFAULT_ID_KEY, host: str = "127.0.0.1",
                timeout: int = 60) -> ControlResult:
        """Runs one command in the guest and returns its output.

        Same ssh options as ssh_check, but the command is the caller's: the
        state of the attached disk can only be answered from inside the guest.
        """
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        argv = ["ssh", "-i", key, "-p", str(port),
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                f"root@{host}", command]
        result = self.control.run_raw(argv, elevate=False, timeout=timeout)
        return ControlResult(result.ok, argv, result.stdout, result.stderr, result.code)

    def detach_disk(self, name: str, target: str = "vdb",
                    device: str = "") -> ControlResult:
        """Gives a hotplugged disk back to the host. Harmless if it is not there."""
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        source = (f"<source dev='{escape(device)}'/>" if device
                  else "<!-- source filled in from the live config -->")
        disk = ("<disk type='block' device='disk'>"
                "<driver name='qemu' type='raw'/>"
                f"{source}"
                f"<target dev='{escape(target)}' bus='virtio'/></disk>")
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
            handle.write(disk)
            xml_path = handle.name
        try:
            result = self.control.run_raw(
                ["virsh", "-c", SYSTEM_URI, "detach-device", name,
                 "--file", xml_path, "--live"], elevate=False, timeout=120)
        finally:
            os.unlink(xml_path)
        if not result.ok:
            raise ControlError(
                f"could not detach {target} from {name}:\n{result.stderr or result.stdout}")
        return ControlResult(True, ["virsh", "detach-device", name, disk, "--live"],
                             f"{target} detached from {name}", "", 0)

    def attach_disk(self, name: str, device: str, readonly: bool = True) -> ControlResult:
        """Hotplugs a raw block device into a running VM as /dev/vdb."""
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        if not DEVPATH_RE.match(device or ""):
            raise ControlError(f"not a valid device node: {device!r}")
        if not os.path.exists(device):
            raise ControlError(f"{device} is not there any more")
        refuse_host_disk(device)
        disk = ("<disk type='block' device='disk'>"
                "<driver name='qemu' type='raw' cache='none' io='native'/>"
                f"<source dev='{escape(device)}'/>"
                "<target dev='vdb' bus='virtio'/>")
        disk += "<readonly/></disk>" if readonly else "</disk>"
        if not readonly:
            # a writable disk lets a hostile guest rewrite the only copy
            raise ControlError(
                f"REFUSING to attach {device} writable.\n"
                "  Evidence must stay byte-identical, and a writable disk gives a "
                "guest that escapes the guest kernel a way to destroy it.\n"
                "  If you really mean it, use the raw virsh call and own the risk.")
        # virsh reads the device description from a file, and passing "-" for
        # stdin does not work here, so it goes through a temporary file. Not
        # elevated: libvirt's own polkit rules decide whether this user may
        # attach a disk. The timeout is generous because libvirt sets up
        # ownership and cgroups for the new node first, which on a slow usb
        # bridge takes far longer than a command usually does.
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
            handle.write(disk)
            xml_path = handle.name
        try:
            result = self.control.run_raw(
                ["virsh", "-c", SYSTEM_URI, "attach-device", name,
                 "--file", xml_path, "--live"], elevate=False, timeout=120)
        finally:
            os.unlink(xml_path)
        if not result.ok:
            raise ControlError(
                f"could not attach {device} to {name}:\n{result.stderr or result.stdout}")
        return ControlResult(
            True, ["virsh", "attach-device", name, disk, "--live"],
            f"{device} attached to {name} as /dev/vdb" +
            (" (read-only)" if readonly else " (writable)"), "", 0)

    def guest_has_disk(self, name: str, port: int = 2222,
                       key: str = DEFAULT_ID_KEY, host: str = "127.0.0.1") -> ControlResult:
        """Asks the running guest whether the hotplugged node appeared.

        lsblk is there for the inventory, but the answer that matters is the node
        itself: lsblk prints 'vdb', not '/dev/vdb', so matching on the name alone
        would silently never find it.
        """
        argv = ["ssh", "-i", key, "-p", str(port),
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                f"root@{host}",
                "lsblk -o NAME,SIZE,TYPE,RO 2>/dev/null; "
                "if [ -b /dev/vdb ]; then echo NODE_PRESENT; else echo NODE_MISSING; fi"]
        result = self.control.run_raw(argv, elevate=False)
        return ControlResult(
            result.ok and "NODE_PRESENT" in (result.stdout or ""), argv,
            (result.stdout or "").strip() or "no answer", result.stderr or "", result.code)

    def define_and_start(self, device: str, **kwargs) -> tuple:
        """Defines the domain, starts it, and reports both steps."""
        name = kwargs.pop("name", None) or domain_name(device)
        if device:
            refuse_host_disk(device)
        kwargs.setdefault("initrd", self.best_initrd(kwargs.get("initrd", DEFAULT_INITRD)))
        problems = access_problems(kwargs.get("kernel") or default_kernel(), kwargs["initrd"])
        if problems:
            raise ControlError(
                "QEMU cannot read the files the VM needs:\n  " + "\n  ".join(problems) +
                "\n\nFix it with 'Fix QEMU file access' on the Virtual machines tab.")
        xml = domain_xml(device, name=name, **kwargs)
        check = self.validate_xml(xml)
        if not check.ok:
            raise ControlError(f"libvirt rejected the domain XML:\n{check.stderr or check.stdout}")
        cleared = self.replace_domain(name)
        defined = self.define(xml)
        if not defined.ok:
            return name, xml, ControlResult(
                False, [*cleared.command, *defined.command],
                f"domain XML:\n{xml}\n\n{cleared.output}\n"
                f"virsh define failed:\n{defined.stderr or defined.stdout}",
                "", defined.code)
        started = self.start(name)
        report = ControlResult(
            started.ok, [*cleared.command, *defined.command, *started.command],
            f"domain {name} defined and started.\n{cleared.output}" if started.ok
            else f"domain {name} defined but not started:\n{started.stderr or started.stdout}",
            "", started.code)
        return name, xml, report

    def launch_with_handoff(self, device: str, ssh_timeout: int = 90, readonly: bool = True,
                            progress=None, **kwargs) -> tuple:
        """Boots the VM with no storage, proves ssh works, only then attaches.

        Returns ``(name, xml, report)``. If the ssh gate never opens, nothing is
        attached and the caller gets the failure text to show.
        """
        say = progress or (lambda *a, **k: None)
        name = kwargs.pop("name", None) or domain_name(device)
        port = kwargs.pop("ssh_port", SSH_PORT)
        key = kwargs.pop("key", DEFAULT_ID_KEY)

        def handoff(message):
            say(message)
            if getattr(self, "on_progress", None):
                self.on_progress(message)

        handoff(f"step 1/4 - define and start {name} with no storage attached")
        name, xml, report = self.define_and_start("", name=name, ssh_port=port, **kwargs)
        if not report.ok:
            return name, xml, report

        handoff(f"step 2/4 - waiting for ssh on 127.0.0.1:{port}")
        gate = self.ssh_check(name, port=port, timeout=ssh_timeout, key=key)
        if not gate.ok:
            fail = ControlResult(
                False, gate.command,
                "ssh did not come up, so the disk was NOT attached.\n"
                "The VM is still running without storage; inspect it with the "
                "serial console.\n\n" + gate.output,
                gate.stderr, gate.code)
            handoff(f"ssh gate failed - {device} stays unattached")
            return name, xml, fail

        handoff(f"step 3/4 - ssh works, now attaching {device}")
        try:
            attach = self.attach_disk(name, device, readonly=readonly)
        except ControlError as exc:
            return name, xml, ControlResult(False, [], str(exc), "", 1)
        handoff(attach.output)

        handoff("step 4/4 - checking the guest sees the disk")
        seen = self.guest_has_disk(name, port=port, key=key)
        final = ControlResult(
            seen.ok, [*report.command, *attach.command, *seen.command],
            (report.output + "\n" + attach.output +
             ("\nguest reports:\n" + seen.output if seen.output else "") +
             "\nStorage was attached only after the ssh check passed."),
            "", 0 if seen.ok else seen.code)
        if not seen.ok:
            handoff("disk attached, but the guest has not shown /dev/vdb yet")
        return name, xml, final

    def remove(self, name: str) -> ControlResult:
        """Stops the VM if needed and removes the domain definition entirely."""
        if not NAME_RE.match(name or ""):
            raise ControlError(f"invalid domain name: {name!r}")
        info = next((d for d in self.domains() if d.name == name), None)
        if info is not None and info.running:
            self.destroy(name)
        return self.undefine(name)