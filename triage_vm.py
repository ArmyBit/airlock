#!/usr/bin/env python3
"""The one VM this app owns.

A single disposable Alpine guest, booted from the golden image with no analysis
storage attached. Storage is only ever handed over afterwards, read-only, and
only after ssh has answered - see ``ARCHITECTURE.md``.

The guest is thrown away after each investigation rather than reused, so a guest
that got compromised while reading a hostile disk cannot influence the next case.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from xml.sax.saxutils import escape

import libvirt_vm as lv
from triage_state import human_size

PROJECT_DIR = Path(__file__).resolve().parent
DOMAIN = "triage-vm"
DOMAIN_PREFIX = "triage-"
DOMAIN_TITLE = "triage - throwaway Alpine guest"

# QEMU runs as libvirt-qemu and cannot read a private home directory, so the
# boot files live in a world-readable staging area (see lv.access_problems).
STAGE = Path(lv.USER_STAGE_DIR)
GOLDEN = STAGE / "golden.qcow2"
INITRAMFS = STAGE / "boot-initramfs.cpio.gz"
RUN_DISK = STAGE / "triage-run.qcow2"

KEY = PROJECT_DIR / "tiny-linux" / "keys" / "golden_id_ed25519"
BUILD_SCRIPT = PROJECT_DIR / "tiny-linux" / "build_golden_image.py"

CONSOLE_LOG = STAGE / "console.log"

MEMORY = 512
VCPUS = 1

# The isolated libvirt network defined in triage-network.xml: forward mode
# 'none', so it carries no route to any other network. The guest hardcodes its
# own address and installs no default route, so the bridge is the only host it
# can even address, and its firewall allows only port 22 from there.
NETWORK_NAME = "triage"
NETWORK_FILE = PROJECT_DIR / "triage-network.xml"
HOST_BRIDGE = "192.168.77.1"
GUEST_IP = "192.168.77.10"
SSH_PORT = 22
CMDLINE = ("console=tty0 console=ttyS0,115200 root=/dev/vda rw rootwait=0 "
           "panic=-1")


class VmError(Exception):
    """Anything that stops the VM from coming up."""


def stage_problems() -> list:
    """What is missing before a boot can even be attempted."""
    problems = []
    for target in (GOLDEN, INITRAMFS, KEY):
        if not target.exists():
            problems.append(f"{target} is missing")
    if not problems:
        problems += lv.access_problems(lv.default_kernel(), str(INITRAMFS))
    return problems


def stage_command(command: str) -> str:
    return (f"sudo {command}\n"
            f"  # run: cd {PROJECT_DIR} && {command}")


def build_image(progress=None) -> None:
    """Rebuilds the golden image from source, including the collector.

    `progress`, when given, receives each output line as it is printed, so a
    UI can stream a build that takes minutes instead of showing nothing until
    the end. Omitting it keeps the old run-to-completion behaviour.

    Root is not required: the script was written without chroot or loop
    mounts, and the single root-owned directory it creates (sshd's
    privilege-separation dir) is faked with fakeroot, which also makes every
    other file in the image correctly root-owned instead of owned by whoever
    ran the build.
    """
    if os.geteuid() != 0 and shutil.which("fakeroot") is None:
        raise VmError("building the golden image needs root or fakeroot "
                      "(install fakeroot, or run:\n  " +
                      stage_command(f"python3 {BUILD_SCRIPT}"))
    say = progress or (lambda line: None)
    prefix = [] if os.geteuid() == 0 else ["fakeroot"]
    child = subprocess.Popen(prefix + ["python3", str(BUILD_SCRIPT)],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, errors="replace")
    tail = []
    for line in child.stdout:
        line = line.rstrip()
        tail.append(line)
        tail = tail[-200:]
        say(line)
    if child.wait() != 0:
        raise VmError("the golden image build failed:\n  " + "\n  ".join(tail[-6:]))


def stage_boot_files() -> None:
    """Copies the built image into the world-readable staging area."""
    STAGE.mkdir(parents=True, exist_ok=True)
    os.chmod(STAGE, 0o755)
    for source, name in ((PROJECT_DIR / "tiny-linux" / "golden.qcow2", GOLDEN.name),
                         (PROJECT_DIR / "tiny-linux" / "boot-initramfs.cpio.gz",
                          INITRAMFS.name)):
        if not source.exists():
            raise VmError(f"{source} is missing; build the image first")
        if source.parent == STAGE:
            continue
        target = STAGE / name
        try:
            shutil.copy2(str(source), str(target))
        except PermissionError:
            # libvirt hands the staged copy to the qemu user, so we cannot
            # overwrite it in place; we own the directory, so replace it
            target.unlink()
            shutil.copy2(str(source), str(target))
        os.chmod(target, 0o644)


def make_overlay() -> str:
    """A throwaway overlay over the golden image, so the golden stays pristine."""
    if RUN_DISK.exists():
        RUN_DISK.unlink()
    done = subprocess.run(
        ["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(GOLDEN),
         "-F", "qcow2", str(RUN_DISK)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if done.returncode != 0:
        raise VmError("could not create the run overlay:\n  " +
                      done.stdout.decode("utf-8", "replace").strip())
    os.chmod(RUN_DISK, 0o644)
    return str(RUN_DISK)


def prepare_console_log() -> str:
    """Creates the guest's boot log file up front, world writable.

    The guest's /sbin/triage-init sends its whole boot log to /dev/ttyS1 when
    that node exists, which is always true on x86 - so port 1 must be wired to a
    file or the log disappears into a dead port. QEMU keeps the mode we set here,
    which is what lets us read the log back without root.
    """
    try:
        CONSOLE_LOG.touch(exist_ok=True)
    except PermissionError:
        # QEMU created it last run and owns it; we own the directory, so we can
        # replace it with one it can write and we can read
        CONSOLE_LOG.unlink()
        CONSOLE_LOG.touch()
    # QEMU appends to this file, so truncate or old boots stay in the log
    CONSOLE_LOG.write_text("")
    os.chmod(CONSOLE_LOG, 0o666)
    return str(CONSOLE_LOG)


def domain_xml(name: str = DOMAIN, kernel: str | None = None, initrd: str = str(INITRAMFS),
               overlay: str = str(RUN_DISK), network: str = NETWORK_NAME,
               memory: int = MEMORY, vcpus: int = VCPUS, vnc: bool = True) -> str:
    kernel = kernel or lv.default_kernel()
    graphics = (
        "    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'>\n"
        "      <listen type='address' address='127.0.0.1'/>\n"
        "    </graphics>\n") if vnc else ""
    # port 1 carries the guest's boot log, see prepare_console_log()
    boot_log = (
        "    <serial type='file'>\n"
        f"      <source path='{escape(str(CONSOLE_LOG))}'/>\n"
        "      <target type='isa-serial' port='1'/>\n"
        "    </serial>\n")
    return f"""<domain type='qemu'>
  <name>{escape(name)}</name>
  <title>{escape(DOMAIN_TITLE)}</title>
  <description>disposable Alpine guest, no analysis storage attached</description>
  <memory unit='MiB'>{memory}</memory>
  <currentMemory unit='MiB'>{memory}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <kernel>{escape(kernel)}</kernel>
    <initrd>{escape(initrd)}</initrd>
    <cmdline>{escape(CMDLINE)}</cmdline>
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
{boot_log}    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <memballoon model='none'/>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <interface type='network'>
      <mac address='52:54:00:7b:1c:01'/>
      <source network='{network}'/>
      <model type='virtio'/>
    </interface>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='writeback'/>
      <source file='{escape(overlay)}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
  </devices>
</domain>
"""


class TriageVM:
    """Start, stop and hand storage to the single guest."""

    def __init__(self, vms: lv.LibvirtVms | None = None):
        self.vms = vms or lv.LibvirtVms()

    # -- state --------------------------------------------------------------

    def is_running(self) -> bool:
        info = next((d for d in self.vms.domains(prefix=DOMAIN_PREFIX)
                     if d.name == DOMAIN), None)
        return bool(info and info.running)

    # -- lifecycle ----------------------------------------------------------

    def start(self, ssh_timeout: int = 120, progress=None) -> dict:
        """Boots the guest with no storage and proves ssh before returning."""
        say = progress or (lambda *a, **k: None)
        problems = stage_problems()
        if problems:
            raise VmError("the boot files are not ready:\n  " + "\n  ".join(problems) +
                          "\n\nFix it with:\n  " + stage_command(f"python3 {BUILD_SCRIPT}"))

        if self.is_running():
            say("the VM is already running")
        else:
            say("staging the built image where QEMU can read it")
            stage_boot_files()
            say("creating a throwaway overlay over the golden image")
            overlay = make_overlay()
            prepare_console_log()
            say("defining the domain")
            xml = domain_xml(overlay=overlay)
            check = self.vms.validate_xml(xml)
            if not check.ok:
                raise VmError("libvirt rejected the domain XML:\n" +
                              (check.stderr or check.stdout))
            self.vms.replace_domain(DOMAIN, prefix=DOMAIN_PREFIX)
            defined = self.vms.define(xml)
            if not defined.ok:
                raise VmError("virsh define failed:\n" + (defined.stderr or defined.stdout))
            say("starting the VM")
            started = self.vms.start(DOMAIN)
            if not started.ok:
                raise VmError("the VM did not start:\n" + (started.stderr or started.stdout))

        say(f"waiting for ssh on {GUEST_IP}:{SSH_PORT}")
        gate = self.vms.ssh_check(DOMAIN, port=SSH_PORT, timeout=ssh_timeout,
                                  key=str(KEY), host=GUEST_IP)
        if not gate.ok:
            raise VmError(
                "ssh never answered, so nothing will be attached.\n" + gate.output +
                "\nThe VM is still running; its console shows the boot log.")
        say("ssh answered; the guest is ready")
        return {"name": DOMAIN, "running": True, "ssh_ok": True,
                "host": GUEST_IP, "port": SSH_PORT}

    def stop(self, detach_first: bool = True) -> dict:
        """Destroys the VM. Safe to call when it is not running.

        detach_first gives the disk back to the host before the domain goes
        away, so libvirt does not leave a read-only disk behind attached to a
        domain that no longer exists.
        """
        info = next((d for d in self.vms.domains(prefix=DOMAIN_PREFIX)
                     if d.name == DOMAIN), None)
        if info is None:
            return {"name": DOMAIN, "running": False, "ssh_ok": False, "port": None}
        if info.running and detach_first:
            try:
                self.detach()
            except Exception:                # noqa: BLE001
                pass                        # destroying anyway; do not block exit
        if info.running:
            self.vms.destroy(DOMAIN)
        self.vms.undefine(DOMAIN)
        if RUN_DISK.exists():
            RUN_DISK.unlink()
        return {"name": DOMAIN, "running": False, "ssh_ok": False, "port": None}

    def restart(self, ssh_timeout: int = 120, progress=None) -> dict:
        self.stop()
        time.sleep(1)
        return self.start(ssh_timeout=ssh_timeout, progress=progress)

    # -- storage ------------------------------------------------------------

    GUEST_NODE = "/dev/vdb"

    def probe_disk(self) -> lv.ControlResult:
        """What the guest sees right now. Raw result, so a failure can be shown."""
        return self.vms.guest_has_disk(DOMAIN, port=SSH_PORT, key=str(KEY), host=GUEST_IP)

    def guest_has_disk(self) -> bool:
        return self.probe_disk().ok

    def guest_disk_readonly(self) -> bool:
        """Asks the guest itself whether the disk can be written to.

        The host-side XML says ``<readonly/>``, but the whole promise of this tool
        is that the evidence stays byte-identical, so it is worth one round trip to
        hear the guest agree rather than trusting the XML.
        """
        return self.vms.ssh_run(
            DOMAIN, f"blockdev --getro {self.GUEST_NODE} 2>/dev/null || echo unknown",
            port=SSH_PORT, key=str(KEY), host=GUEST_IP).stdout.strip() == "1"

    def attach(self, device: str, wait: float = 25.0, progress=None) -> dict:
        """Hands a device over read-only, then proves the handoff happened.

        Never before ssh has answered, and never writable: see
        ``ARCHITECTURE.md`` for why the evidence disk is not touched on the host.
        """
        say = progress or (lambda *a, **k: None)
        if not self.is_running():
            raise VmError("the VM is not running, so nothing can be attached")
        if self.guest_has_disk():
            raise VmError(
                f"{self.GUEST_NODE} is already in the guest from an earlier disk; "
                "forget or stop the VM before sending another one")
        say(f"handing {device} to the guest as {self.GUEST_NODE}, read-only")
        result = self.vms.attach_disk(DOMAIN, device, readonly=True)
        deadline = time.monotonic() + wait
        probe = self.probe_disk()
        while not probe.ok and time.monotonic() < deadline:
            time.sleep(1.0)
            probe = self.probe_disk()
        if not probe.ok:
            raise VmError(
                f"{device} was attached as {self.GUEST_NODE} but the guest does not "
                f"show it.\n{probe.output or 'no answer over ssh'}\n"
                "Nothing is attached that the guest can vouch for, so this is not "
                "being treated as a successful handoff.")
        if not self.guest_disk_readonly():
            self.detach()
            raise VmError(
                f"REFUSING to go on: the guest reports {self.GUEST_NODE} as writable, "
                "so this is not the read-only handoff this tool promises.\n"
                "The disk has been taken back out of the VM.")
        say("the guest has it, and reports it read-only")
        return {"device": device, "attached": True, "guest_node": self.GUEST_NODE,
                "readonly": True, "detail": result.output, "guest": probe.output}

    def detach(self, device: str = "", progress=None) -> dict:
        """Gives the disk back to the host. Safe to call when nothing is attached."""
        say = progress or (lambda *a, **k: None)
        if not self.is_running():
            return {"detached": True, "detail": "the VM is not running"}
        if not self.guest_has_disk():
            return {"detached": True, "detail": "nothing was attached"}
        say(f"taking {self.GUEST_NODE} back out of the guest")
        result = self.vms.detach_disk(DOMAIN, self.GUEST_NODE.rsplit("/", 1)[-1],
                                      device=device)
        deadline = time.monotonic() + 15.0
        while self.guest_has_disk() and time.monotonic() < deadline:
            time.sleep(1.0)
        return {"detached": not self.guest_has_disk(), "detail": result.output}

    def console(self) -> str:
        """Where to look if the guest does not come up."""
        return f"virsh -c qemu:///system console {DOMAIN}"


def image_report() -> dict:
    """What is on disk right now, for the UI."""
    def info(path: Path) -> dict:
        try:
            stat = path.stat()
        except OSError:
            return {"exists": False, "size_human": "-"}
        return {"exists": True, "bytes": stat.st_size,
                "size_human": human_size(stat.st_size), "path": str(path)}
    return {"golden": info(GOLDEN), "initramfs": info(INITRAMFS),
            "key": info(KEY), "overlay": info(RUN_DISK), "problems": stage_problems()}


if __name__ == "__main__":
    # handy for a quick manual check without the web ui
    vm = TriageVM()
    print(image_report())
    print(vm.start(progress=lambda m: print("  " + m, flush=True)))