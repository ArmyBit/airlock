#!/usr/bin/env python3
"""udev control actions used by the GUI.

Every privileged action is funnelled through :class:`UdevControl`, which never
uses a shell, validates every path/key/value it is given, and elevates via
polkit (``pkexec``) when the app is not already running as root.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

UDEVADM = "/usr/bin/udevadm"
RULE_DIRS = ("/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d")
RULE_FILE_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*\.rules$")
DEVNODE_RE = re.compile(r"^/dev/[A-Za-z0-9][A-Za-z0-9_./-]*$")
PROPERTY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
MAX_RULE_BYTES = 64 * 1024


class ControlError(Exception):
    pass


@dataclass
class ControlResult:
    ok: bool
    command: list = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    code: int = 0

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout.strip(), self.stderr.strip()) if part)


def validate_devnode(devnode: str) -> str:
    if not DEVNODE_RE.match(devnode or ""):
        raise ControlError(f"not a valid device node: {devnode!r}")
    return devnode


def validate_syspath(syspath: str) -> str:
    path = os.path.realpath(syspath or "")
    if not path.startswith("/sys/") or not os.path.exists(path):
        raise ControlError(f"not a sysfs path: {syspath!r}")
    return path


def validate_rule_name(name: str) -> str:
    if not RULE_FILE_RE.match(name or ""):
        raise ControlError(f"rule filenames must look like 99-my.rules, got {name!r}")
    return name


def validate_property(key: str, value: str) -> tuple[str, str]:
    if not PROPERTY_RE.match(key or ""):
        raise ControlError(f"property names must be UPPER_SNAKE_CASE, got {key!r}")
    if "\n" in value or len(value) > 512:
        raise ControlError("property value too long or contains a newline")
    return key, value


def _chain(steps: list) -> ControlResult:
    """Runs several actions in order and folds them into one report."""
    lines, failures = [], []
    command: list = []
    for label, result in steps:
        command += result.command
        status = "ok" if result.ok else f"failed (exit {result.code})"
        lines.append(f"{label}: {status}")
        if result.output.strip():
            lines.append(result.output.strip())
        if not result.ok:
            failures.append(f"{label}: {result.stderr.strip() or result.stdout.strip() or status}")
    ok = not failures
    return ControlResult(ok, command, "\n".join(lines), "\n".join(failures), 0 if ok else 1)


class UdevControl:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    @property
    def is_root(self) -> bool:
        return os.geteuid() == 0

    @property
    def elevation(self) -> str:
        if self.is_root:
            return "root"
        if shutil.which("pkexec"):
            return "pkexec"
        if shutil.which("sudo"):
            return "sudo"
        return "none"

    def _elevate(self, argv: list) -> list:
        if self.is_root:
            return argv
        if shutil.which("pkexec"):
            return ["pkexec", *argv]
        if shutil.which("sudo"):
            return ["sudo", *argv]
        raise ControlError(
            "this action needs root; start the app with sudo or install polkit (pkexec)"
        )

    def _execute(self, argv: list, elevate: bool, stdin: str | None = None,
                  timeout: float | None = None) -> ControlResult:
        cmd = self._elevate(argv) if elevate else argv
        limit = self.timeout if timeout is None else timeout
        try:
            proc = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=limit,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ControlResult(False, cmd, "", f"timed out after {limit:.0f}s", 124)
        except OSError as exc:
            return ControlResult(False, cmd, "", str(exc), 126)
        return ControlResult(proc.returncode == 0, cmd, proc.stdout, proc.stderr, proc.returncode)

    def run_raw(self, argv: list, elevate: bool = True, stdin: str | None = None,
                timeout: float | None = None) -> ControlResult:
        return self._execute(list(argv), elevate, stdin, timeout)

    def udevadm(self, *args: str, elevate: bool = False) -> ControlResult:
        return self._execute([UDEVADM, *args], elevate)

    def trigger(self, syspath: str, action: str = "change") -> ControlResult:
        if action not in ("add", "remove", "change", "rename"):
            raise ControlError(f"unsupported action {action!r}")
        return self.udevadm("trigger", f"--action={action}", validate_syspath(syspath), elevate=True)

    def trigger_block(self, action: str = "change") -> ControlResult:
        if action not in ("add", "remove", "change"):
            raise ControlError(f"unsupported action {action!r}")
        return self.udevadm("trigger", f"--action={action}", "--subsystem-match=block", elevate=True)

    def reload_rules(self) -> ControlResult:
        return self.udevadm("control", "--reload-rules", elevate=True)

    def restart_udevd(self) -> ControlResult:
        if shutil.which("systemctl"):
            return self._execute(["systemctl", "restart", "systemd-udevd.service"], True)
        if shutil.which("service"):
            return self._execute(["service", "udev", "restart"], True)
        raise ControlError("neither systemctl nor service found")

    def set_property(self, key: str, value: str) -> ControlResult:
        key, value = validate_property(key, value)
        return self.udevadm("control", f"--property={key}={value}", elevate=True)

    def test_rules(self, syspath: str) -> ControlResult:
        return self.udevadm("test", validate_syspath(syspath), elevate=False)

    def change_access(self, devnode: str, mode: str, owner: str | None = None, group: str | None = None) -> ControlResult:
        validate_devnode(devnode)
        if not re.match(r"^0?[0-7]{3,4}$", mode or ""):
            raise ControlError(f"mode must be octal like 660, got {mode!r}")
        argv = ["chmod", mode, devnode]
        if owner or group:
            target = owner or ":"
            if group:
                target += f":{group}"
            argv = ["chown", target, devnode]
        return self._execute(argv, True)

    def list_rules(self) -> ControlResult:
        dirs = [d for d in RULE_DIRS if os.path.isdir(d)]
        paths = [p for d in dirs for p in sorted(os.listdir(d))]
        listing = "\n".join(f"{d}/{p}" for d in dirs for p in sorted(os.listdir(d)))
        return ControlResult(True, ["ls", *dirs], listing, "", 0)

    def install_rule(self, name: str, text: str, directory: str = "/etc/udev/rules.d") -> ControlResult:
        validate_rule_name(name)
        if directory not in RULE_DIRS:
            raise ControlError(f"rule directory must be one of {', '.join(RULE_DIRS)}")
        if len(text.encode()) > MAX_RULE_BYTES:
            raise ControlError(f"rule file too large (max {MAX_RULE_BYTES // 1024} KiB)")
        target = os.path.join(directory, validate_rule_name(name))
        return self._execute(["tee", target], True, stdin=text)

    def remove_rule(self, name: str, directory: str = "/etc/udev/rules.d") -> ControlResult:
        validate_rule_name(name)
        if directory not in RULE_DIRS:
            raise ControlError(f"rule directory must be one of {', '.join(RULE_DIRS)}")
        return self._execute(["rm", "-f", os.path.join(directory, validate_rule_name(name))], True)

    def automount_rule_text(self, name: str, serial: str | None = None,
                            kernel: str | None = None) -> str:
        return NOAUTO_RULE_TEMPLATE.format(name=name, match=automount_match(serial, kernel))

    def automount_state(self, devnode: str, syspath: str | None = None) -> ControlResult:
        """Reports whether the host currently mounts the disk and what udev says."""
        validate_devnode(devnode)
        mounts, mounts_err = self._mountpoints(devnode)
        parts = []
        if syspath:
            props = self.udevadm("info", "--query=property", "--property=ID_AUTOMOUNT", syspath)
            props2 = self.udevadm("info", "--query=property", "--property=UDISKS_IGNORE", syspath)
            parts.append(f"ID_AUTOMOUNT = {(props.stdout.strip() or '(unset)')}")
            parts.append(f"UDISKS_IGNORE = {(props2.stdout.strip() or '(unset)')}")
        parts.append(f"mounted on host: {mounts or 'no'}")
        if mounts_err:
            parts.append(f"({mounts_err})")
        return ControlResult(True, ["udevadm", "info", devnode], "\n".join(parts), "", 0)

    def _mountpoints(self, devnode: str) -> tuple[str, str]:
        real = os.path.realpath(devnode)
        found, err = [], ""
        try:
            with open("/proc/mounts", "r") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    src = parts[0].replace("\\040", " ")
                    if src == real or src.startswith(f"{real}"):
                        found.append(f"{src} → {parts[1]}")
        except OSError as exc:
            err = f"cannot read /proc/mounts: {exc}"
        return "\n".join(found), err

    def unmount_device(self, devnode: str) -> ControlResult:
        validate_devnode(devnode)
        mounts, _ = self._mountpoints(devnode)
        if not mounts:
            return ControlResult(True, ["umount", devnode], "already unmounted on the host", "", 0)
        if shutil.which("udisksctl"):
            polite = self._execute(["udisksctl", "unmount", "-b", devnode], elevate=False)
            if polite.ok:
                return polite
            polite2 = self._execute(["udisksctl", "unmount", "-b", devnode], elevate=True)
            if polite2.ok:
                return polite2
        return self._execute(["umount", devnode], True)

    def block_automount(self, name: str, serial: str | None = None, kernel: str | None = None,
                        devnode: str | None = None, syspath: str | None = None,
                        directory: str = "/etc/udev/rules.d") -> ControlResult:
        """Writes the noauto rule, reloads udev, then re-applies it to the device."""
        text = self.automount_rule_text(name, serial, kernel)
        steps = [("write rule", self.install_rule(name, text, directory)),
                 ("reload rules", self.reload_rules())]
        if syspath:
            steps.append(("re-trigger device", self.trigger(syspath, "change")))
        if devnode:
            steps.append(("unmount", self.unmount_device(devnode)))
        return _chain(steps)

    def allow_automount(self, name: str, syspath: str | None = None,
                        directory: str = "/etc/udev/rules.d") -> ControlResult:
        steps = [("remove rule", self.remove_rule(name, directory)),
                 ("reload rules", self.reload_rules())]
        if syspath:
            steps.append(("re-trigger device", self.trigger(syspath, "change")))
        return _chain(steps)

DEFAULT_RULE_TEMPLATE = (
    "# managed by storage watcher - {name}\n"
    'ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="{kernel}",'
    ' ATTR{{removable}}=="1", MODE="0660", GROUP="plugdev"\n'
)

NOAUTO_RULE_TEMPLATE = (
    "# managed by storage watcher - {name}\n"
    "# keeps the desktop (udisks2/GVfs/KDE/GNOME) from mounting this disk on the host.\n"
    "# The disk is dedicated to a VM, so the host must leave it alone.\n"
    'ACTION=="add|change", SUBSYSTEM=="block", {match},'
    ' ENV{{UDISKS_IGNORE}}="1", ENV{{ID_AUTOMOUNT}}="0", ENV{{ID_FS_USAGE}}="noauto"\n'
)


def automount_match(serial: str | None = None, kernel: str | None = None) -> str:
    """Picks the most durable way to recognise a disk in a rule."""
    if serial and re.match(r"^[0-9A-Za-z._:+-]{1,64}$", serial):
        return f'ENV{{ID_SERIAL_SHORT}}=="{serial}"'
    if kernel and re.match(r"^[0-9A-Za-z]{1,32}$", kernel):
        return f'KERNEL=="{kernel}", ATTR{{removable}}=="1"'
    raise ControlError("need a device serial or kernel name to write the rule")