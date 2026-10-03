#!/usr/bin/env python3
"""Runs a user-configured command when a device is connected.

The command is executed directly (never through a shell) and receives the
device details as environment variables, so a hook script cannot be tricked
into running shell syntax by a device name.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field

import udev_monitor as ud


@dataclass
class HookResult:
    command: list
    env_name: str = ""
    env_value: str = ""
    code: int = 0
    stdout: str = ""
    stderr: str = ""
    launched: bool = False
    env_overrides: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.launched and self.code == 0

    @property
    def summary(self) -> str:
        if not self.launched:
            return f"not launched ({self.stderr or 'disabled'})"
        return f"pid {self.env_name} exited {self.code}" if self.code else f"running (pid {self.env_name})"


def device_env(event: ud.DeviceEvent) -> dict:
    return {
        "DEV_ACTION": event.action,
        "DEV_SUBSYSTEM": event.subsystem,
        "DEV_NAME": event.name,
        "DEV_NODE": event.devnode,
        "DEV_DEVTYPE": event.devtype,
        "DEV_SIZE": event.size,
        "DEV_FILESYSTEM": event.fstype,
        "DEV_FSLABEL": event.fslabel,
        "DEV_VENDOR": event.vendor,
        "DEV_MODEL": event.model,
        "DEV_SERIAL": event.serial,
        "DEV_BUS": event.bus,
        "DEV_ID_PATH": event.devpath,
        "DEV_SYSFS_PATH": event.syspath,
        "DEV_TIMESTAMP": f"{event.timestamp:.3f}",
    }


class HookRunner:
    def __init__(self, command: str = "", delay: float = 3.0, enabled: bool = False, timeout: float = 20.0):
        self.command = command
        self.delay = max(0.0, delay)
        self.enabled = enabled
        self.timeout = timeout
        self.log: list[HookResult] = []
        self._threads: list[threading.Thread] = []

    def configure(self, command: str, delay: float, enabled: bool) -> None:
        self.command = command.strip()
        self.delay = max(0.0, float(delay))
        self.enabled = bool(enabled)

    @staticmethod
    def parse_env(command: str) -> tuple:
        """Splits leading KEY=VALUE tokens off the command."""
        argv = shlex.split(command)
        extra = {}
        while argv and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", argv[0]):
            key, _, value = argv[0].partition("=")
            extra[key] = value
            argv.pop(0)
        return extra, argv

    @staticmethod
    def parse(command: str) -> list:
        if not command.strip():
            raise ValueError("no command configured")
        _extra, argv = HookRunner.parse_env(command)
        if not argv:
            raise ValueError("no command configured (only environment variables given)")
        program = argv[0]
        resolved = shutil.which(program) if not os.path.sep in program else program
        if not resolved:
            raise ValueError(f"command not found: {program}")
        if not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
            raise ValueError(f"not executable: {resolved}")
        return [resolved, *argv[1:]]

    def dry_run(self, event: ud.DeviceEvent) -> HookResult:
        try:
            argv = self.parse(self.command)
        except ValueError as exc:
            return HookResult([], stderr=str(exc))
        extra, _ = self.parse_env(self.command)
        env = device_env(event)
        return HookResult(argv, env_name=env["DEV_NODE"], code=0, stdout="", stderr="dry run",
                          launched=False, env_overrides=extra)

    def submit(self, event: ud.DeviceEvent) -> HookResult | None:
        if not self.enabled or event.action != "add":
            return None
        try:
            argv = self.parse(self.command)
        except ValueError as exc:
            result = HookResult([], stderr=str(exc))
            self.log.append(result)
            return result
        extra, _ = self.parse_env(self.command)
        env = {**os.environ, **device_env(event), **extra}
        if self.delay:
            time.sleep(self.delay)
        try:
            proc = subprocess.Popen(
                argv, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except OSError as exc:
            result = HookResult(argv, stderr=str(exc))
            self.log.append(result)
            return result
        result = HookResult(argv, env_name=str(proc.pid), launched=True, env_overrides=extra)
        self.log.append(result)

        def collect() -> None:
            try:
                out, err = proc.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                err = (err or "") + f"\n[killed after {self.timeout:.0f}s]"
            result.code = proc.returncode
            result.stdout = (out or "")[-4000:]
            result.stderr = (err or "")[-4000:]

        thread = threading.Thread(target=collect, name="hook-output", daemon=True)
        thread.start()
        self._threads.append(thread)
        return result

    def alive(self) -> list:
        return [t for t in self._threads if t.is_alive()]