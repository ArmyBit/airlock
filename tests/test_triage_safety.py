#!/usr/bin/env python3
"""Tests for the things that must never go wrong.

* the host-side safety rules (refusing the OS disk, read-only attachment, no
  accidental privilege prompts), and
* the guest image policy (locked-down network, key-only ssh).

Everything here runs without a VM, without a disk and without root.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import libvirt_vm as lv  # noqa: E402
from udev_control import ControlResult  # noqa: E402

BUILDER = PROJECT_DIR / "tiny-linux" / "build_golden_image.py"


def load_builder():
    """Imports the image builder so its templates can be inspected."""
    spec = importlib.util.spec_from_file_location("golden_builder", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMachine:
    """A sysfs tree shaped like the real one, plus a fake /proc/mounts.

    ``devices`` maps ``maj:min`` to a spec::

        "253:0": {"name": "luks-abc", "slaves": ["8:2"]},
        "8:2":   {"name": "sda2", "disk": "sda"},
        "8:0":   {"name": "sda", "partitions": {"8:1": "sda1", "8:3": "sda3"}},

    which reproduces the real layout: ``/sys/devices/.../block/<disk>/`` holds
    the disk's ``dev`` file and one directory per partition, and
    ``/sys/dev/block/<maj:min>`` is a symlink to whichever of those is the
    device.
    """

    def __init__(self, root: Path, devices: dict, mounts: str):
        self.block = root / "sys" / "dev" / "block"
        self.names = {}
        self._build(devices)
        self.mounts = root / "mounts"
        self.mounts.write_text(mounts)

    def _dir_for(self, disk: str, part: str | None) -> Path:
        base = self.block.parent.parent / "devices" / "pci" / "fake" / "block" / disk
        return base if part is None else base / part

    def _build(self, devices: dict) -> None:
        self.block.mkdir(parents=True, exist_ok=True)
        disks = {}
        for mm, spec in devices.items():
            disks.setdefault(spec.get("disk", spec["name"]), {})
        for mm, spec in devices.items():
            disk = spec.get("disk", spec["name"])
            part = None if spec["name"] == disk else spec["name"]
            here = self._dir_for(disk, part)
            here.mkdir(parents=True, exist_ok=True)
            (here / "dev").write_text(mm + "\n")
            self.names[spec["name"]] = mm
            (self.block / mm).symlink_to(here)
            for slave in spec.get("slaves", []):
                slave_dir = here / "slaves" / slave
                slave_dir.mkdir(parents=True, exist_ok=True)
                (slave_dir / "dev").write_text(slave + "\n")
            for part_mm, part_name in spec.get("partitions", {}).items():
                part_dir = here / part_name
                part_dir.mkdir(parents=True, exist_ok=True)
                (part_dir / "dev").write_text(part_mm + "\n")
                self.names[part_name] = part_mm
                (self.block / part_mm).symlink_to(part_dir)
        del disks

    def patch(self):
        """Redirects the guard at this fake machine."""
        block = str(self.block)
        names = dict(self.names)

        def fake_maj_min(path):
            return names.get(os.path.basename(str(path)))

        return (mock.patch.object(lv, "SYS_BLOCK", block),
                mock.patch.object(lv, "_maj_min", fake_maj_min))


class RootDiskGuard(unittest.TestCase):
    """The host root stack must never be attachable (invariant T5)."""

    def test_refuses_luks_root_its_disk_and_siblings(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine = FakeMachine(Path(tmp), {
                "253:0": {"name": "luks-abc", "slaves": ["8:2"]},
                "8:2": {"name": "sda2", "disk": "sda"},
                "8:0": {"name": "sda", "partitions": {"8:1": "sda1", "8:3": "sda3"}},
                "8:100": {"name": "sdz"},
            }, "/dev/mapper/luks-abc / btrfs rw 0 0\n"
               "/dev/mapper/luks-abc /home btrfs rw 0 0\n")
            p1, p2 = machine.patch()
            with p1, p2:
                for refused in ("/dev/sda", "/dev/sda2", "/dev/sda1", "/dev/sda3",
                                "/dev/mapper/luks-abc"):
                    with self.subTest(refused), self.assertRaises(lv.ControlError):
                        lv.refuse_host_disk(refused, str(machine.mounts))
                lv.refuse_host_disk("/dev/sdz", str(machine.mounts))

    def test_refuses_plain_root_partition(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine = FakeMachine(Path(tmp), {
                "8:1": {"name": "sdb1", "disk": "sdb"},
                "8:16": {"name": "sdb"},
                "8:100": {"name": "sdz"},
            }, "/dev/sdb1 / ext4 rw 0 0\n")
            p1, p2 = machine.patch()
            with p1, p2:
                for refused in ("/dev/sdb1", "/dev/sdb"):
                    with self.subTest(refused), self.assertRaises(lv.ControlError):
                        lv.refuse_host_disk(refused, str(machine.mounts))
                lv.refuse_host_disk("/dev/sdz", str(machine.mounts))

    def test_lvm_on_raid_is_followed_down_to_the_disks(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine = FakeMachine(Path(tmp), {
                "253:1": {"name": "lvm-root", "slaves": ["9:0"]},
                "9:0": {"name": "md0", "slaves": ["8:3", "8:17"]},
                "8:3": {"name": "sda3", "disk": "sda"},
                "8:17": {"name": "sdb1", "disk": "sdb"},
                "8:100": {"name": "sdz"},
            }, "/dev/mapper/lvm-root / ext4 rw 0 0\n")
            p1, p2 = machine.patch()
            with p1, p2:
                for refused in ("/dev/mapper/lvm-root", "/dev/sda3", "/dev/sdb1"):
                    with self.subTest(refused), self.assertRaises(lv.ControlError):
                        lv.refuse_host_disk(refused, str(machine.mounts))

    def test_btrfs_subvolume_mount_still_resolves(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine = FakeMachine(Path(tmp), {
                "253:0": {"name": "luks-abc", "slaves": ["8:2"]},
                "8:2": {"name": "sda2", "disk": "sda"},
                "8:0": {"name": "sda"},
            }, "/dev/mapper/luks-abc[/@] / btrfs rw 0 0\n")
            p1, p2 = machine.patch()
            with p1, p2:
                with self.assertRaises(lv.ControlError):
                    lv.refuse_host_disk("/dev/sda2", str(machine.mounts))

    def test_missing_mounts_fails_open_for_tests(self):
        # an unreadable /proc/mounts must not wedge every launch; it just means
        # we learn nothing and let the caller proceed
        with tempfile.TemporaryDirectory() as tmp:
            labels, chain = lv.host_root_devices(str(Path(tmp) / "nope"))
        self.assertEqual(labels, {})
        self.assertEqual(chain, [])

    def test_non_block_device_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            machine = FakeMachine(Path(tmp), {
                "8:1": {"name": "sda1", "disk": "sda"},
            }, "/dev/sda1 / ext4 rw 0 0\n")
            p1, p2 = machine.patch()
            with p1, p2:
                with self.assertRaises(lv.ControlError):
                    lv.refuse_host_disk("/etc/passwd", str(machine.mounts))


class FakeControl:
    """Stands in for UdevControl and records what it was asked to run."""

    def __init__(self, results=None):
        self.calls = []
        self.results = results or {}

    def run_raw(self, argv, elevate=True, stdin=None, timeout=None):
        # virsh is handed a file, not stdin, so read back whatever was sent
        xml = stdin
        if "--file" in argv:
            with open(argv[argv.index("--file") + 1], encoding="utf-8") as handle:
                xml = handle.read()
        self.calls.append({"argv": list(argv), "elevate": elevate, "stdin": xml})
        key = " ".join(argv)
        for pattern, result in self.results.items():
            if pattern in key:
                return result
        return ControlResult(True, list(argv), "", "", 0)


class AttachmentSafety(unittest.TestCase):
    """Attachment must be read-only, guarded, and must not prompt for privileges."""

    def setUp(self):
        self.vms = lv.LibvirtVms(control=FakeControl())
        self.key = str(PROJECT_DIR / "libvirt_vm.py")

    def test_readonly_disk_xml_declares_readonly(self):
        with mock.patch.object(lv, "refuse_host_disk"), \
                mock.patch.object(lv.os.path, "exists", return_value=True):
            self.vms.attach_disk("tiny-sdz", "/dev/sdz", readonly=True)
        xml = self.vms.control.calls[-1]["stdin"]
        self.assertIn("<readonly/>", xml)
        self.assertIn("<target dev='vdb' bus='virtio'/>", xml)
        self.assertIn("<source dev='/dev/sdz'/>", xml)

    def test_writable_attach_is_refused(self):
        with mock.patch.object(lv, "refuse_host_disk"), \
                mock.patch.object(lv.os.path, "exists", return_value=True):
            with self.assertRaises(lv.ControlError) as caught:
                self.vms.attach_disk("tiny-sdz", "/dev/sdz", readonly=False)
        self.assertIn("writable", str(caught.exception).lower())
        self.assertEqual(self.vms.control.calls, [], "nothing may reach virsh")

    def test_host_disk_is_refused_before_virsh_is_touched(self):
        with mock.patch.object(lv.os.path, "exists", return_value=True), \
                mock.patch.object(lv, "refuse_host_disk") as guard:
            guard.side_effect = lv.ControlError("REFUSING: /dev/sda")
            with self.assertRaises(lv.ControlError):
                self.vms.attach_disk("tiny-sda", "/dev/sda", readonly=True)
        self.assertEqual(self.vms.control.calls, [])

    def test_define_and_start_refuses_the_host_disk(self):
        with mock.patch.object(lv, "refuse_host_disk") as guard:
            guard.side_effect = lv.ControlError("REFUSING: /dev/sda")
            with self.assertRaises(lv.ControlError):
                self.vms.define_and_start("/dev/sda")
        guard.assert_called_once_with("/dev/sda")

    def test_diskless_boot_skips_the_guard(self):
        vms = self.vms
        with mock.patch.object(lv, "refuse_host_disk") as guard, \
                mock.patch.object(lv, "access_problems", return_value=[]), \
                mock.patch.object(lv.LibvirtVms, "best_initrd",
                                  return_value=str(PROJECT_DIR / "libvirt_vm.py")), \
                mock.patch.object(lv, "default_kernel", return_value=str(PROJECT_DIR / "libvirt_vm.py")), \
                mock.patch.object(lv.LibvirtVms, "validate_xml",
                                  return_value=ControlResult(True, [], "", "", 0)), \
                mock.patch.object(lv.LibvirtVms, "replace_domain",
                                  return_value=ControlResult(True, [], "", "", 0)), \
                mock.patch.object(lv.LibvirtVms, "define",
                                  return_value=ControlResult(True, [], "", "", 0)), \
                mock.patch.object(lv.LibvirtVms, "start",
                                  return_value=ControlResult(True, [], "", "", 0)):
            name, xml, report = vms.define_and_start("", name="tiny-sdz")
        guard.assert_not_called()
        self.assertTrue(report.ok)
        self.assertNotIn("'vdb'", xml, "a disk-less boot must not define a data disk")

    def test_ssh_probes_do_not_escalate_privileges(self):
        self.vms.control.results = {
            "ssh": ControlResult(False, [], "", "Permission denied (publickey)", 255)}
        self.vms.ssh_check("tiny-sdz", port=2222, timeout=5, key=self.key)
        self.assertTrue(self.vms.control.calls, "ssh was never attempted")
        for call in self.vms.control.calls:
            self.assertFalse(call["elevate"], "ssh must not run through pkexec")

        self.vms.control.calls.clear()
        self.vms.guest_has_disk("tiny-sdz", port=2222, key=self.key)
        for call in self.vms.control.calls:
            self.assertFalse(call["elevate"], "ssh must not run through pkexec")


class RealHostGuard(unittest.TestCase):
    """Runs against this machine, reading only sysfs and /proc/mounts.

    The fake trees above prove the logic; this proves the shape of this
    particular machine's root stack, which is the one that would actually
    brick the box.
    """

    @staticmethod
    def _node_for(mm):
        try:
            with open(f"/sys/dev/block/{mm}/uevent") as handle:
                fields = dict(line.strip().split("=", 1)
                              for line in handle if "=" in line)
        except OSError:
            return None
        name = fields.get("DEVNAME")
        return f"/dev/{name}" if name else None

    def test_real_root_stack_is_refused_and_other_disks_are_not(self):
        labels, chain = lv.host_root_devices()
        if not labels:
            self.skipTest("no /dev-backed root mount found")
        self.assertTrue(chain, "the root chain should name what we resolved")

        nodes = []
        for mm in sorted(k for k in labels if not k.endswith(":disk")):
            node = self._node_for(mm)
            if node:
                nodes.append(node)
        self.assertGreaterEqual(len(nodes), 2,
                                "expected the root device and its disk at least")
        for node in nodes:
            with self.subTest(node), self.assertRaises(lv.ControlError):
                lv.refuse_host_disk(node)

        protected = {os.path.basename(node) for node in nodes}
        other = sorted(name for name in os.listdir("/sys/block")
                       if not name.startswith(("loop", "ram", "zram", "dm-", "md"))
                       and name not in protected)
        if not other:
            self.skipTest("no unrelated disk on this machine to check the allow path")
        for name in other:
            with self.subTest(name):
                lv.refuse_host_disk(f"/dev/{name}")


class GuestImagePolicy(unittest.TestCase):
    """The guest must not be able to execute the disk, or phone home."""

    @classmethod
    def setUpClass(cls):
        cls.source = BUILDER.read_text()
        cls.builder = load_builder()

    def test_network_isolation_is_fail_closed(self):
        init = self.builder.INIT_SCRIPT
        self.assertIn("ISOLATION_OK", init)
        self.assertIn("ISOLATION_FAILED", init)
        self.assertIn("poweroff", init)
        # the ruleset must be verified before sshd is allowed to listen
        self.assertLess(init.index("ISOLATION_OK"), init.index("starting sshd"))

    def test_ruleset_drops_everything_by_default(self):
        rules = self.builder.NFT_RULESET
        self.assertEqual(rules.count("policy drop"), 3,
                         "input, forward and output must all default to drop")
        self.assertIn("tcp dport 22", rules)
        self.assertIn("tcp sport 22", rules)
        self.assertNotIn("ct state", rules,
                         "conntrack is unavailable in the guest, do not rely on it")

    def test_ruleset_substitutes_the_real_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            self.builder.write_firewall(root)
            text = (root / "etc" / "nftables.conf").read_text()
        self.assertNotIn("__PST__", text, "placeholder leaked into the ruleset")
        self.assertIn(self.builder.HOST_BRIDGE, text)
        self.assertNotIn("passt", text.lower(),
                         "the ruleset must name the bridge, not the old tunnel")

    def test_sshd_is_key_only(self):
        config = re.search(r'sshd_config"\)\.write_text\(f"""(.*?)"""',
                           self.source, re.S).group(1)
        self.assertRegex(config, r"(?im)^PasswordAuthentication no$")
        self.assertRegex(config, r"(?im)^PermitRootLogin prohibit-password$")
        self.assertRegex(config, r"(?im)^PermitEmptyPasswords no$")
        self.assertNotIn("UsePAM", config)

    def test_root_account_is_not_locked(self):
        # '!' makes OpenSSH refuse publickey logins when PAM is unavailable
        self.assertRegex(self.source, r'parts\[1\] = "\*"')
        self.assertNotRegex(self.source, r'parts\[1\] = "!"')

    def test_guest_boot_does_not_automount_or_execute_the_disk(self):
        init = self.builder.INIT_SCRIPT
        for dangerous in ("udevadm trigger", "mount /dev/vdb", "chroot ", "udisk"):
            self.assertNotIn(dangerous, init,
                             f"the guest init must not contain {dangerous!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)