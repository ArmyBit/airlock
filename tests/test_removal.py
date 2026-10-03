"""Unplugging the subject disk resets the app: the VM stops and the UI goes back
to waiting. These tests use fakes throughout - nothing here may touch libvirt,
udev, or the network."""

import threading
import unittest

import device_listener
import triage_state as ts
import udev_monitor
import web_server


class FakeVM:
    def __init__(self, fail_stop=False):
        self.stops = 0
        self.fail_stop = fail_stop

    def stop(self, detach_first=True):
        self.stops += 1
        if self.fail_stop:
            raise RuntimeError("libvirt is gone")
        return {"running": False, "ssh_ok": False}


def subject(actions, devnode="/dev/sdb", state=ts.ATTACHED, report=None):
    actions.state.set_device(ts.Device(devnode=devnode, size=1000))
    actions.state.set_vm(running=True, ssh_ok=True)
    actions.state.set_report(report)
    actions.state.move(state, "test setup", force=True)
    return actions


class RemovalTests(unittest.TestCase):
    def setUp(self):
        self.state = ts.TriageState()
        self.actions = web_server.Actions(self.state)
        self.vm = FakeVM()
        self.actions._vm = self.vm

    def test_unplug_stops_the_vm_clears_everything_and_waits_again(self):
        subject(self.actions, report={"summary": {}, "rows": []})
        notes_before = len(self.state.snapshot()["events"])
        self.actions.device_removed("/dev/sdb")
        self.assertEqual(self.vm.stops, 1)
        self.assertIsNone(self.state.device)
        self.assertIsNone(self.state.report)
        self.assertEqual(self.state.scan, {})
        self.assertFalse(self.state.vm.get("running"))
        self.assertEqual(self.state.state, ts.IDLE)
        self.assertEqual(self.state.message, "waiting for a device")

    def test_unplug_mid_scan_abandons_the_scan(self):
        subject(self.actions, state=ts.SCANNING)
        self.state.set_scan(node="/dev/vdb", entries=41, running=True)
        self.actions.device_removed("/dev/sdb")
        self.assertEqual(self.state.state, ts.IDLE)
        self.assertEqual(self.state.scan, {})

    def test_another_disk_leaving_changes_nothing(self):
        subject(self.actions)
        self.actions.device_removed("/dev/sdc")
        self.assertEqual(self.vm.stops, 0)
        self.assertIsNotNone(self.state.device)
        self.assertEqual(self.state.state, ts.ATTACHED)

    def test_removal_with_nothing_to_reset_is_a_no_op(self):
        self.actions.device_removed("/dev/sdb")
        self.assertEqual(self.vm.stops, 0)
        self.assertEqual(self.state.state, ts.IDLE)

    def test_a_vm_that_will_not_stop_does_not_block_the_reset(self):
        subject(self.actions)
        self.actions._vm = FakeVM(fail_stop=True)
        self.actions.device_removed("/dev/sdb")      # must not raise
        self.assertIsNone(self.state.device)
        self.assertEqual(self.state.state, ts.IDLE)
        self.assertFalse(self.state.vm.get("running"))

    def test_a_finished_scan_for_a_removed_disk_is_dropped(self):
        # the collector finished after the unplug: no VT quota spent on a disk
        # that is gone, and no dashboard resurrected for it
        subject(self.actions, state=ts.SCANNING)
        self.state.set_scan(node="/dev/vdb", entries=0, running=True)
        enriched = []
        entered_collect = threading.Event()
        unplug_seen = threading.Event()

        def fake_collect(node):
            # the collector only finishes after the disk is already gone
            entered_collect.set()
            assert unplug_seen.wait(timeout=10), "the unplug never happened"
            return {"summary": {"entries": 1, "files": 1, "errors": 0},
                    "rows": []}

        self.actions._collect = fake_collect
        self.actions._enrich = lambda report: enriched.append(report)

        thread = threading.Thread(target=self.actions._scan_worker,
                                  args=("/dev/vdb",))
        thread.start()
        assert entered_collect.wait(timeout=10), "the worker never started"
        self.actions.device_removed("/dev/sdb")
        unplug_seen.set()
        thread.join(timeout=10)
        self.assertEqual(enriched, [])
        self.assertIsNone(self.state.report)
        self.assertEqual(self.state.state, ts.IDLE)


class ListenerRemovalTests(unittest.TestCase):
    def test_the_listener_reports_a_removal_to_the_callback(self):
        seen = []
        listener = device_listener.StorageListener(on_remove=seen.append)
        listener.devices["/dev/sdb"] = ts.Device(devnode="/dev/sdb")
        listener._handle(udev_monitor.DeviceEvent(
            action="remove", subsystem="block", name="sdb",
            syspath="/sys/class/block/sdb", devnode="/dev/sdb"))
        self.assertEqual(seen, ["/dev/sdb"])
        self.assertNotIn("/dev/sdb", listener.devices)

    def test_a_removal_found_by_polling_also_reports(self):
        seen = []
        listener = device_listener.StorageListener(on_remove=seen.append)
        listener.seen = {"block/sdb"}
        listener.devices["/dev/sdb"] = ts.Device(devnode="/dev/sdb")
        real_scan = udev_monitor.scan
        udev_monitor.scan = lambda subsystems=("block",): {}
        try:
            listener._poll()
        finally:
            udev_monitor.scan = real_scan
        self.assertEqual(seen, ["/dev/sdb"])


if __name__ == "__main__":
    unittest.main()