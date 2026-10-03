"""Settings: environment checks, background image builds, configured flag.

The build itself is stubbed - these tests prove the wiring (auth, states,
flag file), never a real image build.
"""

import json
import threading
import unittest
import urllib.error
import urllib.request

import triage_state as ts
import triage_vm
import web_server


class SettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = ts.TriageState()
        cls.server = web_server.serve(cls.state, port=0)
        cls.token = cls.server.RequestHandlerClass.token
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        import pathlib as _pathlib
        import tempfile as _tempfile
        cls.tmp = _tempfile.TemporaryDirectory()
        cls.flag = _pathlib.Path(cls.tmp.name) / "configured"
        cls.real_flag = web_server.CONFIGURED_FILE
        web_server.CONFIGURED_FILE = cls.flag

    @classmethod
    def tearDownClass(cls):
        web_server.CONFIGURED_FILE = cls.real_flag
        cls.tmp.cleanup()
        cls.server.shutdown()
        cls.server.server_close()

    def tearDown(self):
        # one test's flag must not leak into the next
        try:
            self.flag.unlink()
        except OSError:
            pass
        self.server.actions._env_at = 0.0

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path, token="TOKEN"):
        if token == "TOKEN":
            token = self.token
        request = urllib.request.Request(
            self.url(path), headers={"X-Triage-Token": token})
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())

    def post(self, path, body=None, token="TOKEN"):
        if token == "TOKEN":
            token = self.token
        request = urllib.request.Request(
            self.url(path), data=json.dumps(body or {}).encode(),
            headers={"Content-Type": "application/json",
                     "X-Triage-Token": token})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_settings_needs_the_session_token(self):
        try:
            urllib.request.urlopen(self.url("/api/settings"))
            self.fail("settings answered without a token")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 403)

    def test_settings_lists_every_check_the_build_and_the_flag(self):
        status, payload = self.get("/api/settings")
        self.assertEqual(status, 200)
        self.assertEqual([check["id"] for check in payload["checks"]],
                         ["files", "libvirt", "virustotal", "build"])
        for check in payload["checks"]:
            self.assertIn("label", check)
            self.assertIn("ok", check)
            self.assertIn("detail", check)
        self.assertIn("ready", payload)
        self.assertFalse(payload["configured"])
        self.assertIn("running", payload["build"])
        self.assertIn("log", payload["build"])

    def test_the_flag_round_trips_and_shows_in_state(self):
        status, payload = self.post("/api/settings/configured",
                                    {"configured": True})
        self.assertEqual(status, 200)
        self.assertTrue(payload["configured"])
        self.assertTrue(self.flag.exists())
        _, snapshot = self.get("/api/state")
        self.assertTrue(snapshot["environment"]["configured"])

        status, payload = self.post("/api/settings/configured",
                                    {"configured": False})
        self.assertEqual(status, 200)
        self.assertFalse(payload["configured"])
        self.assertFalse(self.flag.exists())
        _, snapshot = self.get("/api/state")
        self.assertFalse(snapshot["environment"]["configured"])

    def test_a_build_runs_in_background_and_reports(self):
        started = threading.Event()
        release = threading.Event()

        def fake_build(progress=None):
            started.set()
            self.assertTrue(release.wait(timeout=10))
            if progress:
                progress("fake line")

        real_build = triage_vm.build_image
        triage_vm.build_image = fake_build
        try:
            status, payload = self.post("/api/settings/build")
            self.assertEqual(status, 202, payload)
            self.assertTrue(started.wait(timeout=10))
            _, settings = self.get("/api/settings")
            self.assertTrue(settings["build"]["running"])
            # a second build while one runs is refused, not queued
            status, payload = self.post("/api/settings/build")
            self.assertEqual(status, 409)
            release.set()
            self.server.actions._build_thread.join(timeout=10)
            _, settings = self.get("/api/settings")
            self.assertFalse(settings["build"]["running"])
            self.assertIn("fake line", settings["build"]["log"])
        finally:
            release.set()
            triage_vm.build_image = real_build

    def test_a_build_is_refused_while_the_vm_runs(self):
        self.state.set_vm(running=True, ssh_ok=True)
        self.addCleanup(self.state.set_vm, running=False, ssh_ok=False)
        status, payload = self.post("/api/settings/build")
        self.assertEqual(status, 409)
        self.assertIn("error", payload)

    def test_a_failed_build_is_said_out_loud(self):
        def fake_build(progress=None):
            raise triage_vm.VmError("no root here")

        real_build = triage_vm.build_image
        triage_vm.build_image = fake_build
        try:
            status, _ = self.post("/api/settings/build")
            self.assertEqual(status, 202)
            self.server.actions._build_thread.join(timeout=10)
            _, settings = self.get("/api/settings")
            self.assertIn("no root here", settings["build"]["error"])
        finally:
            triage_vm.build_image = real_build


class BuildGatingTests(unittest.TestCase):
    """Root is not required: fakeroot stands in for the one chown."""

    def test_neither_root_nor_fakeroot_is_a_clear_error(self):
        from unittest import mock
        with mock.patch("os.geteuid", return_value=1000), \
                mock.patch("shutil.which", return_value=None):
            with self.assertRaises(triage_vm.VmError) as raised:
                triage_vm.build_image()
        self.assertIn("fakeroot", str(raised.exception))

    def test_output_streams_line_by_line_under_fakeroot(self):
        from unittest import mock

        class FakeChild:
            def __init__(self):
                self.stdout = iter(["[golden] one\n", "[golden] two\n"])
                self.argv = None

            def wait(self):
                return 0

        children = []

        def fake_popen(argv, **kw):
            child = FakeChild()
            child.argv = argv
            children.append(child)
            return child

        with mock.patch("os.geteuid", return_value=1000), \
                mock.patch.object(triage_vm.subprocess, "Popen",
                                  side_effect=fake_popen):
            lines = []
            triage_vm.build_image(progress=lines.append)
        self.assertEqual(children[0].argv[0], "fakeroot")
        self.assertEqual(lines, ["[golden] one", "[golden] two"])

    def test_a_failing_build_reports_the_tail(self):
        from unittest import mock

        class FakeChild:
            stdout = iter(["boom\n"])

            def wait(self):
                return 3

        with mock.patch.object(triage_vm.subprocess, "Popen",
                               return_value=FakeChild()):
            with self.assertRaises(triage_vm.VmError) as raised:
                triage_vm.build_image()
        self.assertIn("boom", str(raised.exception))


if __name__ == "__main__":
    unittest.main()