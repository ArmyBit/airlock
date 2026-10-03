"""The two pieces that turn collector output into what the panel shows.

parse_report is pure and worth testing hard: it is the boundary between a
multi-gigabyte JSONL stream and the browser.
"""

import json
import unittest

import virustotal
import web_server


def wanted_keys(client):
    """The key set a normal answer has, for comparison in the shape tests."""
    return set(client._blank(virustotal.STATUS_UNKNOWN))


class ParseReportTests(unittest.TestCase):
    def test_counts_files_dirs_errors_and_sorts_by_size(self):
        lines = [
            json.dumps({"type": "entry", "kind": "dir", "path": "/photos", "size": 0}),
            json.dumps({"type": "entry", "kind": "file", "path": "/small.txt", "size": 5,
                        "sha256": "a" * 64}),
            json.dumps({"type": "entry", "kind": "file", "path": "/big.mkv", "size": 1048576,
                        "sha256": "b" * 64}),
            json.dumps({"type": "error", "path": "/locked", "error": "EACCES"}),
            json.dumps({"type": "done", "entries": 4, "files": 2, "dirs": 1,
                        "errors": 1, "hashed_bytes": 1048581, "seconds": 1.5}),
        ]
        report = web_server.parse_report("\n".join(lines))
        summary = report["summary"]
        self.assertEqual(summary["files"], 2)
        self.assertEqual(summary["dirs"], 1)
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["entries"], 4)
        self.assertEqual(summary["total_records"], 4)
        self.assertEqual([row["path"] for row in report["rows"]],
                         ["/big.mkv", "/small.txt"])

    def test_dot_files_are_counted_separately_from_the_hidden_attribute(self):
        lines = [
            json.dumps({"type": "entry", "kind": "file", "path": "/.config", "size": 1,
                        "sha256": "c" * 64, "hidden_dot": True}),
            json.dumps({"type": "entry", "kind": "file", "path": "/windows.ini", "size": 1,
                        "sha256": "d" * 64, "hidden_attr": True}),
            json.dumps({"type": "entry", "kind": "file", "path": "/plain", "size": 1,
                        "sha256": "e" * 64}),
        ]
        summary = web_server.parse_report("\n".join(lines))["summary"]
        self.assertEqual(summary["hidden_dot"], 1)
        self.assertEqual(summary["hidden"], 1)
        self.assertEqual(summary["hashed"], 3)

    def test_a_truncated_or_corrupt_stream_still_yields_a_report(self):
        lines = [
            '{"type": "entry", "kind": "file", "path": "/ok.txt", "size": 1, "sha256": "' + "f" * 64 + '"}',
            '{"type": "entry", "kind": "file", "pa',            # cut off mid-line
            '',                                  # blank
            'not json at all',
            '{"type": "done", "entries": 1, "files": 1, "errors": 0, "seconds": 0.1}',
        ]
        report = web_server.parse_report("\n".join(lines))
        self.assertEqual(report["summary"]["files"], 1)
        self.assertEqual(report["rows"][0]["path"], "/ok.txt")

    def test_every_file_is_kept_so_every_hash_can_be_checked(self):
        # the table draws the biggest few, but a file that was cut from the
        # table must still be hashed and checked, so nothing is dropped here
        lines = [json.dumps({"type": "entry", "kind": "file", "path": f"/f{n}", "size": n,
                             "sha256": f"{n:064d}"})
                 for n in range(web_server.REPORT_ROWS + 25)]
        report = web_server.parse_report("\n".join(lines))
        self.assertEqual(len(report["rows"]), web_server.REPORT_ROWS + 25)
        self.assertEqual(report["summary"]["rows_shown"], web_server.REPORT_ROWS)
        self.assertEqual(report["summary"]["truncated"], 25)
        self.assertEqual(report["rows"][0]["path"],
                         f"/f{web_server.REPORT_ROWS + 24}")
        self.assertTrue(all(row["sha256"] for row in report["rows"]))

    def test_an_empty_stream_is_not_a_crash(self):
        report = web_server.parse_report("")
        self.assertEqual(report["summary"]["files"], 0)
        self.assertEqual(report["rows"], [])


class CollectorContractTests(unittest.TestCase):
    """The collector and parse_report are halves of one format, in two
    languages on two sides of a VM boundary. This runs the real collector over a
    real tree and feeds its output to the real parser, so a change to either
    side that breaks the other fails here instead of on someone's evidence disk."""

    def setUp(self):
        import tempfile as _tempfile
        self.tmp = _tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    @staticmethod
    def collector():
        import importlib.util
        path = __import__("pathlib").Path(__file__).resolve().parents[1] \
            / "tiny-linux" / "guest_collector.py"
        spec = importlib.util.spec_from_file_location("guest_collector", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_a_real_tree_survives_the_round_trip(self):
        import os
        import tempfile
        collector = self.collector()
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "docs"))
            os.symlink("/etc/passwd", os.path.join(root, "link"))
            with open(os.path.join(root, "docs", "readme.md"), "w") as handle:
                handle.write("hello\n")
            with open(os.path.join(root, ".secret"), "w") as handle:
                handle.write("x")
            # outside the tree being walked: the report must not count itself
            report = os.path.join(self.tmp.name, "report.jsonl")
            collector.scan(root, want_hashes=True, report_path=report)
            with open(report) as handle:
                text = handle.read()

        report = web_server.parse_report(text)
        summary = report["summary"]
        self.assertEqual(summary["files"], 2)
        self.assertGreaterEqual(summary["dirs"], 1)
        self.assertEqual(summary["errors"], 0)
        self.assertEqual(summary["hidden_dot"], 1)
        self.assertEqual(summary["hashed"], 2)
        # paths are absolute inside the guest, with the mountpoint still on them
        paths = {row["path"] for row in report["rows"]}
        self.assertTrue(any(p.endswith("docs/readme.md") for p in paths), paths)
        self.assertTrue(any(p.endswith("/.secret") for p in paths), paths)
        # a symlink is neither a file nor a directory, and must not be counted
        # as either, or the file counters stop matching the disk
        self.assertFalse(any(p.endswith("/link") for p in paths), paths)
        self.assertEqual(summary["others"], 1)
        readme = next(row for row in report["rows"]
                      if row["path"].endswith("docs/readme.md"))
        self.assertEqual(readme["sha256"],
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")
        self.assertFalse(readme["hidden"])
        self.assertFalse(readme["hidden_dot"])

    def test_a_partition_with_no_node_is_said_out_loud_not_skipped_silently(self):
        """sfdisk names the node when the kernel made one. When it does not, the
        collector needs a loop device, and the operator has to hear about it."""
        collector = self.collector()
        rows = {"partitiontable": {"partitions": [
            {"node": "/dev/vdb1", "start": 2048, "size": 61435904},
            {"start": 40960, "size": 1000}]}}
        calls = []

        def fake_run(argv, timeout=300):
            calls.append(argv)
            if argv[:2] == ["sfdisk", "--json"]:
                return json.dumps(rows).encode()
            if argv[:1] == ["blockdev"]:
                return b"41943040\n"
            return None

        collector.run = fake_run
        collector.node_exists = lambda path: path == "/dev/vdb1"
        candidates = collector.partition_candidates("/dev/vdb")
        self.assertEqual(candidates[0], (0, 41943040, "/dev/vdb"))
        # the partition the kernel exposed is used directly, no loop device
        self.assertEqual(candidates[1], (2048 * 512, 61435904 * 512, "/dev/vdb1"))
        # the one it did not expose is None, which the caller reports
        self.assertIsNone(candidates[2][2])

    def test_a_node_sfdisk_names_but_that_is_gone_is_not_trusted(self):
        collector = self.collector()
        rows = {"partitiontable": {"partitions": [
            {"node": "/dev/vdb1", "start": 2048, "size": 61435904}]}}

        def fake_run(argv, timeout=300):
            if argv[:2] == ["sfdisk", "--json"]:
                return json.dumps(rows).encode()
            return b"41943040\n" if argv[:1] == ["blockdev"] else None

        collector.run = fake_run
        collector.node_exists = lambda path: False
        candidates = collector.partition_candidates("/dev/vdb")
        self.assertIsNone(candidates[1][2])

    def test_the_disk_itself_is_never_given_to_losetup_detach(self):
        """The evidence disk must survive the walk. Getting the detach arguments
        the wrong way round asks losetup to detach the user's own disk."""
        collector = self.collector()
        seen = []
        collector.run = lambda argv, timeout=300: seen.append(argv) or b""
        collector.detach_loop("/dev/vdb", "/dev/vdb")      # same node twice
        collector.detach_loop("/dev/vdb1", "/dev/vdb")     # not a loop device
        collector.detach_loop(None, "/dev/vdb")            # nothing to do
        self.assertEqual([a for a in seen if "--detach" in a], [])
        collector.detach_loop("/dev/loop0", "/dev/vdb")
        self.assertEqual(seen[-1], ["losetup", "--detach", "/dev/loop0"])

    def test_every_record_type_the_collector_writes_is_understood(self):
        import io
        collector = self.collector()
        out = io.StringIO()
        collector.record(out, "meta", device="/dev/vdb", pid=1)
        collector.record(out, "fs", node="/dev/vdb1", fstype="exfat", offset=0)
        collector.record(out, "mount", node="/dev/vdb1", target="/mnt/x")
        collector.record(out, "error", path="/locked", error="EACCES")
        collector.record(out, "done", entries=0, files=0, dirs=0, errors=1,
                         seconds=0.2)
        report = web_server.parse_report(out.getvalue())
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(report["filesystems"],
                         [{"node": "/dev/vdb1", "fstype": "exfat", "offset": 0}])
        # an unparsed line would show up as a silently missing file
        self.assertEqual(report["summary"]["entries"], 0)


class VirusTotalTests(unittest.TestCase):
    """No network: the HTTP layer is stubbed so these run anywhere."""

    EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    def setUp(self):
        self.tmp = self.enterContext(__import__("tempfile").TemporaryDirectory())
        self.cache = __import__("pathlib").Path(self.tmp) / "vt.json"
        self.calls = []

    def client(self, responses):
        client = virustotal.VirusTotal("key", cache_path=self.cache,
                                       min_interval=0)
        client._get = lambda sha: (self.calls.append(sha), responses[sha])[1]
        return client

    def malicious_body(self, detections=3, total=68):
        return {"data": {"attributes": {
            "last_analysis_stats": {"malicious": detections, "suspicious": 0,
                                    "undetected": total - detections,
                                    "harmless": 0},
            "meaningful_name": "evil.exe",
            "last_analysis_results": {
                "Engine A": {"category": "malicious", "result": "Trojan.X"},
                "Engine B": {"category": "malicious", "result": "Trojan.X"},
                "Engine C": {"category": "malicious", "result": "Backdoor"},
                "Quiet": {"category": "undetected", "result": None},
            },
            "first_seen_itw_date": 1600000000}}}

    def test_a_flagged_file_reports_the_detection_count(self):
        client = self.client({self.EICAR: (200, self.malicious_body())})
        result = client.lookup(self.EICAR)
        self.assertEqual(result["status"], virustotal.STATUS_MALICIOUS)
        self.assertEqual(result["detections"], 3)
        self.assertEqual(result["scanned"], 68)
        self.assertEqual(result["meaningful_name"], "evil.exe")
        # only the engines that actually flagged something
        self.assertEqual(len(result["engines"]), 3)
        self.assertNotIn("Quiet", [e["engine"] for e in result["engines"]])

    def test_a_hash_virustotal_has_never_seen_is_unknown_not_clean(self):
        unknown = "0" * 64
        client = self.client({unknown: (404, {})})
        result = client.lookup(unknown)
        self.assertEqual(result["status"], virustotal.STATUS_UNKNOWN)
        self.assertEqual(result["detections"], 0)

    def test_a_rejected_key_is_an_error_not_a_clean_result(self):
        client = self.client({self.EICAR: (401, {"error": "bad key"})})
        result = client.lookup(self.EICAR)
        self.assertEqual(result["status"], virustotal.STATUS_ERROR)
        self.assertIn("API key", result["error"])

    def test_a_bad_hash_never_reaches_the_network(self):
        client = self.client({})
        for value in ("", None, "not-a-hash", "f" * 63, "F" * 64):
            self.assertEqual(client.lookup(value)["status"],
                             virustotal.STATUS_ERROR)
        self.assertEqual(self.calls, [])

    def test_duplicate_hashes_are_looked_up_once(self):
        client = self.client({self.EICAR: (200, self.malicious_body())})
        results, counters = client.lookup_many([self.EICAR] * 50)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(counters["wanted"], 1)
        self.assertEqual(counters["malicious"], 1)
        self.assertEqual(len(results), 1)

    def test_the_per_scan_cap_is_reported_not_hidden(self):
        hashes = [f"{n:064x}" for n in range(10)]
        client = self.client({sha: (404, {}) for sha in hashes})
        _, counters = client.lookup_many(hashes, cap=4)
        self.assertEqual(counters["checked"], 4)
        self.assertEqual(counters["skipped"], 6)
        self.assertIn("not checked", virustotal.counters_label(counters))

    def test_by_default_every_hash_is_checked_not_a_handful(self):
        hashes = [f"{n:064x}" for n in range(60)]
        client = self.client({sha: (404, {}) for sha in hashes})
        _, counters = client.lookup_many(hashes)
        self.assertEqual(counters["wanted"], 60)
        self.assertEqual(counters["checked"], 60)
        self.assertEqual(counters["skipped"], 0)
        self.assertEqual(len(self.calls), 60)

    def test_a_usage_limit_stops_the_scan_instead_of_hammering_the_api(self):
        hashes = [f"{n:064x}" for n in range(20)]
        bodies = {sha: (204, {"data": {"type": "usage-limit-reached"}})
                  for sha in hashes}
        client = self.client(bodies)
        _, counters = client.lookup_many(hashes)
        self.assertEqual(len(self.calls), 1, "kept asking after the key ran out")
        self.assertEqual(counters["checked"], 0)
        self.assertEqual(counters["quota"], 1)
        self.assertEqual(counters["skipped"], 20)

    def test_a_refusal_returned_with_a_200_is_an_error_not_a_result(self):
        sha = f"{7:064x}"
        client = self.client({sha: (200, {"error": {"code": "QuotaExceededError",
                                                   "message": "Quota exceeded"}})})
        result = client.lookup(sha)
        self.assertEqual(result["status"], virustotal.STATUS_ERROR)
        self.assertTrue(result["quota"])

    def test_results_are_cached_so_a_rescan_does_not_spend_quota(self):
        client = self.client({self.EICAR: (200, self.malicious_body())})
        client.lookup(self.EICAR)
        self.assertEqual(len(self.calls), 1)
        # a fresh client, so this is the on-disk cache and not a live object
        self.calls.clear()
        again = self.client({})
        result = again.lookup(self.EICAR)
        self.assertEqual(self.calls, [])
        self.assertEqual(result["status"], virustotal.STATUS_MALICIOUS)
        self.assertTrue(result["cached"])

    def test_every_outcome_has_the_same_keys(self):
        """A 404 must look like every other answer. This is the exact crash that
        killed a real scan: `meaningful_name` existed on the malicious branch and
        not on the unknown one, and the report builder read it unconditionally."""
        wanted = None
        for status, body in ((200, self.malicious_body()), (404, {}),
                             (401, {}), (429, {}), (503, {})):
            client = self.client({self.EICAR: (status, body)})
            keys = set(client.lookup(self.EICAR))
            if wanted is None:
                wanted = keys
            self.assertEqual(keys, wanted, f"status {status} has different keys")

    def test_a_transport_failure_has_the_same_shape_too(self):
        client = self.client({})

        def boom(sha):
            raise TimeoutError("timed out")

        client._get = boom
        self.assertEqual(set(client.lookup(self.EICAR)), wanted_keys(client))

    def test_the_key_never_lands_in_the_cache_file(self):
        client = self.client({self.EICAR: (200, self.malicious_body())})
        client.lookup(self.EICAR)
        self.assertNotIn("key", self.cache.read_text())


class EnrichTests(unittest.TestCase):
    """The wiring between a parsed report and VirusTotal."""

    def setUp(self):
        import pathlib as _pathlib
        import tempfile as _tempfile
        import triage_state as ts
        self.state = ts.TriageState()
        self.actions = web_server.Actions(self.state)
        # never touch the real cache: these tests must not spend real quota
        # and must not depend on what a previous run happened to look up
        self.tmp = _tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.real_cache = virustotal.CACHE_FILE
        virustotal.CACHE_FILE = _pathlib.Path(self.tmp.name) / "vt.json"
        self.addCleanup(setattr, virustotal, "CACHE_FILE", self.real_cache)

    def test_no_key_leaves_the_report_intact_and_says_so(self):
        import os
        os.environ.pop(virustotal.KEY_ENV, None)
        saved = virustotal.read_key
        virustotal.read_key = lambda: ""
        try:
            report = {"summary": {"files": 1}, "rows": [
                {"path": "/a", "size": 1, "sha256": "f" * 64}]}
            self.actions._enrich(report)
        finally:
            virustotal.read_key = saved
        self.assertEqual(report["summary"]["virustotal"], "not configured")
        self.assertNotIn("virustotal", report["rows"][0])

    def test_every_row_gets_a_verdict_and_rows_share_a_hash(self):
        import os
        os.environ[virustotal.KEY_ENV] = "test-key"
        client = virustotal.VirusTotal("test-key", min_interval=0,
                                       cache_path=virustotal.CACHE_FILE)
        client._get = lambda sha: (200, {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 5, "undetected": 60}, "meaningful_name": "bad"}}})
        saved = virustotal.VirusTotal
        virustotal.VirusTotal = lambda key, **kwargs: client
        try:
            report = {"summary": {"files": 2}, "rows": [
                {"path": "/copy-one", "size": 1, "sha256": "a" * 64},
                {"path": "/copy-two", "size": 1, "sha256": "a" * 64},
                {"path": "/toobig", "size": 1, "sha256": ""}]}
            self.actions._enrich(report)
        finally:
            virustotal.VirusTotal = saved
            os.environ.pop(virustotal.KEY_ENV, None)
        self.assertEqual(report["summary"]["virustotal"], "1 checked, 1 flagged")
        for row in report["rows"][:2]:
            self.assertEqual(row["virustotal"], "malicious")
            self.assertEqual(row["detections"], 5)
            self.assertEqual(row["scanned"], 65)
        # the unhashable file is accounted for rather than silently clean
        self.assertEqual(report["rows"][2]["virustotal"], "no hash")
        self.assertEqual(report["summary"]["unhashed"], 1)


if __name__ == "__main__":
    unittest.main()