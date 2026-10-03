"""The live feed and the websocket endpoint.

The frame codec is checked against the RFC 6455 examples, and the endpoint is
tested over a real socket, because a websocket that is subtly wrong fails
silently: the page just falls back to polling and nobody notices the live view
never worked.
"""

import base64
import json
import socket
import struct
import threading
import unittest
import urllib.error
import urllib.request

import live_feed
import triage_state as ts
import web_server


def frame(payload: bytes, opcode: int = 0x1, mask: bytes = b"\x00\x00\x00\x00") -> bytes:
    """A client frame. Clients must mask, so this does unless told otherwise."""
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 1 << 16:
        header.append(0x80 | 126)
        header += struct.pack(">H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", length)
    return bytes(header) + mask + payload


class FrameTests(unittest.TestCase):
    def test_the_accept_key_matches_the_rfc_example(self):
        self.assertEqual(live_feed.accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_short_medium_and_long_frames_encode_with_the_right_length(self):
        for size in (5, 125, 126, 70000):
            payload = b"x" * size
            encoded = live_feed.encode(payload.decode())
            length = encoded[1] & 0x7F
            self.assertEqual(length < 126, size < 126)
            if size >= 126:
                self.assertEqual(length, 126 if size < 1 << 16 else 127)
            self.assertEqual(encoded[1] & 0x80, 0,
                             "a server frame must never be masked")

    def test_a_client_frame_is_unmasked(self):
        mask = b"\x37\xfa\x21\x3d"
        payload = b"Hello"
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        import io

        class Fake:
            def __init__(self, data):
                self.data = io.BytesIO(data)

            def recv(self, n):
                return self.data.read(n)

        opcode, got = live_feed.read_frame(Fake(frame(masked, mask=mask)))
        self.assertEqual(opcode, live_feed.OP_TEXT)
        self.assertEqual(got, payload)

    def test_an_oversized_frame_is_refused_rather_than_allocated(self):
        class Fake:
            def __init__(self):
                self.sent = b""

            def recv(self, n):
                # a header claiming 4 GB, then nothing
                if not self.sent:
                    self.sent = b"\x81\x7f" + struct.pack(">Q", 4 << 30)
                    return self.sent[:2]
                return self.sent[2:]

        with self.assertRaises(ValueError):
            live_feed.read_frame(Fake())


class FeedTests(unittest.TestCase):
    def test_every_subscriber_sees_a_publish_and_a_new_one_gets_state_at_once(self):
        feed = live_feed.LiveFeed(lambda: {"state": "idle"})
        one = feed.subscribe()
        two = feed.subscribe()
        self.assertEqual(one.get(0.1)["state"]["state"], "idle")
        self.assertEqual(two.get(0.1)["state"]["state"], "idle")
        feed.publish("log", event={"seq": 1, "text": "hello"})
        self.assertEqual(one.get(0.1)["event"]["text"], "hello")
        self.assertEqual(two.get(0.1)["event"]["text"], "hello")
        feed.unsubscribe(one)
        feed.publish("log", event={"seq": 2, "text": "after"})
        self.assertEqual(two.get(0.1)["event"]["text"], "after")
        self.assertIsNone(one.get(0.05))

    def test_a_subscriber_that_never_reads_is_dropped_not_buffered_forever(self):
        feed = live_feed.LiveFeed(lambda: {})
        slow = feed.subscribe()
        for index in range(live_feed.MAX_QUEUE * 3):
            feed.publish("state", state={"n": index})
        self.assertLessEqual(slow.queue.qsize(), live_feed.MAX_QUEUE)
        # the newest state still gets through: a snapshot is never worth a backlog
        newest = None
        while True:
            message = slow.get(0.01)
            if message is None:
                break
            newest = message
        self.assertEqual(newest["state"]["n"], live_feed.MAX_QUEUE * 3 - 1)
        self.assertGreater(slow.dropped, 0)

    def test_state_publishes_are_throttled_but_log_lines_are_not(self):
        feed = live_feed.LiveFeed(lambda: {"state": "idle"})
        subscriber = feed.subscribe()
        subscriber.get(0.1)
        feed.publish_state(throttle=10.0)
        subscriber.get(0.1)              # the first one seeds the throttle
        for _ in range(20):
            feed.publish_state(throttle=10.0)
        self.assertIsNone(subscriber.get(0.05), "state spam was not throttled")
        feed.publish("log", event={"seq": 1})
        self.assertIsNotNone(subscriber.get(0.1), "log lines must not be throttled")


class EndpointTests(unittest.TestCase):
    """Over a real socket against a real server."""

    @classmethod
    def setUpClass(cls):
        cls.state = ts.TriageState()
        cls.server = web_server.serve(cls.state, port=0)
        cls.token = cls.server.RequestHandlerClass.token
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def connect(self, token=None, path="/live", upgrade=True):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        lines = [f"GET {path}?token={token or ''} HTTP/1.1",
                 f"Host: 127.0.0.1:{self.port}"]
        if upgrade:
            key = base64.b64encode(b"0123456789abcdef").decode()
            lines += ["Upgrade: websocket", "Connection: Upgrade",
                      f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        sock.settimeout(5)
        return sock

    def read_handshake(self, sock):
        """Consume the 101 response so the frames that follow line up."""
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(1)
            if not chunk:
                raise ConnectionError("closed during handshake")
            data += chunk
        return data.decode(errors="replace")

    def read_frame(self, sock):
        head = sock.recv(2)
        if len(head) < 2:
            raise ConnectionError("closed")
        length = head[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        data = b""
        while len(data) < length:
            data += sock.recv(length - len(data))
        return head[0] & 0x0F, data

    def test_a_socket_without_the_token_is_refused(self):
        sock = self.connect(token="wrong-token")
        response = sock.recv(200).decode(errors="replace")
        sock.close()
        self.assertIn("403", response.splitlines()[0])

    def test_an_upgrade_request_without_the_headers_is_a_plain_400(self):
        sock = self.connect(token=self.token, upgrade=False)
        response = sock.recv(200).decode(errors="replace")
        sock.close()
        self.assertIn("400", response.splitlines()[0])

    def test_a_good_connection_gets_state_the_moment_the_app_changes(self):
        sock = self.connect(token=self.token)
        self.assertIn("101", self.read_handshake(sock).splitlines()[0])
        opcode, data = self.read_frame(sock)
        self.assertEqual(opcode, live_feed.OP_TEXT)
        hello = json.loads(data)
        self.assertEqual(hello["type"], "hello")
        self.assertEqual(json.loads(self.read_frame(sock)[1])["type"], "state")

        # something the state machine does, pushed without any polling
        self.state.say("a live event")
        seen = None
        for _ in range(6):
            message = json.loads(self.read_frame(sock)[1])
            if message["type"] == "log":
                seen = message["event"]["text"]
                break
            if message["type"] == "state":
                seen = message["state"]["message"]
        self.assertEqual(seen, "a live event")
        sock.close()

    def test_the_report_downloads_as_pdf(self):
        report = {"summary": {"files": 2, "hashed": 2, "seconds": 4,
                              "virustotal": "1 flagged, 1 clean"},
                  "filesystems": [{"node": "/dev/vdb1", "fstype": "exfat", "offset": 1}],
                  "rows": [{"path": "/evil.exe", "size": 68, "hidden": False,
                            "hidden_dot": False, "sha256": "a" * 64,
                            "virustotal": "malicious", "detections": 3, "scanned": 68,
                            "vt_name": "trojan.exe", "vt_link": "https://x/y",
                            "engines": [{"engine": "E", "result": "Trojan"}]},
                           {"path": "/notes.txt", "size": 12, "hidden": True,
                            "hidden_dot": False, "sha256": "b" * 64,
                            "virustotal": "clean", "detections": 0, "scanned": 70}]}
        self.state.set_report(report)
        self.addCleanup(self.state.set_report, None)

        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/report.pdf",
            headers={"X-Triage-Token": self.token})
        with urllib.request.urlopen(request) as response:
            self.assertIn("application/pdf", response.headers["Content-Type"])
            self.assertIn("attachment;", response.headers["Content-Disposition"])
            self.assertIn(".pdf", response.headers["Content-Disposition"])
            body = response.read()
        self.assertTrue(body.startswith(b"%PDF-"), "not a pdf at all")
        self.assertGreater(len(body), 2000, "a one-page stub, not the report")

    def test_the_export_refuses_another_session(self):
        self.state.set_report({"summary": {"files": 0}, "rows": []})
        self.addCleanup(self.state.set_report, None)
        for headers in ({"X-Triage-Token": "wrong"}, {}):
            try:
                urllib.request.urlopen(urllib.request.Request(
                    f"http://127.0.0.1:{self.port}/api/report.pdf", headers=headers))
                self.fail("the export answered without the session token")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 403)

    def test_exporting_before_there_is_a_report_says_so(self):
        self.state.set_report(None)
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"http://127.0.0.1:{self.port}/api/report.pdf",
                headers={"X-Triage-Token": self.token}))
            self.fail("an empty report exported as a file")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)

    def test_the_page_versions_its_assets_so_deploys_land_whole(self):
        import urllib.request
        page = urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}/").read().decode()
        for asset in ("app.js", "style.css"):
            self.assertRegex(page, f"/static/{asset}\\?v=\\d+")
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/static/{asset}?v=1") as response:
                self.assertEqual(response.status, 200)

    def test_the_page_token_is_what_the_socket_wants(self):
        self.assertTrue(live_feed.token_ok(self.token, self.token))
        self.assertFalse(live_feed.token_ok("", self.token))
        self.assertFalse(live_feed.token_ok(self.token + "x", self.token))


if __name__ == "__main__":
    unittest.main()