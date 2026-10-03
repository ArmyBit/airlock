"""A WebSocket endpoint and a live feed, on top of the stdlib HTTP server.

Live updates used to mean the browser polling /api/state every second, which is
wasteful and makes the UI feel behind. This is a minimal RFC 6455 server: the
handshake, text frames, ping/pong and close. That is all this needs - the client
never sends anything except pings and close.

Two things this is careful about:

- Every connection must present the same session token the page was served
  with. The server can start VMs and hand disks to them, so an unauthenticated
  socket that can drive the UI is a security hole, not a feature.
- The feed is bounded. A browser that stops reading gets dropped rather than
  allowed to make the server buffer without limit.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import queue
import socket
import struct
import threading
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

MAX_FRAME = 1 << 20          # a client that sends more than this is not ours
MAX_QUEUE = 256              # per subscriber, oldest dropped rather than grown
PING_INTERVAL = 25.0
FEED_TIMEOUT = 60.0          # a subscriber that never drains is dropped


def accept_key(client_key: str) -> str:
    return base64.b64encode(
        hashlib.sha1((client_key + GUID).encode()).digest()).decode()


def encode(payload: str, opcode: int = OP_TEXT) -> bytes:
    """A server frame is never masked, which is the one bit of RFC 6455 that
    implementations most often get wrong."""
    data = payload.encode() if isinstance(payload, str) else payload
    header = bytearray([0x80 | opcode])
    length = len(data)
    if length < 126:
        header.append(length)
    elif length < 1 << 16:
        header.append(126)
        header += struct.pack(">H", length)
    else:
        header.append(127)
        header += struct.pack(">Q", length)
    return bytes(header) + data


def _read_exactly(sock, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("the client closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(sock) -> tuple:
    """One frame, with client unmasking. Returns (opcode, payload)."""
    first, second = _read_exactly(sock, 2)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack(">H", _read_exactly(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _read_exactly(sock, 8))[0]
    if length > MAX_FRAME:
        raise ValueError(f"frame of {length} bytes is over the limit")
    mask = _read_exactly(sock, 4) if masked else b""
    payload = _read_exactly(sock, length) if length else b""
    if masked and payload:
        payload = bytes(byte ^ mask[index % 4]
                        for index, byte in enumerate(payload))
    return opcode, payload


class Subscriber:
    """One browser's view of the feed."""

    def __init__(self) -> None:
        self.queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE)
        self.dropped = 0

    def put(self, message: dict) -> None:
        try:
            self.queue.put_nowait(message)
        except queue.Full:
            # a snapshot is never stale enough to be worth a backlog: drop the
            # oldest and let the newest state win
            try:
                self.queue.get_nowait()
                self.dropped += 1
                self.queue.put_nowait(message)
            except (queue.Empty, queue.Full):
                pass

    def get(self, timeout: float):
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None


class LiveFeed:
    """Fan-out of state snapshots and log lines to every open socket."""

    def __init__(self, snapshot) -> None:
        self._snapshot = snapshot
        self._subscribers: set[Subscriber] = set()
        self._lock = threading.Lock()
        self._last = 0.0

    def subscribe(self) -> Subscriber:
        subscriber = Subscriber()
        with self._lock:
            self._subscribers.add(subscriber)
        subscriber.put({"type": "state", "state": self._snapshot()})
        return subscriber

    def unsubscribe(self, subscriber: Subscriber) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, kind: str = "state", **fields) -> None:
        message = {"type": kind, **fields}
        with self._lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            subscriber.put(message)

    def publish_state(self, throttle: float = 0.15) -> None:
        """State snapshots coalesce: a scan updates the counters several times a
        second and the browser cannot use more than that."""
        now = time.monotonic()
        if now - self._last < throttle:
            return
        self._last = now
        self.publish("state", state=self._snapshot())

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._subscribers)


def token_ok(provided: str | None, expected: str) -> bool:
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided, expected)


def serve(feed: LiveFeed, sock, token: str | None) -> None:
    """Drives one connection until the client goes away."""
    sock.settimeout(PING_INTERVAL)
    subscriber = feed.subscribe()
    last_ping = time.monotonic()
    try:
        sock.sendall(encode(json.dumps({"type": "hello",
                                        "subscribers": feed.count})))
        while True:
            message = subscriber.get(timeout=1.0)
            now = time.monotonic()
            if message is not None:
                sock.sendall(encode(json.dumps(message)))
                last_ping = now
            elif now - last_ping > PING_INTERVAL:
                sock.sendall(encode(b"", OP_PING))
                last_ping = now
            if now - last_ping > FEED_TIMEOUT:
                return
            # drain anything the client sent, so a close is noticed promptly
            sock.settimeout(0.01)
            try:
                opcode, payload = read_frame(sock)
            except (socket.timeout, TimeoutError):
                continue
            except (ConnectionError, OSError, ValueError):
                return
            finally:
                sock.settimeout(PING_INTERVAL)
            if opcode == OP_CLOSE:
                return
            if opcode == OP_PING:
                sock.sendall(encode(payload, OP_PONG))
    except (ConnectionError, OSError):
        return
    finally:
        feed.unsubscribe(subscriber)
