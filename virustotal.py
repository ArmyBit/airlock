"""VirusTotal hash lookups, run on the host.

The guest has no route off its isolated bridge, so this never runs there. Only
the sha256 of each file is sent, never the file itself, so a lookup cannot
upload evidence - but it does tell VirusTotal which files you have, and a hash
that is already in their database can be looked up by anyone else, so this is a
decision about disclosure, not a neutral read.

The API key is not in the source tree. Put it in $TRIAGE_VT_KEY, or in
~/.config/triage/virustotal with mode 600, and the panel stays unconfigured
instead of failing the scan when it is missing.
"""

from __future__ import annotations

import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"
PAGE = "https://www.virustotal.com/gui/file/{sha256}"

# a hash VirusTotal has never seen is not worth asking about again for a while
UNKNOWN_TTL = 6 * 3600
KNOWN_TTL = 30 * 24 * 3600
# free keys get a small number of lookups per minute; keep well under whatever
# the quota is rather than discovering it by being throttled mid-scan
MIN_INTERVAL = 0.34
# Every file on the disk is checked. The one thing that can cut that short is
# VirusTotal itself refusing the key, which stops the scan rather than spending
# the rest of the quota on 429s.
VT_LIMIT = int(os.environ.get("TRIAGE_VT_LIMIT", "0") or 0)   # 0 means no limit
# a key that has run out is worth recognising, not retrying once per file
QUOTA_MARKERS = ("usage-limit-reached", "quota", "QuotaExceeded")

STATUS_MALICIOUS = "malicious"
STATUS_CLEAN = "clean"
STATUS_UNKNOWN = "unknown"
STATUS_ERROR = "error"

KEY_ENV = "TRIAGE_VT_KEY"
KEY_FILE = Path.home() / ".config" / "triage" / "virustotal"
CACHE_FILE = Path.home() / ".cache" / "triage" / "virustotal.json"


def read_key() -> str:
    """The key from the environment or the config file. Never logged."""
    key = (os.environ.get(KEY_ENV) or "").strip()
    if key:
        return key
    try:
        return KEY_FILE.read_text().strip()
    except OSError:
        return ""


def sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


class VirusTotal:
    def __init__(self, key: str, cache_path: Path = CACHE_FILE,
                 min_interval: float = MIN_INTERVAL, timeout: int = 20) -> None:
        self.key = key
        self.cache_path = cache_path
        self.min_interval = min_interval
        self.timeout = timeout
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._cache = self._load_cache()

    def _load_cache(self) -> dict:
        try:
            data = json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.parent.chmod(0o700)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache))
            tmp.replace(self.cache_path)
            self.cache_path.chmod(0o600)
        except OSError:
            pass                        # a cache we cannot write is slower, not fatal

    def _cached(self, sha: str):
        entry = self._cache.get(sha)
        if not isinstance(entry, dict):
            return None
        age = time.time() - entry.get("checked", 0)
        ttl = UNKNOWN_TTL if entry.get("status") == STATUS_UNKNOWN else KNOWN_TTL
        return entry if age < ttl else None

    def _wait_turn(self) -> None:
        with self._lock:
            gap = self.min_interval - (time.monotonic() - self._last_call)
            if gap > 0:
                time.sleep(gap)
            self._last_call = time.monotonic()

    def _get(self, sha: str) -> tuple:
        request = urllib.request.Request(
            ENDPOINT.format(sha256=sha),
            headers={"x-apikey": self.key, "accept": "application/json",
                     "user-agent": "triage-watch/1.0"},
            method="GET")
        context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout,
                                        context=context) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            except (OSError, ValueError):
                return exc.code, {}

    def _summarise(self, body: dict, sha: str) -> dict:
        """Only the counters and a few engine names. The full record is tens of
        kilobytes per file and the browser does not need any of the rest."""
        result = self._blank(STATUS_CLEAN)
        data = body.get("data") or {}
        attributes = data.get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        scanned = sum(int(stats.get(key) or 0) for key in
                      ("malicious", "suspicious", "undetected", "harmless"))
        engines = []
        for name, verdict in sorted(
                (attributes.get("last_analysis_results") or {}).items()):
            category = verdict.get("category")
            if category in ("malicious", "suspicious"):
                engines.append({"engine": name,
                                "result": verdict.get("result") or category})
        result.update({
            "status": STATUS_MALICIOUS if malicious + suspicious else STATUS_CLEAN,
            "detections": malicious + suspicious,
            "malicious": malicious,
            "suspicious": suspicious,
            "scanned": scanned,
            "engines": engines[:5],
            "meaningful_name": attributes.get("meaningful_name") or "",
            "permalink": PAGE.format(sha256=sha) if sha else "",
            "first_seen": attributes.get("first_seen_itw_date") or 0,
        })
        return result

    @staticmethod
    def _blank(status: str, **fields) -> dict:
        """Every result has every key. One lookup path returning a dict without
        `meaningful_name` while another returned it with one is how a scan that
        worked fine died on a KeyError in the report builder."""
        result = {"status": status, "detections": 0, "malicious": 0,
                  "suspicious": 0, "scanned": 0, "engines": [],
                  "meaningful_name": "", "permalink": "", "first_seen": 0,
                  "cached": False, "checked": int(time.time()), "error": None}
        result.update(fields)
        return result

    def lookup(self, sha: str) -> dict:
        """One hash. Never raises: a lookup failure is a status, not an exception,
        so one bad answer cannot lose a finished scan."""
        if not sha256_hex(sha or ""):
            return self._blank(STATUS_ERROR,
                               error="no usable sha256 for this file")
        hit = self._cached(sha)
        if hit:
            return dict(hit, cached=True)
        self._wait_turn()
        try:
            status, body = self._get(sha)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return self._blank(STATUS_ERROR, permalink=PAGE.format(sha256=sha),
                               error=f"{type(exc).__name__}: {exc}"[:200])
        if status == 204:
            # 204 means either "nobody has this hash" or, with a usage-limit
            # marker, "the key is out for the day" - the two are not the same
            # answer, so the marker decides
            marker = str((body or {}).get("data", {}).get("type", "")).lower()
            if any(mark in marker for mark in QUOTA_MARKERS):
                result = self._blank(STATUS_ERROR, quota=True,
                                     error="VirusTotal usage limit reached")
            else:
                result = self._blank(STATUS_UNKNOWN,
                                     permalink=PAGE.format(sha256=sha))
        elif status == 404:
            # a hash nobody has submitted is "unknown", never "clean"
            result = self._blank(STATUS_UNKNOWN, permalink=PAGE.format(sha256=sha))
        elif status in (401, 403):
            result = self._blank(STATUS_ERROR,
                                 error=f"VirusTotal rejected the API key (HTTP {status})")
        elif status == 429:
            result = self._blank(STATUS_ERROR,
                                 error="rate limited by VirusTotal (HTTP 429)")
        elif status == 200:
            if (body or {}).get("error"):
                # VirusTotal answers some refusals with a 200 and an error body
                message = str((body or {})["error"].get("message") or "refused")
                result = self._blank(
                    STATUS_ERROR,
                    quota=any(mark.lower() in message.lower() for mark in QUOTA_MARKERS),
                    error=f"VirusTotal refused the lookup: {message}"[:200])
            else:
                result = self._summarise(body, sha)
        else:
            result = self._blank(STATUS_ERROR,
                                 error=f"unexpected HTTP {status} from VirusTotal")
        if not isinstance(result, dict):
            # a cache full of junk is worse than no cache, and one bad answer
            # must not be able to break every later scan
            return self._blank(STATUS_ERROR, error="malformed answer from VirusTotal")
        self._cache[sha] = result
        self._save_cache()
        return dict(result, cached=False)

    def lookup_many(self, shas, cap: int | None = None, progress=None) -> tuple:
        """Looks up every unique hash, in the order given.

        `cap` is only for tests and for TRIAGE_VT_LIMIT; None means every hash
        the scan found. Returns (results keyed by hash, counters). If the key
        runs out of quota the remaining hashes are counted as skipped rather
        than hammering an API that has already said no.
        """
        results: dict = {}
        counters = {"wanted": 0, "checked": 0, "malicious": 0, "clean": 0,
                    "unknown": 0, "errors": 0, "skipped": 0, "cached": 0}
        seen = set()
        for sha in shas:
            if not sha256_hex(sha or ""):
                continue
            if sha in seen:
                continue
            seen.add(sha)
            counters["wanted"] += 1
        done = 0
        for sha in seen:
            if cap is not None and done >= cap:
                counters["skipped"] += 1
                continue
            result = self.lookup(sha)
            if result.get("quota"):
                # the key has run out: every remaining hash would be refused the
                # same way, so stop here and account for all of them
                counters["quota"] = counters.get("quota", 0) + 1
                counters["skipped"] += len(seen) - done
                break
            results[sha] = result
            done += 1
            counters["checked"] += 1
            counters["cached"] += 1 if result.get("cached") else 0
            key = result["status"]
            if key == STATUS_MALICIOUS:
                counters["malicious"] += 1
            elif key == STATUS_CLEAN:
                counters["clean"] += 1
            elif key == STATUS_UNKNOWN:
                counters["unknown"] += 1
            else:
                counters["errors"] += 1
            if progress:
                progress(done, counters)
        return results, counters


def counters_label(counters: dict) -> str:
    """One line for the state message."""
    if not counters.get("wanted"):
        return "no file hashes to check"
    parts = [f"{counters['checked']} checked"]
    if counters["malicious"]:
        parts.append(f"{counters['malicious']} flagged")
    if counters["clean"]:
        parts.append(f"{counters['clean']} clean")
    if counters["unknown"]:
        parts.append(f"{counters['unknown']} unknown to VirusTotal")
    if counters["errors"]:
        parts.append(f"{counters['errors']} errors")
    if counters["skipped"]:
        parts.append(f"{counters['skipped']} not checked (per-scan limit)")
    if counters["cached"]:
        parts.append(f"{counters['cached']} from cache")
    return ", ".join(parts)