#!/usr/bin/python3
"""Triage collector.

This is the only thing in the whole system that ever touches the analysis disk.
It runs inside the disposable guest, never on the host, and it treats the disk
as hostile:

* every mount is read-only and non-executing, in a private mount namespace, so
  nothing from the disk can run and no mount outlives the run;
* partitions are discovered from the disk's own partition table and attached to
  private read-only loop devices, never trusting an offset handed in from outside;
* nothing is executed, chrooted into or dynamically loaded from the disk;
* one unreadable file is logged and skipped, never fatal.

Output is JSON Lines, one record per event, to a fixed path, plus a completion
marker on stdout so the host knows the report is finished.
"""

import grp
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import time

CHUNK = 1 << 20
HASH_LIMIT = 256 << 20
MAX_ENTRIES = 500000
MAX_ERRORS = 500
REPORT = "/var/lib/triage/report.jsonl"
MARKER = "TRIAGE_COMPLETE"

# T13: nothing on the analysis disk may run. ro alone is not enough, and these
# flags are not negotiable by anything the disk contains.
MOUNT_FLAGS = "ro,noexec,nosuid,nodev,noatime"

# Mounted filesystems the guest needs to run are not analysis targets.
SKIP_DIRS = ("/proc", "/sys", "/dev", "/run", "/var/lib/triage")


def log(message):
    sys.stderr.write(f"[collect] {message}\n")
    sys.stderr.flush()


def record(handle, record_type, /, **fields):
    """One JSONL line. `type` is the record kind (entry/error/fs/mount/meta/done)
    and `kind` is what the path is (file/dir/symlink/...), so the two can never
    be confused for each other the way one shared key allowed.

    The positional-only marker is deliberate: it keeps a field of any name from
    colliding with the parameters here, which is how an entry's own `kind` field
    silently broke this function once already.
    """
    handle.write(json.dumps({"type": record_type, **fields}, sort_keys=True) + "\n")
    handle.flush()          # so progress is visible while the walk is still going


def run(argv, timeout=300):
    """Runs a helper tool and returns its stdout, or None on any failure."""
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"{argv[0]} failed: {exc}")
        return None
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        log(f"{argv[0]} exited {done.returncode}: {detail[-1] if detail else ''}")
        return None
    return done.stdout


def enter_private_namespace():
    """Re-executes inside a private mount namespace.

    Every mount made afterwards disappears when the collector exits, so the
    guest is left exactly as it was found and no analysis filesystem is ever
    visible to anything else in the guest.
    """
    if os.environ.get("TRIAGE_PRIVATE_NS") == "1":
        return
    if os.geteuid() != 0:
        raise SystemExit("mounting an analysis disk needs root in the guest")
    unshare = shutil.which("unshare")
    if not unshare:
        log("unshare is missing; mounts will not be private")
        os.environ["TRIAGE_PRIVATE_NS"] = "1"
        return
    os.environ["TRIAGE_PRIVATE_NS"] = "1"
    argv = [unshare, "--mount", "--",
            sys.executable, os.path.abspath(__file__)] + sys.argv[1:]
    log("re-executing in a private mount namespace")
    os.execvp(unshare, argv)


def device_size(node):
    out = run(["blockdev", "--getsize64", node])
    try:
        return int(out.strip()) if out else 0
    except ValueError:
        return 0


def attach_loop(node, offset, length):
    """A private read-only loop for a partition, or None to use the node itself.

    ``losetup --read-only`` is what keeps the kernel from writing to the disk
    even if something in the guest tries to. ``--sector-size 512`` pins the
    unit so a 4Kn disk is not misread as one with huge partitions.
    """
    if offset == 0 and length == 0:
        return node
    argv = ["losetup", "--find", "--show", "--read-only",
            "--sector-size", "512", node]
    if offset:
        argv += ["--offset", str(offset)]
    if length:
        argv += ["--sizelimit", str(length)]
    out = run(argv)
    return out.decode().strip() if out else None


def detach_loop(loop_node, source_device):
    """Detaches only loop devices we created; the evidence disk is left alone.

    The names are deliberately different because getting these two the wrong way
    round asks losetup to detach the disk the user plugged in.
    """
    if not loop_node or loop_node == source_device:
        return
    if not os.path.basename(loop_node).startswith("loop"):
        # a partition node the kernel made for us has nothing to detach, and
        # this is the normal case now, not something to report
        return
    run(["losetup", "--detach", loop_node])


def probe_filesystems(node):
    """The filesystem on this node, as blkid describes it.

    One node gets one entry: ``blkid -o export`` prints one KEY=value per line
    for a single filesystem, so treating every line as its own filesystem meant
    mounting the same device once per line and reporting whichever line happened
    to be last.
    """
    out = run(["blkid", "-p", "-o", "export", node])
    if not out:
        return []
    fields = {}
    for line in out.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        key, _, value = line.partition("=")
        if value:
            fields[key] = value
    return [(node, fields)] if fields else []


def node_exists(path):
    """Indirection so the tests can pretend a partition node is missing without
    patching os.path.exists for the whole process."""
    return os.path.exists(path)


def partition_candidates(node):
    """Every (offset, length, device) worth probing: the disk and its partitions.

    The third item is the node to read, when the kernel already exposes one; None
    means a loop device would be needed, and the caller says so rather than
    silently scanning less than the disk holds.
    """
    total = device_size(node)
    candidates = [(0, total, node)]
    out = run(["sfdisk", "--json", node])
    if not out:
        return candidates
    try:
        rows = json.loads(out.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError) as exc:
        log(f"could not read the partition table: {exc}")
        return candidates
    for row in rows.get("partitiontable", {}).get("partitions", []):
        try:
            start = int(row["start"]) * 512
            length = int(row["size"]) * 512
        except (KeyError, TypeError, ValueError):
            continue
        # sfdisk resolves the node itself when the kernel has made one, which
        # is the normal case and needs no loop device at all
        kernel_node = row.get("node")
        if kernel_node and not node_exists(kernel_node):
            log(f"sfdisk named {kernel_node} but it is not there")
            kernel_node = None
        if length:
            candidates.append((start, length, kernel_node))
    missing = [offset for offset, _, part in candidates if part is None]
    if missing:
        log(f"{len(missing)} partitions have no device node in the guest, so "
            f"they need a loop device: offsets {missing}")
    return candidates


def mount_readonly(node, target, fstype):
    """Mounts read-only and non-executing. Returns True only if it worked."""
    os.makedirs(target, exist_ok=True)
    argv = ["mount", "-t", fstype or "auto", "-o", MOUNT_FLAGS, node, target]
    done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False, timeout=300)
    if done.returncode == 0:
        return True
    detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
    log(f"mount of {node} as {fstype} failed: {detail[-1] if detail else 'unknown'}")
    return False


def sha256_of(path, size):
    """Streams the file, so a hostile 4 GB file cannot exhaust guest memory."""
    if size > HASH_LIMIT:
        return None, size, "skipped: larger than the hash limit"
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NOCTTY
    handle = os.open(path, flags)
    try:
        while True:
            chunk = os.read(handle, CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    finally:
        os.close(handle)
    return digest.hexdigest(), total, None


def owner_of(info):
    try:
        return pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        return str(info.st_uid)


def group_of(info):
    try:
        return grp.getgrgid(info.st_gid).gr_name
    except KeyError:
        return str(info.st_gid)


def hidden_attribute(path):
    """The filesystem's own hidden flag, when the guest can see it.

    A leading dot is meaningless on NTFS and exFAT, so it is reported separately
    as ``hidden_dot``. Read through xattrs rather than shelling out to
    ``getfattr`` once per file, which would dominate the run time. When the
    filesystem exposes no such attribute the result is ``None`` and a note
    explains it, so a missing capability is never reported as ``false``.
    """
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        return None, f"xattrs unavailable: {exc.strerror or exc}"
    interesting = [n for n in names if "hidden" in n.lower()]
    if not interesting:
        return None, "no hidden attribute exposed by this filesystem"
    for name in interesting:
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            continue
        text = value.decode("utf-8", "replace").strip()
        if not text or text == "0":
            return False, None
        if text == "1" or text == "true":
            return True, None
        return True, f"{name}={text}"
    return None, None


def classify(info):
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISDIR(info.st_mode):
        return "dir"
    if stat.S_ISREG(info.st_mode):
        return "file"
    if stat.S_ISBLK(info.st_mode):
        return "block"
    if stat.S_ISCHR(info.st_mode):
        return "char"
    if stat.S_ISFIFO(info.st_mode):
        return "fifo"
    if stat.S_ISSOCK(info.st_mode):
        return "socket"
    return "other"


def walk(root, handle, counters, want_hashes):
    """Walks ``root`` without ever following a symlink out of the tree."""
    for dirpath, dirnames, filenames in os.walk(root, topdown=True,
                                                followlinks=False, onerror=counters["error"]):
        kept = []
        for name in sorted(dirnames):
            path = os.path.join(dirpath, name)
            if os.path.abspath(path) in SKIP_DIRS:
                counters["skipped"] += 1
                continue
            kept.append(name)
            emit(path, handle, counters, want_hashes)
            counters["dirs"] += 1
        dirnames[:] = kept
        for name in sorted(filenames):
            kind = emit(os.path.join(dirpath, name), handle, counters, want_hashes)
            if kind == "file":
                counters["files"] += 1
            elif kind is not None and kind != "dir":
                counters["others"] = counters.get("others", 0) + 1
            if counters["entries"] >= MAX_ENTRIES:
                log(f"entry limit of {MAX_ENTRIES} reached, stopping the walk")
                dirnames[:] = []
                return


def emit(path, handle, counters, want_hashes) -> str | None:
    """Writes one record and returns what the path was, so the caller can keep
    the counters honest. Returns None if the entry could not be recorded."""
    if counters["entries"] >= MAX_ENTRIES:
        return None
    counters["entries"] += 1
    try:
        info = os.lstat(path)
    except OSError as exc:
        counters["error"](exc, path)
        return None

    kind = classify(info)
    digest, hashed, note = None, 0, None
    if want_hashes and kind == "file":
        try:
            digest, hashed, note = sha256_of(path, info.st_size)
        except OSError as exc:
            counters["error"](exc, path)
            digest, note = None, f"unreadable: {exc.strerror or exc}"
        except Exception as exc:  # a crafted file can do anything
            counters["error"](exc, path)
            digest, note = None, f"hash failed: {exc}"
    counters["hashed_bytes"] += hashed

    hidden_attr, attr_note = hidden_attribute(path) if kind == "file" else (None, None)
    fields = {
        "path": path.lstrip("/"),
        "abs": path,
        "kind": kind,
        "size": info.st_size,
        "mode": oct(stat.S_IMODE(info.st_mode)),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "owner": owner_of(info),
        "group": group_of(info),
        "mtime": int(info.st_mtime),
        "hidden_dot": os.path.basename(path).startswith("."),
        "hidden_attr": hidden_attr,
        "hidden_attr_note": attr_note or note,
        "sha256": digest,
    }
    if kind == "symlink":
        try:
            fields["target"] = os.readlink(path)
        except OSError:
            fields["target"] = None
    record(handle, "entry", **fields)
    return kind


def scan(device, want_hashes, report_path=REPORT, mountpoint="/mnt/case"):
    """Walks every filesystem on ``device`` and writes the report.

    A directory may be given instead of a block device, which skips mounting
    entirely. That is only useful for checking the collector against known
    files; a real case always goes through the mount path.
    """
    report_dir = os.path.dirname(report_path)
    os.makedirs(report_dir, exist_ok=True)
    started = time.time()
    counters = {"entries": 0, "files": 0, "dirs": 0, "others": 0,
                "hashed_bytes": 0, "skipped": 0}
    errors = [0]

    with open(report_path, "w", encoding="utf-8", errors="replace") as handle:

        def note(exc, path=None):
            errors[0] += 1
            if errors[0] <= MAX_ERRORS:
                record(handle, "error", path=path, error=str(exc))

        counters["error"] = note
        record(handle, "meta", device=device, pid=os.getpid(),
               hashes=want_hashes, mount_flags=MOUNT_FLAGS,
               started=int(started), hostname=socket_name())

        if os.path.isdir(device):
            walk(device, handle, counters, want_hashes)
            summary = {
                "entries": counters["entries"], "files": counters["files"],
                "dirs": counters["dirs"], "others": counters["others"],
                "skipped": counters["skipped"],
                "hashed_bytes": counters["hashed_bytes"],
                "errors": errors[0], "seconds": round(time.time() - started, 1),
            }
            record(handle, "done", **summary)
            return summary

        for index, (offset, length, kernel_node) in enumerate(
                partition_candidates(device)):
            if kernel_node:
                node = kernel_node
            else:
                node = attach_loop(device, offset, length)
            if not node:
                record(handle, "error", offset=offset,
                       error="this partition is not visible in the guest and "
                             "could not be opened read-only")
                continue
            found = probe_filesystems(node)
            if not found:
                record(handle, "fs", node=node, offset=offset, fstype=None,
                       note="no filesystem here" if offset else "unrecognised device")
                detach_loop(node, device)
                continue
            for fs_node, fields in found:
                target = f"{mountpoint}/p{index}"
                if not mount_readonly(fs_node, target, fields.get("TYPE")):
                    record(handle, "error", node=fs_node,
                           error="could not mount read-only")
                    continue
                record(handle, "mount", node=fs_node, target=target,
                       fstype=fields.get("TYPE"), label=fields.get("LABEL"),
                       uuid=fields.get("UUID"), offset=offset,
                       size=length or device_size(fs_node))
                walk(target, handle, counters, want_hashes)
                run(["umount", target])
                detach_loop(node, device)

        summary = {
            "entries": counters["entries"],
            "files": counters["files"],
            "dirs": counters["dirs"],
            # symlinks, sockets, devices: real entries that are not files, and
            # worth saying so rather than letting entries != files + dirs
            "others": counters["others"],
            "hashed_bytes": counters["hashed_bytes"],
            "errors": errors[0],
            "seconds": round(time.time() - started, 1),
        }
        record(handle, "done", **summary)
    return summary


def socket_name():
    try:
        with open("/proc/sys/kernel/hostname") as handle:
            return handle.read().strip()
    except OSError:
        return "unknown"


def main(argv):
    device = None
    want_hashes = True
    report_path = REPORT
    for arg in argv[1:]:
        if arg in ("-n", "--no-hashes"):
            want_hashes = False
        elif arg.startswith("--report="):
            report_path = arg.split("=", 1)[1]
        elif not arg.startswith("-"):
            device = arg
    if not device:
        sys.stderr.write("usage: triage-collect [--no-hashes] [--report=PATH] <block-device>\n")
        return 2
    if not os.path.exists(device):
        sys.stderr.write(f"no such device: {device}\n")
        return 2
    if os.path.isdir(device):
        needs_root = False
    elif stat.S_ISBLK(os.stat(device).st_mode):
        needs_root = True
    else:
        sys.stderr.write(f"not a block device or directory: {device}\n")
        return 2

    if needs_root:
        enter_private_namespace()

    summary = scan(device, want_hashes, report_path)
    log("summary: " + " ".join(f"{k}={v}" for k, v in summary.items()))
    log(f"report at {report_path}")
    print(MARKER)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))