#!/usr/bin/env python3
"""Builds the Alpine golden image used for disk-triage cases.

Rootless by design: packages are fetched and unpacked as plain files, the root
filesystem is filled with ``mke2fs -d``, and the boot initramfs is assembled with
cpio. No chroot, no loop mounts, no root.

Outputs, all under ``tiny-linux/``:
    golden.qcow2            ext4 root, Alpine + ssh + filesystem tooling
    boot-initramfs.cpio.gz  loads virtio/ext4 then switch_root into golden.qcow2
    keys/golden_*           baked host key and the host-side access key

The image is deliberately minimal: it exists to mount one read-only disk, walk it
and hash what it finds.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / "build" / "cache"
ROOTFS = HERE / "build" / "rootfs"
KEYS = HERE / "keys"

BRANCH = "v3.24"
ALPINE_VERSION = "3.24.2"
REPOS = ("main", "community")
MIRROR = "https://dl-cdn.alpinelinux.org/alpine"

# What the collector needs. Kept small on purpose.
PACKAGES = (
    # the collector itself: it is a python script, so the guest needs an
    # interpreter to run it at all
    "python3",
    "openssh",          # sshd + client
    "coreutils",        # sha256sum
    "findutils",
    "util-linux",       # mount helpers
    "losetup",          # util-linux losetup: busybox's has no --sizelimit and
                        # no --show, which is what reading a partition that the
                        # kernel did not scan for us needs
    "blkid",            # the real blkid; busybox's cannot do '-p -o export',
                        # which is how the collector reads filesystem types
    "sfdisk",           # partition table as json, so offsets come from the
                        # disk's own table rather than from outside
    "e2fsprogs",        # fsck.ext* for ext filesystems
    "e2fsprogs-extra",  # debugfs: read ext filesystems without mounting them
    "lsblk",            # block device inventory for the collector
    "nftables",         # the network isolation ruleset
    "ntfs-3g",          # NTFS
    "fuse3",
    "exfatprogs",       # exFAT
)

# Filesystems the guest must be able to read later, when a disk is attached.
ANALYSIS_MODULES = ("exfat", "ntfs3", "vfat", "udf", "xfs", "btrfs",
                    # loop, plus what it needs: a partition the kernel did not
                    # expose (inside a container, say) is only reachable through
                    # a private loop device, and that needs the driver
                    "loop",
                    # needed for the isolation ruleset
                    "nf_tables", "nft_chain_nat")

# Loaded from the initramfs so the root filesystem can be mounted at all.
BOOT_MODULES = ("virtio_blk", "virtio_net", "virtio-rng", "ext4")

# A dedicated host<->guest link on the isolated libvirt network "triage"
# (forward mode 'none', so it has no route to any other network at all). The
# guest gets a static address and NO default route: the only host it can reach
# is the bridge, and only port 22 is allowed through the firewall.
NETWORK = "triage"
SUBNET = "192.168.77.0/24"
SUBNET_PREFIX = "192.168.77."
HOST_BRIDGE = "192.168.77.1"
GUEST_IP = "192.168.77.10"
GUEST_NETMASK = "255.255.255.0"

IMAGE_SIZE_MB = 2048


def log(message: str) -> None:
    print(f"[golden] {message}", flush=True)


def run(argv: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kw)


def fetch(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size:
        return dest
    log(f"downloading {url.rsplit('/', 1)[-1]}")
    with urllib.request.urlopen(url, timeout=120) as response, dest.open("wb") as out:
        shutil.copyfileobj(response, out)
    return dest


def apk_indexes() -> tuple:
    """(package name -> {version, repo}, provided-capability -> package name)."""
    index: dict = {}
    provides: dict = {}
    for repo in REPOS:
        base = f"{MIRROR}/{BRANCH}/{repo}/x86_64"
        tarball = fetch(f"{base}/APKINDEX.tar.gz", CACHE / f"APKINDEX-{repo}.tar.gz")
        work = CACHE / f"index-{repo}"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        with tarfile.open(tarball, "r:gz") as tar:
            member = next(m for m in tar.getmembers() if m.name == "APKINDEX")
            source = tar.extractfile(member)
            text = source.read().decode("utf-8", "replace")
        for record in text.split("\n\n"):
            fields = dict(
                line.split(":", 1)
                for line in record.strip().splitlines()
                if ":" in line and line[1:2] != " "
            )
            if fields.get("P") and fields.get("V"):
                index[fields["P"]] = {"version": fields["V"], "repo": repo,
                                      "name": fields["P"]}
                for capability in fields.get("p", "").split():
                    provides.setdefault(capability.rsplit("=", 1)[0], fields["P"])
    return index, provides


def already_present(root: Path, name: str) -> bool:
    """Cheap check for packages the minirootfs already ships."""
    probes = {
        "musl": "lib/ld-musl-x86_64.so.1",
        "busybox": "bin/busybox",
        "apk-tools": "sbin/apk",
        "alpine-baselayout": "etc/alpine-release",
        "alpine-keys": "etc/apk/keys",
        "alpine-conf": "sbin/setup-alpine",
        "ca-certificates-bundle": "etc/ssl/certs/ca-certificates.crt",
        "libc-utils": "usr/bin/ls",
    }
    probe = probes.get(name)
    return bool(probe) and (root / probe).exists()


def resolve(index: dict, provides: dict, wanted: tuple, root: Path) -> dict:
    """Walks package dependencies.

    ``so:libacl.so.1`` style dependencies are capabilities, not packages: they are
    mapped back to whichever package provides them. Skipping them (as an earlier
    version of this script did) yields binaries that cannot start because their
    libraries were never unpacked.
    """
    resolved: dict = {}
    queue = list(wanted)
    while queue:
        name = queue.pop(0)
        if name in resolved or already_present(root, name):
            continue
        if name not in index:
            log(f"    warning: {name} not in the index, skipping")
            continue
        resolved[name] = index[name]
        for dep in fetch_deps(resolved[name]):
            if dep.startswith("so:"):
                provider = provides.get(dep)
                if provider and provider not in resolved:
                    queue.append(provider)
                elif not provider:
                    log(f"    warning: nothing provides {dep} (needed by {name})")
            elif dep.startswith(("cmd:", "pc:", "api:")):
                continue
            elif dep not in resolved:
                queue.append(dep)
    return resolved


def fetch_deps(entry: dict) -> list:
    """Dependency list for one package, read back from the index."""
    base = f"{MIRROR}/{BRANCH}/{entry['repo']}/x86_64"
    tarball = fetch(f"{base}/APKINDEX.tar.gz", CACHE / f"APKINDEX-{entry['repo']}.tar.gz")
    with tarfile.open(tarball, "r:gz") as tar:
        member = next(m for m in tar.getmembers() if m.name == "APKINDEX")
        text = tar.extractfile(member).read().decode("utf-8", "replace")
    for record in text.split("\n\n"):
        fields = dict(
            line.split(":", 1)
            for line in record.strip().splitlines()
            if ":" in line and line[1:2] != " "
        )
        if fields.get("P") == entry["name"]:
            deps = []
            for spec in fields.get("D", "").split():
                deps.append(spec.split("=")[0].split(">")[0].split("<")[0])
            return deps
    return []


def install(packages: dict, root: Path) -> None:
    for name, entry in sorted(packages.items()):
        url = f"{MIRROR}/{BRANCH}/{entry['repo']}/x86_64/{name}-{entry['version']}.apk"
        apk = fetch(url, CACHE / "apk" / f"{name}-{entry['version']}.apk")
        # apk files are concatenated gzip members; GNU tar walks them fine.
        result = subprocess.run(
            ["tar", "-xzf", str(apk), "-C", str(root), "--no-same-owner",
             "--no-same-permissions", "--warning=no-unknown-keyword"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"failed to unpack {name}: {result.stderr.strip()}")
        log(f"    {name}-{entry['version']}")


def base_system() -> None:
    log("unpacking the Alpine minirootfs")
    tarball = fetch(
        f"{MIRROR}/v{BRANCH.lstrip('v')}/releases/x86_64/alpine-minirootfs-"
        f"{ALPINE_VERSION}-x86_64.tar.gz",
        CACHE / f"alpine-minirootfs-{ALPINE_VERSION}.tar.gz")
    run(["tar", "-xzf", str(tarball), "-C", str(ROOTFS),
         "--no-same-owner", "--no-same-permissions"])


def module_chain(name: str) -> list:
    """Exact load order for a module, dependencies first, as modprobe computes it.

    Guessing this by hand is what broke ext4 (missing crc32c-cryptoapi) and
    virtio_net (missing failover/net_failover): both then failed to load with
    unresolved symbols.
    """
    result = subprocess.run(
        ["modprobe", "--show-depends", "--ignore-install", "-S",
         os.uname().release, name],
        capture_output=True, text=True)
    chain = []
    for line in result.stdout.splitlines():
        if line.startswith("insmod "):
            path = Path(line.split(None, 1)[1].strip())
            if path.exists():
                chain.append(path)
    return chain


def copy_modules(target: Path, names: tuple) -> list:
    """Copies each module with a numeric prefix so sorted order == load order."""
    target.mkdir(parents=True, exist_ok=True)
    copied = []
    seen = set()
    for name in names:
        for index, path in enumerate(module_chain(name)):
            if path.name in seen:
                continue
            seen.add(path.name)
            shutil.copy(path, target / f"{len(copied):02d}_{path.name}")
            copied.append(path.name)
    return copied


def module_path(name: str) -> str | None:
    result = subprocess.run(["modinfo", "-F", "filename", name],
                            capture_output=True, text=True)
    path = result.stdout.strip()
    return path if path and Path(path).exists() else None


def install_modules(root: Path, names: tuple, label: str) -> list:
    got = copy_modules(root / "lib" / "modules", names)
    log(f"    {label}: {len(got)} modules")
    return got


def audit_libraries(root: Path) -> list:
    """Every NEEDED shared object of every binary must exist in the image.

    This is the check that would have caught the broken coreutils/util-linux
    install before the image was ever booted.
    """
    missing: dict = {}
    readelf = shutil.which("readelf")
    if not readelf:
        log("    readelf unavailable, skipping the library audit")
        return []
    for directory in ("bin", "sbin", "usr/bin", "usr/sbin", "usr/libexec"):
        base = root / directory
        if not base.is_dir():
            continue
        for binary in sorted(base.iterdir()):
            if binary.is_symlink() or not binary.is_file():
                continue
            if binary.read_bytes()[:4] != b"\x7fELF":
                continue
            result = subprocess.run([readelf, "-d", str(binary)],
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "(NEEDED)" not in line or "[" not in line:
                    continue
                library = line.split("[", 1)[1].split("]", 1)[0]
                if not (root / "lib" / library).exists() and \
                        not (root / "usr" / "lib" / library).exists():
                    missing.setdefault(library, []).append(f"{directory}/{binary.name}")
    if missing:
        for library, users in sorted(missing.items()):
            log(f"    MISSING {library}: {', '.join(users[:4])}"
                f"{' ...' if len(users) > 4 else ''}")
    else:
        log("    all shared libraries resolve inside the image")
    return sorted(missing)


def write_ssh_keys(root: Path) -> None:
    KEYS.mkdir(parents=True, exist_ok=True)
    host_key = KEYS / "golden_host_ed25519_key"
    access = KEYS / "golden_id_ed25519"
    for path, comment in ((host_key, "golden-guest-host"), (access, "golden-access")):
        if not path.exists():
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment,
                 "-f", str(path)])
    ssh_dir = root / "etc" / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(host_key, ssh_dir / "ssh_host_ed25519_key")
    shutil.copy(str(host_key) + ".pub", ssh_dir / "ssh_host_ed25519_key.pub")
    os.chmod(ssh_dir / "ssh_host_ed25519_key", 0o600)
    os.chmod(ssh_dir / "ssh_host_ed25519_key.pub", 0o644)
    (ssh_dir / "sshd_config").write_text(f"""# generated by build_golden_image.py
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
StrictModes no
PrintMotd no
X11Forwarding no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/ssh/sftp-server
PidFile /run/sshd.pid
""")
    os.chmod(ssh_dir / "sshd_config", 0o644)
    sshd = root / "usr" / "sbin" / "sshd"
    if not sshd.exists():
        raise SystemExit("openssh did not install sshd where we expected")
    # sshd's privilege-separation directory must exist and be root-owned
    empty = root / "var" / "empty"
    empty.mkdir(parents=True, exist_ok=True)
    os.chown(empty, 0, 0)
    os.chmod(empty, 0o755)
    run_dir = root / "var" / "run"
    if not run_dir.exists():
        run_dir.symlink_to("/run")
    root_ssh = root / "root" / ".ssh"
    root_ssh.mkdir(parents=True, exist_ok=True)
    shutil.copy(str(access) + ".pub", root_ssh / "authorized_keys")
    os.chmod(root_ssh / "authorized_keys", 0o600)
    os.chmod(root_ssh, 0o700)


def write_system(root: Path) -> None:
    (root / "etc" / "hostname").write_text("golden\n")
    # The shadow field must not start with "!" : OpenSSH treats that as a locked
    # account and refuses publickey logins when UsePAM is unavailable. "*" keeps
    # password auth impossible while letting the baked key in.
    shadow = root / "etc" / "shadow"
    lines = []
    for line in shadow.read_text().splitlines() if shadow.exists() else []:
        if line.startswith("root:"):
            parts = line.split(":")
            parts[1] = "*"
            parts[2] = ""
            line = ":".join(parts)
        lines.append(line)
    if not any(l.startswith("root:") for l in lines):
        lines.insert(0, "root:*::0:::::")
    shadow.write_text("\n".join(lines) + "\n")
    (root / "etc" / "motd").write_text("golden triage image\n")
    (root / "etc" / "fstab").write_text("# no persistent mounts by design\n")


INIT_SCRIPT = """#!/bin/sh
# init for the golden triage image: no OpenRC, no services beyond sshd.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# when a second serial port is wired to a log file by libvirt, send everything
# there: that gives an unprivileged, complete boot log
[ -c /dev/ttyS1 ] && exec >/dev/ttyS1 2>&1

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /run 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null

# devpts is what sshd needs to hand out an interactive terminal; without it
# every interactive login fails with "PTY allocation request failed"
mkdir -p /dev/pts 2>/dev/null
if mount -t devpts devpts /dev/pts 2>/dev/null; then
    echo "    devpts mounted, interactive terminals available"
else
    echo "    DEVPTS_FAILED - interactive ssh will get no terminal"
fi

for d in /sys/block/*; do
    [ -d "$d" ] || continue
    n=$(basename "$d")
    [ -e "/dev/$n" ] && continue
    [ -r "$d/dev" ] || continue
    mknod "/dev/$n" b "$(cut -d: -f1 "$d/dev")" "$(cut -d: -f2 "$d/dev")" 2>/dev/null
done

echo "golden: loading analysis modules"
for ko in $(ls /lib/modules/*.ko.xz 2>/dev/null | sort); do
    [ -e "$ko" ] || continue
    if insmod "$ko" 2>/dev/null; then
        echo "    $(basename "$ko")"
    else
        echo "    $(basename "$ko") FAILED"
    fi
done

# keep hotplugged disks visible as device nodes
(
    while true; do
        for d in /sys/block/*; do
            [ -d "$d" ] || continue
            n=$(basename "$d")
            [ -e "/dev/$n" ] && continue
            [ -r "$d/dev" ] || continue
            mknod "/dev/$n" b "$(cut -d: -f1 "$d/dev")" "$(cut -d: -f2 "$d/dev")" 2>/dev/null
        done
        sleep 2
    done
) &

echo "golden: network"
ifconfig lo up 2>/dev/null
ifconfig eth0 __IP__ netmask __NETMASK__ up 2>/dev/null
# deliberately NO default route: ifconfig installs the connected route for
# __SUBNET__ and nothing else, so the guest can only reach the host bridge

# the tripwire: if any route leaves the dedicated subnet, refuse to run.
# only numeric destination lines count, so the header cannot trip it
UNSAFE=0
grep -q "triage_unsafe=1" /proc/cmdline && UNSAFE=1
ROUTES=$(route -n 2>/dev/null | awk '$1 ~ /^[0-9]/ {print}')
echo "$ROUTES" | sed 's/^/    /'
OFFSUB=$(echo "$ROUTES" | grep -v "^__PREFIX__" | grep -v "^127[.]")
if [ -n "$OFFSUB" ]; then
    echo "    ROUTE_ESCAPE - a route leaves __SUBNET__: $OFFSUB"
    if [ "$UNSAFE" = "0" ]; then
        echo "    refusing to run; power off"
        sleep 2
        poweroff -f
        while true; do sleep 60; done
    fi
else
    echo "    no route off __SUBNET__"
fi
ifconfig eth0 2>/dev/null | sed 's/^/    /'

# the guest is a hostile-lander: no route out, no route to the host except ssh
echo "golden: network isolation"
ISOLATION_OK=0
if nft -f /etc/nftables.conf 2>/dev/null && nft list ruleset 2>/dev/null | grep -q "policy drop"; then
    echo "    ISOLATION_OK - input/output policy drop, ssh from __PST__ only"
    ISOLATION_OK=1
else
    echo "    ISOLATION_FAILED - the nftables ruleset did not load"
    nft list ruleset 2>&1 | head -5 | sed 's/^/      /'
    if [ "$UNSAFE" = "0" ]; then
        echo "    refusing to run unprotected; power off"
        echo "    (boot with triage_unsafe=1 on the kernel command line to override)"
        sleep 2
        poweroff -f
        while true; do sleep 60; done
    fi
fi

echo "golden: starting sshd"
ssh-keygen -A >/dev/null 2>&1
# -e sends the sshd log to stderr, which init already points at the console
/usr/sbin/sshd -D -e 2>&1 &
sleep 1
if pgrep sshd >/dev/null 2>&1; then
    echo "    sshd up on port 22"
else
    echo "    SSH_START_FAILED"
fi
sleep 2
echo "    authorized_keys: $(wc -l < /root/.ssh/authorized_keys 2>/dev/null || echo MISSING) line(s)"
echo "    isolation: $ISOLATION_OK"

# a serial console for debugging; PID 1 must never exit
setsid /bin/sh -c 'exec /bin/sh </dev/console >/dev/console 2>&1' &

echo "golden: ready"
while true; do sleep 3600; done
"""

BOOT_INIT = """#!/bin/sh
# boot initramfs: load just enough to mount and switch into the golden root.
export PATH=/bin:/sbin
/bin/busybox --install -s /bin 2>/dev/null

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null

for ko in /modules/*.ko.xz; do
    [ -e "$ko" ] || continue
    insmod "$ko" 2>/dev/null && echo "initramfs: loaded $(basename "$ko")"
done

echo "initramfs: waiting for the root disk"
n=0
while [ ! -b /dev/vda ] && [ $n -lt 50 ]; do
    sleep 1
    n=$((n + 1))
done
[ -b /dev/vda ] || { echo "initramfs: no root disk"; exec sh; }

mkdir -p /newroot
mount -t ext4 -o rw /dev/vda /newroot || {
    echo "initramfs: root mount failed"
    echo "initramfs: dmesg follows"
    dmesg | tail -20
    exec sh
}
mkdir -p /newroot/{proc,sys,dev}
mount -t proc proc /newroot/proc 2>/dev/null
mount -t sysfs sysfs /newroot/sys 2>/dev/null
mount -t devtmpfs devtmpfs /newroot/dev 2>/dev/null
cd /newroot
echo "initramfs: switching to the golden root"
exec switch_root /newroot /sbin/triage-init
"""


NFT_RULESET = """#!/usr/sbin/nft -f
# Golden triage image: the only path in is the host's ssh on the dedicated
# bridge. Everything else is dropped, so the guest cannot reach the host's
# services and cannot reach any other network - a hostile disk cannot phone
# home or attack us. The guest also has no default route at all.
table inet triage {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept comment "loopback"
        ip saddr __PST__ tcp dport 22 accept comment "ssh from the host bridge"
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy drop;
        oif lo accept comment "loopback"
        oifname "eth0" ip daddr __PST__ tcp sport 22 accept comment "replies to the host bridge only"
    }
}
"""

def write_firewall(root: Path) -> None:
    target = root / "etc" / "nftables.conf"
    target.write_text(NFT_RULESET.replace("__PST__", HOST_BRIDGE))
    os.chmod(target, 0o644)


def write_init(root: Path) -> None:
    script = (INIT_SCRIPT
              .replace("__SUBNET__", SUBNET)
              .replace("__PREFIX__", SUBNET_PREFIX)
              .replace("__IP__", GUEST_IP)
              .replace("__NETMASK__", GUEST_NETMASK)
              .replace("__PST__", HOST_BRIDGE))
    path = root / "sbin" / "triage-init"
    path.write_text(script)
    os.chmod(path, 0o755)


def install_collector(root: Path) -> None:
    """The guest-side collector, so the VM can read a disk without host tools."""
    source = HERE / "guest_collector.py"
    if not source.exists():
        log(f"    WARNING: {source} is missing, the guest will have no collector")
        return
    target = root / "usr" / "local" / "bin" / "guest_collector.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(source), str(target))
    os.chmod(target, 0o755)
    log("    guest_collector.py installed")


def build_image(root: Path, output: Path, size_mb: int) -> None:
    raw = HERE / "build" / "golden.raw"
    if raw.exists():
        raw.unlink()
    log(f"building the ext4 root filesystem ({size_mb} MiB)")
    run(["mke2fs", "-q", "-t", "ext4", "-L", "golden",
         "-d", str(root), "-b", "4096", str(raw), f"{size_mb}M"])
    output.unlink(missing_ok=True)
    run(["qemu-img", "convert", "-p", "-O", "qcow2", str(raw), str(output)])
    raw.unlink(missing_ok=True)


def build_boot_initramfs(output: Path) -> None:
    stage = HERE / "build" / "bootinit"
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "modules").mkdir(parents=True)
    (stage / "bin").mkdir()
    shutil.copy(shutil.which("busybox"), stage / "bin" / "busybox")
    os.chmod(stage / "bin" / "busybox", 0o755)
    # /init has a #!/bin/sh shebang, so sh must exist before anything runs
    for applet in ("sh", "ash", "mount", "umount", "mkdir", "insmod", "modprobe",
                   "sleep", "echo", "switch_root", "cut", "basename", "cat",
                   "ls", "poweroff", "test", "dmesg", "ps"):
        link = stage / "bin" / applet
        if not link.exists():
            link.symlink_to("busybox")
    for library in ("/lib64/ld-linux-x86-64.so.2",):
        if Path(library).exists():
            (stage / "lib64").mkdir(exist_ok=True)
            shutil.copy(library, stage / "lib64" / Path(library).name)
    result = subprocess.run(["ldd", shutil.which("busybox")],
                            capture_output=True, text=True)
    for line in result.stdout.splitlines():
        for token in line.split():
            if token.startswith("/") and Path(token).exists():
                dest = stage / token.lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(token, dest)
    (stage / "init").write_text(BOOT_INIT)
    os.chmod(stage / "init", 0o755)
    got = copy_modules(stage / "modules", BOOT_MODULES)
    log(f"    boot modules: {', '.join(got)}")
    output.unlink(missing_ok=True)
    with output.open("wb") as out:
        cpio = subprocess.Popen(
            ["cpio", "--null", "-o", "-H", "newc", "--quiet"],
            cwd=stage, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        find = subprocess.Popen(["find", ".", "-print0"], cwd=stage, stdout=cpio.stdin)
        cpio.stdin.close()
        find.wait()
        gz = subprocess.Popen(["gzip", "-1"], stdin=cpio.stdout, stdout=out)
        cpio.stdout.close()
        gz.communicate()
        if cpio.wait() != 0:
            raise SystemExit("cpio failed while packing the initramfs")
    log(f"    {output.name}: {output.stat().st_size} bytes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true",
                        help="keep the intermediate build directory")
    parser.add_argument("--skip-modules", action="store_true",
                        help="do not copy kernel modules (faster, less useful)")
    args = parser.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)
    if ROOTFS.exists():
        shutil.rmtree(ROOTFS)
    ROOTFS.mkdir(parents=True)

    log("resolving the package set")
    index, provides = apk_indexes()
    base_system()
    packages = resolve(index, provides, PACKAGES, ROOTFS)
    log(f"    {len(packages)} packages to install")
    install(packages, ROOTFS)
    missing = audit_libraries(ROOTFS)
    if missing:
        raise SystemExit(
            "the image would not boot: unresolved libraries\n  " +
            "\n  ".join(missing) +
            "\n\nThis is a dependency-resolution bug in the builder.")

    if not args.skip_modules:
        log("collecting kernel modules")
        install_modules(ROOTFS, ANALYSIS_MODULES, "analysis filesystems")
    log("generating keys and ssh config")
    write_ssh_keys(ROOTFS)
    write_system(ROOTFS)
    write_firewall(ROOTFS)
    write_init(ROOTFS)
    install_collector(ROOTFS)

    log("packing the golden image")
    build_image(ROOTFS, HERE / "golden.qcow2", IMAGE_SIZE_MB)
    build_boot_initramfs(HERE / "boot-initramfs.cpio.gz")

    if not args.keep:
        shutil.rmtree(ROOTFS, ignore_errors=True)
    log("done: golden.qcow2, boot-initramfs.cpio.gz, keys/golden_id_ed25519")
    return 0


if __name__ == "__main__":
    sys.exit(main())