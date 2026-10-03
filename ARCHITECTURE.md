# Suspicious storage triage: host → disposable VM → file list + hashes

Baseline architecture for the project in `/home/armybit/unsecuredev`.
Status: **v0.3** — 2026-10-02. The ssh gate is **proven** and the guest is network-isolated.
Machine state at time of writing: no domains defined, no VM running, no disk attached.

---

## 1. Goal

Take a suspicious storage disk, analyse it without ever letting the **host** see its
filesystem, and get back a **file list, hidden-file findings and file hashes**.

```
USB inserted
  │
  ├─ host udev: automount disabled ─────► host sees /dev/sdb as a block device
  │                                       and NEVER mounts it
  │
  ├─ host app sees the add event
  │
  ├─ clone the golden image: case-N.qcow2 (backing file = golden.qcow2)
  ├─ boot the case VM with NO disk attached
  ├─ ssh gate: log in, require an answer from the guest
  │
  ├─ attach /dev/sdb read-only as vdb
  │
  ├─ guest mounts it, then collects: file list + hidden files + sha256 per file
  │
  └─ host pulls the report over ssh ──────► host app stores it, never opens payloads
```

The guest is disposable. The original disk is never written to and never mounted
by the host.

## 2. Safety invariants

The whole design rests on these. Any change that breaks one is a bug, not a feature.

| # | Invariant | Enforcement |
|---|-----------|-------------|
| T1 | The host never mounts the analysis disk. | udev rule sets `ID_AUTOMOUNT=0`, `UDISKS_IGNORE=1` **by default** for analysis-class devices. |
| T2 | The disk is attached to the VM read-only. | `attach_disk(readonly=True)`; guest mounts `-o ro,noexec,nosuid,nodev`. |
| T3 | The VM boots before any disk is attached, and ssh must answer before attachment. | `launch_with_handoff()` — `ssh_check()` is a hard gate. |
| T4 | Only results cross the boundary, never untrusted payloads. | Guest hashes; host receives lists/hashes only. |
| T5 | The host OS root disk is never attachable. | **Gap (open):** `boot-tiny-linux.sh` refuses it; `libvirt_vm.py` does not yet. |
| T6 | The guest cannot reach the host or the network. | Two layers: passt forward bound to `127.0.0.1`, **and** an in-guest nftables ruleset with `policy drop` on input/output/forward. The ruleset loads before `sshd` and the guest **powers off if it fails to load** (`triage_unsafe=1` on the kernel command line overrides for debugging). |
| T7 | Every case is isolated and disposable. | Per-case qcow2 overlay over an immutable golden image. |
| T8 | Untrusted strings from the disk never reach a shell or a path unchecked. | See §7 report contract. |
| T9 | No analysis disk is attached until the ssh gate passes. | `launch_with_handoff()` calls `ssh_check()` first; see §5. |
| T10 | The guest boots from a real distro, not a hand-rolled initramfs. | Alpine 3.24.2 golden image; the BusyBox path is legacy. |
| T11 | Only devices plugged in **after** the app starts are considered. | The watcher reacts to `add` events only. There is no startup enumeration, so anything already attached when the app launches is never picked up and never scanned. |
| T12 | A disk is never attached writable. | `attach_disk()` refuses `readonly=False` outright; `virsh` is only reached with `<readonly/>` present. |
| T13 | Nothing from the analysis disk is ever executed. | Guest mounts are `ro,noexec,nosuid,nodev,noatime` inside a private mount namespace; the guest has no udev, udisks or desktop to trigger anything; we never `chroot` or `exec` from the disk. |

## 3. Host app components

| File | Role |
|------|------|
| `udev_monitor.py` | Whole-disk `add`/`remove` events, three backends (netlink, pyudev, sysfs polling). |
| `udev_control.py` | Privileged udev/udisks operations; single exec primitive `run_raw(argv, elevate, stdin)`; automount rule generator. |
| `libvirt_vm.py` | Domain layer: XML, lifecycle, golden-image cloning, asset staging, polkit, **ssh gate**, hotplug, console/VNC, and the domain **lister**. |
| `hook.py` | Generic on-connect runner (kept from v0.1; the triage flow now lives in `libvirt_vm.py`). |
| `udev_gui.py` | Tk front end: events, udev control, On connect, Virtual machines (incl. the live-case lister panel). |
| **planned** `triage.py` | Orchestrator: event → case → clone → boot → gate → attach → collect → pull report → cleanup. |
| **planned** `collector.sh` / `collector.py` | The in-guest job (§6). |

## 4. The live-machine lister

The host app already has the primitive: `LibvirtVms.domains(prefix="tiny-")` runs
`virsh list --all` and returns name/state/id, rendered by the "Virtual machines" tab.
For triage it needs three additions:

1. **Case identity** — encode it in the domain name: `tiny-sdb` for the device, plus a
   per-case index so repeated analyses of the same disk are distinguishable:
   `tiny-sdb-3`. Domain names are validated against a strict regex before any virsh call.
2. **State → meaning** — `running` means "case in progress"; `shut off` with an existing
   definition means "case finished or aborted, cleanup pending". The lister should show
   name, state, ssh port and whether a report has been collected.
3. **Port per case** — one loopback ssh port each (`2222 + case_index`), recorded in the
   domain description so the lister can map domain → port without guessing. Concurrent
   cases then work without colliding.

## 5. Golden image

The image is deliberately minimal, because it is a throwaway machine whose only jobs
are: ssh in, mount one disk read-only, walk it, hash it, write a report.

- **Recommended base: Alpine Linux** (musl). Smallest, boots in ~3 s, `openssh`,
  `coreutils`/`findutils` and filesystem tooling are a handful of packages.
- Alternative if glibc-dependent tooling is ever needed: Debian minimal (netinst +
  preseed). Larger, slower, but a more familiar base.
- Never rebuilt per case: built **once**, frozen, copied to `golden.qcow2`, made
  read-only. Cases are overlays with that file as their backing file.

Required in the image:

| Need | Package / content |
|------|-------------------|
| ssh | `openssh`, root key-only login, host key baked in, access key authorised at build time |
| hashing | `coreutils` (`sha256sum`) or busybox equivalent |
| walking | `findutils`, `coreutils` |
| filesystem readers | `ntfs-3g` (NTFS), `exfatprogs` (exFAT), `e2fsprogs` (ext2/3/4), `xfsprogs`, `btrfs-progs` |
| discovery | `blkid`, `lsblk`, `blkid`-based auto-mount of the read-only disk |
| the job | `collector.sh` (or `.py`) — §6 |
| reporting | write to a fixed path in the guest; the host pulls it over ssh |

Boot settings that already work: `console=tty0 console=ttyS0,115200`,
`on_poweroff=destroy`, `on_reboot=restart`, machine `pc` (i440fx).

## 6. In-guest job contract

The guest script is the only thing that touches the hostile filesystem. Interface:

- **Input**: the block device to analyse (`/dev/vdb`), or "auto-detect".
- **Mount**: read-only and hardened —
  `mount -o ro,noexec,nosuid,nodev,noatime /dev/vdb /mnt/case`
- **Work**:
  1. filesystem type via `blkid`, record it;
  2. recursive file list: path, size, type, mode, mtime, links;
  3. hidden files: names beginning with `.`, **plus** filesystem-level hidden/system
     attributes where the driver exposes them (NTFS/exFAT) — a dotfile check alone is
     not "hidden" on those filesystems, and this detail is unresolved (see §9);
  4. `sha256` per file, streaming, never loading a file into memory;
  5. optional size/extension filters to keep the report manageable;
  6. write the report to a fixed path, then print a completion marker on stdout.
- **Output**: a report file in the guest; the host pulls it over ssh (§7). The guest
  has no route out and cannot originate traffic at all (§2 T6), so the ssh reply path
  is the only thing that can cross the NIC.
- **Failure policy**: never abort the whole run on one bad file — log it, continue, and
  record the failure in the report. A crafted image will contain things that break
  tools; partial results beat none.

The guest never initiates network connections. Pull-only keeps the guest's attack
surface and credentials to a minimum.

## 7. Report contract

Report is **JSON Lines** — one record per event, streamable, gzipped, resilient to a
truncated pull.

```
{"t":"meta","case":"tiny-sdb-3","dev":"/dev/vdb","fs":"ntfs","size":31297526304,
 "collected":"2026-10-02T21:40:11Z","collector":"1.0"}
{"t":"file","path":"/photos/img_001.jpg","size":2841922,"sha256":"…",
 "hidden":false,"symlink":false}
{"t":"hidden","path":"/System Volume Information/…","reason":"filesystem-attribute"}
{"t":"error","path":"/weird/\x00name","op":"stat","message":"…"}
{"t":"done","files":48213,"bytes":30014598123,"errors":3}
```

**Everything in this file is attacker-influenced** (paths, sizes, counts, error text):
- write records with a JSON library, never string concatenation into a shell;
- never let a reported `path` be used to build a filesystem path on the host — store it
  as data. If artefacts must be written to disk, sanitise separators, reject `..`,
  cap length, strip control characters;
- treat reported sizes as claims: cap them so a crafted sparse-image header cannot make
  the host allocate;
- count fields are attacker-influenced too — sanity-cap them.

Transport: host pulls with `scp`/`sftp` over the same ssh channel used for the gate,
or streams straight into the parser. Prefer streaming + `gzip`: a 30 GB disk yields
millions of lines.

## 8. Per-case lifecycle

| Phase | Action | On failure |
|-------|--------|-----------|
| 1 | udev `add` for a whole disk; automount disabled | ignore non-block devices |
| 2 | create `case-N.qcow2` with `golden.qcow2` as backing file | delete overlay, log |
| 3 | define + start domain, **no disk attached** | discard overlay, log |
| 4 | **ssh gate** on the case port | destroy VM, delete overlay, log — disk untouched |
| 5 | attach `/dev/sdb` read-only as `vdb` | destroy VM, delete overlay, log |
| 6 | guest mounts and runs the collector | mark report incomplete |
| 7 | host pulls the report | keep partial report, mark incomplete |
| 8 | detach disk, destroy VM, delete overlay | retry cleanup; never leave a disk attached to a shut-off domain |

Cleanup is mandatory in every phase: a leftover domain holding a disk pointer is the
worst failure mode of this design.

## 9. Open issues

| Item | Detail |
|------|--------|
| ~~SSH gate unproven~~ | **Resolved.** Disk-less Alpine VM boots, `sshd` answers, `ssh -i keys/golden_id_ed25519 -p 2222 root@127.0.0.1 'echo TINY_SSH_OK'` succeeds. Root cause of the original failure was passt's network being `192.168.1.0/24`, not slirp's `10.0.2.0/24` — see §10. |
| ~~Guest reachable from the host network~~ | **Resolved.** Verified with `/tmp/opencode/verify_isolation.sh`: the guest cannot ping the gateway, cannot reach a decoy web server bound on the host at `192.168.1.1:9999`, and cannot reach `1.1.1.1` by ping or HTTP, while host→guest ssh still works. Residual risk: a guest kernel compromise can lift its own rules; host-side tap filtering would be the stronger layer if that threat matters. |
| ~~Root-disk guard missing in `libvirt_vm.py`~~ | **Resolved.** `host_root_devices()` walks sysfs `slaves/` down and the containing disk up, so a LUKS/btrfs root resolves to `/dev/mapper/luks-…`, `/dev/sda2` and `/dev/sda`; sibling partitions of that disk (EFI, LUKS swap) are refused too, because they are the same evidence. `refuse_host_disk()` is called from both `attach_disk()` and `define_and_start()` *before* `virsh` runs. Verified against this machine and against fake LVM-on-RAID trees in `tests/test_triage_safety.py`. |
| ~~`attach_disk()` readonly inverted~~ | **Resolved.** `readonly=True` used to emit no `<readonly/>`. Writable attachment is now refused outright (T12), so the XML can only ever carry `<readonly/>`. |
| ~~ssh probes wrapped in pkexec~~ | **Resolved.** `ssh_check()` and `guest_has_disk()` pass `elevate=False`. |
| Hidden-file semantics | "Hidden" on NTFS/exFAT is a filesystem attribute, not a leading dot. Need to confirm how the chosen driver exposes it (`ntfs-3g`/`exfatprogs` tools) before the collector can claim to find hidden files. |
| Port-per-case | Not implemented; `ssh_port` is fixed at 2222. |
| Overlay cloning | Not implemented; needs `qemu-img create -f qcow2 -b golden.qcow2 -F qcow2 case-N.qcow2`. |
| Orchestrator | `triage.py` does not exist yet; the GUI has the primitives. |
| Collector | Does not exist yet. |
| Automount rule not applied by default | Rule generator exists; wiring it into the triage path as a default is pending. |
| Evidence handling | Not decided: whether to `dd` the disk to an image first, or attach the original read-only. Image-first is safer and repeatable; attaching the original is faster and preserves nothing if something goes wrong. |
| Golden image provenance | Not decided: pinned digest vs rebuild-and-verify. |

## 10. Failure modes already hit (keep these in mind)

| Symptom | Cause | Fix in place |
|---------|-------|--------------|
| `domain 'x' already exists with uuid …` | `virsh define` refuses a new UUID for an existing name | `replace_domain()` destroys + undefines first |
| `error reading initrd … Permission denied` | QEMU runs as `libvirt-qemu`, `$HOME` is `0700` | stage initramfs to `/var/tmp/storage-watcher/` (dirs `0755`, file `0644`) |
| `access denied by policy` | no polkit rule | "Fix libvirt access" installs `/etc/polkit-1/rules.d/49-libvirt-user.rules` (manage, monitor, console) |
| `portForward` "unsupported configuration" | needs the passt backend | `<backend type='passt'/>` in the interface |
| port-forward RNG rejected | this libvirt wants `to=`, not `toPort=` | `<range start='2222' to='22'/>` |
| passt `logFile` denied | passt runs as the libvirt user, not as you | leave `logFile` unset; use the journal |
| `virsh vncdisplay` showed `:0` as a port | display number ≠ port | convert: port = 5900 + display |
| `kex_exchange_identification: Connection timed out` | passt defaults to `192.168.1.0/24` (guest `.2`, gateway `.1`); the XML hardcoded slirp's `10.0.2.15`, which is not routed | guest IP comes from `PASST_GATEWAY`/`GUEST_IP` and the domain XML sets `<ip address='192.168.1.2' family='ipv4' prefix='24'/>` |
| `Failed to execute /init (error -2)` | initramfs had no `/bin/sh` | applets symlinked and the two interpreters required at build time |
| `ext4: Unknown symbol`, `virtio_net: Unknown symbol net_failover` | kernel modules loaded in guessed order | module list derived from `modprobe --show-depends` and sorted topologically |
| `Error loading module ... not found` / broken binaries | APKINDEX `p:` capability deps were skipped, so `so:` requirements were never installed | deps resolve `so:` → package; `readelf` audit fails the build if any shared library is unresolved |
| `Unsupported option UsePAM` | Alpine's openssh is not PAM-enabled | `UsePAM` removed |
| `sshd: /var/empty: No such file or directory` | Alpine's `openssh` does not ship it | create root-owned `0700` `/var/empty` |
| `Permission denied (publickey)` on a correct key | root's shadow field was `!` = locked; OpenSSH refuses pubkey for locked accounts when PAM is unavailable | `root:*` — key-only, password impossible |
| `nft ... ct state established: No such file or directory` | the `ct` expression needs `nft_ct`, which was not loaded in the guest | ruleset avoids conntrack entirely: output allows only `tcp sport 22` to the gateway, so the guest can answer ssh and originate nothing |
| `virsh console` denied after granting `manage` | rule lacked the console action | added `org.libvirt.unix.console` |

## 11. Runbook

```sh
cd /home/armybit/unsecuredev

python3 udev_gui.py                     # the app
virsh -c qemu:///system list --all      # live cases
virsh -c qemu:///system console tiny-sdb-3   # detach Ctrl-]
ssh -i tiny-linux/keys/host_id_ed25519 -p 2222 root@127.0.0.1

# nuke everything (disk pointers and all)
for d in $(virsh -c qemu:///system list --all --name); do
    virsh -c qemu:///system destroy "$d" 2>/dev/null
    virsh -c qemu:///system undefine "$d"
done

python3 -m py_compile udev_gui.py libvirt_vm.py udev_control.py hook.py
for t in storage storage_gui full hook automount libvirt; do
    python3 /tmp/opencode/test_$t.py || echo "FAIL: $t"
done
```

Logs: `~/.local/state/storage-watcher/udev_gui.log` (rotating), fallback
`/tmp/opencode/udev_gui.log`. "Save diagnostics…" writes `virsh` state, dumpxml,
`lsblk`, mounts and udev data to `/tmp/opencode/diagnostics-*.txt`.

## 12. Next steps, in order

1. ~~Prove the ssh gate~~ — done (§9).
2. ~~Build the minimal golden image~~ — done: `tiny-linux/build_golden_image.py` → `golden.qcow2` (23 MB, 2 GiB sparse ext4) + `boot-initramfs.cpio.gz` (2.3 MB).
3. ~~Network isolation~~ — done (§2 T6).
4. ~~Add the root-disk guard~~ — done, T5 closed (§9).
5. ~~Fix the `attach_disk()` readonly bug~~ — done, writable attach refused (T12).
6. ~~Fix `run_raw()` elevation~~ — done.
7. **Write the collector** into the golden image and verify its report contract against a deliberately dirty test image. **Next.**
8. **Overlay cloning + port-per-case**, then wire the lister to case identity.
9. **Automount-by-default** for analysis-class devices.
10. Decide evidence handling (`dd` first vs attach original).

## 13. File inventory

```
ARCHITECTURE.md          this document
udev_gui.py              Tk front end (events, udev control, On connect, Virtual machines)
udev_monitor.py          udev event backends
udev_control.py          privileged udev/udisks ops, automount rule generator
hook.py                  generic on-connect runner
libvirt_vm.py            libvirt/QEMU layer: XML, lifecycle, ssh gate, hotplug, lister
boot-tiny-linux.sh       standalone QEMU launcher with root-disk refusal (legacy)
tiny-linux/              golden image build
                         build_golden_image.py  Alpine 3.24.2 builder (packages,
                             module deps, sshd, nftables isolation, initramfs)
                         golden.qcow2          23 MB golden disk, 2 GiB sparse ext4
                         boot-initramfs.cpio.gz  2.3 MB boot + switch_root
                         keys/golden_id_ed25519  host key pair used by the ssh gate
                         keys/golden_host_ed25519_key  guest host key
tiny-linux/build-tiny-linux.sh   legacy busybox builder, bare-QEMU path
tests/test_triage_safety.py  19 tests, no root and no disk needed: the root-disk
                         guard against fake sysfs trees and against this real
                         machine, read-only XML, writable refusal, no pkexec on
                         the ssh path, and the guest image policy
```

The legacy `tiny-linux/` BusyBox image is superseded by the golden image for triage;
it stays only because `boot-tiny-linux.sh` uses it and because it is a useful
low-level debugging tool.