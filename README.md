# Storage Triage

USB storage forensics without ever mounting evidence on the host. Plug a drive
in and the app walks itself through the investigation: it boots a disposable
VM, hands the whole disk to the guest read-only, hashes every file inside the
guest, checks the hashes against VirusTotal from the host, and presents a
report with a PDF export. Unplug the drive at any point and everything resets.

## How it works

1. **Awaiting device** - a listener watches for block devices that appear after
   startup. Anything already plugged in is ignored on purpose.
2. **Device intake** - the subject disk is shown, the VM boots itself, and the
   disk is attached to the guest as read-only `/dev/vdb`. The host never
   mounts it.
3. **Forensic analysis** - a collector inside the guest walks the filesystems
   and computes SHA-256 (files over 256 MB are recorded unhashed). Each hash
   is looked up on VirusTotal from the host; file contents never leave the
   guest.
4. **Report** - verdict, file counts, flagged files with engine names, the full
   file table, plus **Stop VM** and **Export report (PDF)**.

Progress streams to the browser over a WebSocket; the UI falls back to polling
if the socket drops.

## Requirements

- Linux host with KVM/libvirt, `virsh`, `python3`
- Guest build tools: `debootstrap` (or matching distro tools), `mtools`,
  `dosfstools`, `squashfs-tools`, `ssh-keygen`, `qemu-img`, `qemu-nbd`
- Python packages: `reportlab` (PDF export)
- A VirusTotal API key (free tier works; only hashes are ever sent)

## Quick start

```bash
# 1. put the VirusTotal key where the app reads it (0600, never in the repo)
mkdir -p ~/.config/triage && printf 'YOUR_KEY' > ~/.config/triage/virustotal
chmod 600 ~/.config/triage/virustotal

# 2. build the disposable guest (generates golden.qcow2, initramfs, ssh keys)
sudo python3 tiny-linux/build_golden_image.py

# 3. run the app (needs libvirt access for VM control)
python3 web_server.py
# open http://127.0.0.1:8765 and plug a USB drive in
```

Stopping the app destroys the VM. Unplugging the drive mid-flow does the same
and returns the UI to the start.

## Tests

```bash
python3 -m unittest discover -s tests
```

All hardware, network, and VirusTotal access is stubbed in tests; nothing
leaves the machine.

## Layout

| path | what |
|---|---|
| `web_server.py` | HTTP + WebSocket UI server, scan worker, PDF report builder |
| `triage_state.py` | state machine (idle → device → attached → scanning → results) |
| `device_listener.py` | udev/block polling, arrival + removal callbacks |
| `triage_vm.py`, `libvirt_vm.py` | disposable guest lifecycle, read-only attach |
| `tiny-linux/guest_collector.py` | in-guest filesystem walk + hashing (JSONL report) |
| `tiny-linux/build_golden_image.py` | reproducible guest image build |
| `virustotal.py` | host-side hash-only VirusTotal client (cache, throttle, quota stop) |
| `live_feed.py` | minimal RFC 6455 broadcast feed |
| `webui/` | full-screen stepper UI (no build step, no dependencies) |
| `tests/` | unit + endpoint tests |

## Security notes

- Evidence is never mounted, or even touched, on the host.
- VirusTotal receives SHA-256 hashes only - never filenames with content,
  never file bytes.
- The browser session token gates actions and the WebSocket; the server binds
  to localhost only.
- The guest shares the host kernel, so a malicious filesystem is still
  host-kernel attack surface. Treat this as triage, not a sandbox proof.
