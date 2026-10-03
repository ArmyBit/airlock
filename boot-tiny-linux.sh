#!/bin/sh
# Boots the tiny Linux and attaches the device that triggered the hook.
#
# Reads the hook environment (DEV_NODE, DEV_MODEL, ...) exported by the watcher,
# otherwise falls back to $1.  Everything runs as your own user; if the device
# is not readable (usually needs the disk group or root) the script says so
# instead of guessing.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
INITRD="$HERE/tiny-linux/initramfs.cpio.gz"
KERNEL=${TINY_KERNEL:-}
MONITOR=${TINY_MONITOR:-/tmp/tiny-linux.mon}
MEM=${TINY_MEM:-256}
READONLY=${TINY_READONLY:-on}
WRITABLE=${TINY_WRITABLE:-0}
TIMEOUT=${TINY_TIMEOUT:-120}

DEVICE=${DEV_NODE:-${1:-}}
LABEL=${DEV_MODEL:-${DEVICE:-no device}}

for bin in qemu-system-x86_64; do
    command -v "$bin" >/dev/null 2>&1 || { echo "$bin is required (apt install qemu-system-x86)" >&2; exit 1; }
done
[ -f "$INITRD" ] || { echo "missing $INITRD - run tiny-linux/build-tiny-linux.sh" >&2; exit 1; }
[ -n "$DEVICE" ] || { echo "no device: set DEV_NODE or pass a path" >&2; exit 1; }
[ -b "$DEVICE" ] || [ -f "$DEVICE" ] || { echo "not a device or image: $DEVICE" >&2; exit 1; }

refuse_root_disk() {
    root_src=$(findmnt -n -o SOURCE / 2>/dev/null || true)
    root_src=${root_src%%\[*}
    root_mm=$(findmnt -n -o MAJ:MIN / 2>/dev/null | tr -d ' ' || true)
    candidate=$(basename "$(readlink -f "$DEVICE")")
    dev_majmin=$(lsblk -ndo MAJ:MIN "$DEVICE" 2>/dev/null | head -n 1 | tr -d ' ' || true)
    ancestor_mm=$(lsblk -nso NAME,MAJ:MIN "$root_src" 2>/dev/null || true)
    [ -n "$ancestor_mm" ] || ancestor_mm=$(lsblk -nso NAME,MAJ:MIN "$root_mm" 2>/dev/null || true)

    while read -r name mm; do
        name=${name#└─}
        name=${name#─}
        [ -z "$name" ] && continue
        if [ "$name" = "$candidate" ] || [ "$mm" = "$dev_majmin" ]; then
            echo "REFUSING: $DEVICE holds the running root filesystem ($root_src)." >&2
            echo "          backing chain: $(echo "$ancestor_mm" | tr -s ' ' | tr '\n' ' ')" >&2
            echo "          Booting a VM with your OS disk attached is not a good idea." >&2
            exit 1
        fi
    done <<EOF
$ancestor_mm
EOF
}
refuse_root_disk

if [ -z "$KERNEL" ]; then
    KVER=$(cat "$HERE/tiny-linux/kver" 2>/dev/null || uname -r)
    if [ -f "/boot/vmlinuz-$KVER" ]; then
        KERNEL="/boot/vmlinuz-$KVER"
    else
        KERNEL=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sort -V | tail -n 1 || true)
    fi
fi
[ -n "$KERNEL" ] && [ -f "$KERNEL" ] || { echo "no kernel found; set TINY_KERNEL=/boot/vmlinuz-..." >&2; exit 1; }

echo "booting tiny linux for $LABEL ($DEVICE)"
echo "  kernel=$KERNEL"
echo "  monitor=$MONITOR (quit to exit)"
echo

if [ ! -r "$DEVICE" ]; then
    echo "WARNING: $DEVICE is not readable by $(id -un)." >&2
    echo "         For raw passthrough use a udev rule that sets MODE=0666 on that node," >&2
    echo "         add yourself to the 'disk' group, or run: sudo -E $0 $DEVICE" >&2
fi

if [ "${TINY_WINDOW:-0}" = "1" ]; then
    APPEND="console=tty0 console=ttyS0 quiet panic=-1"
    SCREEN="-display gtk"
else
    APPEND="console=ttyS0 quiet panic=-1"
    SCREEN="-nographic"
fi

if [ "${TINY_DRYRUN:-0}" = "1" ]; then
    echo "dry run - would execute:"
    echo "  qemu-system-x86_64 -kernel $KERNEL -initrd $INITRD -append '$APPEND'"
    echo "      -m $MEM $SCREEN -drive file=$DEVICE,readonly=on -device virtio-blk-pci,drive=hooked"
    echo "  (writable=$WRITABLE  timeout=${TIMEOUT}s  window=${TINY_WINDOW:-0}  mem=${MEM}M)"
    exit 0
fi

set -- \
    -kernel "$KERNEL" -initrd "$INITRD" \
    -append "$APPEND" \
    -m "$MEM" -nographic -no-reboot \
    -monitor "unix:$MONITOR,server,nowait" \
    -device virtio-rng-pci

if [ "$WRITABLE" = "1" ]; then
    set -- "$@" -drive "file=$DEVICE,if=none,id=hooked,format=raw,cache=writeback" -device virtio-blk-pci,drive=hooked
else
    set -- "$@" -drive "file=$DEVICE,if=none,id=hooked,format=raw,readonly=on" -device virtio-blk-pci,drive=hooked
fi

if [ -w /dev/kvm ] 2>/dev/null; then
    set -- "$@" -enable-kvm -cpu host
else
    echo "(no /dev/kvm access - using TCG emulation, slower)"
    set -- "$@" -accel tcg
fi

QEMU=$(command -v qemu-system-x86_64)

"$QEMU" "$@" &
QEMU_PID=$!
( sleep "$TIMEOUT"; kill -TERM "$QEMU_PID" 2>/dev/null ) &
WATCHDOG=$!

cleanup() {
    kill "$WATCHDOG" 2>/dev/null || true
    kill -TERM "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait "$QEMU_PID" 2>/dev/null || true
echo "(tiny linux exited, code $?)"