#!/bin/sh
# Builds a minimal Linux (busybox initramfs) that boots in a couple of seconds.
# Output: tiny-linux/initramfs.cpio.gz
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BUILD="$HERE/build"
INITRD="$HERE/initramfs.cpio.gz"
KVER=${TINY_KVER:-$(uname -r)}
echo "$KVER" > "$HERE/kver"

if ! command -v busybox >/dev/null 2>&1; then
    echo "busybox is required (apt install busybox)" >&2
    exit 1
fi

rm -rf "$BUILD"
mkdir -p "$BUILD"/bin "$BUILD"/sbin "$BUILD"/proc "$BUILD"/sys "$BUILD"/dev "$BUILD"/tmp \
         "$BUILD"/root "$BUILD"/usr/bin "$BUILD"/usr/sbin "$BUILD"/modules \
         "$BUILD"/etc/ssh "$BUILD"/run/sshd "$BUILD"/root/.ssh

echo "[*] copying busybox"
cp "$(command -v busybox)" "$BUILD/bin/busybox"
chmod 755 "$BUILD/bin/busybox"

SSH_KEYDIR=${TINY_SSH_KEYDIR:-$HERE/keys}
mkdir -p "$SSH_KEYDIR"

echo "[*] copying sshd and its libraries"
for prog in /usr/sbin/sshd /usr/bin/ssh-keygen; do
    [ -e "$prog" ] || { echo "    $prog missing - the VM will boot without ssh" >&2; continue; }
    cp -L "$prog" "$BUILD${prog%/*}/$(basename "$prog")" 2>/dev/null || cp -L "$prog" "$BUILD/bin/$(basename "$prog")"
    chmod 755 "$BUILD${prog%/*}/$(basename "$prog")" 2>/dev/null || true
    chmod 755 "$BUILD/bin/$(basename "$prog")" 2>/dev/null || true
    ldd "$prog" 2>/dev/null | awk '
        /=>/ { print $3 }
        !/=>/ && /^\// { print $1 }
    ' | grep '^/' | sort -u | while read -r lib; do
        [ -e "$lib" ] || continue
        mkdir -p "$BUILD$(dirname "$lib")"
        cp -L "$lib" "$BUILD$lib"
    done
    echo "    $(basename "$prog")"
done

echo "[*] copying shared libraries"
ldd "$(command -v busybox)" 2>/dev/null | awk '
    /=>/ { print $3 }
    !/=>/ && /^\// { print $1 }
' | grep '^/' | sort -u | while read -r lib; do
    [ -e "$lib" ] || continue
    mkdir -p "$BUILD$(dirname "$lib")"
    cp -L "$lib" "$BUILD$lib"
done
# the loader itself shows up as the interpreter line
for loader in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-aarch64.so.1; do
    [ -e "$loader" ] || continue
    mkdir -p "$BUILD$(dirname "$loader")"
    cp -L "$loader" "$BUILD$loader"
done
echo "    libs: $(find "$BUILD/lib*" "$BUILD/usr/lib*" -type f 2>/dev/null | wc -l)"

for applet in sh ls cat mount echo sleep dmesg lsblk blkid df ps poweroff halt \
              reboot mkdir mknod free grep sed head tail date uname hostname vi more setsid \
              insmod basename expr test ifconfig route ip udhcpc ping nc awk tr cut sort \
              tee watch env id whoami ssh-keygen sshd true false test1; do
    [ -e "$BUILD/bin/$applet" ] || ln -s busybox "$BUILD/bin/$applet"
done

echo "[*] copying modules for $KVER"
for mod in virtio_blk virtio-rng virtio_net virtio_mmio; do
    path=$(modinfo -F filename "$mod" 2>/dev/null || true)
    if [ -n "$path" ] && [ -e "$path" ]; then
        cp -L "$path" "$BUILD/modules/$mod.ko.xz"
        echo "    $mod.ko.xz"
    else
        echo "    $mod: builtin or missing"
    fi
done

echo "[*] preparing ssh keys"
if [ -x "$BUILD/usr/bin/ssh-keygen" ]; then
    if [ ! -f "$SSH_KEYDIR/guest_host_ed25519_key" ]; then
        "$BUILD/usr/bin/ssh-keygen" -q -t ed25519 -N '' -f "$SSH_KEYDIR/guest_host_ed25519_key" \
            -C tiny-linux-guest 2>/dev/null || echo "    could not generate the guest host key" >&2
    fi
    if [ -f "$SSH_KEYDIR/guest_host_ed25519_key" ]; then
        cp "$SSH_KEYDIR/guest_host_ed25519_key" "$BUILD/etc/ssh/ssh_host_ed25519_key"
        cp "$SSH_KEYDIR/guest_host_ed25519_key.pub" "$BUILD/etc/ssh/ssh_host_ed25519_key.pub"
        chmod 600 "$BUILD/etc/ssh/ssh_host_ed25519_key"
        chmod 644 "$BUILD/etc/ssh/ssh_host_ed25519_key.pub"
        echo "    guest host key: $SSH_KEYDIR/guest_host_ed25519_key"
    fi
    if [ ! -f "$SSH_KEYDIR/host_id_ed25519" ]; then
        ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEYDIR/host_id_ed25519" \
            -C tiny-linux-access 2>/dev/null || echo "    could not generate the client key" >&2
    fi
    if [ -f "$SSH_KEYDIR/host_id_ed25519.pub" ]; then
        cp "$SSH_KEYDIR/host_id_ed25519.pub" "$BUILD/root/.ssh/authorized_keys"
        chmod 600 "$BUILD/root/.ssh/authorized_keys"
        chmod 700 "$BUILD/root/.ssh"
        echo "    access key:  $SSH_KEYDIR/host_id_ed25519  (private key stays on the host)"
    fi
    cat > "$BUILD/etc/ssh/sshd_config" <<'SSHD'
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitEmptyPasswords no
StrictModes no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /bin/busybox
PidFile /run/sshd.pid
SSHD
    chmod 644 "$BUILD/etc/ssh/sshd_config"
fi

cat > "$BUILD/init" <<'INIT'
#!/bin/sh
export PATH=/bin
echo "[*] loading modules"
for ko in /modules/*.ko.xz; do
    [ -e "$ko" ] || continue
    insmod "$ko" && echo "    loaded $(basename "$ko")" || echo "    FAILED $(basename "$ko")"
done

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null

for sysdev in /sys/block/*; do
    [ -d "$sysdev" ] || continue
    name=$(basename "$sysdev")
    [ -e "/dev/$name" ] && continue
    if [ -r "$sysdev/dev" ]; then
        mknod "/dev/$name" b "$(cut -d: -f1 "$sysdev/dev")" "$(cut -d: -f2 "$sysdev/dev")" 2>/dev/null
    fi
done

echo
echo "=== tiny linux (busybox initramfs) ==="
uname -srm
echo
echo "-- attached block devices --"
lsblk 2>/dev/null
for node in /dev/vd* /dev/sd* /dev/xvd*; do
    [ -b "$node" ] && echo "  $node  size=$(cat /sys/block/$(basename "$node")/size 2>/dev/null) sectors"
done
echo
echo "-- filesystems --"
blkid 2>/dev/null
echo
echo "-- virtio/detection lines --"
dmesg | grep -iE "virtio|vda|vblk" | tail -n 10
# keep watching for hotplugged disks so they show up as device nodes
(
    while true; do
        for sysdev in /sys/block/*; do
            [ -d "$sysdev" ] || continue
            name=$(basename "$sysdev")
            [ -e "/dev/$name" ] && continue
            [ -r "$sysdev/dev" ] || continue
            mknod "/dev/$name" b "$(cut -d: -f1 "$sysdev/dev")" "$(cut -d: -f2 "$sysdev/dev")" 2>/dev/null
        done
        sleep 2
    done
) &
HOTPLUG_PID=$!

echo
echo "== networking =="
ifconfig lo up 2>/dev/null || true
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null || true
route add default gw 10.0.2.2 2>/dev/null || true
ifconfig eth0 2>/dev/null || echo "    (no eth0)"

echo
echo "== ssh =="
SSHD_BIN=""
for candidate in /usr/sbin/sshd /bin/sshd; do
    [ -x "$candidate" ] && { SSHD_BIN="$candidate"; break; }
done
if [ -n "$SSHD_BIN" ]; then
    "$SSHD_BIN" -D -e 2>/tmp/sshd.log &
    SSH_PID=$!
    sleep 1
    if kill -0 "$SSH_PID" 2>/dev/null; then
        echo "    sshd listening on 10.0.2.15:22 (log: /tmp/sshd.log)"
        echo "    SSH_READY"
    else
        echo "    sshd FAILED to start:"
        sed 's/^/      /' /tmp/sshd.log 2>/dev/null
    fi
else
    echo "    no sshd in this image"
fi

echo
echo "shell ready - type 'poweroff -f' to exit"
exec sh -c 'exec sh </dev/console >/dev/console 2>&1'
INIT
chmod 755 "$BUILD/init"

echo "[*] packing initramfs"
(cd "$BUILD" && find . -print0 | cpio --null -o -H newc --quiet | gzip -9) > "$INITRD"

echo "[*] built $INITRD ($(du -h "$INITRD" | cut -f1))"