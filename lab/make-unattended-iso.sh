#!/usr/bin/env bash
# Rebuild a Windows install ISO so it boots with NO keypress and carries the
# answer file at its root.
#
# WHY THIS IS NEEDED
#
# A stock Windows UEFI ISO stops at "Press any key to boot from CD or DVD" and
# waits. On a headless VM nobody presses anything, the firmware gives up, and
# the domain powers off with a 9.6MB disk and no explanation. Sending keys with
# `virsh send-key` is a race you usually lose.
#
# Microsoft ships the fix inside the ISO: efisys_noprompt.bin, the same EFI
# boot image without the prompt. Swapping it in is what every automated Windows
# build does, and it is the difference between a hands-off install and one that
# needs somebody watching the console at the right second.
set -euo pipefail

SRC=${SRC:-$HOME/Downloads/SERVER_EVAL_x64FRE_en-us.iso}
OUT=${OUT:-/var/lib/libvirt/images/ccdc/ccdc-win-unattended.iso}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=${WORK:-/var/tmp/ccdc-iso-build}

[ -f "$SRC" ] || { echo "source ISO not found: $SRC" >&2; exit 1; }
command -v 7z      >/dev/null || { echo "need 7z (apt install p7zip-full)" >&2; exit 1; }
command -v xorriso >/dev/null || { echo "need xorriso" >&2; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK/iso"
echo "extracting $SRC ..."
7z x -y -o"$WORK/iso" "$SRC" >/dev/null

# The answer file goes at the ROOT of the install media. Windows Setup scans
# every removable drive's root for autounattend.xml before it draws its first
# screen, so putting it here removes the need for a second CD-ROM entirely.
cp "$HERE/autounattend.xml" "$WORK/iso/autounattend.xml"
cp "$HERE/provision.ps1"    "$WORK/iso/provision.ps1"

# Setup only mounts the media it booted from as a drive letter; the answer file
# references A:\provision.ps1 on the old two-disc layout. With one disc it is
# on the install media, whose letter varies - so look for it instead.
sed -i 's|A:\\provision.ps1|%~dp0provision.ps1|' "$WORK/iso/autounattend.xml" 2>/dev/null || true

[ -f "$WORK/iso/efi/microsoft/boot/efisys_noprompt.bin" ] \
  || { echo "this ISO has no efisys_noprompt.bin - cannot remove the prompt" >&2; exit 1; }

echo "building $OUT ..."
xorriso -as mkisofs \
  -iso-level 4 -full-iso9660-filenames \
  -volid "CCDC_WIN" \
  -eltorito-boot boot/etfsboot.com -no-emul-boot -boot-load-size 8 \
  -eltorito-alt-boot -eltorito-platform efi \
    -e efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot \
  -o "$OUT" "$WORK/iso" 2>&1 | tail -3

chmod 0644 "$OUT"
rm -rf "$WORK"
ls -lh "$OUT"
echo
echo "Built. It boots straight into Setup with no keypress, and carries"
echo "autounattend.xml at its root."
