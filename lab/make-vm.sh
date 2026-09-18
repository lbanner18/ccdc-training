#!/usr/bin/env bash
# Build the CCDC practice Windows target: Server 2022 Standard (Desktop
# Experience), unattended, on the ISOLATED ccdc-lab network.
#
# LAB ONLY. The box comes up with a known weak Administrator password and SSH
# open on purpose, because it is a disposable target on a network with no
# route off it. Do not build this on a routed network.
set -euo pipefail

NAME=${NAME:-ccdc-win}
# The REBUILT iso, not the stock one: a stock Windows UEFI ISO stops at
# "Press any key to boot from CD" and a headless VM never presses anything.
# Build it first with make-unattended-iso.sh.
ISO=${ISO:-/var/lib/libvirt/images/ccdc/ccdc-win-unattended.iso}
POOL=${POOL:-/var/lib/libvirt/images/ccdc}
DISK=${DISK:-$POOL/$NAME.qcow2}
SIZE=${SIZE:-60}
RAM=${RAM:-6144}
CPUS=${CPUS:-4}
NET=${NET:-ccdc-lab}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

[ -f "$ISO" ] || { echo "ISO not found: $ISO" >&2; exit 1; }
if virsh dominfo "$NAME" >/dev/null 2>&1; then
  echo "A domain called $NAME already exists. Remove it first:" >&2
  echo "  virsh destroy $NAME; virsh undefine $NAME --nvram --remove-all-storage" >&2
  exit 1
fi

# The answer file is already at the root of the rebuilt ISO, so there is no
# second CD-ROM. One disc is also one fewer drive letter for Setup to guess at.
if [ ! -f "$ISO" ]; then
  echo "Build the install media first:" >&2
  echo "    bash $HERE/make-unattended-iso.sh" >&2
  exit 1
fi

echo "Building $NAME: Server 2022 Standard (Desktop Experience), ${SIZE}G, ${RAM}MB, on $NET"
echo "This takes 15-25 minutes and needs no input."
echo

virt-install \
  --name "$NAME" \
  --memory "$RAM" \
  --vcpus "$CPUS" \
  --cpu host-passthrough \
  --disk path="$DISK",size="$SIZE",bus=sata,format=qcow2 \
  --cdrom "$ISO" \
  --network network="$NET",model=e1000e \
  --graphics spice \
  --video qxl \
  --os-variant win2k22 \
  --boot uefi \
  --noautoconsole

# --cdrom, not a third --disk. virt-install needs to be told explicitly which
# medium is the INSTALL medium; a pair of cdrom disks with a boot order is not
# enough for it and it exits with "An install method must be specified".

cat <<EOF

Started. Watch it with:   virt-viewer $NAME     (or virt-manager)

When it is done it will have:
  hostname      CCDC-WIN
  Administrator CcdcLab!2026        <- lab only, isolated network
  SSH           open, host key authorised
  RDP           open
  a marker file C:\\ccdc-lab-ready.txt

Find its address once it is up:
  virsh domifaddr $NAME
  # or, since the lab network hands out DHCP:
  virsh net-dhcp-leases $NET

Then take the clean snapshot BEFORE you touch it. That is the whole point:
  virsh shutdown $NAME && sleep 45
  virsh snapshot-create-as $NAME clean-windows "clean, pre-CCDC"
  virsh start $NAME

Server 2022 boots UEFI, so an INTERNAL snapshot needs the VM shut down first -
a running UEFI guest cannot take one. Shut it down, snapshot, start it again.
EOF
