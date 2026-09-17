#!/usr/bin/env bash
set -u

# harden.sh cuts things on purpose. Every other tool in this kit is trying not
# to break the box; this one is trying to break as much of it as it safely can,
# which makes the difference between "safe" and "safe-sounding" the whole game.
#
# The detection half cannot be tested from a fixture - it reads the real unit
# list, the real package database and the real block devices. That half is
# tested against the lab VM. What is tested here is every place the tool has
# already been caught claiming something it did not do:
#
#   - a safety check that reads an empty list and passes without comparing
#   - a list membership test called so that only its first word is ever checked
#   - an action that reports "masked" for a thing that is not a unit
#   - an undo that restores more than it removed
#
# All four shipped. All four looked correct in review and failed on the box.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
H="$ROOT/linux/harden.sh"

pass=0; fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

[ -f "$H" ] || { printf 'harden.sh not found\n' >&2; exit 1; }
bash -n "$H" && ok 'harden.sh parses' || no 'harden.sh does not parse'

# --- ccdc_list_contains takes the list as ONE argument -----------------------
#
# Called unquoted, only the first word of the list is ever compared. That is
# how `mount`, `su` and `passwd` came to be listed as setuid bits nothing
# needs - and, far worse, how the protected-package check compared exactly one
# name before approving a purge.
if grep -q 'ccdc_list_contains "\$base" "\$SUID_KEEP"' "$H"; then
  ok 'the SUID keep list is passed as one quoted argument'
else
  no 'the SUID keep list is word-split, so only its first entry is checked'
fi
if grep -q 'ccdc_list_contains "\$p" "\$PKG_PROTECTED"' "$H"; then
  ok 'the protected-package list is passed as one quoted argument'
else
  no 'the protected-package list is word-split; the purge guard checks one name'
fi

# --- a safety check that cannot run must not pass ----------------------------
#
# apt prints "Purg pkg" for a purge and "Remv pkg" for a dependency removal.
# Matching only Remv returned nothing on a plain purge, so the cascade check
# compared an empty list against the protected names and approved everything.
if grep -q "Remv|Purg" "$H"; then
  ok 'the purge cascade reads both Remv and Purg lines'
else
  no 'the purge cascade misses Purg lines, so it approves purges vacuously'
fi
if grep -q 'apt could not work out what purging' "$H"; then
  ok 'an empty cascade refuses instead of passing'
else
  no 'an empty apt simulation reads as "nothing protected would be removed"'
fi

# --- masking is only meaningful for a unit -----------------------------------
#
# `systemctl mask telnet` created /etc/systemd/system/telnet.service -> /dev/null
# for a unit that never existed, left the package installed, and printed
# "masked, so it cannot be started again by name".
if grep -q "elif \[ \"\$kind\" = 'units' \] && \[ -n \"\$members\" \]; then" "$H"; then
  ok 'only unit findings are masked'
else
  no 'a package finding can be masked, inventing a unit that does not exist'
fi
if grep -q "\[ \"\$kind\" = 'units' \] && \[ -n \"\$members\" \] \\\\" "$H"; then
  ok 'only unit findings get a systemctl line in their undo'
else
  no 'a package undo tries to systemctl enable the package name'
fi

# --- an undo restores what that cut removed, and no more ---------------------
if grep -q 'undo="dpkg -i \$debcache/\*\.deb"' "$H"; then
  no 'the undo globs the whole .deb cache, restoring other cuts too'
else
  ok 'the undo names only the .deb files this cut removed'
fi

# --- the dependency walk must not climb through targets ----------------------
#
# systemctl list-dependencies recurses into sysinit.target and basic.target and
# from there into most of the boot. Using it decided that 75 units were
# load-bearing for a python web server, which silently removed open-iscsi,
# multipathd and lvm2-monitor from the candidate list.
# Skip comments: this rule is explained in a comment that names the call.
if grep -v '^[[:space:]]*#' "$H" | grep -q 'list-dependencies'; then
  no 'list-dependencies pulls in the whole boot as scored dependencies'
else
  ok 'the dependency walk does not use recursive list-dependencies'
fi
if grep -q 'case "\$dep" in \*\.target) continue ;; esac' "$H"; then
  ok 'the dependency walk stops at targets'
else
  no 'the dependency walk climbs into targets'
fi

# --- a tool must not find itself ---------------------------------------------
#
# PKG_DUALUSE literally contains the word "tcpdump", so scanning the kit for
# users of tcpdump found harden.sh and reported the kit as depending on it.
if grep -q '\[ "\$f" = "\$SCRIPT_DIR/harden.sh" \] && continue' "$H"; then
  ok 'the dependency scan skips harden.sh itself'
else
  no 'harden.sh matches its own package list and reports itself as a dependent'
fi

# --- order: harden, then bless -----------------------------------------------
if grep -q 'i-know-it-is-blessed' "$H" && grep -q 'would make' "$H"; then
  ok 'cutting a blessed box is refused, because every cut would read as drift'
else
  no 'a blessed box can be hardened silently, turning your own work into drift'
fi

# --- every cut is checked, and a bad one is rolled back ----------------------
if grep -q 'if scored_ok; then' "$H" && grep -q 'Rolling this one back now' "$H"; then
  ok 'each cut is followed by a scored check, and rolled back if it fails'
else
  no 'a cut that takes a scored service down is not reversed'
fi

# --- the package table must survive a release rename -------------------------
#
# ubuntu-advantage-tools became ubuntu-pro-client in noble. Naming only the old
# one meant apt could not simulate the purge, which the cascade guard caught -
# but only because that guard had just been fixed.
if grep -q 'installed_only' "$H"; then
  ok 'package names are filtered to what is actually installed'
else
  no 'a renamed package silently breaks the purge safety check'
fi

# --- dry run ------------------------------------------------------------------
if grep -q 'Dry run. Nothing has changed yet. Add --apply to mean it.' "$H"; then
  ok 'a dry run says plainly that nothing happened'
else
  no 'a dry run is indistinguishable from having acted'
fi

# --- the shared CCDC_TCP_CHECKS parser, behaviourally ------------------------
#
# The operator config was written as "127.0.0.1:8080 127.0.0.1:22" while every
# consumer parsed name|host|port|service. That produced one unmatched field, so
# the port loop found nothing, fell out, and returned success - and baseline.sh
# reported a scored web server "back and answering" having never probed it.
. "$ROOT/linux/lib/common.sh"
CCDC_TCP_CHECKS="127.0.0.1:8080 127.0.0.1:22"
if [ "$(ccdc_tcp_checks 2>/dev/null | wc -l)" -eq 2 ]; then
  ok 'the host:port spelling parses into checks'
else
  no 'the host:port spelling silently produces no checks'
fi
CCDC_TCP_CHECKS="web|127.0.0.1|8080|scored-web"
if [ "$(ccdc_tcp_checks 2>/dev/null)" = 'web|127.0.0.1|8080|scored-web' ]; then
  ok 'the documented name|host|port|service spelling parses'
else
  no 'the documented spelling does not round-trip'
fi
CCDC_TCP_CHECKS="nonsense"
if ccdc_tcp_checks 2>&1 >/dev/null | grep -q 'cannot read'; then
  ok 'an unparseable check warns instead of vanishing'
else
  no 'an unparseable check disappears, and every consumer reads that as a pass'
fi
CCDC_TCP_CHECKS=""

# --- baseline must not claim a port it never probed --------------------------
if grep -q 'VERIFY_PORT_UNTESTED' "$ROOT/linux/baseline.sh"; then
  ok 'baseline.sh distinguishes "active again" from "answering"'
else
  no 'baseline.sh reports "answering" for a unit whose port was never probed'
fi

# --- no flag is printed that the tool does not accept ------------------------
# Only flags printed as part of OUR OWN command line. Scanning every flag in
# the file collected systemctl --now, dpkg --value and apt --quiet, none of
# which harden.sh is claiming to accept.
flags=$(grep -E '\$qself|harden\.sh --config' "$H" \
        | grep -oE '\-\-[a-z][a-z-]+' | sort -u)
accepted=$(sed -n '/^while \[ "\$#" -gt 0 \]/,/^done/p' "$H" \
           | grep -oE '^ *--[a-z][a-z-]+' | tr -d ' ' | sort -u)
missing=''
for f in $flags; do
  case "$f" in --apply|--config|--help) continue ;; esac
  printf '%s\n' "$accepted" | grep -qx -- "$f" || missing="$missing $f"
done
if [ -z "$missing" ]; then
  ok 'every flag harden.sh prints is a flag harden.sh accepts'
else
  no "harden.sh prints flags it does not accept:$missing"
fi

printf 'harden self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
