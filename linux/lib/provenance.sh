#!/usr/bin/env bash

# provenance.sh - "should this file be here at all?"
#
# These three questions are the bounded half of detection. Asking what a file
# CONTAINS is unbounded: there are infinite ways to spell a reverse shell, and a
# check written that way only ever catches the spellings someone thought of. Two
# drill footholds walked past every content check in the kit - a systemd drop-in
# whose body was an ordinary ExecStartPost, and a script in /etc/update-motd.d
# that ran as root on every login - because neither file said anything evil.
#
# Asking whether a file is EXPLAINED is bounded. It is owned by a package, or it
# predates the box, or it is on an allowlist, or it is none of those and you
# should know about it.
#
# This lived inside triage.sh. It moved here so baseline.sh, harden.sh and
# sentry.sh ask the question exactly one way, with one set of edge cases.
#
# Sourced, never executed. Requires lib/common.sh for ccdc_have.

# Does any package own this file?
#
# The naive `dpkg-query -S "$path"` is wrong on every modern Debian, Ubuntu and
# RHEL, and wrong in the direction that matters: it says "nobody owns this"
# about files that ship with the distribution.
#
# The cause is the merged-/usr layout. /bin is a symlink to usr/bin, so `find /`
# reports /usr/bin/fusermount3 while dpkg recorded it as /bin/fusermount3, and
# the lookup misses. On the lab box that produced a permanent AMBER for a
# stock fuse3 binary - and an earlier version of this file drew exactly the
# wrong conclusion from it, concluding the signal was noisy and telling the
# operator "usually a packaging quirk; confirm once and move on". Directly
# above a SUID root shell planted twenty minutes earlier.
#
# So: ask about the path, and about the same path with the merge undone.
# The same path with the merge undone, or the empty string. Both questions
# below need it, and two copies of this table is how they drift apart.
pkg_alt_path() {
  case "$1" in
    /usr/bin/*)  printf '/bin/%s' "${1#/usr/bin/}" ;;
    /usr/sbin/*) printf '/sbin/%s' "${1#/usr/sbin/}" ;;
    /usr/lib/*)  printf '/lib/%s' "${1#/usr/lib/}" ;;
    /bin/*)      printf '/usr/bin/%s' "${1#/bin/}" ;;
    /sbin/*)     printf '/usr/sbin/%s' "${1#/sbin/}" ;;
    /lib/*)      printf '/usr/lib/%s' "${1#/lib/}" ;;
  esac
}

# Is FILE exactly what its package shipped - owned AND unmodified? Owned alone
# is not enough: a package file somebody edited is the best hiding place on the
# box, because every "is this packaged" check waves it through.
pkg_file_pristine() {
  local f=$1 pkg sum want md5file
  [ -f "$f" ] || return 1
  if ccdc_have dpkg-query; then
    pkg=$(dpkg-query -S "$f" 2>/dev/null | grep -v '^diversion' | head -1 | sed 's/: .*//')
    [ -n "$pkg" ] || return 1
    case "$pkg" in *,*) return 1 ;; esac
    sum=$(md5sum <"$f" 2>/dev/null | cut -d' ' -f1)
    want=$(dpkg-query -W -f='${Conffiles}\n' "$pkg" 2>/dev/null | awk -v f="$f" '$1 == f {print $2; exit}')
    if [ -z "$want" ]; then
      md5file=$(dpkg-query --control-path "$pkg" md5sums 2>/dev/null)
      [ -n "$md5file" ] && want=$(awk -v f="${f#/}" '$2 == f {print $1; exit}' "$md5file" 2>/dev/null)
    fi
    [ -n "$want" ] && [ -n "$sum" ] && [ "$sum" = "$want" ]
    return
  elif ccdc_have rpm; then
    rpm -qf "$f" >/dev/null 2>&1 || return 1
    # rpm -V prints only what differs from the package; nothing for this file
    # means it is as shipped.
    [ -z "$(rpm -Vf "$f" 2>/dev/null | awk -v f="$f" '$NF == f')" ]
    return
  fi
  return 1
}

pkg_owns() {
  local f=$1 alt=''
  alt=$(pkg_alt_path "$f")
  if ccdc_have dpkg-query; then
    dpkg-query -S "$f" >/dev/null 2>&1 && return 0
    [ -n "$alt" ] && dpkg-query -S "$alt" >/dev/null 2>&1 && return 0
  elif ccdc_have rpm; then
    rpm -qf "$f" >/dev/null 2>&1 && return 0
    [ -n "$alt" ] && rpm -qf "$alt" >/dev/null 2>&1 && return 0
  fi
  return 1
}

# WHICH package owns this file? Prints the package name, or nothing.
#
# The same merged-/usr trap as pkg_owns, and three tools were in it: sshd.sh,
# surface.sh and baseline.sh each asked dpkg for the owner of the literal path
# only, so a stock binary under /usr/bin came back with an empty owner - which
# reads to an operator as "no package ships this", the exact wrong conclusion
# and the one this library was written to stop.
#
# Note where the status is read. `owner=$(dpkg-query -S "$f" | head -1)` reads
# HEAD's status, which is zero whether or not dpkg found anything; baseline.sh
# printed "owned by a package? yes - " with an empty name because of it.
pkg_owner() {
  local f=$1 alt out=''
  [ -n "$f" ] || return 1
  alt=$(pkg_alt_path "$f")
  if ccdc_have dpkg-query; then
    out=$(dpkg-query -S -- "$f" 2>/dev/null) || out=''
    if [ -z "$out" ] && [ -n "$alt" ]; then
      out=$(dpkg-query -S -- "$alt" 2>/dev/null) || out=''
    fi
    [ -n "$out" ] || return 1
    out=$(printf '%s\n' "$out" | head -1)
    printf '%s\n' "${out%%:*}"
    return 0
  fi
  if ccdc_have rpm; then
    out=$(rpm -qf -- "$f" 2>/dev/null) || out=''
    if [ -z "$out" ] && [ -n "$alt" ]; then
      out=$(rpm -qf -- "$alt" 2>/dev/null) || out=''
    fi
    case "$out" in ''|*'not owned'*|*'no package'*|*'No such file'*) return 1 ;; esac
    printf '%s\n' "$(printf '%s\n' "$out" | head -1)"
    return 0
  fi
  return 1
}

# When was this box built? SSH host keys are generated once at first boot and
# never touched again, which makes them a day-zero marker needing no package
# database. A SUID root binary newer than the box is a different claim from one
# that shipped with it, and the date was sitting in the ls -l output all along
# without anything reading it.
BOX_BUILT=''
for _hk in /etc/ssh/ssh_host_*_key; do
  [ -f "$_hk" ] || continue
  _m=$(stat -c '%Y' "$_hk" 2>/dev/null) || continue
  if [ -z "$BOX_BUILT" ] || [ "$_m" -lt "$BOX_BUILT" ]; then BOX_BUILT=$_m; fi
done
unset _hk _m

# Is this file newer than the box it is on?
#
# The slack was 10 minutes and that was too tight. Host keys are written early
# in first boot; cloud-init then provisions users, keys and packages for a good
# while afterwards. On the lab box the operator's OWN authorized_keys landed 27
# minutes after the host keys and got reported as "written AFTER this box was
# built" - a false positive on the one file they were certain about, which is
# precisely how an operator learns to stop believing this signal.
#
# Two hours covers a provisioning run and is still far short of the gap that
# makes this interesting, which is the days between a box being built and an
# event starting.
newer_than_box() {
  local m
  [ -n "$BOX_BUILT" ] || return 1
  m=$(stat -c '%Y' "$1" 2>/dev/null) || return 1
  [ "$((m - BOX_BUILT))" -gt 7200 ]
}

# A renamed shell is still byte-for-byte the shell. This is the one check that
# turns "an unpackaged SUID binary, which could be anything" into a fact you can
# act on without reading a disassembly: if it is identical to /bin/dash, it is
# /bin/dash, and a SUID root /bin/dash under another name is a root shell.
identical_to() {
  local f=$1 c
  for c in /bin/dash /bin/bash /bin/sh /usr/bin/dash /usr/bin/bash \
           /bin/busybox /usr/bin/busybox /usr/bin/python3 /usr/bin/perl; do
    [ -f "$c" ] || continue
    [ "$c" = "$f" ] && continue
    if cmp -s -- "$f" "$c" 2>/dev/null; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}
