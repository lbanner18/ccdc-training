#!/usr/bin/env bash
set -u

# scan.sh - use the malware scanner that is already on the box, honestly.
#
# This is a wrapper, not a scanner, and the distinction is the whole design.
# ClamAV with signatures from 2023 finds 2023 malware; a red team writing a bash
# reverse shell on the day will not be in any signature set, and the tools in
# this kit that catch that one (triage.sh's socket-owner check, the canaries,
# the audit rules) are not this. So the honest framing is: if a scanner is here,
# run it, record what it says, and know what its answer is worth.
#
#   ./scan.sh --config FILE               what scanning capability exists, and how old
#   ./scan.sh --config FILE --scan        scan the usual drop directories
#   ./scan.sh --config FILE --scan --path /var/www   scan somewhere specific
#
# It NEVER installs anything and NEVER quarantines, moves or deletes a file.
# Both of those are how a scanner takes down a scored service: clamscan --remove
# on a web root deletes the PHP file it disliked, and the service that served it
# is now returning 500 while you read a log. Findings are reported with the
# command to act on them, and you decide.
#
# Exit: 0 clean or nothing to run, 3 findings, 4 the scan could not run.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
mode=capability
scan_path=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --scan) mode=scan; shift ;;
    --path) scan_path=${2:?missing path}; shift 2 ;;
    -h|--help) printf 'usage: %s --config FILE [--scan [--path DIR]]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

# Every command this tool PRINTS is meant to be pasted, so it carries the real
# values rather than a placeholder. "<cfg>" is not a placeholder to bash, it is
# a redirect - pasting `--config <cfg>` is a syntax error, which is exactly what
# an operator hit on the lab box. Paths are absolute so they work from any cwd.
printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/scan.sh"


state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
mkdir -p "$state_dir" 2>/dev/null || ccdc_die "cannot create $state_dir"
log="$state_dir/scan.log"

findings=0
finding() { findings=$((findings + 1)); printf '  SCAN   %s\n' "$*"; }
detail()  { printf '         %s\n' "$*"; }
okline()  { printf '  ok     %s\n' "$*"; }
fixline() { printf '           %s\n' "$*"; }

# Days since a file was last modified. Signature age is the single number that
# decides what a clean scan is worth.
days_old() {
  local path=$1 mtime now
  mtime=$(stat -c '%Y' "$path" 2>/dev/null) || return 1
  now=$(date +%s)
  printf '%s\n' $(( (now - mtime) / 86400 ))
}

newest_signature_age() {
  local best='' age f
  for f in /var/lib/clamav/*.cvd /var/lib/clamav/*.cld \
           /var/lib/clamav/daily.* /usr/local/share/clamav/*.cvd; do
    [ -f "$f" ] || continue
    age=$(days_old "$f") || continue
    if [ -z "$best" ] || [ "$age" -lt "$best" ]; then best=$age; fi
  done
  [ -n "$best" ] || return 1
  printf '%s\n' "$best"
}

scan_targets() {
  if [ -n "$scan_path" ]; then
    printf '%s\n' "$scan_path"
    return 0
  fi
  if [ -n "${CCDC_SCAN_PATHS:-}" ]; then
    printf '%s\n' "$CCDC_SCAN_PATHS"
    return 0
  fi
  # Where a payload lands, not where the box keeps its data. Scanning / on a
  # box with a clock running is a way to spend twenty minutes and a lot of IO
  # for an answer you will not read.
  printf '%s\n' '/tmp
/var/tmp
/dev/shm
/var/www
/home'
}

do_capability() {
  local age tool found=0

  for tool in clamscan clamdscan; do
    if ccdc_have "$tool"; then
      okline "$tool is available"
      found=1
    fi
  done
  if [ "$found" -eq 1 ]; then
    if age=$(newest_signature_age); then
      if [ "$age" -gt 30 ]; then
        finding "ClamAV signatures are $age days old"
        detail "a clean result from signatures this old means very little"
        fixline "sudo freshclam        # only if the box has outbound access and time to spare"
      else
        okline "ClamAV signatures are $age day(s) old"
      fi
    else
      finding "ClamAV is installed but has NO signature database"
      detail "it will scan and find nothing, which reads exactly like a clean box"
      fixline "sudo freshclam"
    fi
  else
    detail "no ClamAV on this box (not a finding: it is not required, and"
    detail "installing it mid-event costs time and bandwidth for a tool that"
    detail "does not catch hand-written payloads anyway)"
  fi

  if ccdc_have yara; then
    okline "yara is available"
    if [ -n "${CCDC_YARA_RULES:-}" ]; then
      if [ -r "${CCDC_YARA_RULES}" ]; then
        okline "yara rules: $CCDC_YARA_RULES"
      else
        finding "CCDC_YARA_RULES is set but unreadable: $CCDC_YARA_RULES"
      fi
    else
      detail "no CCDC_YARA_RULES configured - yara with no rules does nothing"
    fi
  fi

  for tool in rkhunter chkrootkit aide tripwire; do
    ccdc_have "$tool" && okline "$tool is available"
  done

  if [ "$found" -eq 0 ] && ! ccdc_have yara; then
    detail ""
    detail "Nothing to run. That is a normal state for a CCDC box, and the"
    detail "detection that matters here does not depend on it:"
    detail "  ./linux/triage.sh   - who holds a socket, what runs from /tmp"
    detail "  ./linux/canary.sh   - decoys and audit watches"
    detail "  ./linux/hunt.sh     - persistence sweep"
  fi
}

do_scan() {
  local target out ran=0 hits
  local stamp; stamp=$(ccdc_now)
  local outdir="$state_dir/scan-$stamp"
  mkdir -p "$outdir" || ccdc_die "cannot create $outdir"
  chmod 0700 "$outdir" 2>/dev/null || true

  if ! ccdc_have clamscan && ! ccdc_have clamdscan && ! ccdc_have yara; then
    printf '  nothing to scan with. See the capability report:\n'
    printf '      ./linux/scan.sh --config '"$qconfig"'\n'
    return 0
  fi

  while IFS= read -r target; do
    [ -n "$target" ] && [ -d "$target" ] || continue
    out="$outdir/clamscan-$(printf '%s' "${target#/}" | tr '/' '_').txt"
    if ccdc_have clamdscan; then
      # clamdscan uses the running daemon and is much faster; --fdpass avoids
      # permission problems when the daemon runs as a different user.
      clamdscan --fdpass --infected "$target" >"$out" 2>&1
      ran=1
    elif ccdc_have clamscan; then
      # Bounded deliberately. --max-filesize keeps one huge file from eating
      # the whole window, and no --remove/--move appears anywhere in this file.
      clamscan --recursive --infected --no-summary \
        --max-filesize=100M --max-scansize=500M "$target" >"$out" 2>&1
      ran=1
    fi
    [ -s "$out" ] || continue
    hits=$(grep -c 'FOUND$' "$out" 2>/dev/null || true)
    [ -n "$hits" ] || hits=0
    if [ "$hits" -gt 0 ]; then
      finding "$hits ClamAV detection(s) under $target"
      grep 'FOUND$' "$out" 2>/dev/null | head -10 | sed 's/^/           /'
      detail "evidence: $out"
    fi
  done <<EOF
$(scan_targets)
EOF

  if ccdc_have yara && [ -n "${CCDC_YARA_RULES:-}" ] && [ -r "${CCDC_YARA_RULES}" ]; then
    while IFS= read -r target; do
      [ -n "$target" ] && [ -d "$target" ] || continue
      out="$outdir/yara-$(printf '%s' "${target#/}" | tr '/' '_').txt"
      yara -r -w "${CCDC_YARA_RULES}" "$target" >"$out" 2>&1
      ran=1
      if [ -s "$out" ]; then
        finding "YARA match(es) under $target"
        head -10 "$out" | sed 's/^/           /'
        detail "evidence: $out"
      fi
    done <<EOF
$(scan_targets)
EOF
  fi

  ccdc_append_log "$log" "SCAN dir=$outdir findings=$findings"
  [ "$ran" -eq 1 ] || printf '  no scanner ran\n'
  printf '\n  results kept in %s\n' "$outdir"

  if [ "$findings" -gt 0 ]; then
    printf '\n  BEFORE YOU DELETE ANYTHING A SCANNER NAMED:\n'
    printf '    A detection is a claim, not a verdict. Web shells and admin tools\n'
    printf '    share signatures, and the file may be part of the scored service.\n\n'
    printf '    1. preserve it:   sudo ./linux/preserve.sh --config '"$qconfig"'\n'
    printf '    2. read it:       sudo less <the file>\n'
    printf '    3. find out what it belongs to:\n'
    printf '                      dpkg -S <file> 2>/dev/null || rpm -qf <file>\n'
    printf '    4. only then decide. If it is a payload, CARD 6 and CARD 12 apply.\n'
  fi
}

printf 'scan.sh - what this box can scan with, and what that is worth\n'
printf '%s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
case "$mode" in
  capability) do_capability ;;
  scan) do_capability; printf '\n'; do_scan ;;
esac
printf '\n'
if [ "$findings" -gt 0 ]; then
  printf '  %s scanning finding(s) above.\n' "$findings"
  exit 3
fi
printf '  Nothing flagged by the scanners on this box.\n'
printf '  That is not "the box is clean" - see the header of this file.\n'
exit 0
