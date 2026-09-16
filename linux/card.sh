#!/usr/bin/env bash
set -u

# card.sh - read one remediation card in the terminal, safely.
#
# The cards started life as playbooks/remediation-cards.md with the instruction
# "keep this open in a second window". The operator has ONE terminal. So under
# pressure he did the only thing available: opened the markdown and pasted it
# into the shell, where bash tried to execute several hundred lines of prose.
#
#   **Trap:**: command not found
#   find: 'the': No such file or directory
#   userdel: user '' does not exist          <- a real sudo command, fired blind
#
# Nothing broke, but only because every dangerous line referenced an unset
# variable. A markdown file full of sudo commands is a loaded gun pointed at
# whoever is in the biggest hurry, which is precisely who the cards are for.
#
#   ./card.sh          list the cards
#   ./card.sh 1        print card 1, plain text, nothing executable
#   ./card.sh 1 | less
#
# It prints. It never runs anything. Commands are shown indented behind a "$"
# so they are unmistakably things YOU type, one at a time, having read them -
# and so that pasting a whole card back in is obviously not the intended use.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Sourced only for ccdc_load_config, which --config needs. card.sh runs fine
# without a config; this must not become a hard dependency for printing a card.
[ -r "$SCRIPT_DIR/lib/common.sh" ] && . "$SCRIPT_DIR/lib/common.sh"
CARDS="$SCRIPT_DIR/../playbooks/remediation-cards.md"
[ -f "$CARDS" ] || CARDS="$SCRIPT_DIR/remediation-cards.md"
[ -f "$CARDS" ] || { printf 'card.sh: cannot find remediation-cards.md\n' >&2; exit 1; }

list_cards() {
  printf '\nRemediation cards - card.sh N SUBJECT --config FILE to read one\n\n'
  grep -n '^## CARD ' "$CARDS" | sed -E 's/^[0-9]+:## CARD /  /; s/ — / - /'
  printf '\n  triage.sh prints [CARD n] beside each finding.\n'
  printf '  Each card is: kill the access, find the way back in, verify.\n\n'
}

[ "$#" -ge 1 ] || { list_cards; exit 0; }
# --config FILE may appear anywhere; everything else stays positional so the
# footer triage.sh prints keeps working unchanged.
__args=""
__cfg=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) __cfg=${2:-}; shift 2 || shift ;;
    *) __args="$__args $1"; shift ;;
  esac
done
# shellcheck disable=SC2086
set -- $__args
[ "$#" -gt 0 ] || { list_cards; exit 0; }

case "$1" in
  -h|--help)
      printf 'usage: %s N SUBJECT [--config FILE]\n\n' "$0"
      printf '  N          the card number triage.sh printed, e.g. [CARD 5] -> 5\n'
      printf '  SUBJECT    the thing the finding is about: the username, unit,\n'
      printf '             path or PID. Substituted into the card for $U / $F,\n'
      printf '             so there is no variable left to forget to set.\n'
      printf '  --config   optional, and worth passing. With it, card.sh checks\n'
      printf '             SUBJECT against the scored and protected services in\n'
      printf '             your config and warns before rendering a card whose\n'
      printf '             commands would stop or delete your own scored service.\n\n'
      printf '  card.sh PRINTS a card. It never runs one, and it has no other options.\n\n'
      list_cards; exit 0 ;;
  ''|*[!0-9]*) printf 'card.sh: give a card number. Run with no arguments to list them.\n' >&2; exit 1 ;;
esac
n=$1

# --config is OPTIONAL and, when given, is used for exactly one thing: deciding
# whether the subject you passed is something the packet says you are scored on.
#
# CARD 4 prints, among other lines,
#
#     sudo systemctl disable --now "$U"
#     sudo rm -f "/etc/systemd/system/$U"
#     sudo rm -rf "/etc/systemd/system/$U.d"
#
# and `card.sh 4 scored-web.service` rendered that with the scored unit
# substituted in, with nothing anywhere saying so. The card is printed and
# never run, but the whole point of a card is that you paste from it.
#
# This does NOT refuse. A scored service really can be the compromised thing,
# and a tool that blocks the one card you need at the moment you need it is
# worse than the risk. It makes the consequence impossible to miss instead.
card_config=''
protected_note=''

subject_is_protected() {
  local needle=${1##*/} item base
  [ -n "$needle" ] || return 1
  base=$needle
  for suffix in .service .timer .socket .path .mount; do base=${base%$suffix}; done
  for item in ${CCDC_SYSTEMD_SERVICES:-} ${CCDC_PROTECT_SERVICES:-} ${CCDC_SCORED_UNITS:-}; do
    item=${item##*/}
    for suffix in .service .timer .socket .path .mount; do item=${item%$suffix}; done
    if [ "$item" = "$base" ]; then protected_note="a scored/protected SERVICE"; return 0; fi
  done
  for item in ${CCDC_ALLOWED_USERS:-}; do
    if [ "$item" = "$needle" ]; then protected_note="an account your config ALLOWS"; return 0; fi
  done
  return 1
}

warn_if_protected() {
  subject_is_protected "$subject" || return 0
  printf '\n' >&2
  printf '  ================================================================\n' >&2
  printf '   STOP AND READ. "%s" is %s\n' "$subject" "$protected_note" >&2
  printf '   according to %s\n' "$card_config" >&2
  printf '\n' >&2
  printf '   This card contains commands that STOP, DISABLE or DELETE its\n' >&2
  printf '   subject. Pasting them takes it off the scoreboard until you put\n' >&2
  printf '   it back, and the scoring engine will not wait.\n' >&2
  printf '\n' >&2
  printf '   If it really is compromised you may still have to. Before you do:\n' >&2
  printf '     - know how you are putting it back (backup.sh --restore)\n' >&2
  printf '     - expect the watchdog to restart it while you work\n' >&2
  printf '     - prefer the narrowest fix: the payload, the drop-in, the key -\n' >&2
  printf '       not the unit, unless the unit itself is the finding\n' >&2
  printf '  ================================================================\n\n' >&2
}


# The second argument is the thing the finding is ABOUT - a username, a unit, a
# file - and it is substituted into the card before printing.
#
# This exists because the placeholder is what actually failed in practice. The
# card said `sudo grep -rn "$U" /etc/ssh/sshd_config`, $U was never set in the
# operator's shell, and the command matched the empty string and printed all 131
# lines of sshd_config. Every "set U= first" instruction is a step you can skip
# under pressure, and skipping it fails SILENTLY and wrongly rather than loudly.
# Passing the value here means there is no variable to forget.
subject=${2:-}

# A value that looks like a flag is a mistake, not a subject.
#
# Watched on the lab box: the operator typed `./linux/card.sh 1 --approve`,
# reaching for an approval verb this tool does not have. It substituted
# "--approve" into every command on the card and printed, among others,
# `sudo userdel -f -r --approve` and `sudo passwd -l --approve`. None of those
# do what they look like they do, and one of them is a deletion.
#
# The card is printed, never run, so nothing happened - but the next step after
# reading a card is pasting from it, so a card full of plausible-looking
# nonsense is a loaded one. Refuse it and say what the argument is for.
case "$subject" in
  -*)
    printf 'card.sh: "%s" looks like an option, not a subject.\n\n' "$subject" >&2
    printf '  The second argument is the THING the finding is about - the username,\n' >&2
    printf '  unit, path or PID that triage.sh printed next to it. For example:\n\n' >&2
    printf '      ./linux/card.sh %s backupsvc\n' "$n" >&2
    printf '      ./linux/card.sh %s /etc/cron.d/system-metrics\n\n' "$n" >&2
    printf '  card.sh has no options other than -h. It prints a card; it never runs one.\n' >&2
    exit 1 ;;
esac

# Pull out just this card: from its heading to the next heading or ---.
body=$(awk -v want="$n" '
  /^## CARD / {
    # "## CARD 3 - title": field 3 is the number.
    num=$3; sub(/[^0-9].*$/, "", num)
    inside = (num == want) ? 1 : 0
    if (inside) { print; next }
  }
  inside && /^---[[:space:]]*$/ { inside=0 }
  inside { print }
' "$CARDS")

if [ -z "$body" ]; then
  printf 'card.sh: no card %s.\n' "$n" >&2
  list_cards
  exit 1
fi

# Render markdown to something a terminal reader can scan in a hurry:
#   - fences disappear; the lines inside them are commands, marked with "$"
#   - blockquote markers, bold markers and inline backticks are stripped
#   - everything else is prose, indented under the heading
if [ -n "$subject" ]; then
  # Replace the placeholder forms the cards use with the real value.
  body=$(printf '%s' "$body" | sed \
    -e "s|\"\$U\"|$subject|g" -e "s|\$U|$subject|g" \
    -e "s|\"\$F\"|$subject|g" -e "s|\$F|$subject|g" \
    -e "s|^U=.*|U=$subject|" -e "s|^F=.*|F=$subject|")
else
  body="$body
PLACEHOLDER WARNING: this card contains \$U / \$F placeholders. Either pass the
value - ./linux/card.sh $n <name-or-path> - or set it first with U=<name>.
An unset placeholder does not error; it matches EVERYTHING."
fi

if [ -n "$__cfg" ]; then
  card_config=$__cfg
  if command -v ccdc_load_config >/dev/null 2>&1; then
    ccdc_load_config "$__cfg"
  else
    # shellcheck disable=SC1090
    set -a; . "$__cfg" || card_config=''; set +a
  fi
  warn_if_protected
fi

printf '\n'
printf '%s\n' "$body" | awk '
  BEGIN { incode=0 }
  /^```/ {
    if (incode) { incode=0; print "" } else { incode=1; print "" }
    next
  }
  {
    line=$0
    sub(/^> ?/, "", line)                      # blockquote markers
    gsub(/\*\*/, "", line)                     # bold
    gsub(/`/, "", line)                        # inline code ticks
    sub(/^###+ /, "", line)                    # sub-headings
    if (line ~ /^## CARD /) {
      sub(/^## /, "", line)
      print "  " line
      bar=""; for (i=0; i<length(line)+2; i++) bar=bar "-"
      print "  " bar
      next
    }
    if (incode) {
      if (line ~ /^[[:space:]]*$/) { print ""; next }
      if (line ~ /^[[:space:]]*#/) { print "        " line; next }   # comment
      # No "$" prefix: it reads like a prompt and pastes like a syntax error
      # ("$: command not found"). Bash strips leading whitespace, so an
      # indented command pastes and runs exactly as written.
      print "      " line                                            # command
      next
    }
    print "  " line
  }
'
printf '\n  Type these ONE AT A TIME. Do not paste the whole card.\n\n'
