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
CARDS="$SCRIPT_DIR/../playbooks/remediation-cards.md"
[ -f "$CARDS" ] || CARDS="$SCRIPT_DIR/remediation-cards.md"
[ -f "$CARDS" ] || { printf 'card.sh: cannot find remediation-cards.md\n' >&2; exit 1; }

list_cards() {
  printf '\nRemediation cards - ./linux/card.sh <n> to read one\n\n'
  grep -n '^## CARD ' "$CARDS" | sed -E 's/^[0-9]+:## CARD /  /; s/ — / - /'
  printf '\n  triage.sh prints [CARD n] beside each finding.\n'
  printf '  Each card is: kill the access, find the way back in, verify.\n\n'
}

[ "$#" -ge 1 ] || { list_cards; exit 0; }
case "$1" in
  -h|--help) list_cards; exit 0 ;;
  ''|*[!0-9]*) printf 'card.sh: give a card number. Run with no arguments to list them.\n' >&2; exit 1 ;;
esac
n=$1

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
