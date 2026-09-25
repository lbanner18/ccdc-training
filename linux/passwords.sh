#!/usr/bin/env bash
set -u

# One password list for the scored accounts, used everywhere: the block you
# paste into Quotient's Password Change Request is the same block you paste
# into this tool on every box.
#
# The packet gives every competitor the same default password for every
# account, and the red team has read the packet. The first minutes decide who
# owns the box. users.sh deliberately never touches a packet account - changing
# one without telling the scorer costs that service - so the change that matters
# most had no tool at all.
#
#   --generate   print fresh passwords for the scored users in every form you
#                will need: the Quotient block, then how to apply it on Linux,
#                Windows, VyOS and Splunk. Run it on YOUR laptop the night
#                before and write the list on paper. Nothing touches disk
#                unless you pass --out FILE, which must be outside the kit.
#   --apply      read user,password lines from stdin (paste the Quotient block,
#                then press Ctrl-D) and set them. Stdin keeps the passwords out
#                of your shell history; a heredoc would put them in it.
#   (default)    read and check the block, change nothing.
#
# After --apply it logs into FTP and POP3 on this box as each account with its
# NEW password, because a server that keeps its own user list ignores chpasswd
# and the scorer would find that out for you, one failed check a minute.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"
umask 077

config=''
apply=0
generate=0
users=''
out=''
kick=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    --generate) generate=1; shift ;;
    --users) users=${2:?missing user list}; shift 2 ;;
    --out) out=${2:?missing output file}; shift 2 ;;
    --kick) kick=1; shift ;;
    -h|--help)
      printf 'usage: %s --generate [--config FILE | --users "a b c"] [--out FILE]\n' "$0"
      printf '       %s --config FILE [--dry-run|--apply] [--kick]   < the Quotient block\n' "$0"
      printf '\n'
      printf '  --generate  new passwords for the scored users, printed in every\n'
      printf '              form you need. Users come from --users, or from\n'
      printf '              CCDC_INTERACTIVE_USERS in the config.\n'
      printf '  --out FILE  also write that sheet to FILE (mode 600). Refused\n'
      printf '              inside the kit: the kit is a public repo.\n'
      printf '  --apply     set the passwords you paste (user,password per line,\n'
      printf '              exactly the Quotient block), then test FTP and POP3.\n'
      printf '  --kick      also end the other sessions of those accounts. Without\n'
      printf '              it they are listed, each with the command that ends it.\n'
      printf '\n'
      printf '  Every account you change here must go into Quotient'"'"'s PCR too, or\n'
      printf '  the scorer keeps using the old password and fails the service.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"

# Unambiguous on a screen and on paper (no I/l/1, O/0), typeable at a console
# that cannot paste, and safe in every place the password goes: no comma for
# Quotient's user,password; no colon for chpasswd; no quote, space, $, `, \ or
# % for a shell, cmd or VyOS. Four groups of four is ~93 bits, and 19
# characters clears any minimum-length policy an inject is likely to ask for.
PW_UPPER='ABCDEFGHJKLMNPQRSTUVWXYZ'
PW_LOWER='abcdefghijkmnpqrstuvwxyz'
PW_DIGIT='23456789'

new_password() {
  local p
  while :; do
    p=$(LC_ALL=C tr -dc "$PW_UPPER$PW_LOWER$PW_DIGIT" </dev/urandom 2>/dev/null | head -c 16)
    [ "${#p}" -eq 16 ] || continue
    case "$p" in *["$PW_UPPER"]*) ;; *) continue ;; esac
    case "$p" in *["$PW_LOWER"]*) ;; *) continue ;; esac
    case "$p" in *["$PW_DIGIT"]*) ;; *) continue ;; esac
    printf '%s-%s-%s-%s' "${p:0:4}" "${p:4:4}" "${p:8:4}" "${p:12:4}"
    return 0
  done
}

# --- --generate ---------------------------------------------------------------
if [ "$generate" -eq 1 ]; then
  [ -n "$users" ] || users=${CCDC_INTERACTIVE_USERS:-}
  users=$(printf '%s\n' $users | grep -vx root | tr '\n' ' ')
  [ -n "${users// /}" ] || ccdc_die "no users: pass --users \"steve alex ...\" or a config with CCDC_INTERACTIVE_USERS"
  if [ -n "$out" ]; then
    kit_root=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
    out_dir=$(CDPATH= cd -- "$(dirname -- "$out")" 2>/dev/null && pwd) \
      || ccdc_die "the directory for --out does not exist: $(dirname -- "$out")"
    case "$out_dir/" in
      "$kit_root"/*) ccdc_die "refusing to write passwords inside the kit ($kit_root): it is a public repo. Use e.g. --out ~/ccdc-passwords.txt" ;;
    esac
    [ ! -e "$out" ] || ccdc_die "refusing to overwrite $out; move it or pick another name"
  fi
  sheet() {
    local u root_pw vyos_pw splunk_pw admin_pw
    root_pw=$(new_password); vyos_pw=$(new_password); splunk_pw=$(new_password)
    admin_pw=$(new_password)
    printf '# Generated %s. Write this on paper. It is not in the repo and must never be.\n\n' "$(date '+%Y-%m-%d %H:%M')"
    # No comma in this header: pasted into Quotient by mistake, a comma would
    # make the header a "user,password" line.
    printf '===== 1. QUOTIENT: Password Change Request - paste as-is: one line per account =====\n'
    for u in $users; do printf '%s,%s\n' "$u" "$(new_password)"; done
    printf '\n'
    printf '===== 2. EACH LINUX BOX: paste block 1 into this, then press Ctrl-D =====\n'
    printf '  sudo ./linux/passwords.sh --config "$CFG" --apply\n\n'
    printf '===== 3. WINDOWS: paste block 1 into this, then press Enter on an empty line =====\n'
    printf '  .\\windows\\passwords.ps1 -Apply\n\n'
    printf '===== 4. NOT SCORED: change these too, and put NONE of them in Quotient =====\n'
    printf '  root (Linux boxes)     %s   sudo passwd root\n' "$root_pw"
    printf '  Administrator (Win)    %s   net user Administrator *\n' "$admin_pw"
    printf '  backup admin: alex, a packet admin - its password is its block 1 line. No new account:\n'
    printf '        the packet says each box has only its listed users.\n'
    printf '  vyos (router)          %s\n' "$vyos_pw"
    printf '        configure\n'
    printf '        set system login user vyos authentication plaintext-password '"'"'%s'"'"'\n' "$vyos_pw"
    printf '        commit\n        save\n        exit\n'
    printf '  Splunk admin           %s\n' "$splunk_pw"
    printf '        sudo /opt/splunk/bin/splunk edit user admin -password '"'"'%s'"'"' -auth '"'"'admin:OLD_PASSWORD'"'"'\n' "$splunk_pw"
    printf '\n  Same list on every box: one PCR list, and no guessing which box has which.\n'
  }
  if [ -n "$out" ]; then
    sheet | tee "$out"
    chmod 600 "$out" 2>/dev/null || true
    printf '\n(also written to %s, mode 600)\n' "$out" >&2
  else
    sheet
  fi
  exit 0
fi

# --- read and check the block --------------------------------------------------
# Checked before root is asked for: a typo in the block is reported whether or
# not you remembered sudo, and nothing below this point changes anything.
if [ -t 0 ]; then
  printf 'Paste the block (user,password, one per line), then press Ctrl-D:\n' >&2
fi

names=()
secrets=()
errors=''
absent=''
n=0
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  line=${line%$'\r'}
  line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  case "$line" in ''|'#'*|'====='*) continue ;; esac
  case "$line" in
    *,*,*) errors="$errors  line $n: more than one comma - Quotient reads user,password\n"; continue ;;
    *[[:space:]]*) errors="$errors  line $n: contains a space - Quotient's format has none\n"; continue ;;
    *,*) ;;
    *) errors="$errors  line $n: no comma - expected user,password\n"; continue ;;
  esac
  u=${line%%,*}
  p=${line#*,}
  if ! printf '%s' "$u" | grep -Eq '^[a-z_][a-z0-9_.-]*\$?$'; then
    errors="$errors  line $n: '$u' is not a Linux user name (the packet's are lowercase)\n"; continue
  fi
  [ -n "$p" ] || { errors="$errors  line $n: $u has an empty password\n"; continue; }
  if [ "${#p}" -lt "${CCDC_PW_MIN_LENGTH:-8}" ]; then
    errors="$errors  line $n: $u's password is ${#p} characters; the minimum is ${CCDC_PW_MIN_LENGTH:-8}\n"; continue
  fi
  if [ -n "${CCDC_PACKET_PASSWORD:-}" ] && [ "$p" = "$CCDC_PACKET_PASSWORD" ]; then
    errors="$errors  line $n: $u is being set to the packet's default password, which the red team has\n"; continue
  fi
  for seen in "${names[@]+"${names[@]}"}"; do
    [ "$seen" = "$u" ] && { errors="$errors  line $n: $u appears twice\n"; continue 2; }
  done
  # The same block goes on every box, and a box need not have every account
  # (the unscored one may have only the admins): skip, and say so, rather
  # than refuse the accounts it does have.
  if ! getent passwd "$u" >/dev/null 2>&1; then
    absent="$absent $u"; continue
  fi
  names+=("$u")
  secrets+=("$p")
done
unset line p

[ -z "$errors" ] || {
  printf 'Nothing was changed. Fix these and paste again:\n' >&2
  printf '%b' "$errors" >&2
  exit 1
}
if [ "${#names[@]}" -eq 0 ]; then
  [ -z "$absent" ] || ccdc_die "none of these accounts exist on $(hostname):$absent - is this the right box?"
  ccdc_die "no user,password lines were read"
fi

scored=${CCDC_INTERACTIVE_USERS:-}
missing=''
if [ -n "$scored" ]; then
  for s in $scored; do
    [ "$s" = root ] && continue
    ccdc_list_contains "$s" "${names[*]}" && continue
    getent passwd "$s" >/dev/null 2>&1 && missing="$missing $s"
  done
fi

if [ "$apply" -ne 1 ]; then
  printf 'The block reads cleanly: %s account(s): %s\n' "${#names[@]}" "${names[*]}"
  [ -z "$absent" ] || printf 'Not on this box, skipped:%s\n' "$absent"
  [ -z "$missing" ] || printf 'NOT in the block, still on the packet password:%s\n' "$missing"
  printf 'Nothing was changed. Re-run with --apply and paste it again to set them.\n'
  exit 0
fi

# --- apply ----------------------------------------------------------------------
ccdc_require_root
evidence=$(ccdc_timestamp_dir)
[ -n "$evidence" ] || ccdc_die "no usable evidence directory; see the error above"
mkdir -p "$evidence"
log="$evidence/passwords.log"

printf '\nSETTING %s PASSWORD(S) on %s\n' "${#names[@]}" "$(hostname)"
[ -z "$absent" ] || printf '  (not on this box, skipped:%s)\n' "$absent"
printf '\n'
failed=''
i=0
while [ "$i" -lt "${#names[@]}" ]; do
  u=${names[$i]}
  before=$(getent shadow "$u" | cut -d: -f2)
  err=$(printf '%s:%s\n' "$u" "${secrets[$i]}" | chpasswd 2>&1)
  rc=$?
  after=$(getent shadow "$u" | cut -d: -f2)
  notes=''
  st=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
  case "$st" in L|LK) notes="$notes LOCKED(sudo usermod -U $u)" ;; esac
  exp=$(getent shadow "$u" | cut -d: -f8)
  if [ -n "$exp" ] && [ "$exp" -le $(( $(date +%s) / 86400 )) ] 2>/dev/null; then
    notes="$notes EXPIRED(sudo usermod -e '' $u)"
  fi
  case "$(getent passwd "$u" | cut -d: -f7)" in
    */nologin|*/false) notes="$notes NO-SHELL(an SSH check as $u fails)" ;;
  esac
  if [ "$rc" -eq 0 ] && [ "$before" != "$after" ]; then
    printf '  ok      %-16s password set%s\n' "$u" "${notes:+   !!$notes}"
    ccdc_append_log "$log" "set user=$u${notes:+ notes=$notes}"
  else
    printf '  FAILED  %-16s %s\n' "$u" "${err:-the password hash did not change}"
    ccdc_append_log "$log" "FAILED user=$u rc=$rc"
    failed="$failed $u"
  fi
  i=$((i + 1))
done

# --- do the services accept the new passwords? ------------------------------------
listening() { ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"; }

ftp_reply() {
  local line
  ftp_code=''
  while IFS= read -r -t 8 line <&3; do
    line=${line%$'\r'}
    case "$line" in [0-9][0-9][0-9]' '*|[0-9][0-9][0-9]) ftp_code=${line:0:3}; return 0 ;; esac
  done
  return 1
}
ftp_login() {
  exec 3<>/dev/tcp/127.0.0.1/21 2>/dev/null || return 2
  ftp_reply || { exec 3<&- 3>&-; return 2; }
  printf 'USER %s\r\n' "$1" >&3
  ftp_reply || { exec 3<&- 3>&-; return 2; }
  if [ "$ftp_code" = 331 ]; then
    printf 'PASS %s\r\n' "$2" >&3
    ftp_reply || { exec 3<&- 3>&-; return 2; }
  fi
  printf 'QUIT\r\n' >&3 2>/dev/null
  exec 3<&- 3>&-
  [ "$ftp_code" = 230 ]
}
pop3_login() {
  local line
  pop3_last=''
  exec 3<>/dev/tcp/127.0.0.1/110 2>/dev/null || return 2
  IFS= read -r -t 8 line <&3 || { exec 3<&- 3>&-; return 2; }
  printf 'USER %s\r\n' "$1" >&3
  IFS= read -r -t 8 line <&3 || { exec 3<&- 3>&-; return 2; }
  case "$line" in -ERR*) pop3_last=${line%$'\r'}; exec 3<&- 3>&-; return 3 ;; esac
  printf 'PASS %s\r\n' "$2" >&3
  IFS= read -r -t 15 line <&3 || { exec 3<&- 3>&-; return 2; }
  printf 'QUIT\r\n' >&3 2>/dev/null
  exec 3<&- 3>&-
  pop3_last=${line%$'\r'}
  case "$line" in '+OK'*) return 0 ;; esac
  return 1
}

check_service() {
  local label=$1 port=$2 fn=$3 ok='' bad='' untestable='' rc i=0
  listening "$port" || return 0
  while [ "$i" -lt "${#names[@]}" ]; do
    u=${names[$i]}
    if [ "$u" != root ]; then
      "$fn" "$u" "${secrets[$i]}"; rc=$?
      case "$rc" in
        0) ok="$ok $u" ;;
        3) untestable="$untestable $u" ;;
        *) bad="$bad $u" ;;
      esac
    fi
    i=$((i + 1))
  done
  if [ -n "$untestable" ] && [ -z "$ok$bad" ]; then
    printf '  %-5s port %-4s cannot test: %s\n' "$label" "$port" "$pop3_last"
    printf '              (plaintext logins are refused on this port; the scorer then uses TLS)\n'
  elif [ -z "$bad" ]; then
    printf '  %-5s port %-4s accepts every new password\n' "$label" "$port"
  elif [ -z "$ok" ]; then
    printf '  %-5s port %-4s REJECTED EVERY new password:%s\n' "$label" "$port" "$bad"
    printf '              It probably keeps its own user list, which chpasswd does not touch.\n'
    printf '              The scorer will fail this service until that list has the new passwords.\n'
    printf '              Look for: guest_enable / user_config_dir / pam_service_name (vsftpd),\n'
    printf '              passdb {} in /etc/dovecot/conf.d/ (dovecot).\n'
  else
    printf '  %-5s port %-4s accepts:%s\n' "$label" "$port" "$ok"
    printf '              rejects:%s   (normal if the server only admits some accounts - check its user list)\n' "$bad"
  fi
  ccdc_append_log "$log" "service=$label ok=${ok:- } rejected=${bad:- }"
}

if listening 21 || listening 110; then
  printf '\nCAN THE SERVICES LOG IN WITH THE NEW PASSWORDS? (from this box, as the scorer would)\n'
  check_service FTP 21 ftp_login
  check_service POP3 110 pop3_login
fi

# --- who else is logged in as these accounts? -----------------------------------
own_tty=$(ps -o tty= -p $$ 2>/dev/null | tr -d ' ')
case "$own_tty" in ''|'?') own_tty='' ;; esac
# This run's own chain - sudo, your shell, your sshd - is yours whether or not
# it has a terminal. Measured: run over ssh without one, the first version
# offered to kill the session that was running it.
ancestors=' '
a=$$
while [ -n "$a" ] && [ "$a" -gt 1 ] 2>/dev/null; do
  ancestors="$ancestors$a "
  a=$(ps -o ppid= -p "$a" 2>/dev/null | tr -d ' ')
done
# Service workers that run as the account for one FTP or POP3 login (killing
# one fails a scoring check), and the per-user systemd manager, which exists
# while ANY session of that user is open and is not a login itself.
workers='^(vsftpd|proftpd|pure-ftpd|in.ftpd|dovecot|pop3|imap|pop3-login|imap-login|auth|anvil|log|\(sd-pam\))$'
sessions=''
for u in "${names[@]}"; do
  [ "$u" = root ] && continue
  while read -r pid ppid tty etime comm args; do
    [ -n "${pid:-}" ] || continue
    case "$ancestors" in *" $pid "*) continue ;; esac
    # A child of your own shell - the tee or less this was piped into, a job
    # you backgrounded - is yours too. Measured: a pipeline's sed was listed.
    case "$ancestors" in *" $ppid "*) continue ;; esac
    [ -n "$own_tty" ] && [ "$tty" = "$own_tty" ] && continue
    printf '%s' "$comm" | grep -Eq "$workers" && continue
    case "$comm $args" in 'systemd '*--user*) continue ;; esac
    sessions="$sessions$u|$pid|$tty|$etime|$args"$'\n'
  done < <(ps -o pid=,ppid=,tty=,etime=,comm=,args= -u "$u" 2>/dev/null)
done
if [ -n "$sessions" ]; then
  printf '\nSTILL RUNNING AS THESE ACCOUNTS, NOT IN YOUR TERMINAL (%s)\n' "${own_tty:-unknown}"
  printf '  A session opened with the OLD password stays open after the change.\n'
  printf '  If you have a second terminal of your own open, it is in this list too.\n\n'
  ttys=''
  while IFS='|' read -r u pid tty etime args; do
    [ -n "$u" ] || continue
    printf '  %-12s pid %-7s %-6s up %-10s %s\n' "$u" "$pid" "$tty" "$etime" "$(printf '%s' "$args" | cut -c1-60)"
    if [ "$tty" != '?' ]; then
      case " $ttys " in *" $tty "*) ;; *) ttys="$ttys $tty" ;; esac
    fi
  done <<<"$sessions"
  printf '\n'
  if [ "$kick" -eq 1 ] && [ -n "$own_tty" ]; then
    for t in $ttys; do pkill -KILL -t "$t" 2>/dev/null && printf '  ended every process on %s\n' "$t"; done
    while IFS='|' read -r u pid tty etime args; do
      [ -n "$u" ] && [ "$tty" = '?' ] || continue
      kill -KILL "$pid" 2>/dev/null && printf '  killed pid %s (%s)\n' "$pid" "$u"
    done <<<"$sessions"
    ccdc_append_log "$log" "kicked ttys=${ttys:- }"
  else
    [ "$kick" -eq 1 ] && printf '  NOT kicking: cannot tell which terminal is yours.\n'
    for t in $ttys; do printf '  end it:  sudo pkill -KILL -t %s\n' "$t"; done
    while IFS='|' read -r u pid tty etime args; do
      [ -n "$u" ] && [ "$tty" = '?' ] || continue
      printf '  end it:  sudo kill -KILL %s    # %s, no terminal\n' "$pid" "$u"
    done <<<"$sessions"
    printf '  or all of the above at once:  re-run with --kick\n'
  fi
fi

# --- what is left to do ---------------------------------------------------------
printf '\n'
if [ -n "$failed" ]; then
  printf 'NOT CHANGED:%s - they still have their old password. Fix and paste just those lines again.\n' "$failed"
fi
[ -z "$missing" ] || printf 'STILL ON THE PACKET PASSWORD (not in your block):%s\n' "$missing"
printf '==== NOW, IN QUOTIENT ====\n'
printf '  Password Change Request for %s: the same lines you pasted, for:\n' "$(hostname)"
printf '  %s\n' "$(printf '%s\n' "${names[@]}" | grep -vx root | tr '\n' ' ')"
printf '  Until Quotient has them, the scorer logs in with the old ones and fails.\n'
[ -z "$failed" ]
