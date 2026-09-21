# Remediation cards — you found it, now what

There is one card for each finding `triage.sh` can print. Use the same order
each time: stop the access, find what would recreate it, then verify it is gone.

> ## ⛔ DO NOT `cat` OR PASTE THIS FILE INTO A SHELL
>
> Read it with **`./linux/card.sh <n> <name-or-path>`** instead:
>
> ```
> ./linux/card.sh              # list the cards
> ./linux/card.sh 1 backupsvc  # card 1, with the real username filled in
> ```
>
> This file is not a shell script. If you paste it into bash, bash tries to run
> the English sentences as commands. Some real commands in the file could also
> run with the wrong values. Use `card.sh`, `less`, or the web copy instead.
>
> `card.sh` prints one card for you to read. It does not run the commands from
> that card. That is safer than copying a large markdown file into a terminal.
>
> **Also: do not leave `$U` or `$F` empty.** For example,
> `grep -rn "$U" /etc/ssh/sshd_config` with an empty `$U` matches every line.
> `card.sh` fills in the value you give it, so there is less to remember.
>
> ### If the scripts are gone
>
> This file is the fallback, and it is deliberately readable without any of
> them — a red team that deletes `linux/` takes `card.sh` with it, and that is
> the moment you most need these commands. Three ways in, none of which
> execute anything:
>
> ```
> less playbooks/remediation-cards.md          # scroll; /CARD 1 to search
> sed -n '/## CARD 1/,/^---/p' playbooks/remediation-cards.md
> ```
>
> or read it on another device at
> `github.com/lbanner18/ccdc-training/blob/main/playbooks/remediation-cards.md`.
>
> **`less`, not `cat`.** `less` pages it into a viewer; `cat` dumps it into your
> scrollback, and the next thing you do is select-and-paste part of it.

> If `linux/` was deleted, the normal `arm.sh` setup also leaves a root-owned
> restore helper outside the checkout. It verifies the newest saved kit before
> extracting a new copy; it does not overwrite the current directory:
>
> ```bash
> sudo /var/backups/ccdc/ccdc-kit-recover.sh --restore /root/ccdc-recovered --apply
> ```
>
> Use your configured `CCDC_RECOVERY_DIR` instead of `/var/backups/ccdc` if you
> changed it. Then read or run files from `/root/ccdc-recovered/kit` after you
> inspect them.
>
> Every command in this file is a real command you could have typed yourself.
> Nothing here depends on a script in this repo, by design: the scripts are the
> fast path, this is the path that survives.

**Three rules that apply to every card:**

1. **Snapshot before you clean, if the environment allows it.** The snapshot is
   your only forensics and it is the evidence for the incident-report inject.
2. **Removing the artifact is half the job.** An attacker who got root once has
   almost certainly left a second way in. Every card has a "way back in"
   section; do not skip it because the first fix looked clean.
3. **Check the packet before deleting anything that might be scored.** A
   service account you delete is downtime you caused. When unsure: disable it,
   do not remove it. You can always delete later; you cannot un-break uptime.

---

## CARD 1 — UID-0 account that is not root

`RED  account(s) with UID 0 other than root`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# UID-0 accounts that are not root
awk -F: '$3==0 && $1!="root" {print}' /etc/passwd

# accounts with NO password at all
sudo awk -F: '$2=="" {print $1}' /etc/shadow
```

> ### ☠️ READ THIS BEFORE YOU TYPE ANYTHING
>
> **Never run `pkill -u <name>` or `ps -u <name>` on a UID-0 account.** The name
> resolves to **UID 0**, which is root. Measured on the lab box: `ps -u
> svc-monitor` and `ps -u root` both returned **the same 136 processes**. So
> `pkill -9 -u svc-monitor` does not kill the attacker's shell — it kills
> `systemd`, `sshd`, your session and every scored service on the machine.
>
> This card told you to do exactly that until it was tested. Kill by **PID**,
> never by user, for a duplicate-UID-0 account.

```bash
U=svc-monitor                      # <- the name triage printed

# 0. WHERE DOES IT LIVE? Do this first, because it decides step 5.
#    A UID-0 backdoor's home is very often /root - that is the point of it.
H=$(awk -F: -v u="$U" '$1==u {print $6}' /etc/passwd); echo "$H"
awk -F: -v h="$H" '$6==h {print $1}' /etc/passwd    # anyone else living there?

# 1. STOP IT BEING USABLE. Safe, instant, and reversible if it turns out to be
#    a scored account with a mangled UID rather than an implant.
sudo passwd -l "$U"                        # lock the password
sudo usermod -s /usr/sbin/nologin "$U"     # no shell on next login

# 2. Is anyone logged in AS it right now? Find sessions by NAME, then kill the
#    specific PIDs - never by UID (see the warning above).
who; w
ps -ef | grep -w "$U" | grep -v grep       # note the PIDs, kill them one by one
# sudo kill -9 <pid> <pid>

# 3. Is it actually theirs? Check before deleting.
grep "^$U:" /etc/passwd
sudo last "$U" | head
sudo ls -la "$H" 2>/dev/null               # $H from step 0, NOT /home/$U

# 4. THE WAY BACK IN - all of these, not just the first.
sudo crontab -u "$U" -l 2>/dev/null          # their personal crontab
sudo grep -rn "$U" /etc/cron.d /etc/cron.* /etc/sudoers /etc/sudoers.d 2>/dev/null
sudo cat "$H/.ssh/authorized_keys" 2>/dev/null
sudo grep -rn "$U" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null
sudo ls -la "$H/.config/systemd/user/" 2>/dev/null   # user-level units

# 5. REMOVE. The -f is REQUIRED for a UID-0 account and is not optional:
#    without it userdel refuses outright (see the trap below).
#    -r is a SEPARATE decision. It deletes $H. Read the trap below first.
sudo crontab -u "$U" -r 2>/dev/null
sudo userdel -f "$U"                       # add -r ONLY per the trap below

# 6. VERIFY - all four of these
awk -F: '$3==0 {print $1}' /etc/passwd      # should be: root, and only root
grep -c "^$U:" /etc/shadow                  # should be: 0
id "$U" 2>&1                                # should be: no such user
systemctl is-active ssh <your scored unit>  # should still be: active
```

**Trap — and this is why step 5 needs `-f`:** a duplicate-UID-0 account breaks
`userdel` and `usermod`. Both refuse with:

```
userdel: user svc-monitor is currently used by process 1
```

Process 1 is `systemd`. It is not the attacker's — the tools simply cannot tell
the two UID-0 accounts apart. Verified on the lab box: plain `userdel -r` and
`usermod -u` both **failed and changed nothing**, while `userdel -f`
succeeded, removed the `/etc/shadow` entry, and left all 136 root processes and
the scored service running. The warning still prints. Ignore it and check step 6
instead.

**Trap — `-r` deletes `$H`, and `$H` is probably not theirs.** A UID-0 backdoor
usually has `/root` as its home directory, because that is what makes it root.
`userdel -r` on such an account **deletes `/root`**: root's `authorized_keys`,
root's dotfiles, and anything the team or a scored service kept there.

This card and `triage.sh` both printed `userdel -f -r` unconditionally until an
operator pasted it on the lab box and `/root` went with the account — noticed
forty minutes later, and only because a canary deployed under `/root` could no
longer be found. `triage.sh` now works the home directory out for you and omits
`-r` when the directory is not the account's alone.

Use step 0's answer:

| `$H` | what to run |
|---|---|
| `/root`, `/`, `/etc`, `/var`, any system directory | `sudo userdel -f "$U"` — **never** `-r` |
| shared with another account in step 0 | `sudo userdel -f "$U"` — **never** `-r` |
| its own directory, e.g. `/home/svc-monitor` | `sudo userdel -f -r "$U"` is fine |

When you skip `-r`, the directory stays. That is the right outcome: read it
yourself afterwards. On a UID-0 backdoor it is root's own home, and what is in
it is evidence.

**Trap:** a second UID-0 account is a classic pair — the attacker expects you to
find one. Re-run the `awk` in step 6 after removing it.

**If the account is NOT UID 0** (an ordinary rogue user), `pkill -9 -u "$U"` is
safe and is the right first move, and `userdel -r "$U"` works — subject to the
same `$H` check, which an ordinary account will normally pass.

---

## CARD 2 — SSH key you do not recognise

`AMBER  N SSH key(s) grant login`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# every file that grants SSH login, and what is in it
sudo find /root /home -maxdepth 3 -name authorized_keys -exec ls -la {} \;
sudo find /root /home -maxdepth 3 -name authorized_keys -exec cat {} \;

# the two sshd settings that point key auth somewhere you are not watching
sudo grep -rnE 'AuthorizedKeysFile|AuthorizedKeysCommand|Match ' \
     /etc/ssh/sshd_config /etc/ssh/sshd_config.d
```

```bash
# 0. FIRST: which key are YOU using? Do not lock yourself out.
#    Run this from your LOCAL machine, not the box:
#      ssh-keygen -lf ~/.ssh/id_ed25519.pub
#    and match the comment/fingerprint against what triage printed.

F=/root/.ssh/authorized_keys       # <- the file triage printed
sudo cp "$F" "$F.bak.$(date +%s)"  # keep the original; it is evidence

# 1. Look at the whole line before you delete it - the comment at the end is
#    the attacker's own label and belongs in your incident report.
sudo cat "$F"

# 2. Remove just that key. Match on something unique to it.
sudo sed -i '/rt-implant/d' "$F"           # by its comment
# or, safer if the comment is generic, by a chunk of the key itself:
sudo sed -i '\|AAAAC3NzaC1lZDI1NTE5AAAAIHcQ9w|d' "$F"

# 3. THE WAY BACK IN
sudo find /root /home -maxdepth 3 -name authorized_keys -exec ls -la {} \;
sudo grep -rnE 'AuthorizedKeysFile|AuthorizedKeysCommand|Match ' \
     /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null
#    ^ an attacker can point sshd at a file you are not watching, or add a
#      Match block that re-enables password auth for one account.
sudo ls -la /root/.ssh/ /home/*/.ssh/      # rogue authorized_keys2, config, etc.

# 4. VERIFY - and keep your current session OPEN while you do it.
sudo sshd -t && sudo systemctl reload ssh
#    then from your local machine, in a NEW terminal:
#      ssh banneluk@<box>          <- must still work
```

**Trap:** never `> authorized_keys` to empty it. If your own key is in there you
have just locked yourself out of the box mid-competition. Delete the one line.

**Trap:** removing the key does not close an *already-open* session. Check
`who` and `ss -tnp | grep :22`, and kill their PTS if one is live.

---

## CARD 3 — scheduled job that calls home

`RED  scheduled job(s) containing reverse-shell or download-and-run patterns`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
SHELLS='/dev/tcp|/dev/udp|nc -|ncat|netcat|bash -i|sh -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|python.? -c|perl -e|socat'

# scheduled jobs containing a reverse shell or download-and-run
sudo grep -rIlE "$SHELLS" /etc/cron.d /etc/cron.daily /etc/cron.hourly \
     /etc/cron.weekly /etc/cron.monthly /etc/crontab /var/spool/cron

# every scheduler on the box, not just cron.d
sudo ls -la /etc/cron.d/ /etc/cron.daily/
for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -u "$u" -l 2>/dev/null | sed "s|^|$u: |"; done
systemctl list-timers --all --no-pager
sudo atq
```

```bash
F=/etc/cron.d/apt-compat-check     # <- the file triage printed

# 1. Read it and write down what it did, then remove it.
sudo cat "$F"
sudo cp "$F" /var/tmp/evidence-$(basename "$F").$(date +%s)
sudo rm -f "$F"

# 2. DID IT ALREADY RUN? A */6 job has probably fired. Look for the result.
sudo grep -rn "$(basename "$F")" /var/log/syslog /var/log/cron* 2>/dev/null | tail
ps -ef | grep -E 'dev/tcp|nc |ncat|bash -i' | grep -v grep
sudo ss -tnp | grep -v '127.0.0.1'         # live outbound connections

# 3. THE WAY BACK IN - every scheduler on the box, not just the one you found.
sudo ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
sudo cat /etc/crontab
for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -u "$u" -l 2>/dev/null | \
  sed "s|^|$u: |"; done
sudo atq                                    # one-shot `at` jobs
systemctl list-timers --all --no-pager      # systemd timers do the same job
sudo ls -la /etc/systemd/system/*.timer 2>/dev/null

# 4. VERIFY
sudo ./linux/triage.sh --config /tmp/ccdc-linux.env
```

**Trap:** the cron entry is the *schedule*, not the payload. If it ran
`/usr/local/bin/update-helper`, that file is still there. Follow the command in
the entry to whatever it invoked and remove that too.

---

## CARD 4 — systemd unit that calls home, or runs from /tmp

`RED  systemd unit(s) containing reverse-shell...` / `...executing from a

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
SHELLS='/dev/tcp|/dev/udp|nc -|ncat|netcat|bash -i|sh -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|python.? -c|perl -e|socat'

# units whose own text contains a reverse shell
sudo grep -rIlE "$SHELLS" /etc/systemd/system /run/systemd/system

# units executing out of a world-writable directory
sudo grep -rIlE '^Exec[A-Za-z]*=.*(/tmp/|/var/tmp/|/dev/shm/)' /etc/systemd/system

# THE ONE THAT MATTERS: follow ExecStart one level down and read the script.
# A clean path in an ordinary directory hides the payload from both greps above.
for unit in /etc/systemd/system/*.service; do
  t=$(awk -F= '/^ExecStart=/ {print $2; exit}' "$unit" | awk '{print $1}' | sed 's/^[-@+!]*//')
  [ -f "$t" ] && grep -qIE "$SHELLS" "$t" && echo "HIT: $unit -> $t"
done
```
world-writable directory`

```bash
U=evil.service                     # <- the unit triage printed

sudo systemctl cat "$U"            # read it; note ExecStart and User
sudo systemctl disable --now "$U"
sudo cp "/etc/systemd/system/$U" /var/tmp/evidence-$U.$(date +%s) 2>/dev/null
sudo rm -f "/etc/systemd/system/$U" "/run/systemd/system/$U"
sudo rm -rf "/etc/systemd/system/$U.d"      # drop-in overrides live here
sudo systemctl daemon-reload
sudo systemctl reset-failed                 # clears the not-found ghost

# THE WAY BACK IN
sudo grep -rlE '/tmp/|/dev/shm/|/dev/tcp|curl|wget|base64' \
     /etc/systemd/system /run/systemd/system 2>/dev/null
sudo systemctl list-unit-files --state=enabled | grep -vE '^(systemd|dbus|net)'
ls -la /etc/systemd/system/*.wants/         # what pulls it in at boot
sudo ls -la /etc/systemd/system/*.d/        # overrides on LEGITIMATE units

# VERIFY
systemctl is-enabled "$U" 2>&1              # should be: No such file
```

**Trap:** a drop-in (`<unit>.d/override.conf`) leaves the unit file
byte-identical while adding `ExecStartPost=`. Your hash check sees nothing. This
is why the `*.d/` lines above are not optional — and it is the attack
`guardian.sh` defends its own units against.

---

## CARD 5 — SUID interpreter

`RED  SUID interpreter(s)/utilities`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# SUID shells, interpreters and file utilities - never a legitimate choice
sudo find / -xdev -perm -4000 -type f 2>/dev/null \
  | grep -E '/(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|ruby|php|awk|find|vim?|nano|less|more|tar|cp|env|node)$'

# the full lists, when you have time to read them
sudo find / -xdev -perm -4000 -type f 2>/dev/null   # SUID
sudo find / -xdev -perm -2000 -type f 2>/dev/null   # SGID
getcap -r / 2>/dev/null                             # capabilities
```

```bash
F=/usr/bin/python3.12              # <- whatever triage printed

ls -l "$F"                         # record the mode before you change it
sudo chmod u-s "$F"                # remove SUID; do NOT delete the binary -
                                   # it is almost certainly a real system file

# THE WAY BACK IN
sudo find / -xdev -perm -4000 -type f 2>/dev/null    # full list, read it once
sudo find / -xdev -perm -2000 -type f 2>/dev/null    # SGID too
getcap -r / 2>/dev/null                              # capabilities, the quiet
                                                     # equivalent of SUID

# VERIFY
ls -l "$F"                                           # no 's' in the mode
```

**Trap:** removing SUID from the *wrong* binary breaks things — `sudo`, `su`,
`passwd`, `mount`, `ping` are legitimately SUID. Only strip it from shells,
interpreters, and file utilities (`find`, `vim`, `less`, `tar`, `cp`, `env`).

---

## CARD 6 — process running from /tmp, or with a deleted executable

`RED  process(es) executing from /tmp...` / `AMBER  ...executable was deleted`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# processes executing from a world-writable directory
ls -l /proc/*/exe 2>/dev/null | grep -E '/(tmp|var/tmp|dev/shm)/'

# processes whose executable was deleted from disk (memory-only payloads)
ls -l /proc/*/exe 2>/dev/null | grep '(deleted)'

# what is it talking to?
sudo ss -tnp | grep -v 127.0.0.1
```

```bash
P=1234                             # <- the PID triage printed

# 1. Identify it BEFORE you kill it - once it is gone, so is the evidence.
sudo ls -l /proc/$P/exe            # the real path (or "(deleted)")
sudo cat /proc/$P/cmdline | tr '\0' ' '; echo
sudo ls -l /proc/$P/cwd
sudo ss -tnp | grep "pid=$P"       # who is it talking to?
ps -o pid,ppid,user,etime,args -p $P

# 2. If the exe was deleted, recover it from /proc while the process lives -
#    this is the ONLY copy and the IR inject will ask what it was.
sudo cp "/proc/$P/exe" "/var/tmp/recovered-$P.bin"

# 3. Kill it, then remove the file if it still exists on disk.
sudo kill -9 $P
sudo rm -f /tmp/NAME /var/tmp/NAME /dev/shm/NAME

# 4. THE WAY BACK IN - something started it, and will again.
#    Work CARD 3 (schedulers) and CARD 4 (units) now.
ls -la /tmp /var/tmp /dev/shm
```

**Trap:** kill it and it comes back in 60 seconds = it has a scheduler. Do not
keep killing it; find what restarts it.

---

## CARD 7 — passwordless sudo you did not configure

`AMBER  passwordless sudo is configured`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# passwordless sudo
sudo grep -rIh '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d

# read every drop-in - a file named "10-base" is not automatically legitimate
sudo grep -rn '^[^#]' /etc/sudoers.d/
```

```bash
sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d

# Remove the offending line. ALWAYS edit with visudo - it syntax-checks, and a
# broken sudoers file means nobody on the box can use sudo again.
sudo visudo                        # for /etc/sudoers
sudo visudo -f /etc/sudoers.d/FILE

# THE WAY BACK IN
ls -la /etc/sudoers.d/             # a file named "10-base" is not automatically
                                   # legitimate; read every one
sudo grep -rn '^[^#]' /etc/sudoers.d/
getent group sudo admin wheel      # who is in the admin groups?

# VERIFY
sudo -l -U "$U"                    # what can that user actually do now
```

**Trap:** keep your own passwordless sudo if that is how you are working, or
your next command will prompt for a password you may not have.

---

## CARD 8 — unexpected listening port

`AMBER  listening TCP port(s) not in CCDC_ALLOWED_TCP_PORTS`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# every listening socket, with the process that owns it
sudo ss -tulpn

# ignore 127.0.0.x and ::1 - they show on no nmap scan. Compare what is left
# against the scored ports in your packet.
sudo ss -tlnH | awk '$4 !~ /^(127\.|\[::1\])/ {print $4}' | sed 's/.*://' | sort -un
```

```bash
P=4444                             # <- the port triage printed

sudo ss -tlnp "sport = :$P"        # which process owns it
# then follow CARD 6 with that PID if it is not a real service.

# If it IS a real service you simply do not need:
sudo ./linux/services.sh --config /tmp/ccdc-linux.env --review
# ...then add it to CCDC_DISABLE_SERVICES and --disable --apply.

# If it is scored, do NOT close it. Add it to CCDC_ALLOWED_TCP_PORTS so triage
# stops flagging it, and let fw.sh allow it explicitly.
```

**Trap:** an unexpected *outbound* connection matters more than an inbound
listener, and this check does not look for one. `sudo ss -tnp | grep -v 127.0.0.1`
is the command; anything talking to an address you do not recognise is a C2
channel.

---

## CARD 9 — /etc changed and it was not you

`AMBER  /etc file(s) modified in the last N minutes`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# /etc files changed in the last 30 minutes
sudo find /etc -xdev -type f -mmin -30 2>/dev/null

# what changed vs your baseline (this is why recon.sh runs FIRST)
./linux/diff-evidence.sh OLD_DIR NEW_DIR

# package-owned files, checked against the distro's own hashes
sudo dpkg --verify 2>/dev/null | head -20     # Debian/Ubuntu
sudo rpm -Va 2>/dev/null | head -20           # RHEL/CentOS
```

```bash
# 1. WAS it you? Your own hardening shows up here. Check the timestamps against
#    what you ran. Guardian units appearing right after arm.sh is expected.

# 2. For anything you did not do - what changed?
sudo ./linux/diff-evidence.sh OLD_DIR NEW_DIR
#    (this is why recon.sh runs FIRST, before you change anything)

# 3. Restore from your own backup if it is one of the files you saved:
sudo ./linux/backup.sh --config /tmp/ccdc-linux.env --list
sudo ./linux/backup.sh --config /tmp/ccdc-linux.env --restore TARGET_PATH --apply

# 4. Package-owned files can be checked against the distro's own hashes:
sudo dpkg --verify 2>/dev/null | head -20        # Debian/Ubuntu
sudo rpm -Va 2>/dev/null | head -20              # RHEL/CentOS
```

**Trap:** `/etc/passwd`, `/etc/shadow` and `/etc/sudoers` changing together is
an account being added. Go to CARD 1.

---

## CARD 10 — service account with a shell, or in an admin group

`RED  service account(s) with a login shell` / `RED  system account(s) in an admin group`

### Find it yourself

The command that surfaces this. `triage.sh` runs exactly this internally, so
if the scripts are gone - or you just want to check by hand - type this:

```bash
# service accounts (UID < 1000) that have been given a login shell
awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync)$/ {print $1":"$3":"$7}' /etc/passwd

# who can become root. adm is NOT one of these - it grants log read access,
# and syslog is in it on every stock Ubuntu.
getent group sudo wheel admin

# every account with a real shell, for comparison
getent passwd | awk -F: '$7 ~ /(bash|sh)$/ {print $1, $7}'
```

A system account (UID under 1000) runs a daemon. It has no reason to own a
login shell or to be able to become root. Granting either is quiet, durable,
and survives every password reset you do.

```bash
U=www-lab                          # <- the name triage printed

# 1. Take away what it should never have had.
sudo gpasswd -d "$U" sudo          # and wheel / admin if it is in those
sudo usermod -s /usr/sbin/nologin "$U"
sudo pkill -u "$U"                 # the -u matters - see the trap below

# 2. THE WAY BACK IN
sudo crontab -u "$U" -l 2>/dev/null
sudo ls -la "/home/$U/.ssh/" 2>/dev/null
sudo grep -rn "$U" /etc/sudoers /etc/sudoers.d 2>/dev/null

# 3. VERIFY
getent passwd "$U"                 # shell should be nologin
id -nG "$U"                        # no sudo / wheel / admin
```

**Do NOT `userdel` a service account.** `www-lab` probably owns the scored web
content; deleting it is downtime you caused yourself. Remove the shell and the
group membership and leave the account in place.

**Trap:** `pkill www-lab` matches process *names*, not users, so it silently
does nothing. You want `pkill -u www-lab`. This cost real time in a drill.

---

## CARD 11 — something runs on every login, or inside every process

`RED  loader     /etc/ld.so.preload` · `RED  profile  /etc/profile.d/NAME.sh`
`RED  motd       /etc/update-motd.d/NAME` · `NOTE  usershell  /home/NAME/.bashrc`

Two different mechanisms live on this card because they are answered the same
way and found by the same pass.

**A start-up file** runs every time somebody opens a shell — *including the next
time you run `sudo -i`*. This is persistence that fires on the defender's own
hands, and no process or unit listing shows it until after it has run.

**`/etc/ld.so.preload`** is worse. It is not a shell thing at all: the dynamic
loader reads it before `main()` in **every dynamically linked program on the
box**, root or not, shell or daemon, including the tools you are about to use
to investigate. A library listed there can lie to `ls`, `ps`, `ss` and this kit.

### Which one you have decides what you approve

The finding's *kind* tells you, and it is printed on the row:

| kind | what it is | the whole file is the finding? |
|---|---|---|
| `loader` | `/etc/ld.so.preload` | **Yes.** Stock Ubuntu does not ship this file. Its existence is the finding. |
| `profile` | a file in `/etc/profile.d/` | **Yes.** One file per purpose; you are not editing someone else's lines out of it. |
| `motd` | a file in `/etc/update-motd.d/` | **Yes.** Same shape, and it runs as root on every SSH login. |
| `usershell` | `~/.bashrc`, `~/.profile`, `/etc/bash.bashrc` | **No.** It is a real file with real content, and one line of it is theirs. |

### Approve it — the first three

`baseline.sh` prints these with a number. Read it, then approve that number:

```bash
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env --status
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env --explain N   # the full case
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env --approve N --apply
```

It copies the file to evidence, then deletes it. For `loader` that is the right
answer with no caveat: there is nothing legitimate in that file to keep.

**After removing `/etc/ld.so.preload`, find the library it named.** Deleting the
list does not delete what was on it, and nothing loads it any more only for
processes started *after* the change — everything already running still has it
mapped:

```bash
sudo cat /var/tmp/ccdc-evidence/*/1-ld.so.preload    # what it pointed at
sudo grep -l . /proc/*/maps 2>/dev/null | head       # or, per process:
sudo grep -H 'THELIB' /proc/*/maps 2>/dev/null | cut -d/ -f3 | sort -u
sudo cp -a /path/to/THELIB /var/tmp/ccdc-evidence/ && sudo rm -f /path/to/THELIB
```

Every process in that list is still running injected code. Restart them, and
treat anything that will not restart cleanly as a separate finding.

### The fourth one is not approvable, and here is why

`usershell` is held. The file is legitimate; one line in it is not, and there is
no safe way for a tool to guess which. Delete the wrong line from `/root/.bashrc`
and you have broken root's shell on a box you are being scored on.

```bash
F=/home/NAME/.bashrc                     # the path printed on the row
sudo cp -a "$F" /var/tmp/ccdc-evidence/
sudo diff <(sudo cat /etc/skel/.bashrc) "$F"    # what is different from stock
sudo nano "$F"                                  # delete ONLY the offending line
```

Then follow what it launched — the hook is the trigger, not the payload:

```bash
sudo cat /usr/local/bin/NAME
```

### If it is yours

Say so once, and stop being asked. `baseline.sh` records it against the blessed
inventory, with the reason:

```bash
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env \
     --allow /etc/profile.d/company-motd.sh \
     --reason "inject 3: the banner they asked for" --apply
```

For a finding that came from `triage.sh` or `sentry.sh --status` rather than
from the baseline, the equivalent is a standing exception:

```bash
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --muted     # what is silenced now
```

Both keep the reason and the date with the entry, and the count of silenced
findings is printed at the top of every report — so this quiets the list
without hiding anything.

### Find it yourself

```bash
sudo ls -la /etc/ld.so.preload /etc/profile.d/ /etc/update-motd.d/

SHELLS='/dev/tcp|/dev/udp|nc -|ncat|netcat|bash -i|sh -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|python.? -c|perl -e|socat'
for f in /root/.bashrc /root/.profile /root/.bash_profile /etc/bash.bashrc \
         /etc/profile /home/*/.bashrc /home/*/.profile /etc/profile.d/*; do
  [ -f "$f" ] && grep -HIE "$SHELLS|/usr/local/bin/|/tmp/|/dev/shm/" "$f"
done
```

### Two traps

**Your own shell has already sourced it.** Removing the line does not kill what
it started — check `ps -ef` for the child it spawned.

**A hook like this is almost always paired.** Work CARD 4 (units) and CARD 3
(schedulers) afterwards, because the second mechanism does not need you to log
in at all.

---

## CARD 12 — a shell or interpreter is holding a network connection

`RED  process(es) on the network that should not be on the network`

This is the card for the payload that never touched the disk. Every other card
starts from a file; this one starts from a socket, because that is the only
place a memory-only reverse shell exists.

### Find it yourself

```bash
# who is holding a connection OUT of this box? (root, for the process column)
sudo ss -tunapH | grep ESTAB

# the same question, narrowed to the shape that is almost never innocent
sudo ss -tunap | grep -E 'bash|sh,|python|perl|nc|ncat|socat'

# for any PID it names: what IS it?
sudo ls -l /proc/$P/exe             # "(deleted)" here is its own answer
```

The port is not the finding. `443` is allowed on almost every box, which is
exactly why the payload uses it. **The finding is who is on the end of it.**

```bash
P=1234                             # <- the PID triage printed

# 1. FREEZE IT. Not kill - freeze. A stopped process keeps its memory, its
#    sockets and its file descriptors, and stops taking orders at the same time.
sudo kill -STOP $P

# 2. Now take everything, while it still exists.
sudo mkdir -p /var/tmp/case-$P
sudo cp "/proc/$P/exe" "/var/tmp/case-$P/exe"     # works even when deleted
sudo tr '\0' ' ' < /proc/$P/cmdline > /var/tmp/case-$P/cmdline; echo
sudo ls -l /proc/$P/cwd /proc/$P/fd > /var/tmp/case-$P/fds
sudo ss -tunap | grep "pid=$P"    > /var/tmp/case-$P/sockets
sudo cat /proc/$P/status          > /var/tmp/case-$P/status

# 3. THE WAY BACK IN — do this BEFORE you kill it. The parent is the answer.
ps -o pid,ppid,user,lstart,cmd -p $P $(ps -o ppid= -p $P)
#    ppid 1 means its real parent already exited: something SCHEDULED it.
#    Work CARD 3 (cron) and CARD 4 (units) before you kill this.

# 4. Kill it only once you know what starts it.
sudo kill -9 $P

# 5. Verify the channel is actually gone, not just this one process.
sudo ss -tunap | grep -v 127.0.0.1
```

**Trap:** killing the shell and not the scheduler is the most common way to
spend an event fighting the same implant. If it returns, you did step 3 too
late — the parent is gone with it, and you are back to searching files.

**Trap:** `AMBER interpreter(s) serving a port the packet DOES account for` is
a different thing. A scored web app really can be Python or PHP, and killing it
is downtime you caused. Confirm it against the packet; do not reflex-kill it.

**If the peer address is one you do not recognise,** write it down with the
timestamp before you clean up. The address and the time are what the
incident-report inject is asking for, and they are gone the moment you kill it.

---

## After any remediation — the loop that closes it

```bash
sudo ./linux/triage.sh --config /tmp/ccdc-linux.env   # did it clear?
     ./linux/hunt.sh   --config /tmp/ccdc-linux.env   # full sweep for the rest
# verify the scored service FROM OFF THE BOX
```

Then write three lines in your notes: **what you found, when, what you did.**
That is the incident-report inject, and it is worth as many points as the
uptime you just protected.

If the same finding comes back after you cleaned it, you removed the artifact
and missed the way back in. Go back to the card's "way back in" section and work
all of it, not the first command.

---

## CARD 13 — SSH is configured to let them in

`RED  root login is permitted` · `RED  empty passwords are accepted`

This is the config you are logged in **through**. Every other card can be
undone from where you are sitting; this one can end your session and your
access to a scored box in the same second. Read first, change transactionally,
and never edit a file and reload in one step.

### Find it yourself

The setting you care about is not necessarily in the file you would open.
`sshd_config` can say `PermitRootLogin no` while a drop-in two directories away
says yes, and the daemon obeys the drop-in. So ask the daemon, not the file:

```bash
# what the daemon will ACTUALLY do - this resolves every Include
sudo sshd -T | grep -Ei 'permitrootlogin|permitemptypasswords|passwordauth'

# and WHICH file set it
sudo sshd -T -f /etc/ssh/sshd_config 2>/dev/null >/dev/null; \
  grep -rn -Ei 'permitrootlogin|permitemptypasswords' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
```

Three access paths no `authorized_keys` check can see, all legitimate config,
all a way in:

```bash
sudo sshd -T | grep -Ei 'authorizedkeyscommand|trustedusercakeys|authorizedkeysfile'
```

- `AuthorizedKeysCommand` runs a program to produce keys. Read that program.
- `TrustedUserCAKeys` trusts a certificate authority. Any key it signs works.
- `AuthorizedKeysFile` pointed somewhere unusual means the file you are
  auditing is not the file being consulted.

`Match` blocks are **not** evaluated by `sshd -T`. Read them by eye:

```bash
sudo grep -rn -A5 '^Match' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
```

### Fix it

Do not hand-edit and reload. `sshd.sh` snapshots, writes a drop-in, validates
with `sshd -t`, arms a rollback that survives your session dying, and only then
reloads:

```bash
sudo ./linux/sshd.sh --config /tmp/ccdc-linux.env                 # read-only
sudo ./linux/sshd.sh --config /tmp/ccdc-linux.env --dry-run       # the plan
sudo ./linux/sshd.sh --config /tmp/ccdc-linux.env --apply         # arms rollback
```

**Now open a second terminal and log in.** Do not test in the session you
already have — an existing connection survives a config that refuses new ones,
so testing in place proves nothing.

```bash
sudo ./linux/sshd.sh --config /tmp/ccdc-linux.env --confirm       # only if it worked
sudo ./linux/sshd.sh --config /tmp/ccdc-linux.env --rollback      # if it did not
```

If you do nothing, it reverts on its own.

### What it costs you to get wrong

Locking yourself out of a Linux box mid-event means every remaining finding on
it goes unworked, and the console may not be available to you. That is why this
one is never automated, and why the rollback is armed before the change rather
than after.

### If the setting keeps coming back

Something is rewriting it. Look for the mechanism, not the file:

```bash
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env --status
sudo systemctl list-timers --all | grep -iE 'ssh|config'
sudo grep -rn 'sshd_config' /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null
```

---

## CARD 14 — code running below the point your tools can see

`RED  module  MODULENAME` · `AMBER  initramfs  /etc/initramfs-tools/hooks/FILE`

A loaded kernel module runs in ring 0. It can hide processes from `ps`, hide
files from `ls`, hide its own entry from `lsmod`, and lie to every tool on this
list including this kit. If one appeared after you blessed the box, treat the
box's own answers as unreliable from that moment.

### Find it yourself

```bash
# what is loaded now
lsmod | sort

# what the module claims to be, and where it came from
modinfo MODULENAME | head -20

# does any package own that file?
dpkg -S "$(modinfo -n MODULENAME 2>/dev/null)" 2>/dev/null || echo "NO PACKAGE OWNS IT"
```

A module whose file lives outside `/lib/modules/$(uname -r)/kernel/` — or that
no package owns — is not a distribution module.

### Fix it

```bash
sudo cp -a "$(modinfo -n MODULENAME)" /var/tmp/ccdc-evidence/   # evidence FIRST
sudo rmmod MODULENAME
```

### The other half: the initramfs

A module has to get loaded somehow, and the earliest place to arrange that is
the initramfs — the filesystem the kernel mounts before your real root exists.
Scripts under `/etc/initramfs-tools/` are copied into it and run as root, before
auditd, before systemd, before anything on this box that could notice. That is
why an `initramfs` finding belongs on this card and not with the ordinary `/etc`
diffs: it is not a config file, it is code scheduled to run underneath you.

```bash
# what changed, and what is in the image that is actually booting
sudo ls -la /etc/initramfs-tools/hooks/ /etc/initramfs-tools/scripts/
lsinitramfs /boot/initrd.img-$(uname -r) | grep -vE '^(usr|lib|etc/(ld|fonts))' | head -40
dpkg -S /etc/initramfs-tools/hooks/FILE 2>/dev/null || echo "NO PACKAGE OWNS IT"
```

Removing the file is not enough on its own — the image already built from it is
what boots:

```bash
sudo cp -a /etc/initramfs-tools/hooks/FILE /var/tmp/ccdc-evidence/
sudo rm -f /etc/initramfs-tools/hooks/FILE
sudo update-initramfs -u          # rebuild, or the old image still runs it
```

Do the rebuild during a quiet moment, not mid-inject: a bad initramfs is a box
that does not come back from a reboot.

If `rmmod` says the module is in use and nothing legitimate is using it, that
resistance is itself the finding. Stop it from coming back across a reboot:

```bash
echo "blacklist MODULENAME" | sudo tee /etc/modprobe.d/ccdc-blacklist.conf
echo "install MODULENAME /bin/false" | sudo tee -a /etc/modprobe.d/ccdc-blacklist.conf
sudo depmod -a
```

### What this costs you to get wrong

Removing a storage or network module can take the box off the network or make
the filesystem unreadable. Check `modinfo` for what it actually is before you
remove anything you did not plant yourself. `nf_*`, `virtio_*`, `ahci`, `ext4`
and the like are the machine working.

### If you cannot remove it

A module that will not unload, or that reappears, means the box can no longer
be trusted to describe itself. Say so in the incident report, keep the scored
service up, and treat every subsequent "clean" result from this host as
unconfirmed. The only authoritative check left is from **off** the box: does
the scoring engine still see the service behaving correctly.

---

## CARD 15 — a user-level service, running as someone who is not logged in

`RED  userunit  /home/USER/.config/systemd/user/NAME.service`

Everyone looks at `/etc/systemd/system`. Systemd will also run units out of a
user's own home directory, as that user, and with **lingering** enabled they
start at boot with nobody logged in. `systemctl list-units` as root does not
show them.

### Find it yourself

```bash
# the files themselves - every home, not just yours
sudo find /home /root -path '*/.config/systemd/user/*' -name '*.service' -o \
     -path '*/.config/systemd/user/*' -name '*.timer' 2>/dev/null

# who is allowed to run services with nobody logged in
ls -la /var/lib/systemd/linger/

# and what that user is actually running
sudo systemctl --user -M USER@ list-units --type=service --no-pager 2>/dev/null
```

### Fix it

`systemctl --user` will not work from a root shell the way you expect — it
talks to that user's own session bus, which may not exist. Use `-M USER@`, or
disable lingering first so the unit cannot start at all:

```bash
sudo cp -a THE_UNIT_FILE /var/tmp/ccdc-evidence/            # evidence FIRST
sudo loginctl disable-linger USER
sudo systemctl --user -M USER@ disable --now NAME.service 2>/dev/null
sudo rm -f THE_UNIT_FILE
```

Then confirm nothing of that user's is still running:

```bash
ps -u USER -o pid,etime,cmd
```

### If the account should not exist at all

Removing the unit leaves the account. If the account is also a finding, work
CARD 1 or CARD 10 as well — otherwise they simply write the unit again.

---

## CARD 16 — something is running that nothing needs

`units  snapd` · `pkg  telnet` · reported by `harden.sh`, not by `triage.sh`

This card is different from every other one here. Nothing on it is an implant.
Every item is legitimate, package-owned software that would pass a provenance
check forever. The finding is that **no scored service needs it**, and every
daemon you do not need is attack surface you are defending for no points.

### Find it yourself

```bash
sudo ./linux/harden.sh --config /tmp/ccdc-linux.env              # read-only
sudo ./linux/harden.sh --config /tmp/ccdc-linux.env --explain 3  # the full case
```

Read the **WILL NOT TOUCH** block as carefully as the rest. It exists so you
can see what was considered and deliberately kept, rather than wondering.

### Fix it

```bash
sudo ./linux/harden.sh --config /tmp/ccdc-linux.env --cut all-safe --apply
sudo ./linux/harden.sh --config /tmp/ccdc-linux.env --undo --apply    # all of it back
```

After every single cut it re-checks the scored services and reverses that one
cut by itself if any stops answering, so a wrong call costs one item and a few
seconds rather than a scoring round.

### The two that are not obvious

**cloud-init is a persistence mechanism, not just surface.** It re-runs on every
boot and re-applies users and SSH keys from `/var/lib/cloud`. An account you
removed during an incident comes back after the next reboot with nothing in the
logs to explain it.

**open-vm-tools is a judgement call the packet decides.** Its guest-operations
channel can execute commands inside the VM — real attack surface — and it is
also how competition infrastructure may reach the box. On KVM it is dead weight.
On VMware, cutting it costs you the console.

### Order matters

Harden **before** you bless. Cut first, then freeze what is left:

```bash
sudo ./linux/harden.sh   --config /tmp/ccdc-linux.env --cut all-safe --apply
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env --bless --apply
```

Blessing first and hardening after makes every cut you make read as drift for
the rest of the event.

---

## CARD 17 — a binary no package installed is talking on the network

`netunpackaged  pid1777307:/usr/sbin/.sysmon` · reported by `triage.sh` and
carried into `sentry.sh --status`

Every file that arrived through `apt` can be traced back to a package and
checked against a recorded checksum. This one cannot. It is a compiled binary
sitting in a system directory, it belongs to nothing, and it is using the
network — either reaching out, or holding a port the packet does not account
for.

That is not proof of anything. It is also exactly what every from-source
install looks like: `make install` does not tell dpkg anything. So this is
AMBER, and the question it asks you is the only one that separates the two
cases: **do you know what put it there?**

### Why this is not CARD 8

CARD 8 is about a port you did not expect. This is about a *file* you cannot
account for, and it fires just as loudly for an outbound connection, where
there is no listening port to look at at all. Exfiltration has no port to
close.

### Find it yourself

```bash
sudo ss -tulnp | grep -F /usr/sbin/.sysmon   # what socket, which direction
ls -l -- /usr/sbin/.sysmon
dpkg -S -- /usr/sbin/.sysmon                 # "no path found" is the finding
sha256sum -- /usr/sbin/.sysmon               # then look that hash up OFF the box
```

Two questions decide it, in this order:

1. **Does its hash match something you can name?** A copy of `nc`, `busybox`
   or a language runtime under a different name is not a from-source install.
   `cmp -s -- /usr/sbin/.sysmon "$(command -v nc)" && echo 'it IS netcat'`
2. **Is there any record of it being built here?** Source tree, a `make`
   in your shell history, an entry in the packet. No record and a
   hidden-looking name — a leading dot, a plausible system word like
   `.sysmon` or `.netcheck` — is the answer.

### Fix it

Sentry will do the whole sequence, in order, and refuse to kill anything it
could not capture first:

```bash
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --status
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --approve N --apply
```

It captures the process — socket, parent, and the executable, including when
the file has already been unlinked — kills it by PID, then preserves and
removes the binary, and finally re-checks every scored service.

By hand, capture before you kill, always:

```bash
sudo ./linux/preserve.sh --config /tmp/ccdc-linux.env --pid PID --freeze --apply
sudo kill -9 PID
sudo cp -a -- /usr/sbin/.sysmon /var/tmp/ccdc-evidence/
sudo rm -f -- /usr/sbin/.sysmon
```

### The part that matters more than the kill

Something started it, and that something is still there. A binary does not
install itself:

```bash
sudo ps -o ppid= -p PID | xargs -r ps -o pid,user,cmd -p   # who launched it
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env --status
```

If it comes back after you remove it, you removed the payload and left the
mechanism. Work CARD 3, CARD 4 and CARD 11 until nothing rebuilds it.

### If it turns out to be yours

Say so once and stop being asked:

```bash
sudo ./linux/baseline.sh --config /tmp/ccdc-linux.env --bless --apply
```

Blessing records it as a standing exception. Do that only after you have
answered both questions above — a blessed implant is invisible for the rest
of the event.
