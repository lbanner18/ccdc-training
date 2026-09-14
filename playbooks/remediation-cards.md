# Remediation cards — you found it, now what

One card per finding `triage.sh` can print. Each card is: **kill the access,
find the way back in, verify**. Work them in that order every time.

Written because finding a foothold and not knowing the next command is the same
as not finding it.

> ## ⛔ DO NOT `cat` OR PASTE THIS FILE INTO A SHELL
>
> Read it with **`./linux/card.sh <n> <name-or-path>`** instead:
>
> ```
> ./linux/card.sh              # list the cards
> ./linux/card.sh 1 backupsvc  # card 1, with the real username filled in
> ```
>
> This is markdown. Pasted into bash it executes the prose — measured on the
> lab box, hundreds of lines of `command not found`, plus real `sudo userdel`
> and `pkill` lines firing blind. Nothing broke only because the placeholders
> happened to be unset.
>
> The original version of this file said "keep this open in a second window".
> That assumed two terminals. With one, "open it" means `cat`, and `cat` of a
> file full of `sudo` is a loaded gun aimed at whoever is in the biggest hurry
> — which is exactly who these cards are for. `card.sh` prints; it never runs.
>
> **Also: never leave `$U` or `$F` unset.** `grep -rn "$U" /etc/ssh/sshd_config`
> with `$U` empty matches every line and dumps the whole file. It does not
> error. Pass the value to `card.sh` and there is no variable to forget.
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
ls -la "/home/$U" 2>/dev/null

# 4. THE WAY BACK IN - all of these, not just the first.
sudo crontab -u "$U" -l 2>/dev/null          # their personal crontab
sudo grep -rn "$U" /etc/cron.d /etc/cron.* /etc/sudoers /etc/sudoers.d 2>/dev/null
sudo cat "/home/$U/.ssh/authorized_keys" 2>/dev/null
sudo grep -rn "$U" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null
sudo ls -la "/home/$U/.config/systemd/user/" 2>/dev/null   # user-level units

# 5. REMOVE. The -f is REQUIRED for a UID-0 account and is not optional:
#    without it userdel refuses outright (see the trap below).
sudo crontab -u "$U" -r 2>/dev/null
sudo userdel -f -r "$U"

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
`usermod -u` both **failed and changed nothing**, while `userdel -f -r`
succeeded, removed the `/etc/shadow` entry and the home directory, and left all
136 root processes and the scored service running. The warning still prints.
Ignore it and check step 6 instead.

**Trap:** a second UID-0 account is a classic pair — the attacker expects you to
find one. Re-run the `awk` in step 6 after removing it.

**If the account is NOT UID 0** (an ordinary rogue user), `pkill -9 -u "$U"` is
safe and is the right first move, and plain `userdel -r "$U"` works.

---

## CARD 2 — SSH key you do not recognise

`AMBER  N SSH key(s) grant login`

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
sudo rm -f /tmp/<name> /var/tmp/<name> /dev/shm/<name>

# 4. THE WAY BACK IN - something started it, and will again.
#    Work CARD 3 (schedulers) and CARD 4 (units) now.
ls -la /tmp /var/tmp /dev/shm
```

**Trap:** kill it and it comes back in 60 seconds = it has a scheduler. Do not
keep killing it; find what restarts it.

---

## CARD 7 — passwordless sudo you did not configure

`AMBER  passwordless sudo is configured`

```bash
sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d

# Remove the offending line. ALWAYS edit with visudo - it syntax-checks, and a
# broken sudoers file means nobody on the box can use sudo again.
sudo visudo                        # for /etc/sudoers
sudo visudo -f /etc/sudoers.d/<file>

# THE WAY BACK IN
ls -la /etc/sudoers.d/             # a file named "10-base" is not automatically
                                   # legitimate; read every one
sudo grep -rn '^[^#]' /etc/sudoers.d/
getent group sudo admin wheel      # who is in the admin groups?

# VERIFY
sudo -l -U <user>                  # what can that user actually do now
```

**Trap:** keep your own passwordless sudo if that is how you are working, or
your next command will prompt for a password you may not have.

---

## CARD 8 — unexpected listening port

`AMBER  listening TCP port(s) not in CCDC_ALLOWED_TCP_PORTS`

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

```bash
# 1. WAS it you? Your own hardening shows up here. Check the timestamps against
#    what you ran. Guardian units appearing right after arm.sh is expected.

# 2. For anything you did not do - what changed?
sudo ./linux/diff-evidence.sh <old-evidence-dir> <new-evidence-dir>
#    (this is why recon.sh runs FIRST, before you change anything)

# 3. Restore from your own backup if it is one of the files you saved:
sudo ./linux/backup.sh --config /tmp/ccdc-linux.env --list
sudo ./linux/backup.sh --config /tmp/ccdc-linux.env --restore <path> --apply

# 4. Package-owned files can be checked against the distro's own hashes:
sudo dpkg --verify 2>/dev/null | head -20        # Debian/Ubuntu
sudo rpm -Va 2>/dev/null | head -20              # RHEL/CentOS
```

**Trap:** `/etc/passwd`, `/etc/shadow` and `/etc/sudoers` changing together is
an account being added. Go to CARD 1.

---

## CARD 10 — service account with a shell, or in an admin group

`RED  service account(s) with a login shell` / `RED  system account(s) in an admin group`

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

## CARD 11 — shell start-up file that launches something

`RED  shell start-up file(s) launching something`

`.bashrc`, `.profile`, `.bash_profile` and `/etc/profile.d/*` run every time
anyone opens a shell — **including the next time you run `sudo -i`**. This is
persistence that fires on the defender's own hands, and no process or unit
listing will show it until it has already run.

```bash
F=/root/.bashrc                    # <- the file triage printed

sudo cp "$F" /var/tmp/evidence-$(basename "$F")   # evidence first
sudo nano "$F"                     # delete ONLY the offending line
```

Follow whatever it launched — the hook is the trigger, not the payload:

```bash
sudo cat /usr/local/bin/<whatever-it-called>
```

Then work CARD 4 (units) and CARD 3 (schedulers), because a hook like this is
almost always paired with a second mechanism that does not need you to log in.

```bash
# THE WAY BACK IN - every start-up file on the box
sudo ls -la /etc/profile.d/
for f in /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile; do
  echo "== $f"; sudo tail -5 "$f" 2>/dev/null
done
```

**Trap:** your own shell has already sourced it. Removing the line does not
kill anything it started — check `ps -ef` for the child it spawned.

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
