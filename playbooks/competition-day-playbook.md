# Competition-day playbook (solo tryout)

Printable. One operator, four boxes (Linux, Windows, Splunk, firewall), six
hours, uptime + injects scored evenly. This is the order to work in and the
commands to work with. Practice the implementation until the sequence is
muscle memory, because on the day the clock is the enemy as much as the red
team is.

Fill every `<BRACKET>` from the team packet before you touch anything. A
command run against a guessed value is a command run twice.

---

## 0. Before the clock starts

```
[ ] Read the packet. Write down: scored services, scored accounts, scored
    ports, the scoring engine's address, the Splunk address.
[ ] Confirm access to every box (console AND the way the scorer reaches it).
[ ] Note the current time and the competition end time. Injects have hard
    deadlines; a late inject scores zero regardless of quality.
[ ] Snapshot every VM if the environment allows it.
[ ] Copy the kit onto the box -> bootstrap-on-the-box.md (one probe decides
    clone / tarball / push-from-workstation). Copy config/example.env to
    /tmp/ccdc-linux.env and fill it in. Do NOT paste secrets into chat or
    commit the filled copy.
```

The single most important number: **injects are half the score.** You cannot
win on uptime alone. Budget time for injects from minute one — see §6.

---

## 1. First 15 minutes — see the box before you change it

Everything here is read-only. Do not harden anything until you know what normal
looks like, or you will not be able to tell your own change from an intrusion.

```
[ ] sudo ./linux/triage.sh --config /tmp/ccdc-linux.env  # WHAT IS ALREADY WRONG
    High-confidence checks, ranked, ~25 lines. Run this FIRST: the red team's
    access is usually pre-placed, and it is the only tool here that judges
    rather than collects. Each finding names a remediation card.
    Run it with sudo. Without it, the check that finds a reverse shell can
    only see YOUR OWN processes, and it says so instead of printing "clean".
[ ] ./linux/recon.sh --config /tmp/ccdc-linux.env      # baseline snapshot
[ ] ./linux/hunt.sh  --config /tmp/ccdc-linux.env      # persistence sweep (ro)
[ ] Note the evidence path both printed. It is your before-picture.
[ ] sudo ./linux/sshd.sh --config /tmp/ccdc-linux.env  # what SSH will ACTUALLY do
    Reads drop-ins. sshd_config saying PermitRootLogin no proves nothing.
[ ]      ./linux/splunk.sh --config /tmp/ccdc-linux.env # are logs leaving?
```

Three things that are only true until someone changes them, so do them early
and write down the time:

```
[ ] sudo ./linux/audit.sh --config /tmp/ccdc-linux.env --apply
    Persistent audit rules: they survive the `systemctl restart auditd` that
    silently clears every runtime watch.
[ ] sudo ./linux/audit.sh --config /tmp/ccdc-linux.env --capture
    The log baseline. Without it, "they wiped the logs" is something you
    believe rather than something you can show.
[ ] sudo ./linux/splunk.sh --config /tmp/ccdc-linux.env --test-event --apply
    Then FIND THE TOKEN IN SPLUNK. Write the token and the time in your notes:
    "forwarding verified at 10:14 with token X" is an inject answer.
```

Read, by hand, in this order — this is where the red team's pre-placed access
lives. **Every line below is a real command you can paste**; explanations are on
their own `#` lines so nothing here is ambiguous at 10:05:

```
# who is logged in right now, and who has been
[ ] who
[ ] w
[ ] last | head -20
# every listening port. Anything not scored is a question:
# "nothing but scored services should show on an nmap scan"
[ ] ss -tulpn
# accounts with UID 0, or a service account that has a login shell
[ ] awk -F: '$3==0 {print $1}' /etc/passwd
[ ] getent passwd | awk -F: '$7 ~ /(bash|sh)$/ {print $1, $7}'
# who can become root
[ ] getent group sudo admin wheel
# scheduled footholds
[ ] ls -la /etc/cron.d/ /etc/cron.daily/
[ ] systemctl list-timers --all --no-pager
# unknown keys are access
[ ] sudo cat /root/.ssh/authorized_keys
[ ] sudo find /home -name authorized_keys -exec ls -la {} \;
# boot-start services, and SUID binaries
[ ] systemctl list-unit-files --state=enabled
[ ] sudo find / -xdev -perm -4000 -type f 2>/dev/null
```

If you find a foothold now, note it, but do not start pulling threads before
the box is hardened — see §7 for the eradication loop. Closing the front door
first is worth more than chasing one attacker who is already in.

---

## 2. Harden, in this order, one change at a time

The order is deliberate. It is the order a CCDC red teamer publicly names as
the three things that stop most attacks: credentials, firewall, then patch the
exploitable. (https://www.winterknight.net/how-to-win-ccdc-red-team/)

**Verify the scored service from the network after every single change.**
Blocking your own scored service costs exactly as much as the red team taking
it down, and it is the most common self-inflicted wound.

### 2a. Credentials first

The red team's cheapest win is a default or known password. Change them before
they use them.

```
[ ] Change the password on every account that has one you did not set.
[ ] ./linux/users.sh --config /tmp/ccdc-linux.env --dry-run    # review targets
[ ] ./linux/users.sh --config /tmp/ccdc-linux.env --apply      # then apply
[ ] Do NOT lock the scored service account or your own. See the password-policy
    inject draft for the lockout trap.
```

### 2b. Firewall second — with the dead man's switch

The firewall is your biggest single lever, and the fastest way to lock
yourself out. `fw.sh` arms an automatic rollback so a bad rule undoes itself.

```
[ ] ./linux/fw.sh --config /tmp/ccdc-linux.env --dry-run    # read the ruleset
[ ] ./linux/fw.sh --config /tmp/ccdc-linux.env --apply      # arms auto-rollback
[ ] OPEN A NEW SSH SESSION and confirm you still have access + scored service.
[ ] ./linux/fw.sh --config /tmp/ccdc-linux.env --confirm    # keep the rules
    (If you are locked out, do nothing: the rollback fires on its own.)
```

Default-deny inbound, allow only scored ports + the scorer/Splunk/admin
sources. Egress: the packet decides. Blocking outbound kills most C2 callbacks
("if red team can't call home, their persistence dies") but can break DNS or a
scored service — test it, do not assume it.

### 2c. SSH third

See the ssh-access inject draft for the full config. Minimum:

```
[ ] Keys over passwords - BUT if the scorer logs in with a password, keep it
    for that account (Match block). Killing the scorer's login = downtime.
[ ] PermitRootLogin no ; AllowGroups <admins> ; MaxAuthTries 3
[ ] sshd -t   before restart, and hold a second session open during restart.
```

### 2d. Turn off what nothing scores

Every daemon you do not need is attack surface you are defending for free. The
firewall only hides it from the network; it still runs locally as a privesc
target and a place to hide persistence.

```
[ ] ./linux/services.sh --config /tmp/ccdc-linux.env --review    # READ-ONLY
    Four buckets, with listening ports: PROTECTED / LIKELY SCORED /
    CANDIDATES / UNCLASSIFIED. Read the UNCLASSIFIED bucket properly - an
    attacker-installed unit lands there.
[ ] Put the ones you agree with in CCDC_DISABLE_SERVICES. It will not choose
    for you, by design.
[ ] sudo ./linux/services.sh --config /tmp/ccdc-linux.env --disable   # dry run
[ ] sudo ./linux/services.sh --config /tmp/ccdc-linux.env --disable --apply
[ ] VERIFY THE SCORED SERVICE FROM OFF THE BOX. This is the step most likely
    to cost you points by accident.
[ ] Broke something? sudo ./linux/services.sh --config <cfg> --revert --apply
```

It refuses anything scored, anything of yours (sshd, cron, DNS, logging, the
firewall, this kit's own units) and anything that merely looks scored - web,
database, FTP, Samba, mail, DNS. If the packet says one of those really is
disposable, name it in `CCDC_ACK_DISABLE_LIKELY_SCORED`; that second explicit
acknowledgement is different from protecting it.

### 2e. Then, only the exploitable

Do not patch everything - you do not have the bandwidth and you will break
things. Patch what has a public exploit and is reachable.

---

## 3. Arm the standing defence — one command

This is the machinery that works while your attention is on injects. One
command takes a restore point, lays tripwires, starts the guardian/watchdog,
and installs the combined sentry/change detector as a supervised service:

```
[ ] ./linux/arm.sh --config /tmp/ccdc-linux.env               # dry run first
[ ] sudo ./linux/arm.sh --config /tmp/ccdc-linux.env --apply
```

That runs `backup.sh`, `canary.sh --deploy`, `guardian.sh --install`, and
`sentry.sh --install`. Guardian starts the watchdog; sentry runs ranked triage
plus the broader canary/hunt/recon sweep. Both are supervised. **Do not run
either loop by hand**: a foreground loop consumes your only terminal and dies
when your SSH session drops, which is exactly when you need it.

It deliberately does NOT touch the firewall (§2b) or services (§2d). Both need
a human confirming against the packet.

> **After this, every tool needs `sudo`.** Arming makes the evidence directory
> root-owned and `0700`, so a later `./linux/hunt.sh` without sudo stops with
> "evidence directory is not writable". That is deliberate: the alternative is
> a silent fallback that splits your evidence across two directories, and you
> discover it while writing the incident report. Read-only tools run fine
> unprivileged *before* you arm — which is why §1 comes first.

Before you move on, confirm the two settings that decide what this is worth:

```
[ ] CCDC_HTTP_CHECKS / CCDC_TCP_CHECKS use the SAME probe the scorer uses, or
    "recovered" in the log will not mean "scored". Point them at the address
    the scorer reaches, NOT 127.0.0.1.
[ ] CCDC_WATCHDOG_INTERVAL="5". This is the single highest-value number in the
    config: your mean outage is roughly half of it. Measured on the lab box
    against an external scorer, the same killed service cost 57s at 60 and 6s
    at 5. A pass is a curl and two systemctl calls, so 5s is nearly free.
```

**What the canaries are for.** A trip on `/root/.ssh/id_rsa.bak`, or a read of
`/etc/shadow`, is the red team almost without exception. That is your cue to
start §7. Lay as many decoys as are plausible for the box - every extra one is
another tripwire and costs nothing to keep.

### Optional, if you have the time: a second independent chain

If you have the time, arm a second guardian chain so removing one does not
remove your defence. Copy your config, give the copy its own
`CCDC_GUARDIAN_*_NAME` values, its own `CCDC_GUARDIAN_DIR` and its own
`CCDC_GUARDIAN_STATE_DIR`, then install it too:

```
[ ] sudo ./linux/guardian.sh --config /tmp/chain-b.env --install --apply
```

Share `CCDC_EVIDENCE_DIR` between them — do not split it. The watchdog's
singleton lock lives there, and that shared lock is what stops both chains
restarting the same service twice (the second restart is an outage you caused
yourself). The losing chain idles as a hot standby and takes over within
~5s if the active one is killed.

Tested on the lab box: an attacker with root who found chain A, removed all
three of its layers plus its state, and stopped the scored service cost 0–3
seconds of scored downtime, because chain B was still there.

---

## 4. The sentry — check in, do not babysit it

`arm.sh` already started this under systemd. It refreshes ranked findings every
minute, performs the larger change sweep every two minutes, and queues only
actions justified by what is wrong **now**.

```
[ ] systemctl is-active ccdc-sentry.service
```

Then, between injects — this is your whole monitoring loop:

```
[ ] sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --status
[ ] sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --approve --apply
[ ] sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --ack   # after reviewing change events
```

It never acts without `--approve`. Approval is not a replay of an old command:
it takes the lock, re-runs triage, rebuilds the queue, and re-checks the current
packet protection lists immediately before calling a fixed remediation. Queue
records contain data, not shell text. Everything removed is preserved in a
unique evidence directory first.
Two things it deliberately leaves to you, because only the packet can settle
them: which SSH keys are legitimate, and which `NOPASSWD` sudo rules are yours.
They appear in ALERTS under "needs your judgement".

**It refuses to act until the packet is in the config.** `CCDC_ALLOWED_USERS`
and `CCDC_SYSTEMD_SERVICES` must both be set. An empty protect list does not
mean nothing is protected — it means nobody has told the tool what is scored,
and that is the most dangerous state to act from.

A RED finding it will not touch because of those lists is still shown, loudly,
under "sentry will NOT touch — YOU must decide". Protection narrows what it
touches, never what it tells you.

---

## 4b. The change-detection sweep — already part of sentry

The kit collects well and alerts not at all: canary trips go to a log nobody
reads and `hunt.sh` writes a 124K report you cannot re-read every few minutes.
`watch.sh` closes that gap. It runs canary + hunt + recon and reports **only
what changed since the last pass**. Sentry invokes it automatically and keeps
events in `ALERTS` until you acknowledge them.

```
[ ] sudo ./linux/watch.sh --config /tmp/ccdc-linux.env --once   # diagnostic on demand only
```

It changes no system configuration, but it writes/rotates evidence snapshots.
A quiet pass prints one line. A new user, cron entry, listener, or canary trip
is retained by sentry — that is your §7 trigger.

What it **cannot** see: whether the scorer can reach your service. Nothing on
the box can. Check that from off the box yourself.

---

## 5. Splunk — make the box talk

```
[ ] Confirm the forwarder is running and reaching the indexer.
[ ] Load the starter searches in splunk/searches.md.
[ ] Forward the canary alert log and auditd events - that is where an intrusion
    shows up first.
```

---

## 6. Injects — half the score, so treat them as half the job

Do not disappear into the red-team fight and leave injects on the table. Some
are pure writing and score the same as an hour of uptime.

```
[ ] Triage every inject the moment it lands: note its deadline and its
    Deliverables box. The Deliverables box IS the rubric - read it first.
[ ] Start with the drafts in injects/responses/. Six are pre-written:
    login banner, SSH, incident-response procedure, password policy,
    endpoint protection, perimeter assessment.
[ ] Fill every <PLACEHOLDER>. A shipped <TEAM XX> is a scored mistake.
[ ] Subject line = inject name copied EXACTLY. Team number only, no names.
[ ] Screenshot-per-server injects (banner, SSH, AV): collecting the proof is
    half the work and eats the clock. Screenshot as you go, not at the end.
```

Order to attempt them: the memo-only ones first (incident-response procedure,
password policy) - fastest points - then the screenshot-heavy ones, then
anything needing a recording. If an inject wants a video, that cannot be
improvised late; know that going in.

---

## 7. When the red team lands — the eradication loop

Triggered by a canary trip, an audit hit, a strange process, or `/tmp` filling
up. Work the SANS loop (see injects/responses/incident-response-procedure.md):

**If the scripts are gone.** A red team that deletes `linux/` takes every tool
here with it. Each tool's manual equivalent is in the cards or in §1 above, and
`playbooks/remediation-cards.md` is written to be read with `less` and typed by
hand. Re-cloning is usually faster:

```
[ ] git clone https://github.com/lbanner18/ccdc-training /tmp/kit2
[ ] less playbooks/remediation-cards.md      # less, NEVER cat - it is markdown
```

**Every finding has a card with the exact commands:**
`triage.sh` prints `[CARD n]` next to each finding, and it also prints the
literal command with this box's real values already in it. To read a whole
card:

```
[ ] ./linux/card.sh                      # list the nine cards
[ ] ./linux/card.sh 1 backupsvc          # card 1, real username filled in
```

Do NOT `cat` or paste `playbooks/remediation-cards.md` into a shell. It is
markdown; bash executes the prose. Use `card.sh`, or `less` if the scripts are
gone.

```
[ ] IDENTIFY: sudo ./linux/triage.sh --config <cfg>   <- ranks what is wrong
[ ] IDENTIFY: what tripped? ausearch -k ccdc-canary -i  /  ps auxf  /  ss -tulpn
[ ] CONTAIN:  disable the abused account, block the source, snapshot BEFORE you
    clean (the snapshot is your only forensics + your evidence for the IR memo).
[ ] ERADICATE: remove the file AND the way back in - added user, cron, service,
    startup entry, authorized_key. Removing the payload alone leaves the door.
    Re-run ./linux/hunt.sh to sweep for what you missed.
[ ] RECOVER:  confirm the scored service answers from the network. Watch the
    canaries harder for the attacker's return.
[ ] Write it down as you go. Timeline with timestamps = the incident-report
    inject, already half-written in injects/incident-report-template.md.
```

Two traps under pressure: do not chase forensics while the box is being owned -
speed over perfection; and remember you are your own worst enemy - confirm a
"red team" outage is not your own firewall rule before you burn ten minutes on
it.

---

## 8. Quick reference — the whole loop on one card

```
BEFORE : packet -> config -> snapshot -> access confirmed
SEE    : triage.sh (ranked!) ; recon.sh ; hunt.sh ; who ; ss -tulpn ; keys
HARDEN : creds -> fw.sh(+confirm) -> ssh -> services.sh   [verify each]
ARM    : sudo arm.sh --apply      (backup + canary + sentry + guardian/watchdog)
STATUS : sudo sentry.sh --status  (current triage + retained change events)
SIGNOFF: sudo sentry.sh --approve --apply ; --ack reviewed change events
INJECT : triage deadline+deliverables ; use responses/ ; screenshot as you go
HIT?   : identify -> contain(snapshot!) -> eradicate(+way back in) -> recover
ALWAYS : verify the scored service FROM THE NETWORK after every change
```

Four returning commands are the whole operating loop. If you remember nothing else:

```
sudo ./linux/triage.sh   --config /tmp/ccdc-linux.env
sudo ./linux/arm.sh      --config /tmp/ccdc-linux.env --apply
     ./linux/services.sh --config /tmp/ccdc-linux.env --review
sudo ./linux/sentry.sh   --config /tmp/ccdc-linux.env --status
```

Two things no tool here can do for you: check the scored service from off the
box, and write the injects. Both are half your score.

Sources for the strategy above: BYU tryout page (format, even scoring split),
mubix *How to Win CCDC* (https://howtowinccdc.com/), and the CCDC red-team
write-up (https://www.winterknight.net/how-to-win-ccdc-red-team/). Rules and
their citations: playbooks/competition-rules.md.
