# The blessed baseline: design

Written 2026-09-17, after the night drill. This is the design document for
`baseline.sh` and the changes around it. It exists because the decisions in here
came out of a long conversation, and a decision nobody wrote down gets remade
badly later.

---

## What was wrong

The kit detects well and stops at the finish line. The drill on 2026-09-17
planted eight footholds on an armed box. Six were surfaced. None of the seven
bugs found that night were in detection logic — every one was in the handoff to
the operator: a path printed with no command to read it, an `--approve [N]`
placeholder that bash treats as a glob, a preflight that rejected the exact
config format the worksheet documents.

Underneath that were two deeper problems.

**Coverage was example-driven and had no denominator.** Twenty-seven checks
existed because twenty-seven things had gone wrong or been planted. Nobody could
answer "twenty-seven out of what?" A crude audit of common root-execution
triggers found roughly ten with no coverage at all, including `apt.conf.d`
hooks, which run as root on every `apt` command.

**Checks asked what a file CONTAINS, not whether it should exist.** Both
footholds that survived the drill did so for the same reason: a systemd drop-in
whose body was an ordinary `ExecStartPost`, and a script in
`/etc/update-motd.d`. Neither file said anything evil. Content-matching is an
unbounded question — there are infinite ways to spell a reverse shell — so a
check written that way only ever catches the spellings someone imagined.

Asking whether a file is **explained** is bounded.

---

## The model

A thing is EXPLAINED if any of these hold:

1. it is in the blessed baseline, or
2. a package owns it and its checksum is intact, or
3. it is allowlisted in the config.

Everything else is reported. That is the whole idea, and its strength is that it
catches mechanisms nobody enumerated in advance.

Three consequences:

**Drift is measured against the blessed baseline, forever — never against the
previous pass.** `watch.sh` currently compares each pass to the one before it
(`prior_dir=$prev_dir`), which means anything the red team plants becomes normal
after one cycle. This was visible in the drill: a `/dev/shm` process appeared as
a finding at 00:51 and had decayed to "its CPU time changed" by 00:53. Nothing
may decay into normal on its own.

**Bless freezes semantic readings, not just a file inventory.** The blind spot
in pure provenance is a backdoor that is legitimate *content* inside an expected
file: an extra `AuthorizedKeysFile` line in `sshd_config`, a `pam_exec.so` line,
a sudoers rule, an added key, a changed hash. Those files are supposed to exist
and `dpkg` expects conffiles to differ from shipped defaults. So the baseline
also freezes: `sshd -T` effective config, the sudoers ruleset, UID-0 accounts,
authorized keys per account, service-account shells, listening sockets, loaded
kernel modules.

**Everything unnecessary goes.** Not because removal catches content-level
backdoors directly, but because it shrinks the places one can hide while looking
explained. Fewer packages, fewer conffiles, fewer daemons, fewer PAM stacks.

---

## The pipeline

    recon  →  harden  →  triage  →  bless  →  arm

Four commands on competition morning:

```bash
# 1. Look at everything. Read-only. Records the box as found, then prints one
#    numbered list: unexplained things AND unnecessary things together.
sudo ./linux/baseline.sh --config ~/ccdc-real.env

# 2. Work the list.
sudo ./linux/baseline.sh --config ~/ccdc-real.env --approve 3,7,9 --apply

# 3. Freeze what is left as known-good.
sudo ./linux/baseline.sh --config ~/ccdc-real.env --bless

# 4. Start the machinery that watches for drift from it.
sudo ./linux/arm.sh --config ~/ccdc-real.env --apply
```

`recon` runs first and is read-only, because hardening destroys the record of
what was there and that record is inject evidence.

**The bless step cannot be automatic and cannot merge into step 1.** You cannot
freeze a baseline on a box you have not cleaned — you would bless the implants.
That human checkpoint is the one place the pipeline will not collapse further.

### What folds into `baseline.sh`

`recon.sh`, `hunt.sh`, `surface.sh`, `triage.sh`, `services.sh`, `sshd.sh`,
`users.sh`, `policy.sh`.

They stay independently runnable, exactly as `backup.sh` and `canary.sh` did
under `arm.sh` — mid-event you want to re-run triage alone without re-walking
everything.

`sshd.sh` folding in matters specifically: SSH policy was a separate command and
nothing in triage's output told the operator they had to go run it. `fw.sh` does
NOT fold in — it arms a dead man's switch and needs a human inside the window —
but firewall state is *recorded* in the baseline. `audit.sh`, `backup.sh`,
`canary.sh`, `guardian.sh`, `sentry.sh`, `watch.sh`, `watchdog.sh` belong to
`arm.sh`. `banner.sh`, `splunk.sh`, `card.sh`, `preserve.sh`, `diff-evidence.sh`
are inject or incident tools and stay out.

### One walk, three views

`recon.sh` and `triage.sh` today enumerate the same surfaces twice with
separately written code — cron in every form, units and drop-ins, users,
listeners, SUID, rc files. `surface.sh`'s own header admits the overlap. That is
slow on a clock, and worse, the two can disagree with no way to tell which is
right.

So the box gets enumerated ONCE into a structured inventory, and three consumers
read it: recon records it, harden proposes what is unnecessary, triage flags
what is unexplained.

---

## The output contract

Every finding, from every source, renders the same way:

```
  [2] RED  unitdropin  scored-web.service.d/10-hardening.conf
      why:  drop-in on a SCORED unit, unpackaged, created 00:49 today
      will: remove the drop-in only, daemon-reload, restart scored-web,
            then confirm 8080 answers before reporting done.
      run:  sudo .../baseline.sh --config ~/ccdc-real.env --approve 2 --apply
      more: playbooks/remediation-cards.md  CARD 4
      dig:  sudo .../baseline.sh --config ~/ccdc-real.env --explain 2
```

Rules that are not negotiable, each of which exists because it was violated:

**A path is not a command.** The evidence directory is 0700 root. Naming a file
inside it is not an instruction — it cannot be tab-completed, cd'd into, or
globbed against, and `sudo cd` cannot work because `cd` is a shell builtin.
Every message that says where something landed hands over the command that opens
it. Enforced by an assertion.

**No printed command carries a bracketed placeholder.** `[N]` is a valid glob,
so bash passes it through silently and the tool rejects it as not a number.
Enforced by an assertion.

**A destructive command never identifies its target by position in a list.**
`--approve 2` is fine: approving is reversible and logged. `--remove-key b` is
not — a letter is a pointer into a list that may have re-sorted. Destructive
flags name the thing itself (a fingerprint, a path) and say what they do:
`--remove-key`, never `--key`.

**Interlocks, not warnings, for the irreversible ones.** Documentation tells you
not to make the mistake. An interlock means you cannot. The tool refuses to
remove the SSH key that authenticated the current session — it reads the auth
log itself rather than trusting either party — and requires an explicit
`--i-have-console-access` to override.

**Actions verify after acting.** Anything touching a scored unit restarts it and
then confirms the port answers before reporting success.

### The NEEDS YOU voice

Findings that genuinely need a human get prose, not labels. The failing version
read `check: you are logged in right now with (a). Removing (b) cannot lock you
out. Verify with: ssh-add -l` — a pile of fragments, and the command was wrong
besides (`ssh-add -l` lists the local agent, not what the box authorizes).

The shape that works: what I found and when, why I will not touch it, the one
command that resolves the ambiguity, what to do if the answer surprises you, and
a playbook reference. Each destructive option gets its own complete command so
the operator copies a line rather than translating a letter into an action.

```
  [10] RED   An SSH key was added to your account after you armed the box.

       /home/banneluk/.ssh/authorized_keys has two keys in it. One has been
       there since the box was built. The other appeared at 00:49 today,
       twenty seconds after the drop-in and the rogue account.

         a)  banneluk@laptop        SHA256:xK3f...    Sep 11 05:44
         b)  banneluk@workstation   SHA256:9dLm...    Sep 17 00:49

       I am not going to guess which one is yours, because deleting the
       wrong line locks you out of a box you are being scored on.

       You are logged in over SSH right now, and the key that let you in is
       written in the SSH log. Run this and it prints the fingerprint:

         sudo journalctl -u ssh | grep "Accepted publickey" | tail -1

       That fingerprint is yours. To DELETE THE OTHER ONE, paste the command
       for it below - each deletes only the key it names and leaves the rest
       of the file untouched:

         to delete (a) banneluk@laptop:
           sudo .../baseline.sh --approve 10 --remove-key SHA256:xK3f... --apply

         to delete (b) banneluk@workstation:
           sudo .../baseline.sh --approve 10 --remove-key SHA256:9dLm... --apply

       If the log's fingerprint matches neither, stop and read CARD 2 in
       playbooks/remediation-cards.md - that means something else is wrong.
```

### Batch approval

`--approve 1,3,4 --apply` for several. `--approve all-green --apply` for
everything safe, which deliberately refuses to touch anything in the NEEDS YOU
block.

---

## Standing exceptions

An inject will ask for a service that is not in the baseline. Re-enabling it
must be an explicit recorded exception, never a silent unflagging:

```bash
sudo ./linux/baseline.sh --config ~/ccdc-real.env \
     --allow nginx --reason "inject 4: stand up the team web page" --apply
```

Three properties:

- It enters the baseline **with a reason and a timestamp** — not "stop reporting
  nginx" but "nginx is expected as of 14:32 because inject 4."
- **Exceptions are listed every time, forever.** They never fade into normal. An
  exception is a hole you deliberately opened; if it scrolls away it becomes a
  permanent blind spot, which is the `watch.sh` decay bug in another costume.
  Both `--status` and `arm.sh`'s warning block carry a standing block.
- **It doubles as inject evidence.** A timestamped record of every change and
  why is half an inject response already written, and injects are roughly half
  the score.

`CCDC_BASELINE_ALLOW` in the config holds exceptions already known from the
packet, so they are in place before the clock starts.

---

## Alerting

Nothing in the kit notifies the operator of anything. There is no `wall`, no
`notify-send`, no tty write, no mail. The only mechanism that exists is a
terminal bell in `sentry.sh`, and `sentry.sh` hardcodes `--no-bell` into the
systemd unit it installs. You find out when you type the command.

To add, in order of value:

- **`wall` on RED findings only**, deduped. It reaches every logged-in terminal
  in seconds, needs nothing installed, and interrupts what you are typing, which
  is the point. Deduplication is not optional — walled every 60 seconds about
  the same finding, you learn to ignore it within ten minutes.
- **A prompt indicator** for everything below RED: `[!3]` in `PS1` when unacked
  items exist.
- **A dedicated pane** running `watch.sh --loop`.

---

## What bless does NOT promise

`--bless` is not a proof that the box is clean. It is a commitment device: it
makes *future* change expensive to hide. Most red team activity in an event
happens during the event, so that is worth a great deal — but it is a different
claim, and selling the wrong one would be worse than saying nothing.

By category, at bless time:

| What | Confidence | Why |
|---|---|---|
| Anything appearing AFTER bless | Very high | This is what the design is for |
| Unexplained files present at bless | High | Provenance, three-clause test |
| Modified package files | Good | `dpkg --verify` against shipped checksums |
| Backdoor as legitimate content in an expected file | Moderate | Only the frozen semantic readings cover this |
| Kernel module / memory-only implant | Low | Not a file question; `lsmod` is recorded but not baselined |
| Competent root compromise predating you | None | They can edit the package DB. No host tool is authoritative about its own state |

The mitigations for the bottom two rows are off-box: whether the scorer sees the
service behaving, and whether anything reappears after removal.

---

## Build order

1. **Baseline and drift** — the blessed baseline, the three-clause explained
   test, semantic readings frozen alongside the file inventory, drift measured
   against the baseline rather than the previous pass.
2. **The finish line** — every finding carries why/will/run/more. Thirteen of
   twenty-seven check types currently have no action at all: `etcchange`,
   `netproc`, `netprocsvc`, `netunpackaged`, `nopasswd`, `port`, `rogueunit`,
   `sshemptypw`, `sshkey`, `sshrootlogin`, `suidunpackaged`, `tmpproc`,
   `udpport`. Roughly nine of those are simply unwritten. Four are deliberate
   holds — `sshrootlogin` and `sshemptypw` stay manual because careless SSH
   automation locks you out of a scored box, and `etcchange` is informational.
3. **Alerting** — deduped `wall` on RED, prompt indicator otherwise.
4. **Render pass** — drive every tool through every mode and read the output as
   an operator rather than as its author.

## How to iterate from here

The method that produced the gaps was security by anecdote. Replacing it:

- **Get a denominator.** Write out every mechanism on this OS that causes code
  to run as root. It is a finite list, roughly forty entries. Coverage becomes a
  fraction that can be reported.
- **Default to provenance over content.** For each mechanism, ask whether every
  file there is explained, and report the remainder.
- **Generate drills from the inventory, not from imagination.** If `plant.sh`
  picks at random from the mechanism list, a drill stops measuring "did anyone
  think of this" and starts measuring real coverage.
