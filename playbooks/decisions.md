# Decisions

What we agreed and why, in the order we agreed it. This file exists because
context compaction loses **agreements** more readily than it loses requests: a
summary carries "Luke asked about consolidating the tools" and drops "and we
settled on baseline.sh being the single enumeration." On 2026-09-17 that gap
caused a tool to be built the way it had already been decided not to build it.

If a decision is not written here, it does not survive. Add to this file at the
moment of the decision, not later.

This is a decision log, not a competition checklist. It preserves why a choice
was made so a later edit does not undo it by accident. If you need the next
command to run, open `linux-first-15-minutes.md` or
`windows-first-15-minutes.md` instead.

---

## D1 — Provenance, not content (2026-09-17)

Ask why a thing is present, not whether a search happened to find scary text in
it. There are unlimited ways to spell a reverse shell, so text matching only
catches the versions someone imagined. Here, "explained" has three concrete
meanings: it was present when you blessed the clean box, its package owns it and
its checksum still matches, or you explicitly recorded it as allowed.

**Why:** two drill footholds walked past every content check in the kit.

## D2 — Harden to a baseline, then hold it (2026-09-17, Luke's framing)

> "instead of trying to hunt down specific ways attackers can get in, we can
> control for the variable that we can confirm, exactly what processes HAVE to
> be running, and cut out anything else. We should be hardening to a baseline,
> leaving essential and scored features up, and then from there, cutting out
> EVERYTHING ELSE and ensuring that once we hit the baseline it stays that way."

Two questions, not one: what is **unexplained** (provenance) and what is
**unnecessary** (necessity). Both are required. Neither substitutes for the other.

## D3 — One enumeration, several views (2026-09-17) — **NOT YET BUILT**

Luke asked whether recon, harden and triage could be consolidated the way arm.sh
consolidated the tier-1 sequence. Agreed shape:

> The box gets enumerated **once** into one structured inventory, with consumers
> reading it: recon records it, harden proposes what is unnecessary, triage flags
> what is unexplained. One walk, one truth, several views.

**Why it matters:** two separate scans can disagree. For example, one could
show a cron job and the other could say nothing. Under time pressure, you then
have no clear answer about which result to trust.

**Status as of 2026-09-18:** the shared producer is built:
`baseline.sh --inventory` emits `kind|subject|detail`, and `recon.sh`
records it as `execution-inventory.txt`. `recon.sh`, `triage.sh`,
`hunt.sh`, and `harden.sh` still retain their specialised walks, so consumer
migration and parity proof remain the open item.

## D3a — One approval queue, three sources (2026-09-17) — historical proposal

> "The key design decision: **harden.sh proposes, it doesn't act.** Same numbered
> list, same `--approve N --apply`, same why/will/run/more. Which means one
> interface for the whole kit — 'remove this unnecessary service' and 'remove
> this implant' look and work identically. Three sources feed one approval
> queue: harden (unnecessary), triage (unexplained), watch (drift)."

**AMENDED 2026-09-17 by Luke, after seeing the built tool:** harden.sh KEEPS its
own `--cut` / `--undo`. Do not remove them.

The original reasoning was one interface for the whole kit. In practice the two
actions are not the same shape and the difference is worth having: approving a
finding removes ONE thing that should not be there, while cutting is a bulk
decision about a whole family that is legitimately present — and it carries a
scored-service check plus an automatic rollback after every single cut, which
`--approve` does not need. A shared verb would have had to mean both.

**Resolved 2026-09-18:** `baseline.sh --review` lists unexplained findings and
legitimate-but-unnecessary candidates in one read-only screen. Their actions
remain intentionally separate: provenance approval removes one unexplained
item; `harden.sh --cut` retains its scored-service rollback.

## D3b — Get a denominator (2026-09-17) — historical proposal

In answer to "do we need to think differently about how we iterate?", three
method changes were agreed. All three are now implemented, with a deliberately
bounded meaning for the denominator.

1. **Get a denominator.** Write out every mechanism on this OS that causes code
   to run as root — a finite list, perhaps forty entries — so coverage is a
   fraction that can be reported instead of "27 checks" with nothing to divide
   by. *(Done: `baseline.sh --mechanisms` exports the declared mechanisms and
   normal reports state how many are present. It is explicitly inventory
   coverage, not a percentage of all possible compromise paths.)*
2. **Flip the default from content to provenance.** *(Done — see D1.)*
3. **Generate drills from the inventory, not from imagination.** If the planting
   fixture picks at random from the mechanism list, a drill stops measuring "did
   Claude think of this" and starts measuring real coverage. *(Done:
   `redteam/mechanism-drill.sh` turns the exported mechanism inventory into a
   rotating lab plan without blindly modifying authentication or boot paths.)*

## D3c — Alerting, in three tiers (2026-09-17) — **PARTIALLY BUILT**

1. Deduped `wall` on RED findings. *(Done in `watch.sh`; enabled by default
   through `CCDC_WATCH_NOTIFY=1` when `wall` is available.)*
2. A prompt indicator, `[!3]` in `PS1`, for actionable AMBER items. *(Done
   2026-09-18 as opt-in `linux/prompt.sh`; `[!?]` is stale/unknown, and RED
   remains on the interrupting wall path.)*
3. A dedicated pane running the watch loop. *(Not a packaged workflow. The
   installed sentry already runs watch; use `sentry.sh --status` for the queue.)*

## D4 — Blessing is a commitment device, not a cleanliness proof (2026-09-17)

`--bless` does not certify the box is clean. It freezes what is here so that
everything afterwards is measured against it **forever**, never against the
previous pass, so nothing decays into normal. It follows that:

- Bless a box you have not cleaned and you bless the implants with it. Order is
  recon/hunt -> harden -> triage/baseline review -> bless -> arm.
- Drift is measured against the blessing, not the last run.
- An exception is recorded with a reason and a timestamp, which is also a line
  you can paste into the inject that asked for the change.

## D5 — Approve the output before it is built (2026-09-17, Luke's process rule)

> "why don't you give me like a sample of what output you're trying to go for and
> I approve it before you build it rather than after"

This applies to the **shape of the tool**, not only the wording. A sample that
silently introduces a new separate script is not the thing that was approved.

## D6 — Purge, do not merely disable (2026-09-17, Luke's call)

A disabled unit is one `systemctl enable` away from returning, and the person
most likely to type that already has root. So remove the package — but cache its
`.deb` to the evidence directory first, so the undo works on a competition
network that cannot reach a mirror. If nothing can be cached, degrade to
disable-and-mask and **say so** rather than purging blind.

## D7 — Dual-use tools need a human (2026-09-17, Luke's call)

Something that is both an attacker's tool and one of ours (`tcpdump`, `nc`) is
never cut silently. Report it, name which of our own scripts calls it, and let
the operator decide.

## D8 — Never kill what could not be captured (2026-09-17)

A kill destroys the only evidence there was. The tool captures first and kills
only what a capture succeeded on. A refused freeze falls back to capturing the
process while it runs; a total failure leaves the process alone and says so.

## D9 — ART is the adversary, not the denominator (2026-09-17, Luke's correction)

> "since we can't possibly know the exact demoninator of attack methods, we use
> what we do have confirmed, the essential/scoring files, and harden everything
> else."

Atomic Red Team is a corpus for naming mechanisms nobody thought of. It is not a
coverage measure, and "N of 434" must never be printed as one.

## D10 — A check that cannot run must not read as a pass (2026-09-17)

Recurring bug class, found four separate times in one night: a safety check that
compares an empty list, a port probe that finds nothing to probe and returns
success, a capture that fails and is reported as honoured. Any check that could
not execute says so.

## D11 — Every finding ties to a card (2026-09-17, Luke's instruction)

> "don't just check cards for what's showing up rn, look at all the
> possibilities we've looked at and make sure each possible output is tied to a
> card, write it fresh if you need to"

Every finding the kit can emit carries a `more:` line naming a real card —
approvable **and** needs-you, and especially needs-you, because that is where
the operator has to decide something and a reference is the difference between
deciding and guessing.

The kit emits **60 distinct finding kinds** across baseline.sh, triage.sh and
harden.sh. A reference to a card that does not exist, or to the wrong card,
costs a page-turn to discover and is worse than none.

Cards written 2026-09-17 to close the gaps found by enumerating all 60:
- **CARD 13** SSH is configured to let them in (`sshrootlogin`, `sshemptypw`) —
  these are permanent NEEDS-YOU items and had no card at all; they were being
  pointed at CARD 8, which is listening ports.
- **CARD 14** a kernel module that was not loaded when you froze the box
- **CARD 15** a user-level service, running as someone who is not logged in
- **CARD 16** something is running that nothing needs (harden.sh's necessity
  findings, which are a different category from every other card: nothing on it
  is an implant)

## D12 — Sentry's finish line (2026-09-17) — **DONE, proven on the lab box**

The original count: 27 check types, 14 with an action, 13 without. Of the 13,
nine were "simply unwritten" and four are deliberate holds (`sshrootlogin`,
`sshemptypw`, `etcchange`, and `sshkey` as the judgement call).

**Built 2026-09-17:** `nopasswd`, `suidunpackaged`, `rogueunit`, `tmpproc`,
`netproc`. Each captures evidence first; `rogueunit` re-checks the scored
services and restores the unit if one stops answering; the live-process actions
refuse to kill anything they could not capture.

**Built 2026-09-17, second pass:** `port`, `udpport`, `netunpackaged`,
`netprocsvc`. Each names a port or a process that may BE the scored service, so
each re-checks the scored services afterwards. A port held by a *unit* is
stopped and disabled, which is reversible and is the preferred branch; a port
held by a bare process is captured and killed, which is not, so everything that
could be ours is refused before the function is ever reached.

**Proven end to end on the lab box, 2026-09-17 06:18–06:24.** One instance of
each of the nine planted, `--status` showed **16 numbered items**, a bulk
`--approve --apply` applied 8 RED and handed back 8 AMBER by number, each AMBER
was then approved individually, and the run ended at "Nothing waiting for your
sign-off" with scored-web answering 200 at every single step. What is left in
NEEDS YOU is the agreed set: `crondeep`, `sshkey`, `etcchange`, and the two
AMBER holds that are correctly not offered.

**Also fixed on the way:** `nopasswd` emitted the literal subject `"sudoers"` —
a category, not a target, so it could never be acted on. It now emits one
finding per file, RED for a drop-in that postdates the box and AMBER for the
rest. Same defect as the old `see-log` subjects.

## D13 — AMBER findings get numbers too, but never a bulk sweep (2026-09-17)

The queue was RED-only. Every finding about a listening port or a
socket-holding process is AMBER — because every one of them might be yours —
so the entire class could be detected, described, and never offered. That is
the finish line the operator kept falling off.

So the queue admits AMBER, and the split is at the **bulk** approve instead:

- `--approve N --apply` applies any item, RED or AMBER.
- `--approve --apply` with no number applies the RED items and prints each
  AMBER one with its own number and the reason it was skipped.

Because an AMBER action stops a port or kills a process, and a sweep that took
those would be the self-inflicted outage this kit exists to prevent.

**Not every check is offerable at AMBER.** `offerable_at_amber()` lists the
ones that are: `port`, `udpport`, `rogueunit`, `netunpackaged`, `netprocsvc` —
either reversible, or a live process holding a port nothing accounts for. Two
measured cases decided the exclusions. An AMBER `nopasswd` is a sudoers drop-in
that *predates* the box: on the lab VM it was `/etc/sudoers.d/90-cloud-init-users`,
and approving its removal would have taken the operator's own passwordless sudo
with it. An AMBER `suidunpackaged` predates the box too, and triage says so in
as many words. Neither is incident response.

## D14 — Killing a process and deleting its executable are different decisions

Only the second one is about provenance, and getting that wrong is the worst
thing this kit has done to a box.

Measured 2026-09-17: approving a `netprocsvc` finding for a python web shell
deleted **`/usr/bin/python3.12`** — the interpreter the *scored service* runs
on. The running service kept serving, because its binary was already mapped, so
nothing looked wrong; the next restart would have failed, and `/usr/bin/python3`
was left as a dangling symlink. It was recovered byte-for-byte from sentry's own
evidence copy, which is the argument for capture-before-destroy demonstrated on
itself.

The rule now: **an executable is deleted only when no package owns it.** A
dropper in `/dev/shm` is owned by nothing and goes. A shared, package-owned
interpreter is not the attacker's file — the attacker's file is the script it
was told to run, and that is a different finding. The `will:` line says which
of the two will happen, per file.

**And "owned by no package" has to be asked correctly.** `dpkg-query -S
/usr/bin/nc.openbsd` says *no path found*, because dpkg recorded it as
`/bin/nc.openbsd` on a merged-/usr system. `lib/provenance.sh` has handled this
since it was written, and its own header says baseline, harden and sentry all
ask through it — sentry never sourced it, and triage sourced it and then kept a
private copy of the question without the fix. Three more tools (`sshd.sh`,
`surface.sh`, `baseline.sh`) asked dpkg directly for the owning package *name*
and would print an empty owner for a stock binary, which reads as "no package
ships this". All of them now go through `pkg_owns()` / `pkg_owner()`, and a
sweep assertion fails the suite if a new one appears.

## D15 — The offer and the pre-kill re-check must ask the same question

`can_automate` decides whether to offer an item; the action re-checks
immediately before the kill, because the queue can be a minute old and pids are
recycled. If that second check is *stricter* than the first, it is not extra
safety — it is sentry printing an approve command and then refusing its own
offer with "FAILED — partial changes may have occurred" and nothing to do next.

Measured: `netprocsvc` was cleared with the protected-port test skipped and
re-checked with it applied, so the approval could never succeed no matter how
many times it was run. Both now go through one `protection_mode_for()`, and an
assertion fails the suite if either calls `pid_is_protected` without it.

`netprocsvc` is the one check that skips the protected-port test, and only
because it substitutes a stricter one: this finding exists *because* the port
is one the packet accounts for — that is the shape of it, and it is the nastiest
place to hide, since every port-based check waves it through. What is asked
instead is whether a `.service` or `.socket` owns the process. A scored service
arrives as a unit; an interpreter holding a scored port under no unit is not it.

## D16 — "That one is mine, stop asking" (2026-09-17, Luke's ask)

Verbatim: *"I'm not sure exactly what command I need to run if it isn't legit
or what to run to make an exception for it so I'm not getting bloated with
ambers."*

There was no exception mechanism for triage findings at all. The only
suppressions were config lists — `CCDC_ALLOWED_TCP_PORTS`, `CCDC_ALLOWED_USERS`,
`CCDC_SYSTEMD_SERVICES` — and nothing covered "this process is mine". The tool's
answer to a finding the operator had already judged was to report it again on
the next pass, and the pass after that, for the rest of the event. An operator
who cannot silence a known finding learns to skim the list it is in, and that
is the only list that must not be skimmed.

**Three things, in order of how much they matter.**

**1. The biggest source of bloat was a false positive.** `netprocsvc` fired on
`scored-web` — `python3 -m http.server 8080` — every single pass. It could not
be acted on (sentry protects the unit, correctly) and could not be silenced. It
is now suppressed at source: an interpreter holding an accounted-for port, under
a unit the packet *declares*, is not a coincidence — it IS the scored service,
and there is nothing left to decide. A declared service is **explained**, not
silenced, and the held prose now says so and prints the `CCDC_SYSTEMD_SERVICES`
line to paste, already filled in with the current value plus the new unit.

**2. `sentry.sh --mute CHECK SUBJECT --reason "..."`,** with `--unmute` and
`--muted`. Named, never numbered: a held finding has no row number to give, and
a numbered one re-sorts between reading the screen and typing the command. Every
render path — approvable, RED-held, AMBER-held — prints the exact command with
the target already filled in.

Three properties make it safe to have at all:

- a reason is required, so an exception is never indistinguishable from a thing
  someone forgot about;
- the count is printed in every ALERTS header and at the end of every triage
  run, whether or not anything else is wrong, so a muted finding is silenced
  and never invisible — including if someone with root writes the file directly;
- the key drops the pid, because a live-process subject carries the pid it was
  found under and that number changes on every restart. Muting the literal
  string would silence it until the next restart and no longer, which is worse
  than not offering the option: it looks like it worked.

**3. The key has to carry the port, and finding that out was the close call.**
With the pid dropped, `pid3304283:/usr/bin/python3.12` and
`pid3445412:/usr/bin/python3.12` produce the same key. Muting the legitimate
python service would have silenced a python web shell on a different port,
permanently and invisibly — the exact hiding place the `netprocsvc` check exists
to find. Listening socket findings now carry `netid/port` in the subject, so
the two keys differ. Caught on the lab box by muting one and watching the other
disappear, before it shipped.

## D17 — A config change has to reach the running loop (2026-09-17, Luke's ask)

Verbatim: *"I'd like somewhere to remind me the process of adding the exception
to the config. Either a playbook reference or quick commands to get to what I
need to do."*

Asking exposed a trap worth more than the reminder. The supervised sentry does
not read the file the operator edits: `--install` copies the config to
`$install_dir/sentry.env` and the unit's `ExecStart` names that copy. That is
deliberate — an attacker who can write to a home directory must not be able to
steer a root loop — but it means editing `~/ccdc-real.env` changes nothing and
says nothing.

The obvious second attempt is worse. **Measured on the lab box:**
`CCDC_SYSTEMD_SERVICES` was edited in the INSTALLED copy at 15:22 and was the
old value again 75 seconds later, with nothing printed anywhere. Guardian holds
`sentry.env` in its repair tree and cannot tell a legitimate change from
tampering — that ambiguity is the entire point of guardian — so it wins, every
minute, silently. Two dead ends and no error message on either.

So: `sentry.sh --reload-config --apply`. It validates the config parses (a
broken one takes the loop down, and the loop is what would have told you), takes
guardian down, reinstalls sentry, puts guardian back so it re-takes its copy,
verifies the installed config now matches, and prints the three lists that
decide everything. Without `--apply` it prints the three steps and changes
nothing. If the middle step fails it says guardian is still down and prints the
command to restore it.

Every place in the kit that tells the operator to edit a config now names that
command — `sentry.sh`, `baseline.sh` and `triage.sh` — and an assertion fails
the suite if a tool suggests a config edit without it.

`playbooks/packet-to-config.md` gained a "Changing the config once the event has
started" section: the trap with the measured timings, the one command, and a
table of which knob explains which finding. It also records the preference —
**config over exception**: a declared service is *explained*, so the check stops
firing because the box now makes sense, where a muted finding is *silenced*,
still true, and still there.
