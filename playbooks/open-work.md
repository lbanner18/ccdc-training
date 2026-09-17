# Open work

The running checklist. Anything promised and not yet delivered lives here until it is
done. Audit date: 2026-09-16. Competition: 2026-09-26.

Status key: `[ ]` not started, `[~]` in progress, `[x]` done and verified.

## P0 — headline features verified on the lab VM

- [x] **1. Run `baseline.sh --bless --apply` on the lab box and exercise `--status`.**
      `/var/tmp/ccdc-evidence/baseline/` has `queue`, `actions.log`, `dpkg-verify.cache`
      and **no `inventory`**. So `in_blessed()`, `--status`, drift-against-baseline and
      the semantic readings have never run on real data. Every result shown so far came
      from the no-baseline-yet path.
      **Done 2026-09-16.** Full cycle proven on the lab box: bless a clean box
      (531 items) -> plant 8 -> 9 findings, all 8 caught as drift -> `--approve
      all-green` -> `--remove-key` -> `Nothing unexplained`. scored-web stayed up
      (http 200) throughout and SSH still worked afterwards. Two real bugs found
      and fixed, see commit.

- [x] **2. Build the "unnecessary" half — `harden.sh`.**
      The model is *harden to a baseline, cut everything else, keep it that way*.
      `baseline.sh` answers **unexplained**. Nothing answers **unnecessary**. The
      documented pipeline is recon -> harden -> triage -> bless -> arm and `harden`
      was never written.
      **Done 2026-09-16.** `linux/harden.sh`, 20 assertions in
      `redteam/harden-self-test.sh`. Proven on the lab box: 23 findings ->
      `--cut all-safe --apply` -> 19 cut, scored services verified after every
      single one -> `--undo --apply` -> 19 restored, SUID bits back, zero masks
      left, http 200. Seven bugs found by running it, four of them safety
      checks that passed without comparing anything.

## P0 — agreed with Luke and not built (found 2026-09-17 by auditing the
## transcript instead of my own framing)

- [x] **A. One approval queue.** ~~harden.sh should propose, not act.~~
      **Overridden by Luke 2026-09-17: harden.sh keeps `--cut`/`--undo`.** The
      two actions are different shapes — `--approve` removes one thing that
      should not exist; `--cut` is a bulk decision about a family that is
      legitimately present, with a scored check and auto-rollback per cut.
- [ ] **B. `baseline.sh` prints unexplained AND unnecessary together**, one
      numbered sequence. Today it prints only unexplained.
- [ ] **C. A denominator.** Report coverage as a fraction of the known
      root-execution mechanisms rather than as a count of checks. The mechanism
      list already exists (`exec_trigger_dirs`); nothing divides by it.
- [ ] **D. Generate drills from that list**, not from what I thought of. A
      hand-written plant set measures whether I imagined the mechanism, which is
      the exact bias the whole redesign was meant to remove.
- [ ] **E. Prompt indicator** — `[!3]` in `PS1` for findings below RED.
      Described in `baseline-design.md:338`, never built.

## P0b — sentry's finish line (2026-09-17, in progress)

- [x] `more:` card reference on EVERY sentry item, approvable and needs-you.
      Asserted, including that every card named actually exists.
- [x] Cards 13-16 written to close the gaps found by enumerating all 60 finding
      kinds the kit can emit.
- [x] Actions written: `nopasswd`, `suidunpackaged`, `rogueunit`, `tmpproc`,
      `netproc`.
- [x] Actions written: `port`, `udpport`, `netunpackaged`, `netprocsvc`. A port
      held by a unit is stopped and disabled (reversible, preferred); a port
      held by a bare process is captured and killed.
- [x] **Proven end to end on the lab box, 2026-09-17.** One of each of the nine
      planted -> 16 numbered items -> bulk approve applied 8 RED and handed back
      8 AMBER by number -> each AMBER approved individually -> "Nothing waiting
      for your sign-off", with scored-web answering 200 at every step.
- [x] Installed under guardian in the right order; no drift warning, no revert.
- [x] `card_for` completeness wired into baseline.sh, asserted against
      `kind_for`'s whole classification table and `why_for`'s whole vocabulary
      rather than against one run's output. Found two kinds with no card at all
      (`module`, `initramfs`) and three filed under CARD 11, "shell start-up
      file that launches something", that are nothing of the sort (`sysctl`,
      `apparmor`, `kernelhook` - they are /etc files that changed, CARD 9).
      CARD 14 now covers the initramfs, because a hook there runs as root
      before the real root filesystem is mounted and removing the file is not
      enough on its own: the image already built from it is what boots.
- [ ] **Remember:** every sentry change needs guardian uninstall -> sentry
      install -> guardian install, or guardian reverts it within a tick.

- [x] **Standing exceptions.** `sentry.sh --mute CHECK SUBJECT --reason "..."`,
      `--unmute`, `--muted`. Every finding prints its own mute command; the
      count of silenced findings is in every report header. See D16.
- [x] **CARD 11 rewritten** to cover `/etc/ld.so.preload` as well as shell
      start-up files, with a table saying which kinds are approvable as a whole
      file (`loader`, `profile`, `motd`) and which is held because one line of a
      legitimate file is theirs (`usershell`) — and what to do after removing
      `ld.so.preload`, which is find the library it named and restart everything
      that still has it mapped.

- [x] **`sentry.sh --reload-config --apply`** — a config edit reaches the
      running loop. Editing your own config did nothing; editing the installed
      copy was reverted by guardian in 75 seconds with no message. Both measured.
      See D17 and `playbooks/packet-to-config.md`.

### What testing found that writing did not (2026-09-17)

Every one of these was live in code that read correctly and had passed the
suite. This is the argument for running it rather than reading it.

1. **The five actions were unreachable.** `can_automate` had no arm for any of
   them, so the queue never held one and `--approve` never routed to one. Dead
   code that read like a feature. A three-way parity assertion now fails the
   suite if `execute_action`, `can_automate` and `render_action` ever disagree.
2. **Approving `netprocsvc` deleted `/usr/bin/python3.12`** — the interpreter
   the scored service runs on. See D14.
3. **`exe_is_unpackaged` called `/usr/bin/nc.openbsd` unowned**, because dpkg
   recorded it as `/bin/nc.openbsd`. The library that has always handled this
   was never sourced by sentry. See D14.
4. **The rollback did nothing.** Both rollbacks rebuilt the preserved path by
   hand and missed the sequence number `preserve_into_case` writes, then sent
   the error to `/dev/null`. A rogue unit holding a scored port was removed, the
   scored check correctly failed, the report correctly said FAILED — and the
   unit file was gone, under a line promising it would be put back.
5. **Net findings named a binary, not a process.** Three `netproc` findings all
   naming `/usr/bin/nc.openbsd` resolved to one arbitrary pid; two `netprocsvc`
   findings naming `/usr/bin/python3.12` both resolved to scored-web, which is
   protected, so neither could ever be acted on. Subjects now carry the pid.
6. **Queued findings were printed twice** — once with an approve command, once
   under NEEDS YOU. Queueing AMBER made the two sets overlap for the first time.
7. **Sentry refused its own offer.** `can_automate` cleared an item and the
   action's pre-kill re-check rejected it. See D15.
8. **`action_unit` had no scored re-check** while `action_rogueunit` did, so the
   same unit file had two different safety levels depending on which detector
   named it first.

## P1 — promised in writing, not built

- [x] 3. `--explain N` — built in `harden.sh` and back-ported to `baseline.sh`.
      Reports which of the three tests failed and why, shows the subject as it is
      on the box right now, and expands the action into ordered steps. Every card
      now carries the `dig:` line the design contract promised.
- [x] 4. Bless the sudoers ruleset — done, **and the group route with it**.
      `usermod -aG sudo mallory` grants root while leaving every sudoers file
      byte-identical, so `sudogrp|` rows freeze membership of sudo/admin/wheel/
      adm/root/staff too. Both proven to drift-detect and clear on the lab box.
      Never edited automatically: it hands over `visudo`.
- [x] 5. The unactioned check types in `triage.sh` / `sentry.sh`.
      **Answered by measuring instead of building.** On the drill set,
      `baseline.sh` found every finding `triage.sh` found, plus two it did not
      (the `/etc/update-motd.d` script and the `/etc/ld.so.preload` hijack),
      and named each with its own action where triage reported them inside an
      "/etc files modified" bucket. Writing nine more sentry actions would have
      produced two tools that can disagree about the same finding. What the two
      DO differ on is worth keeping: **baseline reports change, triage reports
      state.** A box that shipped with `PermitRootLogin yes` and was blessed
      that way never drifts, and baseline stays silent about it forever.
      triage.sh now says which question it answers and routes to baseline for
      the other one.
      Separately, this closed a real gap it exposed: the generic `file` kind had
      no action and no written reason, and the coverage assertion excluded it by
      hand with a comment claiming the default arms handled it. They did not.
- [~] 6. Render pass. Done for `--help` across all 25 tools, which found that
      **19 of 25 answered with a single usage line.** The flags were all there
      (an assertion already enforced that), but `fw.sh --config FILE
      [--dry-run|--apply] [--confirm|...]` never said that `--apply` arms a
      rollback you must confirm or lose — the one fact you need at minute 12.
      All 13 mutating tools now explain their modes, and a new assertion fails
      the suite if a tool that accepts `--apply` has help shorter than four
      lines. Still to do: read the main report bodies end to end on the box.
- [x] 7. ART harness — `redteam/atomic.sh`. Runs real atomics, asks baseline.sh
      and triage.sh before and after each, cleans up, scores CAUGHT / MISSED /
      NOOP / ERROR. Two interlocks (`CCDC_ATOMIC_LAB=1` on the sudo line **and**
      `--i-accept-this-box-is-disposable`) and a deny-list of techniques that
      destroy the box rather than persist on it.
      First persistence sweep: 33 run, 13 caught, **15 missed**. After the
      fixes those misses drove: 33 run, **21 caught, 0 missed**, 5 that do not
      execute on this image, 7 no-ops. 14 assertions in
      `redteam/atomic-self-test.sh`. Corpus is not in this repo; sparse-clone
      `atomics/` and pass `--corpus`.
      **Note:** a snapshot revert wipes `~/art` on the lab box, so the corpus
      needs re-syncing after every revert.

## P2 — docs and tests

- [x] 8. `baseline.sh` and `harden.sh` are now in `linux-first-15-minutes.md`
      (with bless placed *after* triage and harden, and the reason why),
      `competition-day-playbook.md` (§2d rewritten, new §2e for the freeze),
      `GUIDE.md`, `ROADMAP.md` and `README.md`.
      Also settled the overlap with the pre-existing `services.sh`: they take
      deliberately opposite positions (harden classifies and acts; services.sh
      shows you buckets and disables only the list you write), so they now hand
      off to each other rather than competing.
- [x] 9. `CCDC_BASELINE_ALLOW` is missing from `config/example.env`, so the packet
      worksheet never teaches that the exception mechanism exists.
- [x] 10. Documented commands that do not exist: `backup.sh --list` was real and
      is now **implemented** (CARD 9 needs it - `--restore` is useless without a
      way to see what there is to restore). `watch.sh --loop` corrected. The
      `baseline.sh --explain` reference became true when item 3 shipped.

- [x] 11. Extended the ghost-flag assertion (pasteable-self-test #72) to scan
      to the docs. Scans only fenced code blocks and only paths-with-a-slash,
      because prose legitimately says "policy.sh has no `--apply`". Negative-tested.
- [x] 12. README assertion-count check was a `>= 250` floor and cannot detect staleness.

## P3 — not code, deadline-bound

- [ ] 13. **Tryout sign-up — due 2026-09-24.**
- [ ] 14. Public-repo decision. Rule 5.6.1 wants three months public before the regional;
      "private now, public on competition day" does not satisfy it.
- [x] 15. Reviewed all six drafts against their numbered asks. They hold up
      better than the audit implied: all six carry the memo, the commands, and
      the evidence step; the two without a "deliverable beyond the memo" line
      are correct (IR procedure is memo-only, password policy's deliverable IS
      the citation). Login banner names five legal concepts, the two deliberate
      omissions, cites DISA, and catches the `/etc/issue` vs `/etc/issue.net`
      trap that decides pass or fail.
- [ ] 16. VPN Options inject needs a 3-minute recorded video. The catalog itself says it
      "cannot be improvised at minute 50."
- [x] 17. Unnecessary software audit inject — written
      (`injects/responses/unnecessary-software.md`), and `harden.sh --table`
      emits the location / ports / removal-steps table the inject asks for,
      already filled in. Section 3 is the part that matters: what was found and
      deliberately NOT removed, with the question each one turns on.
- [~] 18. Windows coverage. The three cross-platform injects (login banner, SSH
      access, endpoint protection) now carry their Windows commands, each with
      the trap that actually catches people: the banner appears at the NEXT
      logon; OpenSSH on Windows reads
      `C:\ProgramData\ssh\administrators_authorized_keys` for anything in the
      Administrators group and ignores the user profile entirely; Defender's
      `RealTimeProtectionEnabled` being false IS the finding, not something to
      quietly fix.
      **Marked untested** — the lab win11 VM has SSH open but will not take my
      key, so none of it has been run. Verify on the box before claiming it in a
      memo. `windows/` is still only recon.ps1 + watchdog.ps1 (63 lines); there
      is no Windows equivalent of baseline.sh or harden.sh and there will not be
      one before 2026-09-26.
