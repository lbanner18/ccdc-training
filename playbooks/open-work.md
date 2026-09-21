# Open work

The running checklist. Anything promised and not yet delivered lives here until it is
done. Audit date: 2026-09-18. Competition: 2026-09-26.

**Picking this up cold?** Jump to the HANDOFF section under "Windows" — it has
how to reach the lab box, the conventions that are not visible in the code, and
what to do next in priority order.

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

## P0 — agreed with Luke, now complete (found 2026-09-17 by auditing the
## transcript instead of my own framing)

- [x] **A. One approval queue.** ~~harden.sh should propose, not act.~~
      **Overridden by Luke 2026-09-17: harden.sh keeps `--cut`/`--undo`.** The
      two actions are different shapes — `--approve` removes one thing that
      should not exist; `--cut` is a bulk decision about a family that is
      legitimately present, with a scored check and auto-rollback per cut.
- [x] **B. One review index.** `baseline.sh --review` now prints unexplained
      and legitimate-but-unnecessary candidates in one numbered, read-only
      screen. It keeps their verbs separate: `--approve` uses provenance
      remediation; `harden.sh --cut` keeps its independent scored-service
      rollback.
- [x] **C. A denominator.** Every baseline report prints the fraction of the
      declared root-execution mechanisms present and enumerated. It explicitly
      says this is an inventory denominator, not an impossible percentage of
      all Linux compromise paths.
- [x] **D. Generate drills from that list.** `redteam/mechanism-drill.sh`
      consumes `baseline.sh --mechanisms` and prints a rotating lab drill plan.
      It plans rather than blindly plants PAM/sudoers/generator fixtures, which
      would change real authentication or boot behavior.
- [x] **E. Prompt indicator.** `linux/prompt.sh` is an opt-in Bash profile
      hook: `[!N]` counts pending actionable AMBER approvals; `[!?]` means the
      root-published sentry snapshot is stale, failed, or unknown. It does not
      auto-install through `arm.sh`, because `/etc/profile.d` is real baseline
      drift that must be reviewed and blessed deliberately.

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
- [x] **Guardian-coordinated sentry upgrade.** Every sentry change uses guardian
      uninstall -> sentry install -> guardian install, or guardian reverts it
      within a tick. `sentry.sh --install` now explicitly restarts an already
      active service after copying its private tree; `enable --now` had only
      reported success while the old shell process kept running.

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
9. **SUID evidence became a new SUID finding.** `cp -a` preserved the original
   special bit inside root-only removal evidence, and the next sweep correctly
   found it there. The action now records original mode/owner metadata and
   clears special bits only on the retained copy.
10. **`nc -z` was called a reverse shell.** The shared payload expression
    treated every netcat option as execution. It now recognises only netcat
    execution modes (`-e`, `-c`, `--exec`, `--sh-exec`), with both the harmless
    liveness probe and a real `-e /bin/sh` regression covered.
11. **An upgrade did not upgrade the running sentry.** `systemctl enable --now`
    starts a stopped unit but does not restart an active one. The installer now
    enables first, then restarts an active unit or starts an inactive unit; the
    real lab proof compared its MainPID before and after.

## Windows (started 2026-09-17; proven on real Windows 2026-09-18)

Built to the **Basic Windows Hardening Checklist** from the team's own course
material (`ccdc-coursework/.../Basic hrdning Chklst.pdf`), which is the closest
thing to a spec anyone has handed us.

The original ten tools, 5,580 lines, and 58 triage checks have run on a real
Windows Server 2022 box, not only against stubs. Guardian and its integrity
task also completed the disposable-VM failure drills on 2026-09-21. The
off-box exporter remains source-tested until it has copied a bundle to a real
team-controlled share and verified the remote hash.

- [x] `lib/Common.ps1` — config (the SAME file the Linux tools read), findings
      in the same `SEV|check|subject|desc` format, evidence, scored-service
      checks, and a capability probe that says out loud which checks cannot run
      on this box rather than skipping them silently.
- [x] `lib/Provenance.ps1` — "is this file explained?" via Authenticode. Never
      says a file is fine because it is signed; names the PUBLISHER and lets
      that be disbelieved. Knows that most of Windows is CATALOG signed, so an
      unsigned file under a system root is reported as a catalog question, not
      as a bad binary.
- [x] `triage.ps1` — 58 checks, RED/AMBER/NOTE, every finding printing the
      command that fixes it and a card reference.
- [x] `harden.ps1` — the checklist in order, `-Apply` gated, scored re-check
      after every step, and the firewall step writes your own access rules
      BEFORE it sets default-inbound to Block.
- [x] `users.ps1` — audit, backup admin, password rotation that refuses to
      touch a scored account without `-IncludeScoredUsers`.
- [x] `watchdog.ps1` — restarts stopped scored services, re-enables disabled
      scored ACCOUNTS, installs as a SYSTEM scheduled task.
- [x] `recon.ps1` — rewritten 2026-09-18. Was the last file predating
      `lib/Common.ps1`. Now records a GAP as a gap: a collection that failed
      writes a file saying so rather than an empty one.
- [x] `sentry.ps1` — the approval queue. 25 of the 58 checks are automatable;
      `-Status` freezes a numbered snapshot, `-Approve` re-verifies identity
      against a fresh scan, a sweep takes SWEEP-tier only.
- [x] `baseline.ps1` — configuration drift. Scoped to config plus the
      executable surface (~250 files, 9s), NOT the filesystem (~14,000 files,
      5 min, measured).
- [x] `canary.ps1` — tripwires via SACL + audit policy + event 4663, which
      reports WHO read a decoy. Hashing cannot answer that question.
- [x] `playbooks/windows-cards.md` — 13 cards, asserted to exist.
- [x] `playbooks/windows-first-15-minutes.md`
- [x] `redteam/windows-self-test.ps1` — 69 assertions against planted fixtures
      and the read-only Windows tools' static safety contracts.
- [x] `redteam/windows-plant.ps1` — LAB ONLY, two interlocks, verifies what
      survived rather than assuming (Defender eats some fixtures in real time).
- [x] `integrity.ps1` — third SYSTEM task that detects a missing, stopped, or
      redirected Guardian task. Proven on `ccdc-win` 2026-09-21 by removing
      Guardian's task: it wrote `INTEGRITY-GAP code=MISSING` and exited 2.
- [~] `evidence.ps1` — source-tested explicit UNC evidence exporter. Still
      needs a real share and an end-to-end copied-hash check on the lab VM.

### NOT YET TRUE OF THE WINDOWS HALF — read before trusting it

- [ ] **No domain hardening.** `users.ps1` refuses to run on a DC and hands over
      the AD commands instead. GPO, delegation, AD ACLs, Kerberos, ADCS: all by
      hand. This is the largest remaining gap by far and it is deliberate — see
      the handoff below for why it was not attempted before the tryout.
- [ ] **No tamper-proof watchdog.** `guardian.ps1` adds a second SYSTEM task
      that repairs the watchdog task, and `integrity.ps1` adds a third task
      that reports when Guardian itself is missing or redirected. An
      administrator can still remove or alter all three tasks and their private copies. That limit is intentional and
      printed by `guardian.ps1 -Status`.
- [~] **Autostart coverage is bounded.** The fallback now covers scheduled
      tasks; Run/RunOnce, 32-bit and policy Run keys; all local Startup folders;
      Winlogon; AppInit DLLs; IFEO debuggers; Active Setup; and permanent WMI
      consumers. An explicitly configured, validly Microsoft-signed Autorunsc
      adds read-only wider evidence without downloads, PATH lookup, or silent
      EULA acceptance. Without that opt-in, browser/shell extensions, print
      monitors, LSA providers, drivers, and vendor-specific hooks remain a
      stated gap. Proven read-only on `ccdc-win` 2026-09-18; SSH stayed closed
      and WinRM stayed up.
- [ ] **`sentry.ps1` acts on 25 of 58 checks.** The rest print a command because
      their fix needs judgement. Four are deliberately never automatable and the
      suite asserts it: `fwinbound`, `lsappl`, `svcpath`, `svcdiracl`.
- [ ] **The baseline does not cover files nothing wires to run.** By design.

---

# HANDOFF — read this first if you did not write the above

Written 2026-09-18. Competition **2026-09-26**. Luke competes **solo**.

## Getting to the lab box

**`ccdc-win` at 192.168.100.142. Use WinRM (5985), not SSH.** SSH is not
installed and cannot be: the unattend runs `Add-WindowsCapability -Online -Name
OpenSSH.Server`, which downloads from Windows Update, and the `ccdc-lab`
network has no `<forward>` element so there is no route out. The step fails,
the rest of provisioning continues, and the box comes up with
`C:\ccdc-lab-ready.txt` present and port 22 closed. That looks like a
provisioning failure and is not one.

There is no WinRM client on the Linux host either. `pip install pywinrm
requests_ntlm` into a venv, then `winrm.Session(..., transport="ntlm")`.
Administrator / `CcdcLab!2026`, lab only, isolated network.

Three things bite over WinRM and each cost real time:

- **`run_ps` sends `powershell -encodedcommand`, and Windows caps a command
  line at 8191 characters.** A 6000-character script becomes ~16000 encoded and
  fails with an EMPTY stderr. Keep each call under ~2000 characters, or write to
  a file on the box and fetch it in chunks.
- **PowerShell exits 1 whenever the last statement sets `$?` false**, even when
  the error was suppressed with `-ErrorAction SilentlyContinue`. `Remove-Item`
  on a missing path is enough. Wrap remote scripts and `exit 0` explicitly.
- **Responses truncate around 6KB** (`no element found: line 1, column 6088`).
  Redirect with `*> file` and fetch the file rather than reading stdout.

`win11` at 192.168.122.77 is **Luke's CI runner, not a target.** Do not
snapshot, revert or plant on it. `ccdc-win` has a `clean-windows` snapshot;
note that an internal snapshot fails on a running UEFI/pflash guest but works
once it is shut off, and `virsh shutdown` is ignored when nobody is logged in
at the console — use `shutdown /s /f` over WinRM.

## Conventions that are not obvious from the code

- **PowerShell 5.1 is the floor.** No `??`, `?.`, `&&`, `||`, `-Parallel`. A
  token-stream check in `windows-self-test.ps1` fails the suite on any of them.
- **`Set-StrictMode -Version 2.0` everywhere.** Reaching for a property that
  does not exist THROWS. Guard with
  `$o.PSObject.Properties.Name -contains 'X'`.
- **Never `return ,$array`.** Functions return collections plainly; callers
  always write `@()`. `return ,$a` is correct only for bare assignment — `@(f)`
  re-wraps it into one element that is an empty array, and piping does the same.
  There is a lint for this in `pasteable-self-test.sh`.
- **One `Write-Host` per LINE, never per segment.** `-NoNewline` is dropped when
  a run is redirected to a file, which splits a heading across three lines in
  the transcript people keep.
- **`ConvertTo-Json` needs an explicit `-Depth`.** 5.1 defaults to 2 and
  silently writes `System.Collections.Hashtable` for anything deeper.
- **A `$_` inside a double-quoted string is interpolated away.** There is a
  parser-based lint at `redteam/lib/ps-interpolation-lint.ps1`; a regex cannot
  do this job because a closing quote looks exactly like an opening one.
- **Nothing mutates without `-Apply`**, and no destructive command identifies
  its target by position in a list.
- **Every tool says what it could NOT check.** A check that silently did not run
  reads exactly like a check that found nothing, and that is the failure mode
  this whole kit is written against.

## How to verify anything you change

```bash
CCDC_PWSH=/path/to/pwsh bash redteam/self-test.sh     # 500 assertions
bash redteam/self-test.sh                             # 430, skips the Windows suite
```

The suite asserts its own assertion count against the README, so adding one
means updating two numbers in `README.md`.

## Deployment names are a migration, not an edit-in-place

The running Linux unit/process and Windows SYSTEM task/private payload names
are config-backed neutral operational labels. They do not impersonate OS
components, and Guardian remains the inventory of record. Changing those keys
on an armed box requires uninstalling the old layout first, then installing the
new one: Linux is Guardian → Sentry → edit config → Sentry → Guardian; Windows
is Guardian `-Uninstall -Apply -TaskName CCDC-Guardian -WatchdogTaskName
CCDC-Watchdog` → edit config → Guardian `-Install -Apply`.
The source tree remains deliberately descriptive for operator auditability.
Windows Guardian now keeps a hash-verified `.repair` payload authority and
rebuilds altered/deleted active copies from it; it intentionally stops at an
altered repair authority instead of treating it as trustworthy.

Guardian also installs `Continuity-Audit` by default: a third SYSTEM task that
checks whether Guardian is still scheduled, running, and aimed at its expected
private `health-check.ps1`. It logs state changes as `INTEGRITY-GAP` in
`integrity.log`. Guardian repairs that task while Guardian is still alive; this
is an extra alarm and recovery path, not an answer to an Administrator who
removes every task.

**Real-VM proof, 2026-09-21:** deleting the live watchdog payload made
Guardian restore it; deleting the watchdog task made Guardian recreate it;
removing Guardian's own task made `Continuity-Audit` report `MISSING`; and
altering a `.repair` payload made Guardian report an integrity gap without
copying that altered file back. Guardian was then reinstalled and all three
tasks were confirmed running. This is evidence for the stated behavior, not a
claim that an Administrator cannot remove the whole chain.

Linux has the matching *recovery* layer for a different failure: `arm.sh`
creates a root-owned, checksummed archive of `linux/`, the playbooks, and the
chosen config. It also copies a small restore helper beside that archive, so a
deleted checkout does not delete the command needed to restore it. The helper
extracts into a new directory only; it never replaces the live checkout. This
does not beat an administrator who can alter both the helper and its archive.

**Green means the logic is right, never that it works.** The only thing that
proves the second is the box. To prove something on it: push the kit, plant
fixtures with `redteam/windows-plant.ps1 -IAcceptThisBoxIsDisposable` (needs
`$env:CCDC_WIN_LAB = 1` as well — two interlocks, on purpose), run the tool,
then `-Cleanup` and confirm the box returns to its prior state. A detector that
is quiet on a clean box looks exactly like a detector that is broken.

## What to do next, in the order I would do it

**1. Domain / Active Directory — only if the packet says there is a domain.**
The single biggest gap. `users.ps1` refuses on a DC by design. If the tryout
has a domain controller, the highest-value additions are: `krbtgt` password age,
DCSync rights (`Get-ACL` on the domain head for
`DS-Replication-Get-Changes`), GPO startup scripts, SYSVOL `cpassword`,
AdminSDHolder, and unconstrained delegation. **Do not start this speculatively**
— it is a week of work, and a four-device tryout probably has no forest. Read
`playbooks/environment-reality.md` first: the tryout is one Linux box, one
Windows box, a Splunk indexer and a firewall.

**2. Wire `canary.ps1 -Check` into `watchdog.ps1`.** **Done 2026-09-18.** The
SYSTEM watchdog now checks automatically after tripwires are laid, records a
trip durably in `watchdog.log`, and stays alive when `-Check` returns its
intentional exit 2. `watchdog.ps1 -Status` shows that a canary has tripped and
where to get the account/process detail. Real-box testing also caught two
Windows-only edges: 4663 can arrive several seconds after a SACL is attached,
so deploy gives those self-events a ten-second settling margin; and task
replacement now stops a running instance before unregistering it, so it cannot
leave duplicate loops behind.

**3. `sentry.ps1` could offer more of the 58 checks.** **Done 2026-09-18:**
`taskcmd` exports then disables a clear payload task (SWEEP); `newtask` exports
then disables a newly registered task by number (LOOK); `winlogon` restores the
two stock values (SWEEP); and `svcaccount` captures then disables an unapproved
service by number (LOOK). The suite asserts every action names a real triage
check and these four retain their before-state.

**4. A Windows equivalent of `surface.ps1 --table`.** **Done 2026-09-18.**
`windows/surface.ps1 -Table` joins TCP/UDP listeners to their process/service,
marks packet-listed ports and services, and adds scheduled tasks, Run keys and
Startup folders in paste-ready Markdown. It is read-only: `REVIEW` means the
packet does not explain it, not that the tool chose to remove it.

**5. `guardian.ps1`.** **Done 2026-09-18.** A second SYSTEM task keeps private
copies of guardian/watchdog and re-registers `CCDC-Watchdog` when its task is
removed or changed. It deliberately does not claim tamper-proofing: an
Administrator can remove or alter both tasks and their files. This converts an
ordinary one-task kill into a logged, automatically repaired incident; it does
not solve the Administrator threat model.

## Things I would not change without asking Luke

- `arm.sh` must never automatically mutate SSH/PAM/firewall/services.
- `policy.sh` has no `--apply` by design; `fw.sh` stays out of `harden.sh`.
- `harden.sh` keeps `--cut`/`--undo` — Luke overrode an earlier proposal to
  make it propose-only, and the reasoning is recorded above under item A.
- The `ccdc-lab` libvirt network has no `<forward>` element. That is
  deliberate isolation, not an oversight.
- Passwords are never typed on a command line (`net user NAME *` prompts).

## Linux changes from the same training (2026-09-17)

- [x] **Scored accounts are checked for availability.** The notes say it
      outright: *"We have scored users in addition to scored services. We have
      to make sure scoring users are available."* `CCDC_INTERACTIVE_USERS`
      separates those logins from `CCDC_ALLOWED_USERS`, which also has to name
      nologin service identities. A locked or expired explicitly interactive
      account emits RED `scoreduser`, and it has the one action in the kit that
      RESTORES rather than removes.

## P1 — promised in writing, not built

- [~] 1. **One enumeration, several views.** `baseline.sh --inventory` now
      exposes the structured `kind|subject|detail` producer and recon records
      it as `execution-inventory.txt`; `inventory-compare.sh` measures what
      recon’s detailed report also names. The specialised reports still use
      their own walkers; prove parity before moving any decision-making consumer.
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

- [x] 13. **Tryout sign-up.** Done 2026-09-18.
- [x] 14. Public-repo decision. **Made the repo public 2026-09-18**, to link it
      on an application. Luke weighed the cost — the red team can read the
      detection logic — and took it deliberately.
      Two consequences worth remembering rather than rediscovering:
      the gap documentation is the part that helps an opponent most (it is a
      list of what the kit does NOT catch), and renaming files on the morning
      of the competition does not help, because git history is permanent and a
      public repo is forked and indexed within hours.
      Scanned before publishing: no `.env`, key or `.pem` was ever committed,
      no private-key blocks in history, no password assignments in tracked
      files. `lab/provision.ps1` no longer carries an SSH key — it is a
      template and `make-unattended-iso.sh` substitutes one at build time.
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
      access, endpoint protection) carry their Windows commands, each with the
      trap that actually catches people: the banner appears at the NEXT logon;
      OpenSSH on Windows reads
      `C:\ProgramData\ssh\administrators_authorized_keys` for anything in the
      Administrators group and ignores the user profile entirely; Defender's
      `RealTimeProtectionEnabled` being false IS the finding, not something to
      quietly fix.
      The old “recon + watchdog, 63 lines, never run” description is obsolete:
      `windows/` now has ten tools, and all 58 triage checks have run on the
      Server 2022 lab target over WinRM. That target intentionally has no SSH
      listener—OpenSSH installation would attempt Windows Update on the isolated
      lab network—so a closed port 22 is provisioning reality, not a failed test.
      The response-specific inject prose remains Luke’s work; verify each exact
      command against the packet and its scored host before claiming it in a memo.
