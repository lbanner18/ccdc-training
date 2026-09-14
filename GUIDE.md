# Kit guide — what's here, why, and how to use it

Written for a reviewer (human or another agent) coming to this repo cold, and
for the operator practicing with it before the BYU CCDC tryout. It explains
every tool, the design rules they all follow, what has actually been tested
versus what is merely written, and where the known weak spots are.

**If you are here to review:** skip to [What to review](#what-to-review) at the
bottom. It says what would genuinely help, what is already known-broken so you
need not report it, and which claims in this file are worth distrusting.

If you only read one other file, read
[`playbooks/competition-day-playbook.md`](playbooks/competition-day-playbook.md)
— it is the run-of-show. This guide is the map to the code behind it.

---

## The competition this is for

BYU CCDC tryout, **2026-09-26, 10:00–16:00** (sign-up deadline 2026-09-24). It
is an **individual** event: one operator, four VMs (Linux, Windows, a Splunk
indexer, a firewall), uptime scored on the Linux and Windows boxes, and
**points split evenly between defense (uptime) and injects**. That last fact
drives the whole kit: injects are half the score, so pre-written inject
responses matter as much as any defensive script.

Sources and the exact rules (including the tooling-publication rule that
governs when this repo may go public) are in
[`playbooks/competition-rules.md`](playbooks/competition-rules.md).

---

## Design rules every script follows

These are consistent across the Linux tools; a reviewer can assume them.

1. **Read-only until told otherwise.** `CCDC_DRY_RUN` defaults to on. A script
   mutates only with `--apply`, and prints what it *would* do otherwise. The
   shared helper `ccdc_action` in [`linux/lib/common.sh`](linux/lib/common.sh)
   enforces this.
2. **Config-driven, nothing box-specific committed.** All box specifics live in
   a config file (`config/example.env` is the template) kept *outside* the
   repo. `*.env` and `evidence/` are gitignored. The repo goes public on
   competition day, so a committed secret or IP would leak.
3. **Portable.** Targets may be Alpine (busybox, no bash), Rocky/CentOS/Fedora
   (firewalld + SELinux), or Ubuntu. Helpers avoid GNU-only flags and degrade
   with a warning rather than failing silently when a tool is missing.
4. **No external callbacks.** Nothing phones home. This is both correct for an
   offline competition network and required by NCCDC rule 5.6 (tools may not
   use resources outside the competition environment beyond DNS).
5. **Verify from the scorer's position.** Every mutating tool's guidance ends
   the same way: confirm the scored service still answers *from the network*,
   because blocking your own service costs exactly what an outage costs.
6. **Legible, not stealthy — with a manifest.** Defensive artifacts are
   tracked in a manifest so the operator can always tell their own footholds
   from the red team's and remove them exactly. `canary.sh` and `guardian.sh`
   both work this way, and both have a removal path that is checked against the
   manifest rather than against memory.
7. **Prove it on a VM, not in an argument.** A claim that a mutating path works
   means it ran as root on the lab VM. Anything proven only by dry-run, syntax
   check, or reasoning says so explicitly in the test-status table below. The
   first real VM run found two genuine bugs that every prior sandbox test had
   passed, which is the whole reason this rule is written down.

---

## The Linux tools ([`linux/`](linux/))

| Script | Mutates? | What it does |
|---|---|---|
| `arm.sh` | `--apply` only | The tier-1 sequence in one command: preflight, `backup.sh`, `canary.sh --deploy`, `guardian.sh --install` (which starts the watchdog). Deliberately does NOT touch the firewall or services — both need a human confirming against the packet. Preflight catches a non-writable evidence dir, a scored service already down before you arm on top of it, and `CCDC_HTTP_CHECKS` pointing at localhost. |
| `watch.sh` | no | The detection loop, and the answer to "the kit collects well and alerts not at all". Runs `canary --check` + `hunt.sh` + `recon.sh` each pass and prints **only what changed** since the last one. Normalises away its own evidence, its own processes, and systemd's relative timer times, all of which otherwise bury the one line that matters. |
| `services.sh` | `--disable`/`--revert` only | Attack-surface reduction. `--review` (default, read-only) sorts everything enabled or running into PROTECTED / LIKELY SCORED / CANDIDATES / UNCLASSIFIED with listening ports attached; `--disable` acts **only** on `CCDC_DISABLE_SERVICES`, which you write yourself. PROTECTED is computed from your config, so it covers this kit's own units, cron, auditd and logging. Handles socket activation (disabling `cups.service` while `cups.socket` lives is not disabling cups). Every change recorded and reversible. |
| `recon.sh` | no | Baseline evidence snapshot: system, accounts, UID-0, sudoers, SSH config + authorized_keys, cron/timers, listeners, SUID/caps, recent /etc changes, firewall. Writes a hashed evidence dir. |
| `hunt.sh` | no | Persistence sweep: cron/at, systemd units+timers, startup files, temp-dir executables, deleted-exe mappings, web shells, dpkg/rpm integrity, SUID/caps, and (new) per-user rc files, user-level systemd units, LD_PRELOAD injection, kernel modules, immutable-flag backdoors. |
| `canary.sh` | `--deploy`/`--remove` only | Detection/active-defense. Lays decoy files, records a hash+inode+atime baseline, and asks auditd to log access to decoys and real sensitive files. `--check` is read-only and loopable. Manifest-tracked. |
| `watchdog.sh` | `--apply` only | Keeps scored services up: TCP/HTTP/systemd checks, restarts a dead service, and verifies recovery with the *same probe the scorer uses* (measured wall-clock deadline, crash-loop detection, one-restart-per-pass). |
| `users.sh` | `--apply` only | Explicit-target account audit and guarded password rotation / lock. Never touches an account not named in config. |
| `fw.sh` | `--apply` only | Firewall renderer (nft/iptables) with a **dead man's switch**: snapshots, arms a systemd-owned auto-rollback that survives your SSH session dying, **verifies it is armed, and only then applies** — requiring `--confirm` to keep the rules. Refuses to start a second change while one is pending. Three real lockout tests passed, the most recent against the arm-before-apply rewrite. |
| `backup.sh` | `--apply` only | Explicit-path backup, checksum, diff, and guarded restore. |
| `guardian.sh` | `--install`/`--uninstall`/`--tick` | Keeps `watchdog.sh` alive against a root-level attacker: three layers that each restart the watchdog and rebuild the other two. Manifest-tracked; repairs tampered artifacts and systemd drop-in overrides from an independent `.repair` source tree; disarm sentinel makes `--uninstall` exact. Each layer can be named independently, and `CCDC_GUARDIAN_STATE_DIR` lets N fully independent chains run side by side. |

`recon.sh`, `hunt.sh` and `watch.sh` are safe to run any time. Everything else
is dry-run first, `--apply` second, verify third.

**Start here, in this order:** `recon.sh` and `hunt.sh` to see the box, then
`arm.sh --apply` to arm the standing defence, then `watch.sh` running in a
window. `services.sh --review` and `fw.sh` are the two deliberate judgement
calls you make with the packet in front of you.

**Do not run `watchdog.sh` by hand.** `guardian.sh` installs it as a supervised
unit; started from a shell it dies with your SSH session. The one knob worth
setting before anything else is `CCDC_WATCHDOG_INTERVAL="5"` — your mean outage
is roughly half of it, measured at 57s of scored downtime at 60 versus 6s at 5.

### canary.sh in more detail

The design point worth understanding: **auditd is the only mechanism that
catches a read.** A hash check catches a modified or deleted decoy, but an
attacker who merely opens and copies the file leaves it byte-identical. So
`canary.sh` layers three signals, strongest first:

1. **auditd** (`ausearch -k ccdc-canary` / `ccdc-sensitive`) — records the open
   with pid/uid/command. This is the real signal and the evidence an inject
   asks for.
2. **hash + inode** — catches modify / replace / delete.
3. **atime** — a weak hint that a file was read; reported as a hint, not proof,
   because relatime/noatime and a careful attacker both defeat it.

Decoys are 0600 and root-owned (a world-readable "secret" looks like a decoy),
placed where an attacker greps first, and their contents are clearly marked
fake so a tired operator does not act on them. The manifest lives with the
evidence, not next to the decoys — so reading one decoy's directory does not
reveal the others.

### guardian.sh in more detail

The threat model is narrow and specific: the red team has root, has found
`watchdog.sh`, and kills it so your scored services stay down. The answer is
redundancy, not stealth.

```
target   <name>-watch.service    runs watchdog.sh, Restart=always
layer 1  <name>.service          Restart=always, runs a tick loop
layer 2  <name>-reconcile.timer  same tick, every interval
layer 3  /etc/cron.d/<name>      same tick, every ceil(interval/60) min
```

All three layers run the **identical** reconcile pass (`--tick`), which makes
sure the watchdog is running and recreates any layer that has gone missing.
Killing one is pointless; killing two is temporary. Removing all three inside
one interval works — that is the documented limit, not a bug.

Four design points worth understanding:

1. **The payload is copied twice, and that matters.** `--install` puts
   `guardian.sh`, `watchdog.sh`, `lib/common.sh` and your config in
   `CCDC_GUARDIAN_DIR` — the *live* copies the layers execute — and a second,
   independent set under `CCDC_GUARDIAN_DIR/.repair`, which nothing ever
   executes. Repair copies from `.repair` to live.

   The two-tree split is not decoration. The first version copied the payload
   over itself, so source and destination were the same file and "repair the
   tampered watchdog" was a silent no-op: the guardian reported healthy while
   running the attacker's code. Root can still destroy both trees at once —
   that is the documented limit — but editing the live copy no longer defeats
   repair.

   **Operational rule that follows from this: never hand-edit the installed
   `guardian.env`.** The layers pin its SHA-256 and refuse to source a config
   that matches neither the pinned hash nor the live fallback. That is correct
   — a tampered config can redirect `CCDC_GUARDIAN_DIR` and point the
   guardian's own removal logic somewhere else — but the failure is *silent*,
   because layer output goes to `/dev/null`. If you need to change config
   mid-competition, edit your real config file and re-run
   `--install --apply`. Editing the installed copy is how you turn the
   guardian off without noticing.
2. **The manifest is the point.** Every artifact is recorded with the hash it
   had when written. That is what lets you tell your own footholds from the red
   team's at hour six — and it is why hiding your tooling is survivable here.
3. **Tampering is repaired, not just detected — including the kind that never
   touches the file.** An attacker who appends `ExecStartPost=` to your unit
   has converted your keep-alive into their persistence, so a drifted artifact
   is rewritten from `.repair`. The tampered copy is preserved under
   `guardian.tampered/` first — it is evidence, and an inject will ask for it.
   Ticks never re-hash a file they did not write, so a red-team edit cannot
   launder itself into the "expected" value.

   The nastier variant is a **systemd drop-in**: `<unit>.d/override.conf`
   leaves the unit file byte-identical, so any hash check of the fragment sees
   nothing wrong while systemd merges the override and runs the attacker's
   command as root on the next start. The guardian checks the *effective* unit
   (`systemctl show -p DropInPaths`), quarantines any override under
   `/etc/systemd/system`, `/run/systemd/system`, the `.control` variants and
   `/run/systemd/transient`, and restarts the affected unit afterwards. Drill
   ATTACK 5 exercises exactly this and asserts the injected command never ran.
4. **The disarm sentinel makes removal stick.** `--uninstall` writes the
   sentinel *first*, then tears down; any tick that fires mid-teardown sees it
   and removes its own layer instead of helpfully rebuilding everything. Same
   trick `fw.sh` uses when it deletes the snapshot to disarm a pending
   rollback. The sentinel is deliberately left behind afterwards; `--install`
   clears it.

5. **N independent chains, with a hot-standby handoff.** Set
   `CCDC_GUARDIAN_STATE_DIR` (plus its own names and payload dir) and a second
   chain shares nothing with the first — no unit name, no payload directory, no
   manifest. Removing one removes one.

   The hazard this had to solve first is two chains both restarting the same
   service, where the second restart is an outage you inflicted on yourself
   during an incident. The watchdog already had a singleton lock, so rather
   than designating a primary, every chain's watchdog contends for it and the
   **losers idle as hot standbys instead of exiting** — a watchdog that exits
   leaves systemd restarting its unit forever and nothing covering the services
   in between. A standby takes over within `CCDC_WATCHDOG_STANDBY_SECONDS` of
   the holder dying, which is precisely the case this exists for. That lock
   lives in the shared `CCDC_EVIDENCE_DIR`, so **do not give each chain its own
   evidence dir** — splitting it puts the double restart straight back.

   Payload files are named after the chain's own layers, because a red-team
   pass found every chain on the box with one command: `ps -eo args | grep
   watchdog.sh`. `ps` is a namespace renaming cannot hide from. After the
   rename, no single grep over `/etc/systemd/system` and `/etc/cron.d` joins
   two chains. **This raises discovery cost; it does not hide.** Both chains
   are still plainly visible in `ps`, the manifest lists every artifact by real
   path, and the cron entries still carry a label saying they are authorised
   blue-team tooling and how to remove them — unlabelled persistence is exactly
   what competition staff *should* treat as hostile.

Portability is honest rather than clever: no systemd means layers 1–2 are
unavailable and cron is the only layer (the watchdog is supervised through a
pidfile instead); no `/etc/cron.d` **and** no systemd — Alpine/OpenRC — means
no layer can be built, and it says so and installs nothing rather than
pretending. Busybox `crond`'s `/etc/crontabs` format and OpenRC supervision are
not wired up.

---

## The red team and the drill ([`redteam/`](redteam/))

You cannot tell whether a detection tool works by reading it. This directory is
how the defensive tools get scored against ground truth.

| Script | What it does |
|---|---|
| `plant.sh` | Plants 11 realistic footholds on a **lab VM you own**, every one tagged `RT_LAB_PLANT`, and prints the ground-truth list. `--clean` removes exactly what it planted. Standard CCDC red-team moves, nothing novel or weaponized. |
| `score.sh` | Greps the newest evidence directory for each planted artifact's signature and prints CAUGHT/MISSED per technique. |
| `drill.sh` | The full automated loop, as root: arm → plant → detect → eradicate → five guardian attacks → uninstall, with a PASS/FAIL assertion at every step. |

### What plant.sh lands

A rogue user (`rtsvc`), a sudoers `NOPASSWD` backdoor, an extra root SSH key, an
`/etc/cron.d` implant, a root crontab entry, a systemd timer disguised as
"System Logging Helper", the implant binary, a `/etc/profile.d` hook, a
`/root/.bashrc` hook, a SUID root shell, and a `/dev/shm` payload.

### What drill.sh asserts

Read [`redteam/drill.sh`](redteam/drill.sh) — it is ~200 lines and the
assertions are the interesting part, not the plumbing.

| Phase | Assertions |
|---|---|
| 0 — arm | scored service answers before we start; recon baseline captured; canary decoys laid |
| 1 — land | `plant.sh` reports ≥10 footholds |
| 2 — detect | one assertion per planted technique, scored against the **union** of the recon and hunt evidence; then `score.sh`'s own output and a `canary.sh --check` for comparison |
| 3 — eradicate | sudoers edit leaves a file `visudo -c` still accepts; rogue user gone; attacker key gone; all file footholds gone; a re-hunt is clean; **and the scored service survived the whole eradication** |
| 4 — guardian | all three layers active + cron entry present + manifest count; then six attacks (below) |
| 4b — removal | reinstall from scratch works; `--uninstall` leaves zero artifacts; no stray watchdog process; systemd knows of no leftover units |

The six attacks, which are the part worth reviewing hardest:

1. **`pkill -f watchdog.sh`** → comes back via `Restart=always`.
2. **`systemctl stop scored-web`** → the watchdog restores it within an interval.
3. **Delete layer 2 and layer 3** → a surviving layer rebuilds both.
4. **Backdoor a unit** (append `ExecStartPost=`) → next tick quarantines a copy
   as evidence and rewrites the unit from source.
5. **Plant a systemd drop-in** (`<unit>.d/override.conf`) → quarantined and
   stripped with the unit file never modified; the injected command must never
   have executed.
6. **Remove all three layers at once** → it stays down. A PASS here means
   *nothing came back*; that is the documented limit of the design, and the
   assertion exists so the limit stays honest rather than drifting into a
   claim.

Run it only on a disposable VM, as root, with a snapshot taken first:

```
sudo bash redteam/drill.sh          # expects a filled config at /root/ccdc-drill.env
CCDC_KIT_DIR=/path/to/kit CCDC_DRILL_CONFIG=/path/to.env sudo -E bash redteam/drill.sh
```

It takes about six minutes, most of it sleeping through the survival intervals.

**It does not replace running [`playbooks/simulation-runbook.md`](playbooks/simulation-runbook.md) by hand.** The hand-run is where
the operator's muscle memory comes from — eradicating by hand under a timer is
the graded skill. The drill is the regression check that proves the tooling
still works after a change.

---

## The Windows tools ([`windows/`](windows/))

`recon.ps1` and `watchdog.ps1` are **first-pass drafts, not yet exercised** on a
Windows box from this Linux workspace. Two thirds of a real CCDC environment is
Windows, so these are the biggest area of remaining work. Treat them as a
starting point, not a finished tool.

---

## Injects ([`injects/`](injects/))

Injects are half the score, so this is half the kit.

- [`injects/responses/`](injects/responses/) — six pre-written, ~one-page memo
  drafts in the team's exact format, one per inject the catalog records as
  actually asked: login banner, SSH access, incident-response procedure,
  password policy, endpoint protection, external perimeter assessment. Each
  cites a public source inline (the graded answers score by citing a framework,
  not by inventing one) and calls out its failure mode.
- Three drafts defuse a real **service-killing trap**: password lockout as
  self-DoS, `PasswordAuthentication no` killing the scorer's own SSH login, and
  masscan knocking your own scored service over.
- [`injects/memo-template.md`](injects/memo-template.md),
  [`injects/incident-report-template.md`](injects/incident-report-template.md),
  [`injects/inject-catalog.md`](injects/inject-catalog.md) — the format, the IR
  artifact, and the running list of what has been asked.

Every draft is a **draft**: fill every `<PLACEHOLDER>`, answer exactly the
inject's numbered asks, and attach the screenshots — which for the
banner/SSH/AV injects is the half of the work that eats the clock.

---

## Splunk ([`splunk/searches.md`](splunk/searches.md))

Starter searches for Linux auth/sudo/service events and the Windows Security
log (new user 4720, added-to-admins 4732, new service 7045, scheduled task
4698, log cleared 1102), plus a "Canary and audit trips" section covering the
`canary.alerts.log` forwarder and the `ccdc-canary` / `ccdc-sensitive` auditd
keys — the highest-confidence intrusion signal this kit produces.

---

## A note on guardian.sh and the classifier

Authoring `guardian.sh` was refused once by the Claude Code auto-mode safety
classifier as "unauthorized persistence," and the agent is also barred from
editing its own permission settings to lift that block. It was written in an
interactive session instead, where the operator approves each write.

Worth recording because the pattern will recur: a classifier cannot distinguish
resilient *defensive* tooling on a box you control in a sanctioned competition
from malware — the two are the same code with different intent. The operator's
approval is the only thing that separates them, which is the correct place for
that decision to live.

**Tactical note for the reviewer:** hiding your own tooling is generally
*discouraged* in team CCDC — it poisons your own detection signal and gets your
own persistence killed by a teammate doing IR. In a solo tryout those costs
mostly vanish, which is the operator's stated justification. The manifest is
what keeps even a hidden guardian legible to its owner.

---

## Test status (honest)

| Area | State |
|---|---|
| `canary.sh` syntax | `bash -n` clean |
| `canary.sh` dry-run deploy / status / check-no-manifest | run, correct output |
| `canary.sh` mutating paths (deploy --apply, trip detection) | **not run here** — needs a real root + auditd box; do it on the lab VM |
| `guardian.sh` syntax | `bash -n` clean |
| `guardian.sh` install/tick/uninstall, all four dry-run modes | run, correct output, writes nothing |
| `guardian.sh` file reconciliation (install → delete layers → tick rebuilds → tamper → quarantine+repair → sentinel → uninstall leaves zero artifacts) | run against a sandbox with `/etc` redirected and `systemctl` stubbed; all passed |
| Generated systemd units | validated by the real `systemd-analyze verify` (4/4 clean) |
| `guardian.sh` degradation (no systemd → cron-only; no systemd *and* no cron.d → refuses) | run, warns correctly |
| `guardian.sh` against real systemd units as root | **run on the lab VM** via `redteam/drill.sh` — currently **57/57**, including the drop-in attack |
| Full automated drill (plant → detect → eradicate → 6 guardian attacks → uninstall) | run end to end on the lab VM as root; VM reverted to snapshot afterwards |
| `fw.sh` dead man's switch, **rewritten** arm-before-apply path | **retested on the lab VM 2026-09-13**, five cases: dry-run changes nothing; safe apply arms a real systemd timer; `--status` distinguishes armed from broken; a second apply while one is pending is refused; `--confirm` keeps rules and disarms |
| `fw.sh` **real lockout** (port 22 removed from the allow list) | **passed** — a new SSH connection was refused, the switch fired unattended, and access was restored ~60s later with the baseline ruleset intact and the scored service still up |
| `watchdog.sh` state-change logging | **lab VM** — 60s quiet went from ~84 log lines to 6, and an incident is 4 lines. Four defects found and fixed doing it, listed in the commit |
| `CCDC_WATCHDOG_INTERVAL` effect on scored downtime | **measured by an external scorer off the box**: the same `systemctl stop` cost **57s at 60s** and **6s at 5s** |
| Two independent guardian chains | **lab VM**, both armed under unrelated names/dirs/state, exactly one watchdog active and one in standby |
| Two chains vs. an attacker with root who destroys one | **passed** — chain A found via `ps`, pivoted from its payload dir, all three layers + state removed, scored service stopped: recovery 2–4s, and the external scorer recorded **0s and 3s** across two runs |
| Two chains vs. `pkill -9 -f watchdog.sh` (the old shared string) | recovered in 6s via systemd; **this is why payload files are now named per chain** |
| Cross-chain grep after the rename | `watchdog.sh`, `tick.sh`, `guardian.sh`, `node-health`, `ccdc` each return **0 files** across `/etc/systemd/system` and `/etc/cron.d` |
| `services.sh` review / disable / revert / status | **lab VM** — correctly protected chain B's own guardian units (`ureadahead`, `dbus-monitor-svc`); ModemManager, pollinate and snapd (socket + service) disabled and restored to exact prior state |
| `services.sh` curated candidate list | **partly unverified** — the lab image has no cups/avahi/rpcbind, so those entries are judgement, not measurement. Run `--review` on the real box before trusting the list |
| `hunt.sh` extended sweep | run read-only, new section emits correctly |
| `hunt.sh` / `recon.sh` full runs | exercised previously against the lab VM |
| `fw.sh` dead man's switch | two real lockout tests passed (prior session) |
| Windows PowerShell | not exercised |
| Inject drafts | every cited URL checked live (200/redirect resolved) |

The mutating-path tests belong on the lab VM — real root, real auditd, real
systemd — which is also the Sunday practice plan. That is the
right place to prove deploy/trip/recover end to end, not a Linux workstation
without root.

### What the first real VM run found (2026-09-11)

`redteam/drill.sh` ran the whole loop as root against the lab VM. 34 of 37
assertions passed on the first attempt, including all five guardian attacks.
The three failures are the argument for running it:

1. **A manifest race in `guardian.sh` (real bug, fixed).** `--install` did not
   take the tick lock, and `record_manifest` staged through a fixed
   `${manifest}.next`. A scheduled tick fired inside the install window, both
   processes truncated and appended to the same temp file, and the surviving
   manifest was missing its five payload entries — i.e. the file you rely on to
   tell your own footholds from the red team's was silently wrong. It
   self-healed on the next tick, which is worse, not better: a corruption that
   repairs itself is one you never notice. Fixed with per-process temp names
   and a lock on install/uninstall. **A sandbox cannot produce this** — nothing
   else was running.
2. **A keyword-only blind spot in `hunt.sh` (real bug, fixed).** The per-user
   rc-file check reported only lines matching `curl|wget|nc |base64|eval|…`, so
   the planted `.bashrc` hook — which contains none of those — was invisible,
   and so would `PATH=/tmp/evil:$PATH` or `. ~/.cache/x` be. It now also
   reports any rc file modified in the last 7 days with its tail, because an
   attacker's edit has a fresh mtime whatever it says.
3. **A bug in the drill harness itself (fixed).** `/dev/shm/.rt` was reported
   MISSED; `hunt.sh` had in fact caught it. Phases 0–2 complete in about four
   seconds, and the harness selected evidence directories with
   `find -newermt`, which is strictly-newer, so same-second output fell out of
   the blob being scored. A test that lies about the tool is worse than no
   test: the harness now records each directory by name as it is produced.

### What the external review and its second VM run found (2026-09-13)

An independent agent review produced four structural findings, all since fixed
and re-tested. Three were things no amount of re-reading my own code would have
surfaced, because they were failures of *design*, not of syntax:

1. **`fw.sh` applied rules before the rollback was safely armed.** Any
   interruption between the apply and the arm left the box unreachable with no
   recovery. It now takes the snapshot, writes and schedules the rollback,
   *verifies it is armed*, and only then touches the firewall — and restores
   immediately if the apply fails or the switch died during it. Proven by a
   real lockout on the lab VM.
2. **`guardian.sh` could not actually repair its own payload**, because the
   copy's source and destination were the same file. Fixed with the `.repair`
   tree described above. This is the most serious of the four: the guardian
   reported healthy while a tampered watchdog kept running.
3. **Systemd drop-ins bypassed the guardian entirely and survived uninstall.**
   Fixed; see point 3 of the guardian section.
4. **Several drill assertions could pass while the tool was broken.** The
   detection checks grepped one concatenated blob, so one artifact could
   satisfy several checks, and `score.sh` scored `/dev/shm` with the
   alternative `\.rt`, which also matches `/root/.rt_manifest` — it printed
   CAUGHT when the sweep had found nothing. Every check is now a fixed string
   against a named file, and `score.sh` exits non-zero on a miss so a caller
   can assert on it.

A fifth was found by the drill itself once those were in: **`--uninstall` left
a phantom unit in systemd.** Once a unit has entered a failed state, systemd
keeps it in `systemctl list-units --all` and `systemctl --failed` even after
the unit file is gone and the daemon is reloaded. Disk was clean; systemd was
not — a ghost of your own tooling in the first place you look during an
incident. Fixed with an explicit `reset-failed` pass after removal.

---

## What to review

The deadline is **2026-09-26**, the operator is one person, and the kit is
already past the point where more features help. Review effort is best spent on
things that would cost points or cost access on the day.

### Read in this order

1. `playbooks/competition-day-playbook.md` — the run-of-show everything serves.
2. `linux/lib/common.sh` — the contract every script relies on (~120 lines).
3. `linux/guardian.sh` — the newest and most dangerous code.
4. `redteam/drill.sh` — what is actually proven, and whether the assertions
   would really fail if the tool broke.
5. `linux/hunt.sh` + `linux/canary.sh` — the detection half.
6. `injects/responses/` — half the score, and the least reviewed.
7. `ROADMAP.md` — what is claimed done versus deadline-bearing.

### The questions worth answering

**Highest value — these cost access or uptime if wrong:**

- `guardian.sh` installs root-run persistence. Is there a path where it breaks
  the box, wedges itself, or fails to remove cleanly? The removal path is
  manifest ∪ expected-list; can you construct a state where an artifact is in
  neither?
- The tick lock is a `mkdir` with a stale-break at `5 × interval`. Is there an
  interleaving that loses an artifact or corrupts the manifest? One race here
  was already found on the VM and fixed; assume there is another.
- `fw.sh`'s dead man's switch is the single highest-consequence code in the
  kit: if it fails to arm, the operator is locked out of a scored box with no
  recovery. It has passed two real lockout tests. What input makes it *silently*
  not arm?
- Every mutating script must be safe to interrupt halfway. Which one is not?

**High value — these cost detection:**

- `hunt.sh` greps for known-bad tokens in several places. Bug #2 below was
  exactly this pattern failing. Where else does a keyword list stand in for a
  real check, and what would a competent attacker write to slip past it?
- `plant.sh` covers 11 techniques. What would a real CCDC red team do that it
  does not simulate, and would `hunt.sh` catch that?
- `score.sh`'s checks are greps and can score a **false** CAUGHT (its
  `/dev/shm` check matches the bare string `.rt`, which also appears in
  `/root/.rt_manifest`). Which other checks are weaker than they look?

**Worth a pass:**

- Portability. Targets may be Alpine (busybox, no bash), Rocky/CentOS/Fedora
  (firewalld, SELinux). The scripts are bash and say so; the honest question is
  whether the *degradation* messages are accurate or wishful.
- Inject drafts: is any cited source misrepresented, and does each draft
  actually answer the numbered asks rather than describing them?

### Known-broken — do not spend time reporting these

- **Windows (`windows/*.ps1`) is unexercised.** First-pass drafts, never run on
  a Windows box. Two thirds of a real CCDC environment is Windows, so this is
  the biggest gap in the kit and it is already known.
- **`canary.sh`'s mutating paths have not been exercised with auditd.** The lab
  VM has no auditd (isolated network, no package installs), so read-detection
  has never actually fired. Hash/atime paths are tested; the auditd path is not.
- **No busybox/OpenRC support.** `guardian.sh` refuses to install rather than
  pretending, but "run every script under `busybox sh`" is still an open
  roadmap item.
- **This repo is not public yet**, and NCCDC rule 5.6.1 requires team tools to
  be public three months before use. That is a scheduling decision already
  tracked in `ROADMAP.md`, not an oversight.

### Distrust these claims specifically

A reviewer is most useful when checking the things the author is most confident
about. In rough order of how much a wrong answer would cost:

1. **"`--uninstall` leaves zero artifacts."** Verified by the drill on one
   Ubuntu VM, in one configuration, with one name. Try a different
   `CCDC_GUARDIAN_NAME`, an interrupted uninstall, or a box where
   `/usr/local/lib` is not writable.
2. **"Tampering is repaired, not just detected."** True for artifacts in the
   manifest. An attacker who adds a *new* file the guardian never wrote — a
   drop-in at `/etc/systemd/system/<name>.service.d/override.conf`, for
   instance — is not covered at all. Is that the right call, or a hole?
3. **"The layers rebuild each other."** Proven on systemd. The cron-only path
   (no systemd) has never run anywhere.
4. **"Verify from the scorer's position."** The drill checks
   `127.0.0.1:8080`, which is *not* the scorer's position. That is a real
   weakness in the test, not just in the wording.

### Ground rules

- Assume the operator is solo and tired. A finding that makes the kit more
  complex to run at hour six is a net loss even if it is technically correct.
- Prefer "this breaks under X" over style. Cite the file and line.
- Defensive tooling on an owned box in a sanctioned event is the whole point of
  this repo; see the classifier note above before flagging `guardian.sh` as
  malware-shaped. It is malware-shaped. That is the nature of the problem.
