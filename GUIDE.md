# Kit guide — what's here, why, and how to use it

Written for a reviewer (human or another agent) coming to this repo cold, and
for the operator practicing with it before the BYU CCDC tryout. It explains
every tool, the design rules they all follow, what has been tested, and the one
capability that is deliberately not built yet.

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
   from the red team's and remove them exactly. (See the guardian note below
   for the one place stealth is wanted, and why it is gated.)

---

## The Linux tools ([`linux/`](linux/))

| Script | Mutates? | What it does |
|---|---|---|
| `recon.sh` | no | Baseline evidence snapshot: system, accounts, UID-0, sudoers, SSH config + authorized_keys, cron/timers, listeners, SUID/caps, recent /etc changes, firewall. Writes a hashed evidence dir. |
| `hunt.sh` | no | Persistence sweep: cron/at, systemd units+timers, startup files, temp-dir executables, deleted-exe mappings, web shells, dpkg/rpm integrity, SUID/caps, and (new) per-user rc files, user-level systemd units, LD_PRELOAD injection, kernel modules, immutable-flag backdoors. |
| `canary.sh` | `--deploy`/`--remove` only | Detection/active-defense. Lays decoy files, records a hash+inode+atime baseline, and asks auditd to log access to decoys and real sensitive files. `--check` is read-only and loopable. Manifest-tracked. |
| `watchdog.sh` | `--apply` only | Keeps scored services up: TCP/HTTP/systemd checks, restarts a dead service, and verifies recovery with the *same probe the scorer uses* (measured wall-clock deadline, crash-loop detection, one-restart-per-pass). |
| `users.sh` | `--apply` only | Explicit-target account audit and guarded password rotation / lock. Never touches an account not named in config. |
| `fw.sh` | `--apply` only | Firewall renderer (nft/iptables) with a **dead man's switch**: applies rules, arms a systemd-owned auto-rollback that survives your SSH session dying, and requires `--confirm` to keep the rules. Two real lockout tests passed. |
| `backup.sh` | `--apply` only | Explicit-path backup, checksum, diff, and guarded restore. |
| `guardian.sh` | `--install`/`--uninstall`/`--tick` | Keeps `watchdog.sh` alive against a root-level attacker: three layers that each restart the watchdog and rebuild the other two. Manifest-tracked, repairs tampered artifacts, disarm sentinel makes `--uninstall` exact. |

`recon.sh` and `hunt.sh` are the first thing you run and are safe to run any
time. Everything else is dry-run first, `--apply` second, verify third.

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

1. **The payload is copied.** `--install` puts `guardian.sh`, `watchdog.sh`,
   `lib/common.sh` and your config in `CCDC_GUARDIAN_DIR`, and the layers run
   the copies. The defense must not die because someone deleted your home
   directory, and it must not change under you when you edit the checkout
   mid-competition.
2. **The manifest is the point.** Every artifact is recorded with the hash it
   had when written. That is what lets you tell your own footholds from the red
   team's at hour six — and it is why hiding your tooling is survivable here.
3. **Tampering is repaired, not just detected.** An attacker who appends
   `ExecStartPost=` to your unit has converted your keep-alive into their
   persistence, so a drifted artifact is rewritten from source. The tampered
   copy is preserved under `guardian.tampered/` first — it is evidence, and an
   inject will ask for it. Ticks never re-hash a file they did not write, so a
   red-team edit cannot launder itself into the "expected" value.
4. **The disarm sentinel makes removal stick.** `--uninstall` writes the
   sentinel *first*, then tears down; any tick that fires mid-teardown sees it
   and removes its own layer instead of helpfully rebuilding everything. Same
   trick `fw.sh` uses when it deletes the snapshot to disarm a pending
   rollback. The sentinel is deliberately left behind afterwards; `--install`
   clears it.

Portability is honest rather than clever: no systemd means layers 1–2 are
unavailable and cron is the only layer (the watchdog is supervised through a
pidfile instead); no `/etc/cron.d` **and** no systemd — Alpine/OpenRC — means
no layer can be built, and it says so and installs nothing rather than
pretending. Busybox `crond`'s `/etc/crontabs` format and OpenRC supervision are
not wired up.

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
| `guardian.sh` against real systemd units as root | **run on the lab VM 2026-09-11** via `redteam/drill.sh` — 34/37 assertions passed; the 3 failures are analysed below and all three are now fixed |
| Full automated drill (plant → detect → eradicate → 5 guardian attacks → uninstall) | run end to end on the lab VM as root; VM reverted to snapshot afterwards |
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

---

## Suggested order for a reviewer

1. `playbooks/competition-day-playbook.md` — the operational flow.
2. `playbooks/competition-rules.md` — the constraints and their citations.
3. `linux/lib/common.sh` — the shared contract every script relies on.
4. `linux/canary.sh` and the new block in `linux/hunt.sh` — the newest code.
5. `injects/responses/` — the half-the-score deliverables.
6. `ROADMAP.md` — what is done, blocked, and deadline-bearing.
