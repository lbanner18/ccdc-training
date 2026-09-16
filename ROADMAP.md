# CCDC training roadmap

## Done in this workspace

- Linux recon snapshot and evidence diff.
- Linux report-only persistence hunt.
- Configured service watchdog with TCP, HTTP, systemd, and file-hash checks.
- Explicit-target account audit and guarded access mutations.
- Explicit-path backup, checksum, diff, and guarded restore.
- Firewall rule renderer with dry-run output and timed rollback state.
- First-pass Windows recon/watchdog PowerShell scripts.
- Splunk starter searches for the event IDs in the team notes.
- Inject memo, incident report, timed drill, and first-15-minutes playbook.
- Verified fw.sh dead man's switch with two real lockout tests.
- Red-team persistence sim (`redteam/plant.sh`) and the hunt/recon fixes it
  forced.
- Six pre-written inject responses with cited sources (`injects/responses/`).
- Cited rules research (`playbooks/competition-rules.md`).
- Canary/tripwire detection (`linux/canary.sh`): decoy files + auditd watches,
  read-only `--check`, manifest-tracked so removal is exact.
- Printable competition-day playbook (`playbooks/competition-day-playbook.md`).
- Sunday simulation runbook (`playbooks/simulation-runbook.md`): the timed
  plant → detect → eradicate → guardian-survival drill.
- Reconciling watchdog keep-alive (`linux/guardian.sh`): three layers that
  rebuild each other, manifest-tracked, tamper-repairing, disarm sentinel.
- Automated destructive regression drill (`redteam/drill.sh`) that exits
  non-zero on any failed assertion, plus a fast non-root `redteam/self-test.sh`.
- Supervised sentry installed by `arm.sh`: current structured approval queue,
  approval-time revalidation, unique pre-removal evidence, and integrated
  canary/hunt/recon change events without occupying the operator terminal.
- **The attacks that leave the disk looking normal** (2026-09-15). Everything
  before this line finds an artifact in a file. These find the ones that do not
  have one:
  - `triage.sh` now asks who HOLDS each socket, not which port is open, so a
    memory-only reverse shell over an allowed 443 is RED on the owner (a shell,
    an interpreter, a deleted or unpackaged binary). Plus UDP listeners, with
    the kernel's ephemeral range excluded so the check stays readable.
  - `audit.sh`: persistent rules in `rules.d` that survive the `auditd` restart
    which silently cleared every runtime watch, repaired every tick by guardian
    from its own hash-pinned copy; and log-tamper detection by size/inode that
    tells truncation from a real logrotate.
  - `splunk.sh`: forwarder health and a token probe, because a forwarder can be
    running, green, and shipping nothing.
  - `sshd.sh`: the effective config (drop-ins win over the file you would read),
    alternate key sources no `authorized_keys` check can see, and transactional
    changes behind fw.sh's dead man's switch.
  - `preserve.sh`, `surface.sh`, `policy.sh`, `scan.sh`, `banner.sh`.
  - `plant.sh`/`drill.sh` gained the five matching attacks, including proving
    the audit rules survive a real `auditd` restart.
  - Non-root suite: 199 assertions across ten sub-suites.
  - Found while doing it: `guardian-sentry-self-test.sh` had been failing 9 of
    18 assertions silently (no writable `/etc/cron.d` in its sandbox), so
    "guardian protects sentry" was not actually being tested.
- External agent review of the whole kit, plus the hardening pass it produced:
  arm-before-apply in `fw.sh`, an independent `.repair` source tree and drop-in
  defence in `guardian.sh`, collision/interruption handling in `canary.sh`,
  process-start-token locking in `guardian.sh`/`watchdog.sh`, and real
  home-directory enumeration in `recon.sh`.

## Next lab session

0. **Run the new drill on a real VM.** Everything in the 2026-09-15 block above
   passes its own non-root suite and NONE of the mutating paths have run on
   real systemd. Specifically unproven until that happens:
   - `sshd.sh --apply` against a real sshd: the drop-in, `sshd -t`, the armed
     rollback, and a reload that does not drop the session running it. **Test
     this from a second SSH connection, and do not skip the login test.**
   - `audit.sh --apply` against a real auditd, and the drill assertion that the
     rules survive `systemctl restart auditd`.
   - guardian's new audit-repair tick phase on a live chain.
   - `plant.sh`'s five live attacks, including that it refuses to take port 443
     when a scored service already has it.
1. Boot the Ubuntu target and take a clean snapshot.
2. Copy `config/example.env` outside the repo and fill in only the packet's
   scored users, services, ports, and addresses.
3. Run recon and hunt; review the evidence manually.
4. ~~Run the **current** full root `redteam/drill.sh`.~~ **Done 2026-09-14 on
   the lab VM: 63/63, exit 0**, re-run after the review fixes. The prior 57/57
   was correctly not inherited. An earlier 62/63 in the same session was a test
   artifact - canaries left deployed from a previous run, so the drill's deploy
   was correctly refused by canary.sh's own collision check.
5. Verify sentry install/restart/status/uninstall and an approved disposable
   cron/unit action on the snapshot.
6. Test a firewall change with a short rollback window from a second SSH
   connection. Do not use the competition box for the first test.
7. Confirm backups can be read and restored on a disposable copy.

## Raised by the training material (2026-09-11)

- ~~**fw.sh rollback on an empty Ubuntu nft ruleset.**~~ Fixed and proven with
  a deliberate lockout; the snapshot now includes `flush ruleset` even when
  the original ruleset is otherwise empty.
- **Run every script under `busybox sh`.** Alpine appears in the real
  environment and has no bash.
- **Add `firewalld` and SELinux handling.** Rocky, CentOS, and Fedora are all
  in the environment.
- **Build a table generator for enumeration injects** (IP, host, OS, service,
  port, needed?). That table is the deliverable for at least two known injects.
- **Decide who records the VPN video.** One inject requires a three-minute
  recorded presentation posted to YouTube; it cannot be improvised late.

## After Windows/firewall training

- Replace placeholder Windows service checks with scorer-style endpoint checks.
- Add a PowerShell firewall renderer with an equivalent rollback workflow.
- Add Windows event-forwarding validation and a small Splunk dashboard.
- Reconcile these scripts against the team's current internal/public toolkit
  before submitting fixes upstream.

## Blocked / needs a call

- ~~**guardian.sh**~~ — **built 2026-09-11.** Authoring it was refused once by
  the agent's auto-mode safety classifier as "unauthorized persistence"; it was
  written in an interactive session where the operator approves each write.
  Recorded here because the pattern will recur: resilient defensive tooling and
  malware look identical to a classifier, and the operator's approval is the
  thing that separates them.
- ~~**guardian.sh's original mutating paths had never run as root**~~ — the
  prior version passed **57/57**, including a systemd drop-in attack. The
  current hardening pass needs the fresh root rerun listed above.
- ~~**fw.sh's rewritten dead man's switch is untested**~~ — **done 2026-09-13.**
  Retested on the lab VM including a real lockout: port 22 removed from the
  allow list, a new SSH connection refused, the switch fired unattended, access
  restored with the baseline ruleset intact and the scored service still up.
- **The inject drafts have not been re-checked since the external review.**
  The shell code has had another review and non-root regression pass; the
  review priority — whether each draft in `injects/responses/` actually
  answers its inject's numbered asks and cites its source honestly — was never
  reached. That is half the score and it is the least-examined part of the kit.

## Decisions with deadlines

- **Publish this repository publicly, and decide when.** National CCDC rule
  5.6.1 requires team-written tools to have been public for **at least 3 months
  prior to use** in any CCDC event, declared to officials, and frozen at
  submission. "Private now, public on competition day" does not satisfy it. The
  BYU tryout on 2026-09-26 is not obviously bound by this — the regional it
  feeds is. Working backwards from a spring regional, this repo needs to be
  public over the winter and frozen before the event. See
  `playbooks/competition-rules.md` §2.
- **Sign up for tryouts by 2026-09-24.** Competition is 2026-09-26, 10:00-16:00.

## Before competition day

- Fill configs from the team packet and keep them outside the public repo.
- Run a timed two-to-three-hour practice on snapshots.
- Test the fresh-VM download/setup path.
- Print the playbook and memo template.
- Verify every scored service from the network, not just from local service
  state.
