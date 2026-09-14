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
- External agent review of the whole kit, plus the hardening pass it produced:
  arm-before-apply in `fw.sh`, an independent `.repair` source tree and drop-in
  defence in `guardian.sh`, collision/interruption handling in `canary.sh`,
  process-start-token locking in `guardian.sh`/`watchdog.sh`, and real
  home-directory enumeration in `recon.sh`.

## Next lab session

1. Boot the Ubuntu target and take a clean snapshot.
2. Copy `config/example.env` outside the repo and fill in only the packet's
   scored users, services, ports, and addresses.
3. Run recon and hunt; review the evidence manually.
4. Run the **current** full root `redteam/drill.sh`. The prior guardian version
   passed 57/57; manifest, collision, payload-name, and sentry changes since
   then require a fresh result rather than inheriting that claim.
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
