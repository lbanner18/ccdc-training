# CCDC training kit

A defensive, lab-first toolkit for a CCDC-style competition box, built around
two questions: **is the scored service up**, and **can I prove what changed**.

- **Linux** — 26 tools: recon, hunt, harden, triage, baseline/drift, tripwires,
  and a supervised approval queue that applies fixes only when you say so.
- **Windows** — 17 tools, 66 checks: triage, a checklist-driven harden, account
  and password handling, a scored-service/canary watchdog, the same approval queue,
  configuration drift against a frozen baseline, and tripwires that report who
  read them.
- **Playbooks** — 16 documents. Cards you can follow at 2am with a red team on
  the box.
- **Tested** — 559 assertions across 20 suites, including fixtures that plant
  real persistence on a lab VM and assert the tools find it.

Everything is read-only until you pass `--apply` (`-Apply` on Windows). No
destructive command identifies its target by position in a list. Every tool
says what it could *not* check, because a check that silently did not run reads
exactly like a check that found nothing.

It is organized around uptime and evidence: collect a baseline, check the
scored services the way a scorer would, make only configured changes, and
collect a post-change snapshot.

## Quick start on a Linux target

```bash
cd ccdc-training
cp config/example.env /tmp/ccdc-linux.env
# Edit /tmp/ccdc-linux.env for this box. Do not commit it.
CFG=/tmp/ccdc-linux.env

# 1. Record the box before you change it (read-only). This is your evidence of
#    what was already there.
./linux/recon.sh --config "$CFG"
./linux/hunt.sh --config "$CFG"

# 2. Remove what the scored services do not need. Read the plan first; the
#    all-safe cut verifies every configured scored check after each removal.
sudo ./linux/harden.sh --config "$CFG"
# One numbered read-only decision screen: unexplained AND unnecessary.
sudo ./linux/baseline.sh --config "$CFG" --review
sudo ./linux/harden.sh --config "$CFG" --cut all-safe --apply

# 3. Review what remains unexplained. Triage is the immediate ranked view;
#    baseline also asks whether each item is blessed, package-intact, or allowed.
sudo ./linux/triage.sh --config "$CFG"
sudo ./linux/baseline.sh --config "$CFG"

# 4. Freeze only the box you intend to keep. Do NOT bless an unresolved foothold.
# --stable-for takes a second inventory after 20 seconds and refuses to bless
# if anything changed while you were making the decision.
sudo ./linux/baseline.sh --config "$CFG" --bless --stable-for 20 --apply

# 5. Arm everything persistent: a machine backup, a separate kit recovery copy,
#    canaries, sentry, and guardian/watchdog.
#    Both monitoring loops become supervised services; your terminal stays free.
./linux/arm.sh --config "$CFG"
sudo ./linux/arm.sh --config "$CFG" --apply

# 6. Check in between injects. Status freezes the numbered review snapshot.
sudo ./linux/sentry.sh --config "$CFG" --status
#    Use the exact --approve N command printed for the item you chose.
#    With no N, bulk approval acts on RED items only and leaves AMBER items alone.
sudo ./linux/sentry.sh --config "$CFG" --approve N --apply
# Optional: show pending AMBER approvals as [!N] in new Bash login shells.
# This does not run from arm.sh because it deliberately changes /etc/profile.d.
sudo ./linux/prompt.sh --config "$CFG" --install --apply
```

The supervised sentry keeps a current ranked queue, folds in canary and broader
host-change events, and works out the exact remediation. It never acts on its
own — findings queue for your sign-off:

The quick start above sets `CFG` to the filled-in config for this box.

```bash
sudo ./linux/sentry.sh --config "$CFG" --status             # freeze and review the queue
sudo ./linux/sentry.sh --config "$CFG" --approve N --apply  # apply one chosen item
sudo ./linux/sentry.sh --config "$CFG" --approve --apply    # bulk: RED only, never AMBER
sudo ./linux/sentry.sh --config "$CFG" --ack                # reviewed change events
```

That split is the point: detection, diagnosis, evidence capture, and typing are
automatic; the destructive decision is yours. Status freezes the identities
behind the item numbers you reviewed; approval then re-runs triage and
re-evaluates those exact identities against current protection lists, so a
reordered or stale queue cannot act on something else after the box or config
changes. It **refuses to act at all** until
`CCDC_ALLOWED_USERS` and `CCDC_SYSTEMD_SERVICES` are filled in from the packet —
an empty protect list does not mean nothing is protected, it means nobody has
told the tool what is scored.

**Alerting:** after `arm.sh --apply`, the supervised watch pass sends one
deduplicated `wall` message for each new RED baseline finding when `wall` is
available. It is on by default (`CCDC_WATCH_NOTIFY="1"`). This reaches logged-in
terminals; it is not email, desktop, or phone notification, and AMBER findings
do not interrupt you. The separate, opt-in `prompt.sh` hook shows `[!N]` for
pending actionable AMBER approvals in new interactive Bash login shells.
`[!?]` means its sentry snapshot is stale or unknown, never “all clear.” It is
not part of `arm.sh`: installing a profile hook is a real provenance change
that you should review and bless deliberately. Keep using `sentry.sh --status`
between injects to see the full queue and retained change events.

Every destructive tool is dry-run by default and needs `--apply`. Detection
tools write evidence but do not change system configuration.

Once `arm.sh --apply` has run, the evidence directory is root-owned `0700`, so
**every tool needs `sudo` from then on**. Unprivileged runs stop with a clear
error rather than silently writing to a second directory and splitting your
evidence in half.

Do not start `watchdog.sh` by hand — `guardian.sh` (via `arm.sh`) installs it
as a supervised unit. Launched from a shell it dies with your SSH session,
which is the moment you need it most.

`arm.sh` installs sentry before guardian so guardian can independently snapshot
and hash sentry's systemd unit, config, ownership marker, and complete installed
file tree. Each reconcile pass repairs drift from guardian's private copy,
removes sentry-specific systemd drop-ins/runtime shadows, and restarts sentry so
the repaired files become the running code. Guardian does not own the live
sentry installation: when disarming, uninstall guardian first, then sentry.

Treat the config outside the repo as the source of truth. After changing users,
services, or checks, re-run `sudo ./linux/arm.sh --config "$CFG" --apply` (or run
the individual sentry install followed immediately by guardian install). Never
hand-edit the root-owned installed copies: the guardian intentionally rejects
an unpinned config, and a manual edit can leave monitoring on different
assumptions.

Deployment names are config too. `CCDC_SENTRY_NAME` names the service and
`CCDC_SENTRY_ENTRY` names its long-lived executable; Guardian has independent
layer and payload-name keys. Use neutral operational labels, never a fake OS
component. Renaming an armed chain is a layout migration: uninstall Guardian,
uninstall Sentry with the old config, edit the names, then install Sentry and
Guardian again in that order. This avoids an old root loop and a new root loop
running at once.

`arm.sh` deliberately leaves these to you, because each one can take a scored
service off the board if you get it wrong:

```bash
./linux/services.sh --config /tmp/ccdc-linux.env --review   # what should not run
./linux/fw.sh       --config /tmp/ccdc-linux.env            # what should not be reachable
./linux/sshd.sh     --config /tmp/ccdc-linux.env            # what the daemon will ACTUALLY do
./linux/policy.sh   --config /tmp/ccdc-linux.env            # what a password has to be
```

## The four that answer a question nothing else does

```bash
sudo ./linux/triage.sh   --config "$CFG"   # who is holding a socket right now
sudo ./linux/audit.sh    --config "$CFG"   # can this box still prove what happened?
     ./linux/splunk.sh   --config "$CFG"   # are the logs actually leaving?
sudo ./linux/preserve.sh --config "$CFG" --pid N   # take it BEFORE you kill it
```

The first three all answer "no" in ways that look like "yes" from a normal
check: a reverse shell over port 443 is a permitted connection, an `auditd`
restart clears every runtime watch while the disk looks untouched, and a
forwarder can be running, green, and shipping nothing. The fourth exists
because the evidence an incident report needs — the socket, the parent
process, an unlinked binary — stops existing the moment you remediate.

Two produce the table an inject asks for directly:

```bash
./linux/surface.sh --config "$CFG" --table   # ports, owners, "needed?"
./linux/policy.sh  --config "$CFG" --table   # the password-policy findings row
```

## Practising against it

Two fixtures, and they exercise different skills:

```bash
sudo ./redteam/walkthrough.sh          # five planted artifacts; clean them up
sudo ./redteam/live.sh                 # five RUNNING footholds; different discipline
sudo ./redteam/walkthrough.sh --clean  # (or live.sh --clean) to remove them
```

`walkthrough.sh` plants things that sit still while you think — an account, a
drop-in, a SUID binary, a timer, a sudoers rule. `live.sh` starts processes,
where the order inverts: **freeze, capture, identify the parent, and only then
kill.** `kill -9` first takes the memory, the open sockets and the parent with
it, and the parent is how it comes back. One of the five runs with its
executable already unlinked, so `/proc/PID/exe` is the only copy that exists.

`plant.sh` + `drill.sh` are the larger scored version: sixteen artifacts and a
pass/fail count, for measuring the tools rather than practising with them.

## Before any mutation

1. Take a VM snapshot.
2. Run `recon.sh` and save the evidence folder.
3. Fill in scored users, services, ports, and the scoring/Splunk addresses.
4. Run the command with `--dry-run` and inspect its output.
5. Apply one change at a time, verify the scored service, then run recon again.

## Layout

```text
config/example.env       safe template; real config stays outside the repo
linux/                    Bash tools for Linux boxes:
  arm.sh                  one command to arm the standing defence
  recovery.sh             checksummed recovery copy of the kit; restores only
                          into a new directory if the checkout is lost. Its
                          root-owned helper lives beside the recovery bundle
  recon.sh hunt.sh        read-only baseline and persistence sweeps
  sentry.sh               supervised: detect, diagnose, current sign-off queue
  prompt.sh               opt-in [!N] Bash prompt signal for pending AMBER work
  triage.sh               one-shot ranked view of what is wrong NOW
  card.sh                 read one remediation card in the terminal
  watch.sh                detection sweep; folded into sentry, also runnable alone
  canary.sh               decoy files + auditd tripwires
  audit.sh                persistent audit rules; catches a wiped log
  baseline.sh             what is on this box that nothing explains, and what
                          to do about each one. Bless a known-good state, then
                          every later change is measured against it forever
  inventory-compare.sh    cross-check canonical inventory against recon evidence
  watchdog.sh             restarts a dead scored service (run via guardian)
  guardian.sh             keeps the watchdog alive against an attacker w/ root
  harden.sh               what is running that nothing scored NEEDS. Cuts it,
                          checks the scored services after every cut, and
                          reverses that cut by itself if one stops answering
  services.sh             review and reversibly disable unneeded daemons - the
                          buckets harden.sh has no opinion about
  fw.sh                   firewall with an automatic lockout rollback
  sshd.sh                 SSH audit + transactional change with a rollback
  splunk.sh               is this box actually shipping its logs?
  preserve.sh             volatile evidence, before you remediate
  surface.sh              every reachable port, with an owner and a verdict
  policy.sh               password policy audit (report-only, no --apply)
  scan.sh banner.sh       AV/YARA wrapper; login-banner inject
  users.sh backup.sh      accounts; restore points
  diff-evidence.sh        compare two evidence snapshots
workstation/              tools for the assigned external workstation:
  perimeter.sh            scope-confirmed nmap evidence + inject table
windows/                  PowerShell tools for Windows boxes. Target is Windows
                          PowerShell 5.1 - what ships on Windows 10 and Server
                          2016/2019 - so they run on a box you did not build:
  lib/Common.ps1          config, findings, evidence, scored-service checks.
                          Reads THE SAME config file as the Linux tools
  triage.ps1              read-only. What should alarm you right now, ranked,
                          with the command that fixes each thing under it
  harden.ps1              the hardening checklist from the team training, in
                          order, one command. Re-checks the scored services
                          after every step and STOPS if one stopped answering
  users.ps1               accounts and passwords. Separate from harden.ps1
                          because it will not rotate a SCORED account's password
                          without being told twice - on many setups that is how
                          the scoring engine logs in
  watchdog.ps1            restarts a stopped scored service, re-enables a
                          disabled scored ACCOUNT, checks laid canaries, and
                          installs as a SYSTEM task
  guardian.ps1            second SYSTEM task that repairs the watchdog task;
                          redundancy only - Administrator can remove every layer
  integrity.ps1           separate SYSTEM check that reports a missing, stopped,
                          or redirected Guardian task; Guardian repairs it
  arm.ps1                 lays canaries, installs the three-task recovery chain,
                          and verifies the result; never changes packet decisions
  recovery.ps1            checksummed whole-kit archive outside the checkout;
                          restores only to a new empty folder, never over source
  audit.ps1               logging/audit health check, bounded evidence capture,
                          and repair through harden.ps1's existing Logging step
  evidence.ps1            bundles key defense records and verifies a copy to a
                          user-supplied UNC share; never chooses a destination
  splunk.ps1              are the event logs actually reaching Splunk? Reads
                          effective config via btool, checks the live indexer
                          connection, and -TestEvent -Apply proves delivery
  timeline.ps1            read-only, time-bounded incident timeline across
                          Security, System, PowerShell, Task Scheduler, and Defender
  surface.ps1             read-only listener/service/selected-autostart map;
                          --Table is markdown ready and states its remaining
                          coverage gaps; can include explicitly configured
                          Autorunsc evidence
  recon.ps1               read-only evidence capture, before you change anything
lab/                      building the practice targets:
  make-vm.sh              create the Windows target on the isolated lab network
  make-unattended-iso.sh  rebuild a Windows ISO so it installs hands-off
  autounattend.xml        the answer file it uses
redteam/                  red-team fixtures and the regression suite:
  self-test.sh            runs every suite below (559 assertions, non-root;
                          448 without the Windows suite, which needs pwsh -
                          set CCDC_PWSH=/path/to/pwsh, or it skips and says so)
  pasteable-self-test.sh  what the tools PRINT: no unpastable command, no
                          remediation that damages your own box, no flag
                          without documentation, and no flag a tool advertises
                          but cannot parse
  baseline-self-test.sh   every finding kind has an action or a written reason
                          it needs a human; nothing destructive can reach a
                          path outside the trigger directories
  night-drill.sh          eight footholds, including two that no content-based
                          check can see
  walkthrough.sh          five planted footholds for hands-on practice
  live.sh                 five footholds that are RUNNING, for the
                          freeze-before-kill drill
  plant.sh drill.sh       the full sixteen-artifact fixture, and the scored
                          detect/eradicate drill against it
splunk/                   starter searches and field notes
injects/                  memo and incident-report templates
injects/responses/        pre-written drafts for the known injects
playbooks/                printable competition checklists
```

## Important limitation

The scripts are deliberately conservative and are not a substitute for the
team packet. The packet decides which users, ports, IPs, and services are
scored. A setting that is safe on the Ubuntu lab VM can still be wrong for the
competition image.

Detection: `linux/canary.sh` lays decoy files and auditd tripwires and reports
when they are touched — the endorsed active-defense shape. A full printable
run-of-show is in
[`playbooks/competition-day-playbook.md`](playbooks/competition-day-playbook.md).

Injects are **half the score** — the tryout page says points are split evenly
between the defense competition and the injects. Six drafts are pre-written in
[`injects/responses/`](injects/responses/). Read
[`playbooks/competition-rules.md`](playbooks/competition-rules.md) for the
cited rules, including the one that governs when this repository has to be
public.

See [`ROADMAP.md`](ROADMAP.md) for the lab sequence and the remaining Windows
and competition-day work. The PowerShell tools have run on a real Windows Server
2022 lab box as well as against the stubbed suite; `playbooks/open-work.md`
records what was proven there and what was not.
