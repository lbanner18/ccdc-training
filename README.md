# CCDC training kit

This is a defensive, lab-first toolkit for a CCDC-style competition box. It is
organized around uptime and evidence: collect a baseline, check the scored
services the way a scorer would, make only configured changes, and collect a
post-change snapshot.

## Quick start on a Linux target

```bash
cd ccdc-training
cp config/example.env /tmp/ccdc-linux.env
# Edit /tmp/ccdc-linux.env for this box. Do not commit it.
CFG=/tmp/ccdc-linux.env

# 1. See the box before you change it (both read-only)
sudo ./linux/triage.sh --config "$CFG"
./linux/recon.sh --config "$CFG"
./linux/hunt.sh --config "$CFG"

# 2. Resolve the findings you understand, then freeze the box you intend to keep.
#    Do NOT bless a box with an unresolved foothold.
sudo ./linux/baseline.sh --config "$CFG"
sudo ./linux/baseline.sh --config "$CFG" --bless --apply

# 3. Arm everything persistent: backup + canaries + sentry + guardian/watchdog.
#    Both monitoring loops become supervised services; your terminal stays free.
./linux/arm.sh --config "$CFG"
sudo ./linux/arm.sh --config "$CFG" --apply

# 4. Check in between injects (both commands return immediately).
sudo ./linux/sentry.sh --config "$CFG" --status
sudo ./linux/sentry.sh --config "$CFG" --approve --apply
```

The supervised sentry keeps a current ranked queue, folds in canary and broader
host-change events, and works out the exact remediation. It never acts on its
own — findings queue for your sign-off:

The quick start above sets `CFG` to the filled-in config for this box.

```bash
sudo ./linux/sentry.sh --config "$CFG" --status             # what is waiting
sudo ./linux/sentry.sh --config "$CFG" --approve --apply    # do it
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
  recon.sh hunt.sh        read-only baseline and persistence sweeps
  sentry.sh               supervised: detect, diagnose, current sign-off queue
  triage.sh               one-shot ranked view of what is wrong NOW
  card.sh                 read one remediation card in the terminal
  watch.sh                detection sweep; folded into sentry, also runnable alone
  canary.sh               decoy files + auditd tripwires
  audit.sh                persistent audit rules; catches a wiped log
  baseline.sh             what is on this box that nothing explains, and what
                          to do about each one. Bless a known-good state, then
                          every later change is measured against it forever
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
windows/                  PowerShell first-pass tools
redteam/                  red-team fixtures and the regression suite:
  self-test.sh            runs every suite below (391 assertions, non-root)
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
and competition-day work. The PowerShell files are first-pass drafts and have
not been executed in this Linux workspace.
