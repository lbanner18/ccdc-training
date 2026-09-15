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

# 1. See the box before you change it (both read-only)
./linux/recon.sh --config /tmp/ccdc-linux.env
./linux/hunt.sh  --config /tmp/ccdc-linux.env

# 2. Arm everything persistent: backup + canaries + sentry + guardian/watchdog.
#    Both monitoring loops become supervised services; your terminal stays free.
./linux/arm.sh      --config /tmp/ccdc-linux.env
sudo ./linux/arm.sh --config /tmp/ccdc-linux.env --apply

# 3. Check in between injects (both commands return immediately).
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --status
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --approve --apply
```

The supervised sentry keeps a current ranked queue, folds in canary and broader
host-change events, and works out the exact remediation. It never acts on its
own — findings queue for your sign-off:

```bash
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --status             # what is waiting
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --approve --apply    # do it
sudo ./linux/sentry.sh --config /tmp/ccdc-linux.env --ack                # reviewed change events
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
services, or checks, re-run `sudo ./linux/arm.sh --config <cfg> --apply` (or run
the individual sentry install followed immediately by guardian install). Never
hand-edit the root-owned installed copies: the guardian intentionally rejects
an unpinned config, and a manual edit can leave monitoring on different
assumptions.

`arm.sh` deliberately leaves two things to you, because both can take a scored
service off the board if you get them wrong:

```bash
./linux/services.sh --config /tmp/ccdc-linux.env --review   # what should not run
./linux/fw.sh       --config /tmp/ccdc-linux.env            # what should not be reachable
```

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
  watchdog.sh             restarts a dead scored service (run via guardian)
  guardian.sh             keeps the watchdog alive against an attacker w/ root
  services.sh             review and reversibly disable unneeded daemons
  fw.sh                   firewall with an automatic lockout rollback
  users.sh backup.sh      accounts; restore points
  diff-evidence.sh        compare two evidence snapshots
windows/                  PowerShell first-pass tools
redteam/self-test.sh      fast non-root regression suite
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
