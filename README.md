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

# 2. Arm the standing defence: backup + canaries + guardian, and guardian
#    starts the watchdog as a supervised unit. Dry run first, as always.
./linux/arm.sh      --config /tmp/ccdc-linux.env
sudo ./linux/arm.sh --config /tmp/ccdc-linux.env --apply

# 3. Watch. Read-only, and prints only what CHANGED since the last pass.
./linux/watch.sh --config /tmp/ccdc-linux.env --interval 120
```

Every mutating tool is dry-run by default and needs `--apply`.

Do not start `watchdog.sh` by hand — `guardian.sh` (via `arm.sh`) installs it
as a supervised unit. Launched from a shell it dies with your SSH session,
which is the moment you need it most.

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
  watch.sh                detection loop; reports only what changed
  canary.sh               decoy files + auditd tripwires
  watchdog.sh             restarts a dead scored service (run via guardian)
  guardian.sh             keeps the watchdog alive against an attacker w/ root
  services.sh             review and reversibly disable unneeded daemons
  fw.sh                   firewall with an automatic lockout rollback
  users.sh backup.sh      accounts; restore points
  diff-evidence.sh        compare two evidence snapshots
windows/                  PowerShell first-pass tools
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
