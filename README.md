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

./linux/recon.sh --config /tmp/ccdc-linux.env
./linux/hunt.sh --config /tmp/ccdc-linux.env
./linux/watchdog.sh --config /tmp/ccdc-linux.env --once --dry-run
```

The first two commands are read-only. `watchdog.sh` is also non-mutating until
you pass `--apply`; it logs an unhealthy service rather than restarting it in
dry-run mode.

## Before any mutation

1. Take a VM snapshot.
2. Run `recon.sh` and save the evidence folder.
3. Fill in scored users, services, ports, and the scoring/Splunk addresses.
4. Run the command with `--dry-run` and inspect its output.
5. Apply one change at a time, verify the scored service, then run recon again.

## Layout

```text
config/example.env       safe template; real config stays outside the repo
linux/                    Bash tools for Linux boxes
windows/                  PowerShell first-pass tools
splunk/                   starter searches and field notes
injects/                  memo and incident-report templates
playbooks/                printable competition checklists
```

## Important limitation

The scripts are deliberately conservative and are not a substitute for the
team packet. The packet decides which users, ports, IPs, and services are
scored. A setting that is safe on the Ubuntu lab VM can still be wrong for the
competition image.

See [`ROADMAP.md`](ROADMAP.md) for the lab sequence and the remaining Windows
and competition-day work. The PowerShell files are first-pass drafts and have
not been executed in this Linux workspace.
