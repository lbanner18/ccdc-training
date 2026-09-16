# CCDC training kit — implementation scope

## Goal

Provide a small, auditable defensive kit for a CCDC-style Linux box. The kit
must support the loop used in the team checklist:

1. investigate and preserve evidence;
2. document what was found;
3. act only on explicitly configured targets;
4. verify scored services after a change.

The scripts are intended for an isolated lab and a competition box owned or
authorized by the team. They are not a general-purpose remote administration
framework.

## Initial deliverables

- `linux/recon.sh`: read-only host snapshot with a timestamped evidence folder.
- `linux/hunt.sh`: read-only persistence and tamper sweep.
- `linux/watchdog.sh`: configurable service checks; restart only a configured
  service that is actually unhealthy.
- `linux/sentry.sh`: supervised ranked detection plus a current, structured
  approval queue; every action is revalidated and evidence-backed at sign-off.
- `linux/users.sh`: access audit by default; mutations require `--apply` and
  use an explicit allowlist.
- `linux/backup.sh`: explicit-path backups with checksums and guarded restore.
- `linux/fw.sh`: generated firewall rules with dry-run output and an automatic
  rollback window.
- `linux/sshd.sh`: effective-config audit (drop-ins, Match blocks, alternate
  key sources) and transactional policy changes behind a timed rollback.
- `linux/audit.sh`: persistent audit rules that survive an `auditd` restart,
  log-tampering detection, and an evidence capture of the logs.
- `linux/splunk.sh`: forwarder health and an end-to-end delivery probe.
- `linux/preserve.sh`: volatile evidence capture before remediation.
- `linux/surface.sh`, `linux/policy.sh`: the two inject tables, with the
  judgement column filled in from the config rather than guessed.
- `linux/scan.sh`, `linux/banner.sh`: use an installed AV/YARA honestly;
  the login-banner inject.
- `linux/diff-evidence.sh`: compare two recon snapshots.
- `windows/recon.ps1` and `windows/watchdog.ps1`: read-only first-pass Windows
  equivalents for the post-training phase.
- `splunk/searches.md`: starter searches for the Linux and Windows events named
  in the team notes.
- `injects/` and `playbooks/`: memo/report templates and a timed drill.

## Safety constraints

- Every destructive script supports `--dry-run`; destructive scripts default
  to dry run unless `--apply` is present. Detection may write private evidence
  and bounded state, but must not change system configuration.
- Real box-specific values belong in an untracked config file copied from
  `config/example.env`. No credentials, backup-admin names, IPs, or keys are
  committed.
- Evidence is written before a mutation whenever practical.
- Findings and approval queues are data, never shell source. An approval must
  refresh detection and protection policy immediately before acting.
- Root-run tools validate dedicated state/install paths before mkdir/chmod/rm,
  and status or dry-run modes must not change ownership or permissions.
- SSH/firewall changes must have a rollback path and must be tested in a lab
  snapshot before competition use. The rollback must be armed BEFORE the change
  is applied, and owned by something that outlives the session making it.
- A tool that reports must never state something it did not check. Where a
  value could not be read (no privileges, no such file), it says so instead of
  printing a plausible default — these reports are submitted as injects.
- Repair of the kit's OWN detection (audit rules, guardian's units, sentry's
  tree) is automatic, because restoring our tooling to its declared state is
  not a change to the box's security posture. Anything that changes the BOX
  goes through sentry and a human.
- Scripts use POSIX-ish shell commands and fallbacks because the target may be
  an old Linux distribution with a minimal userland.

## Out of scope for this pass

- automated exploitation, credential harvesting, or offensive tooling;
- unattended remote execution across multiple boxes;
- claiming a Windows implementation has been tested on this Linux workstation;
- provisioning or changing the host hypervisor.
