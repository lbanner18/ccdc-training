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

## Next lab session

1. Boot the Ubuntu target and take a clean snapshot.
2. Copy `config/example.env` outside the repo and fill in only the packet's
   scored users, services, ports, and addresses.
3. Run recon and hunt; review the evidence manually.
4. Create a harmless local test service and verify watchdog behavior in dry-run
   mode, then in apply mode.
5. Test a firewall change with a short rollback window from a second SSH
   connection. Do not use the competition box for the first test.
6. Confirm backups can be read and restored on a disposable copy.

## After Windows/firewall training

- Replace placeholder Windows service checks with scorer-style endpoint checks.
- Add a PowerShell firewall renderer with an equivalent rollback workflow.
- Add Windows event-forwarding validation and a small Splunk dashboard.
- Reconcile these scripts against the team's current internal/public toolkit
  before submitting fixes upstream.

## Before competition day

- Fill configs from the team packet and keep them outside the public repo.
- Run a timed two-to-three-hour practice on snapshots.
- Test the fresh-VM download/setup path.
- Print the playbook and memo template.
- Verify every scored service from the network, not just from local service
  state.

