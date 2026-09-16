# Linux first 15 minutes

Use the team packet to fill the bracketed values before competition day.

Before using this card, set the config path once in the shell:

```bash
CFG=/tmp/ccdc-linux.env
```

`[ ]` marks a task on this printable card; copy the command after it, not the
checkbox.

```text
[ ] Confirm host, console/SSH access, and current time.
[ ] Take a VM snapshot if the environment permits it.
[ ] Get the kit on the box: bootstrap-on-the-box.md (STEP 1 probe).
[ ] Copy the kit and local config; do not paste secrets into chat.
[ ] sudo ./linux/triage.sh --config "$CFG"   # ranked: what is ALREADY wrong
    It prints the fix command too. ./linux/card.sh <n> <name> for the full card.
    NEVER cat playbooks/remediation-cards.md - use less, it is markdown.
    Each finding names a card in playbooks/remediation-cards.md
[ ] Run recon.sh and save the evidence path.
[ ] Run hunt.sh and review persistence, keys, sudoers, and listening ports.
[ ] Check scored services from the outside, not only systemctl status.
[ ] Set CCDC_WATCHDOG_INTERVAL="5" and point CCDC_HTTP_CHECKS at the address
    the SCORER uses, not 127.0.0.1.
[ ] sudo ./linux/arm.sh --config "$CFG" --apply
    -> backup + canaries + supervised sentry, then guardian/watchdog.
       Guardian independently enrolls sentry's unit, config, and installed tree.
       Never run either loop by hand; systemd keeps both alive and your one
       terminal remains free.
[ ] Check the current queue: sudo ./linux/sentry.sh --config "$CFG" --status
[ ] sudo ./linux/audit.sh --config "$CFG" --apply
    Persistent audit rules, so the next `systemctl restart auditd` does not
    silently clear every watch canary.sh loaded. Then --capture, which is the
    log baseline that makes "they wiped the logs" provable later.
[ ] ./linux/splunk.sh --config "$CFG"          # is it actually shipping?
    then: sudo ./linux/splunk.sh --config "$CFG" --test-event --apply
    and FIND THE TOKEN IN SPLUNK. A forwarder can be running and shipping
    nothing; only the token proves delivery. Record the token and the time.
[ ] sudo ./linux/sshd.sh --config "$CFG"       # what the daemon will ACTUALLY do
    Reads drop-ins and Match blocks. sshd_config saying PermitRootLogin no
    means nothing if a file in sshd_config.d says yes.
[ ] Review the packet's scored users, ports, and firewall exceptions.
[ ] sudo ./linux/surface.sh --config "$CFG"    # every port, with an owner
[ ] `sudo ./linux/services.sh --config "$CFG" --review` — then decide deliberately what to disable.
[ ] Apply one change at a time with --dry-run first.
[ ] Verify the scored service after every change.
[ ] Run recon.sh again and note the evidence path in the incident report.
```

## When you find something live

Not a file on disk — a process, a connection, a login. The order matters, and
it is the opposite of the instinct:

```text
[ ] DO NOT KILL IT YET.
[ ] sudo ./linux/preserve.sh --config "$CFG" --pid <PID> --freeze --apply
    Stops it, then takes the socket, the parent chain, the open files, and a
    copy of the binary recovered through /proc (which works even when the file
    was deleted). All of that is gone the moment you kill it.
[ ] Read 00-CASE.txt. The three sentences it names ARE the incident report.
[ ] Find what STARTED it before you kill it: ancestry.txt. ppid 1 means the
    real parent already exited, so something scheduled it — work CARD 3 and
    CARD 4 before killing, or it comes back in 60 seconds.
[ ] Then: kill -9 <PID>, and re-run triage to confirm the finding CLEARS.
```

## The three questions nothing else on the box answers

```text
[ ] sudo ./linux/triage.sh --config "$CFG"   who is holding a socket right now?
    A reverse shell over 443 is a permitted connection on an allowed port.
    The finding is never the port; it is that bash is on the end of it.
[ ] sudo ./linux/audit.sh --config "$CFG"    can this box still prove anything?
[ ]      ./linux/splunk.sh --config "$CFG"   are the logs leaving the box?
```
