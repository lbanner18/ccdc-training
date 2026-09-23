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
[ ] Create the local config once if it is not already present:
        test -f "$CFG" || cp config/example.env "$CFG"
        chmod 600 "$CFG"
    Fill in the packet facts: accounts that must remain, services that are
    scored, allowed ports, and checks the scorer makes. Example: if the scorer
    opens `http://10.0.0.5/`, put that address in CCDC_HTTP_CHECKS; do not use
    `127.0.0.1` unless the scorer really connects from the same machine. Do not
    paste the finished config into chat.
[ ] Run recon.sh and save the evidence path it prints. This is the "before"
    record. Example: later you can show that a scheduled task existed before
    you changed anything.
[ ] Run hunt.sh. Read its sections for startup jobs, SSH keys, sudo access, and
    listening ports. A "listening port" is a program waiting for a connection.
[ ] Check scored services from the outside, not only systemctl status.
[ ] Set CCDC_WATCHDOG_INTERVAL="5" and point CCDC_HTTP_CHECKS at the address
    the SCORER uses, not 127.0.0.1.
[ ] sudo ./linux/harden.sh --config "$CFG"      # what nothing scored NEEDS
    Read the list, then run:
        sudo ./linux/harden.sh --config "$CFG" --cut all-safe --apply
    Every cut is checked against the scored services and reversed automatically
    if one stops answering. For an item you do not understand, run:
        sudo ./linux/harden.sh --config "$CFG" --explain N
[ ] sudo ./linux/triage.sh --config "$CFG"      # problems to handle now
    Read RED findings first. Each finding either prints a command you can copy
    or tells you exactly what to compare before changing anything. `dig:` means
    "show me the evidence for this one finding". `more:` names the card with a
    slower, step-by-step version.
[ ] sudo ./linux/baseline.sh --config "$CFG"    # what remains unexplained
[ ] sudo ./linux/baseline.sh --config "$CFG" --bless --stable-for 20 --apply
    ONLY once the box looks the way you want it. This freezes what remains as
    known-good. New drift stays visible until you remove it or allow it; it
    never becomes normal merely because another watch pass completed.
    `--stable-for 20` takes a second full inventory after 20 seconds and
    refuses to bless if anything changed while you were reviewing.
[ ] If the opposing team is actively changing the box while you review, it is
    reasonable to run `arm.sh --apply` earlier, after the packet config is
    correct. Its first pass cannot prove the old state is clean, but it gives
    you canaries and change evidence during the final review. After blessing,
    re-run `arm.sh --apply` once so its recovery bundle includes the newly
    blessed inventory.
[ ] sudo ./linux/arm.sh --config "$CFG" --apply
    This starts the long-running protection: a machine backup, a separate
    checksummed kit recovery copy, canaries, sentry, and guardian/watchdog.
    After it finishes, `systemctl` keeps the monitoring programs running in
    the background. Do not start their `--loop` modes in your shell.
[ ] Check the current queue: sudo ./linux/sentry.sh --config "$CFG" --status
[ ] A new RED baseline finding is broadcast once to logged-in terminals with
    `wall` when it is installed (CCDC_WATCH_NOTIFY="1" is the default). This is
    not email or a pager, so keep checking the sentry queue between injects.
[ ] Optional, after reviewing the profile change: sudo ./linux/prompt.sh --config "$CFG" --install --apply
    New Bash login shells show [!N] for pending AMBER approvals; [!?] means
    the sentry count is stale or unknown, not clear.
[ ] sudo ./linux/audit.sh --config "$CFG" --apply
    Persistent audit rules, so the next `systemctl restart auditd` does not
    silently clear every watch canary.sh loaded. Then --capture, which is the
    log baseline that makes "they wiped the logs" provable later.
[ ] sudo ./linux/audit.sh --config "$CFG" --capture
    Saves hashes and recent log evidence. It does not restart services or edit
    logs; `--dry-run` only previews where the evidence would be saved.
[ ] ./linux/splunk.sh --config "$CFG"          # is it actually shipping?
    then: sudo ./linux/splunk.sh --config "$CFG" --test-event --apply
    and FIND THE TOKEN IN SPLUNK. A forwarder can be running and shipping
    nothing; only the token proves delivery. Record the token and the time.
[ ] sudo ./linux/sshd.sh --config "$CFG"       # what the daemon will ACTUALLY do
    Reads drop-ins and Match blocks. sshd_config saying PermitRootLogin no
    means nothing if a file in sshd_config.d says yes.
[ ] Review the packet's scored users, ports, and firewall exceptions.
[ ] sudo ./linux/surface.sh --config "$CFG"    # every port, with an owner
[ ] `sudo ./linux/services.sh --config "$CFG" --review` — for everything harden.sh
    had no opinion about. It disables only the list you write yourself.
[ ] Apply one change at a time with --dry-run first.
[ ] Verify the scored service after every change.
[ ] Run recon.sh again and note the evidence path in the incident report.
[ ] From here on, the question is `--status`, and it is the one to keep asking:
        sudo ./linux/sentry.sh --config "$CFG" --status
    `watch.sh` also runs the baseline check every pass. Each finding carries
    what it will do, the command that does it, and `--explain N` for the full
    case.
```

## When you find something live

Use this when the suspicious thing is active now: a running process, a live
network connection, or an active login. `PID` below means the process ID shown
by `triage.sh` or `ps`.

```text
[ ] DO NOT KILL IT YET.
[ ] sudo ./linux/preserve.sh --config "$CFG" --pid <PID> --freeze --apply
    Stops it, then takes the socket, the parent chain, the open files, and a
    copy of the binary recovered through /proc (which works even when the file
    was deleted). All of that is gone the moment you kill it.
[ ] Read 00-CASE.txt. It gives you the short incident-report summary.
[ ] Open ancestry.txt to see what started it. If it says `ppid 1`, the original
    parent already exited. That usually means a service, timer, or cron job
    started it. Check CARD 3 and CARD 4 before killing it, or it may return.
[ ] Then: kill -9 <PID>, and re-run triage to confirm the finding CLEARS.
```

## The three questions nothing else on the box answers

```text
[ ] sudo ./linux/triage.sh --config "$CFG"   who owns each network connection?
    Example: port 443 may be allowed for HTTPS, but `bash` connected to an
    outside address on port 443 is not a web server. The owner matters, not
    just the port number.
[ ] sudo ./linux/audit.sh --config "$CFG"    can this box still prove anything?
[ ]      ./linux/splunk.sh --config "$CFG"   are the logs leaving the box?
```
