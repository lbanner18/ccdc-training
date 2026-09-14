# Linux first 15 minutes

Use the team packet to fill the bracketed values before competition day.

```text
[ ] Confirm host, console/SSH access, and current time.
[ ] Take a VM snapshot if the environment permits it.
[ ] Get the kit on the box: bootstrap-on-the-box.md (STEP 1 probe).
[ ] Copy the kit and local config; do not paste secrets into chat.
[ ] sudo ./linux/triage.sh --config <cfg>   # ranked: what is ALREADY wrong
    Each finding names a card in playbooks/remediation-cards.md
[ ] Run recon.sh and save the evidence path.
[ ] Run hunt.sh and review persistence, keys, sudoers, and listening ports.
[ ] Check scored services from the outside, not only systemctl status.
[ ] Set CCDC_WATCHDOG_INTERVAL="5" and point CCDC_HTTP_CHECKS at the address
    the SCORER uses, not 127.0.0.1.
[ ] sudo ./linux/arm.sh --config <cfg> --apply
    -> backup + canaries + guardian, and guardian starts the watchdog.
       Never run watchdog.sh by hand; it dies with your SSH session.
[ ] Start the detection loop: ./linux/watch.sh --config <cfg> --interval 120
[ ] Check Splunk forwarding and record the result.
[ ] Review the packet's scored users, ports, and firewall exceptions.
[ ] ./linux/services.sh --config <cfg> --review, then disable deliberately.
[ ] Apply one change at a time with --dry-run first.
[ ] Verify the scored service after every change.
[ ] Run recon.sh again and note the evidence path in the incident report.
```

