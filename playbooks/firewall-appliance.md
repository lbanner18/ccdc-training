# The firewall appliance: first 15 minutes

The tryout's fourth device is a network firewall. The training names five
possibilities: **VyOS, pfSense, OPNsense, Cisco, Palo Alto**. The packet will
say which. This card is the order of work, which is the same on all of them,
and the handful of commands per vendor that the order needs.

> **None of the vendor commands below were run in the lab.** There is no
> firewall appliance in it. They are standard, documented commands, but check
> each one against the version in front of you. VyOS changed its firewall
> syntax between 1.3 and 1.4, and PAN-OS moves menus between releases.

`splunk-and-firewalls.md` covers the *thinking* (what to allow, and why
"block everything" causes outages). This card covers the *device*.

## The order, on any vendor

1. **Find the undo button first.** Before any change, know how this device
   reverts. It is in the table below. On a device with a timed rollback, use it
   for every change that touches your own access.
2. **Save a copy of the current config off the box.** It is your evidence of
   what was there, and your restore point if the red team changes it.
3. **Change the admin password.** Default credentials are the first thing the
   red team tries.
4. **Restrict management.** Allow the web UI and SSH only from the inside
   network or your workstation, never from outside.
5. **Read the rules before writing any.** List what is allowed now. Look for
   any-any rules, port forwards (NAT) to boxes that are not scored, and rules
   nobody can explain.
6. **Allow scored services explicitly, then tighten.** One change at a time.
   After each one, test the scored service and your own admin access from a
   **new** session.
7. **Send the firewall's logs to Splunk** (UDP 514 syslog to the indexer), so
   blocked traffic shows up where you already search.
8. **Save/commit so it survives a reboot**, then save another copy off the box.

## Per vendor

| | VyOS | pfSense | OPNsense | Cisco IOS | Palo Alto |
|---|---|---|---|---|---|
| default login | `vyos` / `vyos` | `admin` / `pfsense` | `root` / `opnsense` | set at install | `admin` / `admin` |
| managed from | SSH / console CLI | web UI | web UI | SSH / console CLI | web UI (+ CLI) |
| **timed undo** | `commit-confirm 10`, then `confirm` | none built in; use config history | none built in; use config history | `reload in 10`, then `reload cancel` | none; see below |
| undo after the fact | `rollback N` | Diagnostics → Backup & Restore → Config History | System → Configuration → History | reload without saving | Device → Setup → Operations → Revert |
| show config | `show configuration commands` | Diagnostics → Backup & Restore → download | System → Configuration → Backups → download | `show running-config` | Device → Setup → Operations → Export |
| make it stick | `save` (commit alone is lost on reboot) | automatic on Save/Apply | automatic on Apply | `copy running-config startup-config` | **Commit** (nothing applies until you do) |

### VyOS (CLI)

```
configure
set system login user vyos authentication plaintext-password 'NEW-PASSWORD'
commit-confirm 10          # reverts by itself in 10 minutes unless you...
confirm                    # ...confirm from a NEW session that still works
save
show configuration commands | match firewall     # read the rules
set system syslog host SPLUNK-IP facility all level info
```

The `commit-confirm` / `confirm` pair works like `linux/fw.sh --apply` /
`--confirm`: a change that locks you out undoes itself. Use it for every change.

### pfSense / OPNsense (web UI)

- Change the password: System → User Manager → admin.
- Management: System → Advanced → Admin Access (pfSense) or System → Settings →
  Administration (OPNsense). Keep the web UI on LAN only. Leave the
  anti-lockout rule on until your own allow rule is proven.
- Rules are **per interface, inbound, first match wins**. Read the WAN tab for
  anything allowed in from outside, and Firewall → NAT → Port Forward for
  anything forwarded to an inside box.
- Logs to Splunk: Status → System Logs → Settings → Remote Logging (pfSense);
  System → Settings → Logging → Remote (OPNsense).
- If you lock yourself out of the web UI: the console menu has "Reset
  webConfigurator password" and "Restore recent configuration".

### Cisco IOS (CLI)

```
enable
reload in 10               # safety net: reboots into the SAVED config in 10 min
configure terminal
enable secret NEW-SECRET
line vty 0 4
 transport input ssh
end
show running-config        # read every access-list and ip nat line
reload cancel              # only after a NEW session proves access still works
copy running-config startup-config
```

`logging host SPLUNK-IP` sends syslog to the indexer.

### Palo Alto (web UI)

- Nothing you change takes effect until **Commit** (top right). Until then it
  is a candidate config, and Config → Revert Changes throws it away.
- Save a snapshot before committing anything: Device → Setup → Operations →
  Save named configuration snapshot, then Export it off the box.
- Password: Device → Administrators. Management access: Device → Setup →
  Interfaces → Management → Permitted IP Addresses.
- Rules: Policies → Security, top down. Check the two default rules at the
  bottom: intrazone is allowed and interzone is denied by default.
- Logs to Splunk: Device → Server Profiles → Syslog, then attach that profile
  to the rules' Log Forwarding.

## What to write down (it is inject material)

The config you found (the saved copy), each change with its time and reason,
and the test that proved the scored service still worked afterwards. "Blocked
inbound 4444 at 14:10 after Splunk showed a connection from 10.0.0.9; scored
HTTP verified at 14:11" is a complete incident-report line.
