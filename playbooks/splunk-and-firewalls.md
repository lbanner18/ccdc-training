# Splunk and firewalls: the 2am reference

This is the short version for a competition round. It does not assume that
every team has the same Splunk add-ons, index names, or firewall manager.

The rule for both jobs is simple: **make one small, explainable change, then
prove the scored service and your own access still work from outside the box.**

## Splunk: start with one event, then ask a better question

Splunk stores each log line or event with a timestamp. The three labels that
usually help you narrow it down are:

| label | plain-English meaning | example |
|---|---|---|
| `host` | which machine sent it | `web-01` |
| `source` | which file or channel it came from | `WinEventLog:Security` |
| `sourcetype` | Splunk's guess about the event format | `WinEventLog:Security` or `syslog` |

Do not begin by pasting `index=main` from somebody else's guide. Open an event
from the machine you care about and look at its `host`, `source`,
`sourcetype`, and index. Use those real values in the searches below.

The working pattern is:

1. Pick a short, **absolute** time window: for example, 13:00 through 14:00.
   Do this before a broad search. "Last 24 hours" is how you hide the one
   minute that matters in noise.
2. Narrow to the affected machine with `host="the-real-host-name"`.
3. Search for one behavior: failed logins, a new user, a service install, or
   the suspicious IP. Read a few raw events before trusting a field name.
4. Use a pipe (`|`) only after the events look right. `table` makes a readable
   list; `stats` counts/group things; `timechart` shows whether an event rate
   spiked.

### Safe starter searches

Replace the quoted values with what you saw in Splunk. Field names vary with
the Windows add-on and source, so if `EventCode`, `user`, or `src_ip` is blank,
click a raw event and use the field name Splunk actually shows you.

```spl
index=* host="WINDOWS-HOST" earliest=-60m
(EventCode=4624 OR EventCode=4625 OR EventCode=4672 OR EventCode=4720 OR
 EventCode=4728 OR EventCode=4732 OR EventCode=4697 OR EventCode=4698 OR
 EventCode=4702 OR EventCode=1102)
| table _time host EventCode user src_ip source
```

That is a compact Windows timeline: successful/failed logons, special admin
logons, account or group changes, service/task changes, and a cleared Security
log. It is a lead, not proof by itself. Open the raw event to see who did what.

```spl
index=* host="LINUX-HOST" earliest=-60m
("Failed password" OR "Accepted password" OR sudo OR sshd)
| table _time host source _raw
```

That is the Linux equivalent when you do not yet know the field extractions.
It deliberately keeps `_raw`, the original event text, visible.

```spl
index=* earliest=-60m "10.0.0.8"
| stats count by host source sourcetype
| sort - count
```

Use this after you find a suspicious address. It answers, "Which boxes and log
sources have seen it?" before you try to block it.

```spl
index=* host="WINDOWS-HOST" earliest=-60m EventCode=4625
| stats count by user src_ip
| sort - count
```

This turns many failed Windows logons into a short list. A high count from one
address may be a password spray; it can also be a broken service using an old
password. Check before blocking it.

```spl
index=* host="THE-HOST" earliest=-60m
| timechart span=5m count
```

This is a simple "when did activity jump?" chart. Click the spike, then search
that smaller time range for the actual events.

### Habits that prevent bad searches

- Start narrow: a known host and a short time range beat a giant search.
- Search exact values before reaching for wildcards or regular expressions.
  `"powershell.exe"` is easier to explain and cheaper to run than a giant
  wildcard search.
- Do not use a real-time search as your default. A scheduled search over a
  defined time range is easier on Splunk and leaves a repeatable record.
- When you find something important, write down the event time, host, user,
  source address, query, and the raw-event text or screenshot. That is the
  evidence for the inject, not just a hunch.
- Prove forwarding once per box. On Linux,
  `sudo ./linux/splunk.sh --config "$CFG" --test-event --apply`; on Windows,
  `.\windows\splunk.ps1 -Config CONFIG -TestEvent -Apply`. Each writes a
  tagged test event and prints the search for that exact token. Finding the
  token in Splunk proves delivery; a green local service alone does not.
- Building the indexer and forwarders yourself? Follow
  [`splunk-setup.md`](splunk-setup.md): every command in it was run in the lab,
  with the traps that silently ship nothing.

Splunk's own documentation covers indexed-field searches and time bounds,
fields such as `host`, `source`, and `sourcetype`, and the basic SPL commands:
[search command usage](https://docs.splunk.com/Documentation/SCS/latest/SearchReference/SearchCommandUsage),
[about fields](https://docs.splunk.com/Documentation/SplunkCloud/latest/Knowledge/Aboutfields),
and the [SPL tutorial](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchTutorial/Usethesearchlanguage).

## Firewalls: do not confuse "closed" with "safe"

For the firewall *appliance* itself (VyOS, pfSense, OPNsense, Cisco, Palo
Alto): default logins, how each one undoes a change, and the order of work are
in [`firewall-appliance.md`](firewall-appliance.md).

For the firewall *appliance* itself (VyOS, pfSense, OPNsense, Cisco, Palo
Alto): default logins, how each one undoes a change, and the order of work are
in [`firewall-appliance.md`](firewall-appliance.md).

A firewall rule is a traffic decision. Before you make one, be able to answer
all seven of these questions:

| question | example answer |
|---|---|
| What is the service? | the scored web site |
| Who must reach it? | scorer and users on the competition subnet |
| What protocol and port? | TCP 443 |
| Which direction? | inbound to this server |
| How will I still administer it? | WinRM/RDP/SSH from the team workstation |
| How will I test it? | a fresh connection from the workstation, plus the scored check |
| How do I undo it? | a saved rule set or the Linux timed rollback |

Make a small table from the packet before you apply rules. If a row is blank,
that is a reason to investigate, not a reason to guess.

| service or need | source allowed | destination/port | decision | proof after change |
|---|---|---|---|---|
| team administration | team workstation subnet | TCP 22 / 3389 / 5985 as applicable | allow | open a **new** session |
| scored web service | scorer subnet or required users | TCP 80 or 443 | allow | scorer-style HTTP request |
| unknown listener | nobody until identified | its port | investigate first | owner/process + packet check |

### The safe order

1. Record the current rules and listeners. On Linux, `sudo ss -lntup` shows
   what is listening; `sudo nft list ruleset` shows nftables rules if nftables
   is in use. On Windows,
   `Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked`
   shows the profile defaults.
2. Keep your management path and every packet-required/scored port first.
   Existing terminal sessions can survive a rule that prevents **new** sessions,
   so test from a second terminal or workstation.
3. Apply one policy change.
4. Test from off the box: your fresh admin connection and the scored service.
5. Keep or undo the change. Then record what you changed and why.

For Linux, `./linux/fw.sh --config "$CFG"` is a dry-run by default. Its
`--apply` path snapshots the old rules and starts a timed rollback; only run
`sudo ./linux/fw.sh --config "$CFG" --confirm` after a **new** connection and
the scorer-style check work. `--rollback` restores immediately if they do not.

For Windows, first inspect the plan:

```powershell
.\windows\harden.ps1 -Config CONFIG -Only Firewall
```

Then apply only after the packet/config has the correct scored ports and you
know how you will get back in:

```powershell
.\windows\harden.ps1 -Config CONFIG -Only Firewall -Apply
```

The kit enables the profiles, blocks inbound traffic by default, leaves
outbound traffic allowed, logs blocked traffic, and makes explicit allow rules
for your configured management and scored ports. It intentionally does not
make an outbound deny-all policy: that often breaks DNS, package updates,
logging, and services before you can find every dependency.

### Things that look tempting and cause outages

- "Block every open port." A listening port could be a scored service, the
  scorer's management path, or your own way back in. Identify its owner first.
- "Deny all outbound traffic." This may stop command-and-control, but it can
  also stop name lookup, Windows updates, Splunk forwarding, databases, and
  external dependencies. Do it only when the packet and tests make the needed
  outbound paths explicit.
- "Trust localhost." A local `curl` can work while a firewall has cut off the
  scorer. Test from the actual scorer-side network when possible.
- "Turn off logging to reduce noise." Dropped-packet logs are often how you
  discover that a rule blocked a needed service or that somebody is probing
  you.

NIST's firewall guidance recommends managed policy changes, rules that are
documented and commented, restricted firewall administration, and logging of
ruleset/policy changes. That is why this process is deliberately boring and
written down: [NIST SP 800-41, Guidelines on Firewalls and Firewall Policy](https://www.nist.gov/publications/guidelines-firewalls-and-firewall-policy).

## The one-minute loop

When you are tired, use this loop instead of improvising:

1. See it in Splunk or on the box.
2. Identify the host, user/process, time, and whether the packet permits it.
3. Preserve the event/evidence.
4. Make one reversible change.
5. Test admin access and scored service from outside.
6. Search again to confirm the behavior stopped or changed.

If you cannot name the rollback and the test before applying the rule, stop and
ask the team. That is not hesitation; it is how you avoid an own-goal.
