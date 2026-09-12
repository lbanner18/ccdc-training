# What the competition environment actually looks like

Drawn from graded team responses in the training material. This is much larger
and more heterogeneous than the four-VM tryout, and it changes what the kit
has to survive.

## Hosts seen in real competition responses

One team's audit covered **eleven hosts**; another's login-banner inject listed
**seven**. Operating systems named across them:

- Ubuntu 22.04, Ubuntu (e-commerce), Ubuntu workstation
- Fedora (webmail), Rocky Linux (x2), CentOS 8
- **Alpine Linux**
- Windows Server 2019 (web, domain controller), Windows Server 2022 (FTP)
- Windows 10, Windows 11 (x2)
- A Splunk indexer

## What that means for this kit

**Alpine is the portability test that matters.** Alpine has no bash by default,
no GNU coreutils, and busybox versions of `find`, `awk`, and `ps` that do not
accept every flag used here. `#!/usr/bin/env bash` fails outright if bash is not
installed. Before competition, every script needs a run under `busybox sh`.

**Red Hat family means a different firewall and SELinux.** Rocky, CentOS, and
Fedora default to `firewalld` over nftables, and SELinux is enforcing. A
service that starts fine and still refuses connections is usually SELinux, not
your firewall rule. `rpm -Va` replaces `dpkg --verify`; `hunt.sh` already
handles both.

**Package managers differ per box:** `apt`, `dnf`/`yum`, and `apk`. Any inject
answered with "install this tool on every server" needs three command forms.

**Most boxes are Windows.** Roughly two thirds of the hosts in these responses
run Windows, including a domain controller. Linux-only preparation covers a
minority of the environment.

## Deliverable patterns worth pre-building

- Enumeration injects want **a table**: IP, hostname, OS, finding, ports.
  Build the table generator, not the prose.
- Procedure injects want a **cited public framework**, not invention. One
  graded response followed the SANS incident-response cycle and linked it.
  That citation is why the answer reads as authoritative.
- Response length is about **one page**. Depth beyond that is not what scores.
