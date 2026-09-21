# Environment: the tryout, and the regional it feeds

**The tryout is four devices: one Linux box, one Windows box, a Splunk
indexer, and a firewall.** Uptime is scored on the Linux and Windows boxes.
That is the target to prepare against, and everything in this kit should work
there first.

This is context, not a promise that all of the systems below will appear. For
the tryout, start by securing the two scored hosts. Do not spend the first hour
building domain-controller tooling unless the packet actually says there is a
domain controller.

The larger picture below comes from graded responses to *regional*
competitions. It is not what you will see at tryouts. It is recorded because
it shows where the skills go next, and because a few of its lessons are cheap
to adopt now and expensive to retrofit later.

## Hosts seen in regional competition responses (not the tryout)

One team's audit covered **eleven hosts**; another's login-banner inject listed
**seven**. Operating systems named across them:

- Ubuntu 22.04, Ubuntu (e-commerce), Ubuntu workstation
- Fedora (webmail), Rocky Linux (x2), CentOS 8
- **Alpine Linux**
- Windows Server 2019 (web, domain controller), Windows Server 2022 (FTP)
- Windows 10, Windows 11 (x2)
- A Splunk indexer

## What to actually carry back to the tryout

Only two of these matter for a four-device tryout, and both are cheap:

1. **Portability discipline.** Even if the tryout box is Ubuntu, a script that
   assumes GNU-only flags breaks on any image that is not. The busybox pass
   costs an hour and removes a whole class of competition-day surprise.
2. **The deliverable patterns at the bottom of this file.** Inject style does
   not change between tryout and regional.

The rest is context for later.

## What the wider environment would mean for this kit

**Alpine is a useful portability test.** Alpine usually has no Bash and uses
smaller BusyBox versions of commands such as `find`, `awk`, and `ps`. A script
whose first line asks for Bash fails immediately if Bash is absent. Before a
regional, try the scripts under `busybox sh` and note which ones need a Bash
install instead of discovering it during scoring.

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
