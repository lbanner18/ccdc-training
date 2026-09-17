# Draft: Unnecessary Software / Configuration Audit

**Deliverable beyond the memo:** a report naming, for each thing removed, **where
it lived, what it was listening on, and how it was removed.** That is a table,
and `harden.sh --table` emits it already filled in — this inject is a rendering
job, not a research job, provided you run the audit before you are asked for it.

**The mechanical part:**

```bash
CFG=/tmp/ccdc-linux.env
sudo ./linux/harden.sh --config "$CFG"                    # read it first
sudo ./linux/harden.sh --config "$CFG" --explain N        # anything you doubt
sudo ./linux/harden.sh --config "$CFG" --cut all-safe --apply
sudo ./linux/harden.sh --config "$CFG" --table            # the inject table
```

Run `--table` **after** the cut, not before: the "how it was removed" column
reads the ledger, and before the cut there is nothing in it.

Two things to say out loud in the memo, because a grader who knows Linux will
look for them:

- **Removal, not just disabling.** A disabled unit is one `systemctl enable`
  away from returning, and the person most likely to type that is whoever
  already has root on the box. Say that you purged.
- **Reversibility.** Purging on a network that cannot reach a mirror is a
  one-way door, so each package's `.deb` is cached to the evidence directory
  before removal and the restore is `dpkg -i` from that cache with no network.
  This is the sentence that turns "they deleted things" into "they managed a
  change."

---

```text
INTEROFFICE MEMORANDUM

To:      <ROLE THE INJECT CAME FROM>
From:    Team <XX>
Date:    <DATE>
Subject: Unnecessary Software and Configuration Audit

Summary: We were asked to review our environment for software and
         configuration that serves no business purpose, remove it, and
         report what was removed. <N> items were identified across <M>
         systems and removed. <K> further items were identified but NOT
         removed, because removing them requires a decision that belongs
         with you rather than with us; they are listed separately below
         with the question each one turns on.

1. How we decided what was unnecessary

   We did not work from a list of known-bad software, because that only
   ever finds the things somebody thought of in advance. We worked from
   the opposite direction: we established what each system must run in
   order to deliver the services it is scored on, computed everything
   those services depend on, and treated the remainder as a candidate for
   removal.

   Three categories were never candidates, and we want to be explicit that
   they were considered and kept rather than overlooked:

   a. The scored services themselves and everything in their dependency
      chain.
   b. The services that keep a system administrable and auditable - remote
      access, logging, auditing, the firewall, and time synchronisation.
      Losing these does not reduce risk, it reduces our ability to see and
      answer it.
   c. Anything whose necessity depends on facts about our infrastructure
      that are not visible from the host itself. These are in section 3.

2. What was removed

   For each item: where it lived, what it was listening on, and how it was
   removed.

   <PASTE THE OUTPUT OF `harden.sh --table` HERE>

   Every removal was followed immediately by a check that the scored
   services on that host still answered on their ports. Any removal that
   coincided with a service failing that check was reversed automatically
   before the next item was processed. No scored service was interrupted
   during this work.

3. What we found but did not remove

   These reduce attack surface if removed and cost us something real if
   removed wrongly. Each needs a decision from you.

   a. VMware guest tools (open-vm-tools, vgauth). These provide the
      hypervisor's console access, graceful shutdown, and a
      guest-operations channel that can execute commands inside the
      virtual machine. That channel is genuine attack surface. It is also
      how your infrastructure team may reach these machines. The question
      is whether console access to these VMs goes through the hypervisor.
      If it does, we keep them.

   b. Automatic security updates (unattended-upgrades). This closes
      vulnerabilities without anyone doing anything, which is worth a
      great deal. It also restarts services on a schedule we do not
      choose, and an unplanned restart of a customer-facing service is an
      outage. Our recommendation is to keep the package, disable the
      automatic restart, and apply updates on a maintenance window.

   c. Diagnostic network tooling (tcpdump, netcat). These are the tools an
      intruder reaches for, and they are also the tools we use to
      demonstrate that a service is reachable and to capture evidence
      during an incident. Removing them hardens the host and blinds the
      people responding to it. We recommend retaining them and restricting
      execution to administrators.

4. Configuration, as distinct from software

   The inject asks about configuration as well as applications, and the
   two fail differently. Removing an application removes its code;
   removing a configuration file can silently restore a default that is
   less safe than what it replaced. We therefore treated configuration as
   report-first:

   a. Cloud-init was removed from hosts that are not re-provisioned. It
      re-runs on every boot and re-applies accounts and SSH keys from a
      local directory, which means an account removed during an incident
      returns after the next reboot with nothing in the logs to explain
      it. This is a persistence mechanism as much as it is surface.

   b. On-demand installers were removed. One socket unit on these systems
      existed to install a container runtime the moment anyone typed a
      particular command. A mistyped command should not be able to
      install software.

   c. Kernel-parameter drop-ins were reviewed individually rather than
      removed in bulk, because our own hardening and an attacker's
      changes take exactly the same form - an unowned file setting kernel
      parameters. Each was compared against the value the kernel is
      actually running.

5. Reversibility

   Every removal is reversible without network access. Each package was
   cached locally before it was removed, and the restore procedure is a
   single command per item, recorded at the time of removal. We did this
   specifically because a removal that can only be undone by reaching a
   package mirror is not a managed change - it is a bet that the network
   will be available at the moment we discover we were wrong.

6. What we recommend next

   a. A decision on each item in section 3.
   b. Re-running this audit after any system is rebuilt, since a fresh
      image reintroduces everything removed here.
   c. Recording the approved baseline, so that anything appearing on these
      systems afterwards is visible as a change rather than blending into
      the installed software.

Attachments: removal table (section 2); per-host restore commands.
```

---

## Where this draft can go wrong

- **`--table` before `--cut`.** The removal column comes from the ledger. Run
  the cut first or the table's last column is empty and the report reads as a
  plan rather than a result.
- **Claiming a number you did not verify.** `<N> items across <M> systems` is
  the first thing a grader can check. Count from the table, not from memory.
- **Section 3 is not padding.** An audit that removed everything and asked
  nothing reads as reckless to anyone who has run production infrastructure.
  The items you declined to remove, with the question each turns on, are the
  part that shows judgement.
- **This is the same work as the harden step**, so it is free if you did the
  hardening in the first hour and expensive if you did not. If the inject
  arrives and you have not hardened, run `harden.sh` read-only first and write
  the memo in the future tense about what you are about to do — do not cut
  fifteen things at minute 50 while a scoreboard is running.
