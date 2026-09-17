# Draft: External Perimeter Assessment (EVAL04T)

**Deliverable beyond the memo:** screenshots of the command lines and their
output, plus a table of host → service → "should this be exposed?" The table is
the graded artifact.

**The host half of that table generates itself, per box:**

```bash
CFG=/tmp/ccdc-linux.env  # change if this box's filled config is elsewhere
sudo ./linux/surface.sh --config "$CFG" --table
```

Every listening port with its process, systemd unit, owning package, and a
verdict (scored / local only / REVIEW) taken from the packet values in your
config. Run it on each box and paste the rows in. It reads local state only -
the external scan the inject asks for still has to come from the workstation
it names.

**Scope discipline:** run this only from the workstation the inject names,
against only the range the inject names. Scanning outside your assigned network
is the one thing in CCDC that gets a team disqualified rather than penalized.

**The external evidence path, on that workstation:**

```bash
CFG=/tmp/ccdc-linux.env  # filled from the packet, including CCDC_PERIMETER_SCOPE
./workstation/perimeter.sh --config "$CFG" --plan
./workstation/perimeter.sh --config "$CFG" --tcp --apply --confirm-scope
# Copy the .gnmap path printed above into this command:
./workstation/perimeter.sh --config "$CFG" --report /tmp/ccdc-perimeter/SCAN.gnmap
```

The TCP scan is a conservative `nmap` connect scan capped at 1,000 packets per
second; its exact command and normal/XML/grepable outputs are saved and hashed.
The report joins observed ports to `CCDC_ALLOWED_TCP_PORTS`, producing the
yes/REVIEW column for the memo. Run the optional UDP pass only when the inject
requires it: `sudo ./workstation/perimeter.sh --config "$CFG" --udp --apply --confirm-scope`.

---

```text
INTEROFFICE MEMORANDUM

To:      <ROLE THE INJECT CAME FROM>
From:    Team <XX>
Date:    <DATE>
Subject: External Perimeter Assessment

Summary: We were asked to assess what our network exposes to the outside world
         and to report which of those services should be reachable. We scanned
         our assigned external range from the external workstation, identified
         <N> reachable services across <N> hosts, and recommend closing <N> of
         them. Details and evidence are below.

1. Method

   We followed the approach in NIST Special Publication 800-115, Technical
   Guide to Information Security Testing and Assessment
   (https://csrc.nist.gov/pubs/sp/800/115/final), working from broad
   discovery to specific identification:

   a. A fast sweep of the full assigned range to find which addresses respond
      and which ports are open.
   b. A slower, detailed scan of only the responding hosts, to identify what
      software and version is behind each open port.
   c. A separate scan of the most commonly used UDP ports, which the first
      two steps do not cover.

   All scanning was performed from the designated external workstation
   against only our own assigned address range, during <TIME WINDOW>.

2. Commands used

   Step 1, conservative TCP reachability and version scan:
     <PASTE THE SAVED COMMAND FROM perimeter.sh HERE>

   Step 2, optional UDP scan if the inject requires it:
     <PASTE THE SAVED COMMAND FROM perimeter.sh HERE>

   Screenshots of each command and its output are attached.

3. What is exposed

   | Host | Address | OS | Port | Service and version | Should this be exposed? | Reasoning |
   |------|---------|----|------|--------------------|------------------------|-----------|
   | <NAME> | <IP> | <OS> | 443/tcp | <SOFTWARE> | Yes | Public web service; this is the business |
   | <NAME> | <IP> | <OS> | 22/tcp | OpenSSH <VER> | No | Administrative access; should be reachable only from the internal administrative network |
   | <NAME> | <IP> | <OS> | 3389/tcp | RDP | No | Remote desktop exposed to the internet; highest-risk finding |
   | <NAME> | <IP> | <OS> | 3306/tcp | MySQL <VER> | No | Database should never be directly reachable from outside |

4. Findings, most serious first

   a. <REMOTE ADMINISTRATION EXPOSED TO THE INTERNET>. Remote desktop and SSH
      reachable from anywhere means every password on those systems is exposed
      to continuous guessing from the internet. This is the finding we would
      fix first.
   b. <DATABASE OR MANAGEMENT INTERFACE EXPOSED>. These services are designed
      to be reached by our own applications, not by the public. Exposure gives
      an attacker a direct path to our data without going through the
      application.
   c. <OUTDATED SOFTWARE VERSIONS>. <SOFTWARE VERSION> is <N> versions behind
      and has publicly documented vulnerabilities.
   d. <SERVICES NO ONE OWNS>. <PORT/SERVICE> is reachable and no business
      purpose for it was identified.

5. Recommendation

   The perimeter should present only the services the business sells:
   <LIST THE SCORED/PUBLIC SERVICES>. Everything else should be blocked at the
   firewall and reachable only from inside. We recommend blocking the services
   marked "No" in the table above, beginning with remote administration, and
   re-running this assessment afterward to confirm the change.

   We did not attempt to exploit any of the findings. This was an assessment
   of exposure only.

If there are any concerns, questions, or clarifications, please do not
hesitate to reach out.

With Regards,
Team <XX>
```

---

## The trap: your own scan can take a scored service down

An unconstrained scan can saturate a small competition network and knock over
the exact services you are being scored on. You lose uptime points for the
duration, and the cause looks like a red team action.

- Keep the wrapper's 1,000-packet TCP and 100-packet UDP caps. There is no
  prize for finishing the sweep faster.
- Do not run the sweep during a period when you are already firefighting a
  service — you will not be able to tell your scan from an attack.
- Tell your team before you start. On a real team, a scan nobody announced gets
  investigated as an incident, and that wastes two people.

## Other notes

- **Scope is a disqualification risk, not a points risk.** NCCDC rules state
  that offensive activity against anything outside the team's assigned network
  means immediate disqualification. Read the range off the inject, type it
  carefully, and screenshot the command so your scope is on the record.
- **UDP is slow and the clock is real.** `--top-ports 100` is the compromise
  the inject expects; a full 65535-port UDP scan will not finish.
- **Screenshot the command line, not just the results.** The inject asks for
  both, and the command line is what proves the scope was correct.
- **The "should this be exposed?" column is the actual deliverable.** A port
  list with no judgment in it is an nmap output, not an assessment. Every row
  needs a yes or no and one clause of reasoning.
- **Answer from the outside.** This inject is asking what an attacker sees.
  Findings taken from `ss -tulpn` on the host are a different, inferior answer.
