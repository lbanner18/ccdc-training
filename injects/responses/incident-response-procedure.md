# Draft: Write an Incident Response Procedure (SCEN20T(E))

**Deliverable:** memo only. That makes this the cheapest inject on the board
and the one most worth pre-writing. The catalog note applies directly here —
graded answers score by following a public framework and linking it.

---

```text
INTEROFFICE MEMORANDUM

To:      <ROLE THE INJECT CAME FROM>
From:    Team <XX>
Date:    <DATE>
Subject: Write an Incident Response Procedure

Summary: Following the <EVENT DESCRIBED IN THE INJECT>, we were asked to turn
         that response into a written procedure the company can reuse. The
         procedure below follows the six-phase incident handling process
         published by the SANS Institute and aligns our reporting with NIST
         guidance. It applies to any suspected compromise, not only malware.

Basis for this procedure

   We did not invent a process. This follows the SANS Institute incident
   handling model - Preparation, Identification, Containment, Eradication,
   Recovery, Lessons Learned - set out in Patrick Kral's "Incident Handler's
   Handbook" (https://www.sans.org/white-papers/33901), which is the most
   widely taught public framework. It is written to be consistent
   with NIST Special Publication 800-61 Revision 3, Incident Response
   Recommendations and Considerations for Cybersecurity Risk Management
   (https://csrc.nist.gov/news/2025/nist-revises-sp-800-61), which places
   incident response inside the organization's ongoing risk management rather
   than treating it as a one-time event.

1. Preparation (before anything happens)

   - Maintain a current list of systems, the services each one provides, and
     who is responsible for it.
   - Keep verified backups and confirm they can actually be restored.
   - Centralize logs so evidence survives the loss of the affected machine.
   - Keep a contact list: who declares an incident, who speaks to customers,
     who may authorize taking a service offline.
   - Keep a known-good baseline of each system so "different from normal" is
     a question we can answer.

2. Identification (deciding this is an incident)

   - Any employee may report a suspicion. Reporting is never penalized.
   - The handler confirms whether the event is an incident, records the time,
     and assigns a severity based on what is affected and whether the
     business service is degraded.
   - Evidence collection begins here: logs, running processes, network
     connections, and file changes are captured before anything is altered.
   - From this point every action is written down with the time it was taken.

3. Containment (stopping the spread without destroying the evidence)

   - Short term: isolate the affected system from the network, disable the
     compromised accounts, and block the attacker's access path.
   - Preserve state first where possible. A snapshot taken before cleanup is
     the only chance to understand what happened.
   - Long term: apply temporary controls so the business can keep operating
     while a permanent fix is prepared.

4. Eradication (removing the attacker)

   - Remove the malicious software and, more importantly, every method the
     attacker left behind to get back in: added accounts, scheduled tasks,
     startup entries, service definitions, and authorized keys.
   - Identify how the attacker got in and close that path, or the same
     incident repeats within hours.
   - Where the extent of the compromise cannot be established, rebuild the
     system from known-good media rather than cleaning it.

5. Recovery (returning to service)

   - Restore service and confirm it works from the customer's position, not
     only from the server.
   - Monitor the recovered system more closely than normal for a defined
     period, specifically watching for the attacker's return.
   - Confirm with the business owner before declaring the incident closed.

6. Lessons learned (the part usually skipped)

   - Within two weeks, hold a review that answers: what happened, how we
     found out, what slowed us down, and what change would have prevented or
     shortened it.
   - Produce a short written report and a list of owned, dated follow-up
     actions.
   - Update this procedure with what was learned. A procedure that is never
     revised is a procedure no one used.

Roles

   | Role | Responsibility |
   |------|----------------|
   | Incident handler | Runs the response, records the timeline, decides phase transitions |
   | System owner | Executes changes on the affected system |
   | Communications lead | Updates management and customers; sole external voice |
   | Management | Authorizes service outage and, if needed, law enforcement contact |

Reporting

   Every incident produces a written report containing the timeline, the
   systems affected, what the attacker did, what was done in response, and
   the follow-up actions. Reports are retained and reviewed for patterns.

If there are any concerns, questions, or clarifications, please do not
hesitate to reach out.

With Regards,
Team <XX>
```

---

## Notes before you send this

- **Tie it to the inject's event in the Summary line.** The inject hands you a
  specific malware event; a procedure that never mentions it reads as
  pre-written, which it is. One clause naming the event fixes that.
- **Keep both URLs.** The SANS link is the spine of the procedure; the NIST
  link shows you know the current federal guidance. NIST withdrew SP 800-61
  Revision 2 in April 2025 — citing r2 dates the memo.
- **Do not add commands.** The reader is an IT Director. "Capture running
  processes and network connections" belongs in the memo; `ss -tulpn` does not.
- **If the inject asks for the incident report too**, use
  [`../incident-report-template.md`](../incident-report-template.md) — that is
  the artifact, this is the procedure, and they are different deliverables.
