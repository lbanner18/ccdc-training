# Rules and constraints, with sources

Researched 2026-09-11. Everything here is cited. Where a commonly repeated
claim turned out to be unsupported, it is marked as such rather than deleted,
because the claim will come up again.

## 1. The BYU tryout

From the team's own tryout page (https://ccdc.byu.edu/tryouts/):

| | |
|---|---|
| Date | **September 26, 2026**, 9am-5pm, Tanner Building room 3405 |
| Competition window | 10:00 AM - 4:00 PM, lunch at noon |
| Sign-up deadline | **September 24, 2026** |
| Format | **Individual.** Each person is a "team" of one |
| Environment | Four VMs: one Linux, one Windows, a Splunk indexer, a firewall |
| Uptime scoring | Services on the **Linux and Windows** boxes |
| Scoring split | **"Points will be split evenly between the defense competition and the injects"** |
| Slots | At least 4 alternate slots and 1 full team member slot |
| Prerequisites | None. No cybersecurity experience or major required |

The full team is 12 students (https://ccdc.byu.edu/about/).

**The scoring split is the single most useful fact here.** Injects are half the
score, confirmed by the organizers rather than inferred. An hour spent on the
inject drafts in `../injects/responses/` is worth the same as an hour spent
keeping a service alive, and it is far more predictable.

The team's page also links its own recommended reading: mubix's *How to Win
CCDC* (https://howtowinccdc.com/) and Akshay Rohatgi's write-up
(https://akshayrohatgi.com/blog/posts/How-To-Win-CCDC/).

## 2. Team-written tools must be public three months in advance

**This constrains this repository directly.**

National CCDC rule 5.6 (https://www.nationalccdc.org/rules.html):

> Scripts, executables, tools, and programs written by active team members may
> be used in CCDC events provided:
>
> **5.6.1** The scripts, executables, tools, and programs have been published
> as a publicly available resource on a public and non-university affiliated
> site such as GitHub or SourceForge **for at least 3 months prior to their
> use** in any CCDC event.
>
> **5.6.2** Team written tools [...] must be declared to competition officials
> prior to their use [...] Teams must consent to the distribution of the
> submitted links and descriptions to **all other teams** competing in the same
> CCDC event.

Submitted repositories must also be **frozen at time of submission**, with no
further modification unless officials permit it.

Consequences for this kit:

- The plan of "private now, public on competition day" **does not satisfy 5.6.1
  for any real CCDC event**. Publication starts a three-month clock; it is not
  a same-day disclosure.
- The BYU tryout is an internal BYU event and its published rules say nothing
  about pre-written tooling, so this does not obviously bind the September 26
  tryout. It binds the regional that the tryout feeds.
- Therefore: if this kit is ever meant to be used at a regional, **it must go
  public roughly three months before that regional**, and then stop changing.
  Working backwards from a spring regional, the publication deadline is in the
  winter, not the spring.
- "Frozen" also means the useful work is the work done *before* the freeze.

## 2b. Getting the kit onto the box: what the rules allow

Researched 2026-09-13 against https://www.nationalccdc.org/rules.html.

**Rule 8.1 — removable media is banned:**

> No memory sticks, flash drives, removable drives, CDROMs, electronic media,
> or other similar electronic devices are allowed in the room during the
> competition unless specifically authorized by the Operations or White Team in
> advance.

So a USB fallback is not a fallback. Delivery has to be network-based.

**Rule 5.1 — public internet resources are valid:**

> Internet resources such as FAQs, how-to's, existing forums and responses, and
> company websites, are completely valid for competition use provided there is
> no fee required to access those resources [...]

**Rule 5.2 — but nothing private:**

> Teams may not use any external, private electronic staging area or FTP site
> for patches, software, etc. during the competition [...] All Internet
> resources used during the competition must be freely available to all other
> teams.

This is the rule that makes the plan work. A **public** GitHub repo is freely
available to all other teams; a private repo or a personal server would be a
prohibited private staging area. Publishing this repo therefore does two jobs:
it starts the 5.6.1 three-month clock, *and* it makes cloning it mid-event
legitimate under 5.2.

**The 5.6 clause that looks contradictory.** Rule 5.6 also prohibits "team
written tools, scripts, or executables that use resources outside of the
competition environment other than simple DNS lookups." That governs what the
tools **do when they run** — no beaconing, no callbacks, which is design rule 4
of this kit — not how the operator obtains them. Acquisition is 5.1/5.2;
runtime behaviour is 5.6.

**Consequences for delivery**, in `playbooks/bootstrap-on-the-box.md`:

- Egress available -> `git clone` (or `curl | tar` if git is absent).
- No egress -> push from the workstation over SSH. Needs nothing but SSH and no
  media in the room.
- Never `apt install` to bootstrap: if apt works you already had egress, and
  installing packages at minute one is a change you cannot later distinguish
  from the red team's.

**Still unconfirmed for the BYU tryout** (ask before the event): whether
competitors use their own laptops or provided workstations, whether the boxes
have outbound internet, and whether the tryout follows the national rules on
team-written tools at all. Contacts: `#team-tryouts` on the BYU Cybersecurity
Discord, or justin_giboney@byu.edu.

## 3. Does the white team penalize blue-team persistence that looks like malware?

**Unsupported by the published rules. Treat the claim as false as stated.**

Searched the national rules (https://www.nationalccdc.org/rules.html) and the
ISEAGE CDC rules (https://docs.iseage.org/rules/latest/rules/index.html). Neither
contains any rule prohibiting or penalizing blue teams for installing
persistence, backdoors, or tooling on their own systems that resembles malware.
No such rule was found.

What the rules **do** say, which is what the claim is probably a distortion of:

- **Destructive self-defense is banned.** Tools "that deliberately break
  expected functionality and operations of team systems" are prohibited - the
  examples given are setting all Linux user shells to `/bin/false` and
  indiscriminately killing outbound connections. So the line is not "looks
  malicious," it is "breaks the system you are supposed to be running."
- **Offensive action is disqualifying.** "Any team performing offensive
  activity against any system outside the team's assigned network(s) will be
  immediately disqualified." Anything that reaches toward the red team is the
  real hazard, not anything on your own box.
- **Tools may not phone home.** Tools "that use resources outside of the
  competition environment other than simple DNS lookups are prohibited" - which
  does rule out a beacon-style watchdog with an external callback.
- **White team discretion is broad and explicitly open-ended.** ISEAGE states
  penalties "MAY be assigned for any reason, and for any amount, again at White
  Teams discretion." So while no rule names this, an official *can* penalize
  anything they judge to be against the spirit of the event.

**Practical conclusion:** you will not be penalized under a named rule for
defensive automation on your own hosts. You can be penalized under discretion,
and you can lose points by breaking your own scored service. Keep defensive
tooling legible - real names, real paths, logged actions, no hiding - because
the cost of legibility is zero and the cost of being misread is discretionary.

## 4. Do real blue teams rename or hide their own processes?

**The public guidance says no, and says to do the opposite.**

The most detailed public write-up from a CCDC red teamer
(https://www.winterknight.net/how-to-win-ccdc-red-team/) is entirely about
detecting red team artifacts and does not recommend concealing blue team
activity anywhere. Its named priorities are the unglamorous ones:

> "There are 3 primary things that need to be done to mitigate the worst of our
> attacks. 1. Change default credentials 2. Set up strong firewall rules
> 3. Mitigate exploitable vulnerabilities"

and on attack surface:

> "We shouldn't see anything that isn't a scored service on our nmap scans, yet
> every year we do."

The tradeoff argument against hiding your own tooling, which is the actual
answer to the question:

1. **You have to find things by looking normal yourself.** Detection works by
   spotting what does not belong. A team that hides its own processes has
   poisoned the signal it depends on - every hunt result now needs "is this
   ours?" resolved first, under time pressure, by someone who may not have
   written it.
2. **Teammates are the first casualty.** In an individual tryout this cost is
   hidden. On a team, a disguised watchdog gets killed by whoever is doing
   incident response, or worse, gets investigated for twenty minutes.
3. **It competes with the work that scores.** Every minute on concealment is a
   minute not spent on credentials, egress filtering, or an inject worth half
   the score.
4. **Legible automation is not a weakness.** The red team already knows you
   have a watchdog; watching a service come back is not a secret. What actually
   stops them is not being able to reach the box.

The one technique in this space that is genuinely endorsed is **active defense
in the John Strand sense** - canary tokens, deliberate traps, redirected
services - which is cited approvingly in the same write-up as something that
"slow[s] us down immensely." That is decoys the attacker trips over, not
disguises on your own tools. Different thing, and the legitimate version.

## 5. Penalty structure worth knowing

From mubix's *How to Win CCDC* (https://howtowinccdc.com/) and the national
rules:

- Compromise penalties scale with depth: user-level is minor, root/admin is
  major, and PII/PHI exfiltration is the largest single category at nationals.
- Asking for a system to be restored costs points, and the cost escalates with
  each request.
- Communications blackout violations - phones, outside help, coaches in the
  competition space - are disqualifying, not point penalties.
- Blocking the scoring engine costs exactly as much as the service being down,
  and it is self-inflicted. Verify scored services from the network after every
  firewall change.
