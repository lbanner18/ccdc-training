# Inject catalog — what has actually been asked

Notes taken from the team's training material. Summaries only: the prompts and
the team's example responses are course material and stay out of this repo.

Two distinct styles show up, and they read differently:

1. **Official CCDC form** — a table of `Inject Name / Inject ID / Description /
   Deliverables`. Terse, numbered asks, and the Deliverables box is the grading
   rubric. Read that box first.
2. **In-character business letter** — a memo from a fictional company's COO or
   CTO. The ask is buried in prose and is easy to under-read. Extract the
   requests into a numbered list before you start writing, or you will miss one.

## Seen so far

| Inject | ID | The ask | Deliverable beyond a memo |
|---|---|---|---|
| Identify Key Concepts in a Login Banner | LEGP11T | Name the legal concepts a banner needs, write one, install it everywhere | Screenshot on **every** server and network device |
| Plan & Protect SSH Access | SVRA08A | Secure SSH on Linux *and* Windows, then implement | Evidence of implementation on each server |
| Install & Validate End-Point Protection | SOFT04A | Pick an open-source/OS-provided AV per server, install, full scan | Status screenshots + findings report per server |
| External Perimeter Assessment | EVAL04T | masscan sweep → nmap TCP/version → nmap UDP top-ports, from the external workstation | Screenshots of command lines/output, plus a table of host → service → "should this be exposed?" |
| Write an Incident Response Procedure | SCEN20T(E) | Turn a malware event into a reusable IR procedure | Memo only |
| VPN Options | — | Research three VPNs, pick one, justify it | **3-minute recorded video on YouTube** + a non-technical illustrated user guide |
| Unnecessary Software / Configuration Audit | — | Trawl the environment for unneeded apps and configs, remove them | Report naming location, ports opened, and removal steps |
| Password Policy | — | Audit password policy across servers, machines, and hosted apps; update to modern standards | Note what standard you based it on |

## What this changes about preparation

- **Screenshot-heavy injects dominate.** Login banner, SSH, and AV all mean
  "do it on every box and prove it." Doing the change fast is half the work;
  collecting proof across every box is the other half, and it is the half that
  runs out the clock.
- **One inject needs a video.** VPN Options wants three minutes recorded and
  posted. That is a completely different task from everything else here and
  cannot be improvised at minute 50. Know who records and how, in advance.
- **Password Policy has a trap.** Locking accounts after N failed logins lets
  the red team lock out a scored account deliberately and take the service down
  for you. Prefer length and rotation requirements over aggressive lockout, and
  say why in the memo.
- **Cite the standard.** Password Policy explicitly asks what modern standard
  you based the policy on. The citable answer is NIST SP 800-63B-4
  (https://csrc.nist.gov/pubs/sp/800/63/b/4/final) — note the -4 revision, and
  note that it recommends rate limiting rather than hard lockout, which is what
  makes the trap above defensible in the memo rather than just convenient.

## Drafts exist for all eight of these

All eight of the injects above are pre-written in [`responses/`](responses/): login
banner, SSH access, incident response procedure, password policy, endpoint
protection, perimeter assessment, unnecessary software audit, and VPN options.
Each is in the team's memo format, with its source cited inline, failure modes
called out, and alignment with the Canvas training course rubric.

The unnecessary software audit is a rendering job rather than a research job,
because `harden.sh --table` emits the "location / ports opened / removal steps"
table the inject asks for, already filled in — *provided the hardening was done
in the first hour.* If it was not, the inject arrives and the honest move is to
run `harden.sh` read-only and write the memo about what you are about to do,
rather than cut fifteen things at minute 50 with a scoreboard running.

The **VPN Options** draft ([`responses/vpn-options.md`](responses/vpn-options.md))
provides the complete written 3-way evaluation (Tailscale vs OpenVPN vs Cloudflare),
a fully timed 3-minute script to read into a video recorder, slide deck outline,
and an illustrated step-by-step user guide for non-technical employees, addressing
the exact grading feedback from past competition tryouts.
