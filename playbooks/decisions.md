# Decisions

What we agreed and why, in the order we agreed it. This file exists because
context compaction loses **agreements** more readily than it loses requests: a
summary carries "Luke asked about consolidating the tools" and drops "and we
settled on baseline.sh being the single enumeration." On 2026-09-17 that gap
caused a tool to be built the way it had already been decided not to build it.

If a decision is not written here, it does not survive. Add to this file at the
moment of the decision, not later.

---

## D1 — Provenance, not content (2026-09-17)

Ask what a thing IS EXPLAINED BY, not what it contains. Content matching is
unbounded — infinite ways to spell a reverse shell — so it only ever catches the
spellings someone imagined. "Is this explained?" is bounded: blessed baseline,
**or** package-owned with an intact checksum, **or** allowlisted.

**Why:** two drill footholds walked past every content check in the kit.

## D2 — Harden to a baseline, then hold it (2026-09-17, Luke's framing)

> "instead of trying to hunt down specific ways attackers can get in, we can
> control for the variable that we can confirm, exactly what processes HAVE to
> be running, and cut out anything else. We should be hardening to a baseline,
> leaving essential and scored features up, and then from there, cutting out
> EVERYTHING ELSE and ensuring that once we hit the baseline it stays that way."

Two questions, not one: what is **unexplained** (provenance) and what is
**unnecessary** (necessity). Both are required. Neither substitutes for the other.

## D3 — One enumeration, several views (2026-09-17) — **NOT YET BUILT**

Luke asked whether recon, harden and triage could be consolidated the way arm.sh
consolidated the tier-1 sequence. Agreed shape:

> The box gets enumerated **once** into one structured inventory, with consumers
> reading it: recon records it, harden proposes what is unnecessary, triage flags
> what is unexplained. One walk, one truth, several views.

**Why it matters, in the words used at the time:** separate enumerators *can
disagree*, and when they do you get a finding in one and silence in the other
with no way to tell which is right.

**Status as of 2026-09-17:** not done. `recon.sh`, `triage.sh`, `hunt.sh` and
`baseline.sh` each walk cron, units, SUID and passwd independently, and
`harden.sh` was built as a fifth separate tool rather than a view. This is the
open item.

## D3a — One approval queue, three sources (2026-09-17) — **NOT BUILT**

> "The key design decision: **harden.sh proposes, it doesn't act.** Same numbered
> list, same `--approve N --apply`, same why/will/run/more. Which means one
> interface for the whole kit — 'remove this unnecessary service' and 'remove
> this implant' look and work identically. Three sources feed one approval
> queue: harden (unnecessary), triage (unexplained), watch (drift)."

**Status:** violated. `harden.sh` was built with its own `--cut` and `--undo`,
a second action interface alongside `baseline.sh --approve`.

## D3b — Get a denominator (2026-09-17) — **NOT BUILT**

In answer to "do we need to think differently about how we iterate?", three
method changes were agreed. Only the second was done.

1. **Get a denominator.** Write out every mechanism on this OS that causes code
   to run as root — a finite list, perhaps forty entries — so coverage is a
   fraction that can be reported instead of "27 checks" with nothing to divide
   by. *(The list now exists as `exec_trigger_dirs`. No fraction is ever
   reported. NOT DONE.)*
2. **Flip the default from content to provenance.** *(Done — see D1.)*
3. **Generate drills from the inventory, not from imagination.** If the planting
   fixture picks at random from the mechanism list, a drill stops measuring "did
   Claude think of this" and starts measuring real coverage. *(NOT DONE —
   `night-drill.sh` plants are hand-written.)*

## D3c — Alerting, in three tiers (2026-09-17) — **PARTIALLY BUILT**

1. Deduped `wall` on RED findings. *(Done.)*
2. A prompt indicator, `[!3]` in `PS1`, for everything below RED. *(NOT DONE —
   described in baseline-design.md, never built.)*
3. A dedicated pane running the watch loop. *(Done.)*

## D4 — Blessing is a commitment device, not a cleanliness proof (2026-09-17)

`--bless` does not certify the box is clean. It freezes what is here so that
everything afterwards is measured against it **forever**, never against the
previous pass, so nothing decays into normal. It follows that:

- Bless a box you have not cleaned and you bless the implants with it. Order is
  triage -> harden -> bless.
- Drift is measured against the blessing, not the last run.
- An exception is recorded with a reason and a timestamp, which is also a line
  you can paste into the inject that asked for the change.

## D5 — Approve the output before it is built (2026-09-17, Luke's process rule)

> "why don't you give me like a sample of what output you're trying to go for and
> I approve it before you build it rather than after"

This applies to the **shape of the tool**, not only the wording. A sample that
silently introduces a new separate script is not the thing that was approved.

## D6 — Purge, do not merely disable (2026-09-17, Luke's call)

A disabled unit is one `systemctl enable` away from returning, and the person
most likely to type that already has root. So remove the package — but cache its
`.deb` to the evidence directory first, so the undo works on a competition
network that cannot reach a mirror. If nothing can be cached, degrade to
disable-and-mask and **say so** rather than purging blind.

## D7 — Dual-use tools need a human (2026-09-17, Luke's call)

Something that is both an attacker's tool and one of ours (`tcpdump`, `nc`) is
never cut silently. Report it, name which of our own scripts calls it, and let
the operator decide.

## D8 — Never kill what could not be captured (2026-09-17)

A kill destroys the only evidence there was. The tool captures first and kills
only what a capture succeeded on. A refused freeze falls back to capturing the
process while it runs; a total failure leaves the process alone and says so.

## D9 — ART is the adversary, not the denominator (2026-09-17, Luke's correction)

> "since we can't possibly know the exact demoninator of attack methods, we use
> what we do have confirmed, the essential/scoring files, and harden everything
> else."

Atomic Red Team is a corpus for naming mechanisms nobody thought of. It is not a
coverage measure, and "N of 434" must never be printed as one.

## D10 — A check that cannot run must not read as a pass (2026-09-17)

Recurring bug class, found four separate times in one night: a safety check that
compares an empty list, a port probe that finds nothing to probe and returns
success, a capture that fails and is reported as honoured. Any check that could
not execute says so.
