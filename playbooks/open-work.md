# Open work

The running checklist. Anything promised and not yet delivered lives here until it is
done. Audit date: 2026-09-16. Competition: 2026-09-26.

Status key: `[ ]` not started, `[~]` in progress, `[x]` done and verified.

## P0 — the headline feature is untested

- [x] **1. Run `baseline.sh --bless --apply` on the lab box and exercise `--status`.**
      `/var/tmp/ccdc-evidence/baseline/` has `queue`, `actions.log`, `dpkg-verify.cache`
      and **no `inventory`**. So `in_blessed()`, `--status`, drift-against-baseline and
      the semantic readings have never run on real data. Every result shown so far came
      from the no-baseline-yet path.
      **Done 2026-09-16.** Full cycle proven on the lab box: bless a clean box
      (531 items) -> plant 8 -> 9 findings, all 8 caught as drift -> `--approve
      all-green` -> `--remove-key` -> `Nothing unexplained`. scored-web stayed up
      (http 200) throughout and SSH still worked afterwards. Two real bugs found
      and fixed, see commit.

- [ ] **2. Build the "unnecessary" half — `harden.sh`.**
      The model is *harden to a baseline, cut everything else, keep it that way*.
      `baseline.sh` answers **unexplained**. Nothing answers **unnecessary**. The
      documented pipeline is recon -> harden -> triage -> bless -> arm and `harden`
      was never written.

## P1 — promised in writing, not built

- [ ] 3. `baseline.sh --explain N` — appears in `baseline-design.md:143`, not implemented.
- [ ] 4. Bless the sudoers ruleset — design doc says `--bless` freezes it;
      `inventory_semantic()` does not enumerate sudoers content.
- [ ] 5. The 13 unactioned check types in `triage.sh` / `sentry.sh`.
      `baseline.sh` grew its own actions; those two tools still only report.
- [ ] 6. Render pass — drive every tool through every mode and read the output as the
      operator sees it.
- [ ] 7. ART harness (`redteam/atomic.sh`) — Atomic Red Team as adversary corpus, not
      as a denominator.

## P2 — docs and tests

- [ ] 8. `baseline.sh` appears in **zero** playbooks. Add it to
      `linux-first-15-minutes.md`, `competition-day-playbook.md`, `GUIDE.md`, `ROADMAP.md`.
- [ ] 9. `CCDC_BASELINE_ALLOW` is missing from `config/example.env`, so the packet
      worksheet never teaches that the exception mechanism exists.
- [ ] 10. Three documented commands that do not exist:
      - `backup.sh --list` in **remediation-cards.md CARD 9** (pasted mid-incident)
      - `baseline.sh --explain 2` in `baseline-design.md:143`
      - `watch.sh --loop` in `baseline-design.md:267` (the flag is `--once`)
- [ ] 11. Extend the ghost-flag assertion (pasteable-self-test #72) to scan
      `playbooks/*.md`, `*.md`, `injects/**/*.md`. It only scans `linux/*.sh`, which is
      exactly why item 10 survived.
- [ ] 12. README assertion-count check is a `>= 250` floor and cannot detect staleness.

## P3 — not code, deadline-bound

- [ ] 13. **Tryout sign-up — due 2026-09-24.**
- [ ] 14. Public-repo decision. Rule 5.6.1 wants three months public before the regional;
      "private now, public on competition day" does not satisfy it.
- [ ] 15. Review all six inject drafts against their numbered asks. One of six read.
- [ ] 16. VPN Options inject needs a 3-minute recorded video. The catalog itself says it
      "cannot be improvised at minute 50."
- [ ] 17. Unnecessary software audit inject — unwritten, and the same shape as item 2.
- [ ] 18. Windows coverage. Login banner, SSH and endpoint protection injects say
      *every server* / *Linux and Windows*. `windows/` is first-pass PowerShell.
