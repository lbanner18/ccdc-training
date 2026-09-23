# Pre-written inject responses

Eight drafts, covering every inject that the training coursework and past competitions
have asked. Each is already in the team's memo format, with every fill-in marked
`<LIKE THIS>`.

**These are drafts, not answers.** The inject in front of you decides what the
memo says. Before sending any of these:

1. Re-read the inject's Deliverables box and make it your checklist.
2. Replace every `<PLACEHOLDER>`. A shipped `<TEAM XX>` is an immediate deduction.
3. Delete any numbered answer the inject did not ask for, and add any it did.
4. Attach the screenshots. Most of these injects are graded on the evidence,
   not the prose.
5. Export as a PDF and name it according to the packet (generally `team##_inject##.pdf`).

## Why every memo carries a citation

The training course's calibration note is that procedure injects score by citing a
public framework with a URL, not by inventing a process. Each draft names its
source inline. Keep the URL in the memo — it is doing work.

| Draft | Inject | Cited source |
|---|---|---|
| [login-banner.md](login-banner.md) | Identify Key Concepts in a Login Banner (LEGP11T) | DoD CIO banner policy; DOJ CCIPS; CFAA |
| [ssh-access.md](ssh-access.md) | Plan & Protect SSH Access (SVRA08A) | Mozilla OpenSSH guidelines |
| [incident-response-procedure.md](incident-response-procedure.md) | Write an Incident Response Procedure (SCEN20T(E)) | SANS PICERL; NIST SP 800-61r3 |
| [password-policy.md](password-policy.md) | Password Policy | NIST SP 800-63B-4 |
| [endpoint-protection.md](endpoint-protection.md) | Install & Validate End-Point Protection (SOFT04A) | ClamAV docs; Microsoft Defender docs |
| [perimeter-assessment.md](perimeter-assessment.md) | External Perimeter Assessment (EVAL04T) | NIST SP 800-115 |
| [unnecessary-software.md](unnecessary-software.md) | Unnecessary Software / Configuration Audit | CIS Benchmarks; package manifest provenance |
| [vpn-options.md](vpn-options.md) | VPN Options (Presentation + Guide) | NIST SP 800-77r1; WireGuard / Tailscale security |

## Traps that cost points (from the Canvas course grading feedback)

- **AI screening:** The Canvas coursework warns that injects are screened with an
  AI detector; submissions showing 20% or more AI-generated text receive **0 points**.
  Never paste raw LLM boilerplate. Use concrete hostnames, real command syntax,
  actual file paths, and a direct engineering voice.
- **Perspective:** When describing actions *your team completed*, write in **1st
  person plural ("we", "our")**. Writing in 3rd person ("The IT Team", "Team 03")
  was explicitly penalized in course grading. When writing a *formal business policy*,
  write in **3rd person ("Employees", "Users", "Management")**.
- **Screenshot layout:** Crop screenshots tightly to the terminal or dialog box
  (never full multi-monitor desktops). Center screenshots on the page, number them
  (`Figure 1: ...`), and ensure a screenshot's caption does not sit orphaned at the
  bottom of a page separate from the image.
- **Password policy → account lockout.** Aggressive lockout thresholds let the
  red team lock a scored account out on purpose. NIST SP 800-63B-4 asks for
  throttling, not hard lockout. See [password-policy.md](password-policy.md).
- **SSH hardening → killing password auth the scorer uses.** If the scoring
  engine authenticates to SSH with a password, `PasswordAuthentication no`
  scores as downtime. See [ssh-access.md](ssh-access.md).
- **Perimeter scan → scanning your own scored services over.** masscan at
  default rate can knock a scored service down. See
  [perimeter-assessment.md](perimeter-assessment.md).
- **VPN Options → omitting written analysis or slides.** The Canvas grader
  penalized submissions that only spoke about research in the video without
  including the written comparison in the memo, or that linked only YouTube without
  the slide deck. See [vpn-options.md](vpn-options.md).
