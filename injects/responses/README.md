# Pre-written inject responses

Six drafts, one per inject that the catalog says has actually been asked. Each
is about one page, already in the team's memo format, with every fill-in marked
`<LIKE THIS>`.

**These are drafts, not answers.** The inject in front of you decides what the
memo says. Before sending any of these:

1. Re-read the inject's Deliverables box and make it the checklist.
2. Replace every `<PLACEHOLDER>`. A shipped `<TEAM XX>` is a scored mistake.
3. Delete any numbered answer the inject did not ask for, and add any it did.
4. Attach the screenshots. Most of these injects are graded on the evidence,
   not the prose.

## Why every memo carries a citation

The catalog's calibration note is that procedure injects score by citing a
public framework with a URL, not by inventing a process. Each draft names its
source inline. Keep the URL in the memo — it is doing work.

| Draft | Inject | Cited source |
|---|---|---|
| [login-banner.md](login-banner.md) | Identify Key Concepts in a Login Banner (LEGP11T) | DoD CIO banner policy; DOJ CCIPS |
| [ssh-access.md](ssh-access.md) | Plan & Protect SSH Access (SVRA08A) | Mozilla OpenSSH guidelines |
| [incident-response-procedure.md](incident-response-procedure.md) | Write an Incident Response Procedure (SCEN20T(E)) | SANS PICERL; NIST SP 800-61r3 |
| [password-policy.md](password-policy.md) | Password Policy | NIST SP 800-63B-4 |
| [endpoint-protection.md](endpoint-protection.md) | Install & Validate End-Point Protection (SOFT04A) | ClamAV docs; Microsoft Defender docs |
| [perimeter-assessment.md](perimeter-assessment.md) | External Perimeter Assessment (EVAL04T) | NIST SP 800-115 |

## The three traps these drafts defuse

Each of these is a real way to answer the inject correctly and lose service
points doing it. They are called out in the drafts, at the point of the risk.

- **Password policy → account lockout.** Aggressive lockout thresholds let the
  red team lock a scored account out on purpose. NIST SP 800-63B-4 asks for
  throttling, not hard lockout. See [password-policy.md](password-policy.md).
- **SSH hardening → killing password auth the scorer uses.** If the scoring
  engine authenticates to SSH with a password, `PasswordAuthentication no`
  scores as downtime. See [ssh-access.md](ssh-access.md).
- **Perimeter scan → scanning your own scored services over.** masscan at
  default rate can knock a scored service down. See
  [perimeter-assessment.md](perimeter-assessment.md).
