# Draft: Password Policy

**The inject explicitly asks what modern standard you based the policy on.**
That is a scored sentence. The answer is NIST SP 800-63B-4.

**This is the inject with the lockout trap.** Read the bottom section before
you set a lockout threshold anywhere.

**Section 2's table generates itself, one row per host:**

```bash
./linux/policy.sh --config <cfg> --table    # the row
./linux/policy.sh --config <cfg>            # the full audit behind it
```

It reads the effective settings rather than the obvious file - a `minlen` passed
as an argument to `pam_pwquality` in the PAM stack beats the one in
`pwquality.conf`, and reporting the file value puts a wrong number in a graded
document. It prints no password hashes, deliberately: this report gets pasted
into a memo.

`policy.sh` has **no `--apply`**. Every fix it suggests is a hand edit to PAM or
`login.defs`, a broken PAM stack locks out every account including root, and the
way back is single-user mode - which is a reboot, which is scored downtime. Keep
a second root shell open, change one thing, test a login in a third session.

---

```text
INTEROFFICE MEMORANDUM

To:      <ROLE THE INJECT CAME FROM>
From:    Team <XX>
Date:    <DATE>
Subject: <INJECT NAME, COPIED EXACTLY>

Summary: We were asked to audit password practices across our servers,
         workstations, and hosted applications and bring them up to modern
         standards. Our audit findings and the new policy are below. The
         policy is based on NIST Special Publication 800-63B-4, Digital
         Identity Guidelines.

1. What standard this is based on

   This policy follows NIST Special Publication 800-63B-4, Digital Identity
   Guidelines: Authentication and Authenticator Management
   (https://csrc.nist.gov/pubs/sp/800/63/b/4/final), the current U.S. federal
   standard for authentication. Its guidance reverses several practices that
   were common a decade ago, because evidence showed they made passwords
   weaker in practice rather than stronger. Where this policy differs from
   what staff are used to, that is the reason.

2. What we found

   | System | Minimum length | Complexity required | Forced expiry | Lockout | Other findings |
   |--------|----------------|--------------------|--------------|---------|----------------|
   | <HOST> | <N> | <yes/no> | <N days> | <N attempts> | <shared or default accounts, reused passwords, passwords stored in plain text> |

   The most serious findings were <DEFAULT CREDENTIALS STILL IN PLACE /
   SHARED ADMINISTRATIVE ACCOUNTS / PASSWORDS STORED IN PLAINTEXT>, which we
   have corrected as part of this work.

3. The new policy

   a. Length is the requirement. Minimum 15 characters for any account with
      administrative rights, minimum 12 for standard user accounts. Systems
      must accept passwords up to at least 64 characters. Length does more for
      password strength than any other rule.

   b. Passphrases are encouraged. A sequence of unrelated words is both
      stronger and easier to remember than a short password with substituted
      characters.

   c. No composition rules. We do not require a mix of uppercase, digits, and
      symbols. NIST recommends against it, because it pushes users toward
      predictable patterns such as capitalizing the first letter and appending
      "1!" - patterns attackers test first.

   d. No scheduled expiry. Passwords are not forced to change on a calendar.
      Routine expiry produces small predictable changes to the same password.
      Passwords are changed immediately when there is evidence or suspicion of
      compromise, which is when changing them actually helps.

   e. Screen new passwords against known-breached and common password lists,
      and reject matches. This blocks the passwords attackers try first.

   f. All passwords must be unique per account and per system. No shared
      accounts. Where staff need common access, they get individual accounts
      with the same rights, so actions remain attributable.

   g. Multi-factor authentication on all administrative and remote access,
      where the system supports it. This is worth more than any password rule
      on this list.

   h. Password managers are permitted and encouraged, and pasting into
      password fields must not be blocked.

   i. No password hints and no security questions. Both are recoverable from
      public information.

   j. Stored passwords must be salted and hashed with a purpose-built
      algorithm. Plaintext or reversibly encrypted storage is prohibited.

4. Failed login attempts: throttling rather than lockout

   Repeated failed logins are limited by increasing delay between attempts and
   by alerting, rather than by locking the account after a fixed number of
   failures. NIST SP 800-63B-4 recommends rate limiting for this purpose.

   Our reason is operational: an account that locks after a small number of
   wrong passwords can be locked deliberately by anyone who can reach the login
   page. Applied to the accounts our customer-facing services run under, that
   turns a minor nuisance into a self-inflicted outage - the attacker does not
   need to guess the password, only to guess wrong repeatedly. Throttling slows
   an attacker just as effectively without handing out that switch.

   Where a system supports only a fixed lockout threshold, we set a high
   threshold with a short automatic unlock window, and we exclude service
   accounts entirely, monitoring them by alert instead.

5. Implementation status

   | System | Policy applied | Method | Verified |
   |--------|----------------|--------|----------|
   | <HOST> | <yes> | <password quality module / group policy / application setting> | <yes> |

6. Recommendation

   Password rules are the weakest of the controls listed here. The two changes
   that would most reduce our risk are multi-factor authentication on remote
   access and the elimination of shared administrative accounts. We recommend
   both be scheduled.

If there are any concerns, questions, or clarifications, please do not
hesitate to reach out.

With Regards,
Team <XX>
```

---

## The lockout trap, stated plainly

Account lockout is a denial-of-service control pointed at yourself. If a scored
service authenticates as `svc_web`, and `svc_web` locks after 5 bad passwords,
the red team locks it out in seconds and your service is down until you notice
and unlock it. They will do this repeatedly, because it is cheaper than
exploiting anything.

So:

- **Never apply a lockout threshold to an account a scored service uses.**
  Identify those accounts from the team packet first.
- Prefer throttling (`pam_faillock` with a long unlock interval, `fail2ban` on
  source addresses rather than accounts).
- If the inject or the packet *requires* a lockout threshold, set it and say in
  the memo which accounts are excluded and why. The memo is where you get the
  points back.

This is a real tradeoff, not a dodge, and NIST SP 800-63B-4 is on your side —
which is why section 4 cites it rather than just asserting it.

## Implementation notes

- **Linux:** `/etc/security/pwquality.conf` for `minlen`; `pam_faillock` for
  throttling. `chage -M 99999` removes scheduled expiry on existing accounts —
  and note that `/etc/login.defs` only affects accounts created afterward.
- **Windows domain:** Default Domain Policy sets length, history, and lockout;
  fine-grained password policies handle the service-account exceptions. Maximum
  password age of 0 means "never expires."
- **Hosted applications** are the ones teams forget. The inject says "hosted
  apps" — that means the web app admin panel, the database root account, and
  the appliance web interface, each configured separately.
- **Screening against breached lists needs a wordlist on disk**, and the
  competition network may have no internet. Carry one or drop item (e) rather
  than claiming a control you did not implement.
