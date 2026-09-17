# Draft: Identify Key Concepts in a Login Banner (LEGP11T)

**Deliverable beyond the memo:** a screenshot of the banner on **every** server
and network device. That is the graded half. Budget time for it.

**On a Linux box, the mechanical part is two commands:**

```bash
CFG=/tmp/ccdc-linux.env  # change if this box's filled config is elsewhere
sudo ./linux/banner.sh --config "$CFG" --apply    # /etc/issue and /etc/issue.net
# then, so SSH actually SHOWS it - this is the half people miss:
#   CCDC_SSH_BANNER="/etc/issue.net"  in the config, then
sudo ./linux/sshd.sh --config "$CFG" --apply
```

`/etc/issue` is the console banner and `/etc/issue.net` is the network one. A
box that sets only the first passes a look at the console and fails the inject,
because the grader connects over SSH. `banner.sh --config "$CFG"` (no --apply)
prints which of the two this box currently serves.

**On a Windows box, it is two registry values under Policies\System:**

```powershell
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $k -Name legalnoticecaption -Value 'NOTICE TO USERS'
Set-ItemProperty $k -Name legalnoticetext    -Value "Authorized use only. ..."
# read it back - this is also your screenshot if the lock screen is awkward:
Get-ItemProperty $k | Select-Object legalnoticecaption, legalnoticetext
```

It appears at the NEXT interactive logon, not immediately, so log out and back
in before you screenshot. `legalnoticetext` is a single REG_SZ; put line breaks
in with a here-string rather than trying to embed `\n`.

*Untested against this kit's lab Windows VM — the values and the path are
standard, but verify on the box before you claim it in the memo.*

**On a network device**, it is the pre-login banner, and the keyword differs by
vendor: `banner login` on Cisco IOS, `set system login message` on JunOS. The
inject asks for every device, so find out which you have before minute 40.

---

```text
INTEROFFICE MEMORANDUM

To:      <ROLE THE INJECT CAME FROM>
From:    Team <XX>
Date:    <DATE>
Subject: Identify Key Concepts in a Login Banner

Summary: We were asked to identify the legal concepts a login banner must
         convey, draft a banner containing them, and install it across our
         systems. A banner has been written and deployed to all <N> systems in
         scope; screenshots are attached.

1. Key concepts a login banner must convey

   A login banner is not decoration. Its purpose is to remove a user's claim
   that they did not know the system was private or did not know they were
   being watched. To do that it must state five things:

   a. Authorized use only. The system is private property and access is
      restricted to authorized users for authorized purposes.
   b. No expectation of privacy. Anything done on the system may be seen by
      the organization.
   c. Consent to monitoring. Use of the system is itself consent to having
      activity monitored, recorded, and reviewed.
   d. Consent to disclosure. Records of that activity may be provided to
      management and to law enforcement.
   e. Continuing to log in constitutes agreement. The user is given the
      choice to disconnect instead.

   Two concepts are as important for what they leave out. The banner must not
   welcome the user, because a welcome has been argued as an invitation to
   connect, and it must apply to authorized users as well as outsiders,
   because insider misuse is the more common case.

   This structure follows the U.S. Department of Defense standard notice and
   consent banner - the most widely copied public example, published in the
   Defense Information Systems Agency configuration guides
   (https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8/2025-05-14/finding/V-230225)
   - and the U.S. Department of Justice guidance on when a banner generates
   consent to monitoring
   (https://www.justice.gov/criminal/criminal-ccips/ccips-documents-and-reports).

2. The banner we deployed

   ------------------------------------------------------------------
   NOTICE TO USERS

   This is a private computer system owned by <COMPANY>. Access is
   restricted to authorized users for authorized business purposes
   only.

   By logging in, you acknowledge and consent to the following:

   - Your activity on this system may be monitored, recorded, and
     reviewed at any time.
   - You have no expectation of privacy in anything you do on this
     system, including files stored on it and communications sent
     through it.
   - Records of your activity may be disclosed to management, to
     security personnel, and to law enforcement.
   - Unauthorized or improper use may result in disciplinary action
     and civil or criminal penalties.

   If you do not consent to these conditions, disconnect now.
   ------------------------------------------------------------------

3. Where it was installed

   | # | System | Role | Banner shown at |
   |---|--------|------|-----------------|
   | 1 | <HOST> | <ROLE> | <SSH / console / web login / device login> |

   On Linux systems the text was placed in /etc/issue, /etc/issue.net, and
   /etc/motd, and the SSH service was configured to display it before
   authentication. On Windows systems it was set as the logon notice title
   and text. On network devices it was set as the pre-login banner.

   Screenshots for each system are attached in the order of the table above.

4. Recommendation

   The banner should be reviewed by counsel before it is treated as the
   organization's final language, and it should be re-checked after any
   system rebuild, since rebuilt systems return to their default banner.

If there are any concerns, questions, or clarifications, please do not
hesitate to reach out.

With Regards,
Team <XX>
```

---

## Notes before you send this

- **The screenshot list is the grade.** If the inject names seven hosts and you
  attach six, it scores as partial. Take the screenshots as you go, not at the
  end.
- **Do not paste the DoD banner itself.** It says "U.S. Government Information
  System," which is false for a fictional company and reads as copied. The
  draft above rebuilds the same five concepts in the company's voice, which is
  what the inject is actually testing.
- **Banner before authentication, not after.** On SSH that means the `Banner`
  directive in `sshd_config` pointing at `/etc/issue.net`; `/etc/motd` alone
  displays only after a successful login, which defeats the legal purpose.
- **Restart the SSH service and verify from another machine.** A banner you
  cannot see from a second connection is not deployed.
