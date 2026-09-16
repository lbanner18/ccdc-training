# Draft: Plan & Protect SSH Access (SVRA08A)

**Deliverable beyond the memo:** evidence of implementation on each server,
Linux *and* Windows.

**Read the trap at the bottom before you apply anything.**

**The audit that fills in section 2 of this memo:**

```bash
sudo ./linux/sshd.sh --config <cfg>          # read-only; the EFFECTIVE config
```

It reports what the daemon will actually do rather than what `sshd_config`
says - drop-ins in `sshd_config.d` override it, and that difference is exactly
what this inject is asking you to find. It also reports the access paths no
`authorized_keys` review can see: `AuthorizedKeysCommand`, `TrustedUserCAKeys`,
and `Match` blocks.

Changes go through `--apply`, which validates with `sshd -t` and arms a timed
rollback before reloading. **Test the new login in a second terminal before
running `--confirm`.**

---

```text
INTEROFFICE MEMORANDUM

To:      <ROLE THE INJECT CAME FROM>
From:    Team <XX>
Date:    <DATE>
Subject: Plan & Protect SSH Access

Summary: We were asked to secure remote administrative access over SSH on our
         Linux and Windows systems and to implement that plan. The plan is
         below and has been applied to all <N> systems in scope; evidence is
         attached.

1. The risk in plain terms

   SSH is the door administrators use to reach our servers. In its default
   state that door accepts a password from anyone on the network and allows
   unlimited guessing. An attacker who guesses one administrator password
   gains the same access our staff has. The goal of this plan is to make the
   door reachable by fewer people, openable only with a key, and noisy when
   someone tries.

2. The plan

   a. Replace passwords with keys. Each administrator gets a cryptographic
      key pair. The private half never leaves their workstation. Password
      login is then disabled, which makes password guessing impossible
      rather than merely slow.
   b. No direct administrator login. The root and Administrator accounts may
      not log in over SSH. Staff log in as themselves and elevate, so that
      every action is attributable to a person.
   c. Limit who may connect at all. SSH access is restricted to a named
      group of administrators rather than every account on the system.
   d. Limit where they may connect from. The firewall permits SSH only from
      the administrative network, not from the internet.
   e. Modern cryptography only. Older ciphers and key exchange methods are
      disabled, following the Mozilla OpenSSH guidelines
      (https://infosec.mozilla.org/guidelines/openssh), a public standard
      maintained for exactly this purpose.
   f. Fail fast and log. Login attempts are capped and the grace period
      shortened, so a stalled or repeated attempt closes quickly and appears
      in the logs.

3. What was changed on Linux systems

   In /etc/ssh/sshd_config:

     PermitRootLogin no
     PubkeyAuthentication yes
     PasswordAuthentication no          <SEE NOTE 6>
     PermitEmptyPasswords no
     AllowGroups <ADMIN GROUP>
     MaxAuthTries 3
     LoginGraceTime 30
     X11Forwarding no
     Banner /etc/issue.net
     KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
     Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
     MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

   The configuration was checked with `sshd -t` before the service was
   restarted, and a second session was held open during the restart so that a
   mistake could be undone without losing access.

4. What was changed on Windows systems

   Windows uses the same OpenSSH software, configured at
   C:\ProgramData\ssh\sshd_config, with the same settings as above. Two
   differences were handled:

   - Keys for administrator accounts are read from
     C:\ProgramData\ssh\administrators_authorized_keys, not from the user's
     own folder, and that file must be readable only by Administrators and
     SYSTEM or the service ignores it.
   - A Windows Firewall rule restricts inbound port 22 to the
     administrative network.

5. Evidence

   | # | System | OS | Key auth working | Password auth refused | Root/Admin refused |
   |---|--------|----|------------------|----------------------|--------------------|
   | 1 | <HOST> | <OS> | <yes> | <yes> | <yes> |

   Screenshots of each system's configuration and of a verification login are
   attached in the order of the table.

6. One exception we are flagging

   <IF APPLICABLE: The account <NAME> is used by an automated process that
   authenticates with a password. Disabling password authentication system-wide
   would break that process. Password authentication has been left enabled for
   that account only, using a Match block, and the account is restricted to the
   single source address it connects from. We recommend moving it to key
   authentication when the process can be changed.>

If there are any concerns, questions, or clarifications, please do not
hesitate to reach out.

With Regards,
Team <XX>
```

---

## The trap: `PasswordAuthentication no` can score as downtime

If the scoring engine checks SSH by logging in with a **password**, turning
password authentication off takes the service down from the scorer's point of
view, and you lose uptime points for a change you wrote a memo bragging about.

Before you apply item (a):

1. Check the team packet for how SSH is scored and which account it uses.
2. If the scored account uses a password, keep password auth for that account
   and that source address only, with a `Match User` block — and say so in the
   memo, as section 6 does. A documented exception scores better than a broken
   service.
3. Apply the change, then **verify the scored service from the network**, not
   by reading the config back.

## Other ways this goes wrong

- **Locking yourself out.** Keep a second SSH session open while restarting
  sshd. If the new config is bad, the held session is the only way back in.
  Same discipline as the firewall dead man's switch.
- **`AllowGroups` with an empty group.** If the admin group has no members, or
  your user is not in it, the restart locks out everyone including you. Add
  yourself to the group and confirm with `id` *before* restarting.
- **Alpine.** OpenSSH config lives in the same place, but the service is
  managed by OpenRC (`rc-service sshd restart`), not systemd.
- **SELinux on the Red Hat family.** Moving SSH to a non-standard port fails
  silently unless the port is relabeled with `semanage port`. If you change the
  port, expect this.
