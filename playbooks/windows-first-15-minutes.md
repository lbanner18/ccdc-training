# Windows: the first fifteen minutes

You have six hours. Half your points are injects. The box is already
compromised — assume that, because it usually is before you log in.

This page is the order to do things in. It is not the complete list; it is the
list that stops you losing points while you work out the rest.

> **Everything here needs an elevated PowerShell.** Start → type `powershell` →
> **Ctrl+Shift+Enter**. Without it the Security log reads empty, other users'
> scheduled tasks are invisible, and you will decide a dirty box is clean.

---

## Minute 0 — get the kit onto the box

You have GitHub access. That is the fastest path and it survives you breaking
something:

```powershell
cd C:\
git clone https://github.com/YOURUSER/ccdc-training.git
cd ccdc-training
```

No git? Download the ZIP and expand it:

```powershell
Invoke-WebRequest -Uri 'https://github.com/YOURUSER/ccdc-training/archive/refs/heads/main.zip' -OutFile C:\kit.zip
Expand-Archive C:\kit.zip -DestinationPath C:\ -Force
cd C:\ccdc-training-main
```

If PowerShell refuses to run the scripts:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

`-Scope Process` on purpose: it lasts for this window only and changes nothing
that persists, so it is not a finding for the next person.

---

## Minute 1 — fill in the config

**The same file the Linux box uses.** One format, both boxes.

```powershell
copy config\example.env C:\ProgramData\CCDC\ccdc.env
notepad C:\ProgramData\CCDC\ccdc.env
```

Five lines matter more than the rest. Everything else can wait:

```ini
CCDC_ALLOWED_USERS="Administrator youraccount svc_whatever"   # accounts that must keep working
CCDC_WINDOWS_SERVICES="W3SVC MSSQLSERVER"                     # services you are scored on
CCDC_ALLOWED_TCP_PORTS="80 443 3389"                          # ports the packet says are open
CCDC_TCP_CHECKS="127.0.0.1:80"                                # how to tell a service is alive
CCDC_HTTP_CHECKS="http://127.0.0.1/"
```

The tools **refuse to act** while `CCDC_ALLOWED_USERS` and
`CCDC_WINDOWS_SERVICES` are empty. That is deliberate: an empty list does not
mean "nothing is protected", it means nothing has told the tool what is scored,
and the account you did not mean to disable is usually the one the scoring
engine logs in with.

---

## Minute 2 — record the box before you change it

Read-only. This is your evidence of what was already here, and it is what the
incident report is written from.

```powershell
.\windows\recon.ps1
```

---

## Minutes 3–6 — what is wrong right now

```powershell
.\windows\triage.ps1 -Config C:\ProgramData\CCDC\ccdc.env
```

Read **RED** first. Two of them are points, not hygiene, and they come before
everything else on this page:

- `scoreduser` — **an account the packet says must work has been disabled.**
- `scoredservice` — **a service you are graded on is stopped.**

Fix those two before you read another line:

```powershell
net user NAME /active:yes
Start-Service NAME
```

Every other finding prints the command that fixes it, and a card reference.
The cards are in [`windows-cards.md`](windows-cards.md).

---

## Minutes 6–10 — credentials

The training's own words: *"Generally the #1 priority is to change passwords.
The red team knows the default passwords."*

```powershell
.\windows\users.ps1 -Config C:\ProgramData\CCDC\ccdc.env
```

Read the table. The column that matters is the last one — `** NO **` means
enabled and not named in your packet list.

**Make a second administrator first.** If they take your account out of
Administrators, this is the difference between a bad ten minutes and a lost box:

```powershell
.\windows\users.ps1 -Config C:\ProgramData\CCDC\ccdc.env -CreateAdmin ops2 -Apply
```

Then rotate everything that is not scored:

```powershell
.\windows\users.ps1 -Config C:\ProgramData\CCDC\ccdc.env -RotateAll -Apply
```

> **It skips scored accounts on purpose.** On many setups the scoring engine
> logs in as those accounts using a password from the packet. Changing it takes
> the check down. If the packet says to change them — it often does, with a form
> to submit the new password on — add `-IncludeScoredUsers` and do it
> deliberately.

**Write the passwords on paper.** The tool saves them to
`C:\ProgramData\CCDC\state\passwords-*.txt`, which is a file on the box
somebody is attacking.

---

## Minutes 10–14 — the checklist, one command

```powershell
.\windows\harden.ps1 -Config C:\ProgramData\CCDC\ccdc.env
```

That is a **dry run**. It prints every change it would make and does nothing.
Read it. Then:

```powershell
.\windows\harden.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Apply
```

In order, it does: backup → firewall → Defender → logging → password policy →
services → remote access → persistence report. After every step that could
affect a scored service it re-checks, and **stops** if one stopped answering —
so you find out which step did it, not that something did.

The firewall step writes your RDP and SSH allow rules **before** it sets
default-inbound to Block. That ordering is the difference between hardening a
box and locking yourself out of one.

---

## Minute 15 — keep it up while you do injects

```powershell
.\windows\watchdog.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Install
```

Restarts a stopped scored service and logs every time it had to. Your terminal
stays free for the thing that is worth half the points.

---

## Then: check from somewhere that is not this box

Nothing running on the box can tell you whether the scoring engine can reach
it. From your laptop, or the Linux box:

```bash
curl -I http://WINDOWS_IP/
nc -z -v WINDOWS_IP 3389
```

---

## The five things that cost people the most

1. **Locking yourself out with the firewall.** Allow your own access *first*.
   `harden.ps1` does this; doing it by hand, do it in that order.
2. **Changing a scored account's password.** Read the packet before `-RotateAll`.
3. **Deny-all-outbound.** Windows allows most outbound by default and a scored
   service usually needs some of it. Change outbound last, if at all.
4. **Killing a process without reading its command line.** The command line is
   the evidence, and it is gone the moment you kill it.
5. **Reverting.** A revert costs points. Restoring one file does not. That is
   why `harden.ps1` backs up first.

---

## Where everything is

| you want to | run |
|---|---|
| see what is wrong | `.\windows\triage.ps1 -Config CONFIG` |
| record the box, read-only | `.\windows\recon.ps1` |
| accounts and passwords | `.\windows\users.ps1 -Config CONFIG` |
| the whole hardening checklist | `.\windows\harden.ps1 -Config CONFIG` |
| just the firewall | `.\windows\harden.ps1 -Config CONFIG -Only Firewall -Apply` |
| keep scored services up | `.\windows\watchdog.ps1 -Config CONFIG -Install` |
| know what a finding means | [`windows-cards.md`](windows-cards.md) |
| the Linux box | [`linux-first-15-minutes.md`](linux-first-15-minutes.md) |

---

## What this kit does NOT do on Windows

Said plainly, because a tool that overstates its coverage is worse than one
that does less.

- **No domain hardening.** On a domain controller `users.ps1` refuses to run and
  tells you the AD commands instead. GPO, delegation and AD ACLs are by hand.
- **No approval queue yet.** The Linux side has `sentry.sh` — numbered findings,
  each with its own approve command. Windows prints the command; you paste it.
- **No baseline/drift.** The Linux side can freeze a known-good box and report
  everything that changed since. Windows has no equivalent yet.
- **Detection is a list, not a proof.** "Nothing found" means "none of the
  things this tool looks for", never "clean".
