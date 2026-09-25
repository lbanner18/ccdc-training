# Windows: the first fifteen minutes

You have six hours. Half your points are injects. The box is already
compromised — assume that, because it usually is before you log in.

This page is the order to do things in. It is not the complete list; it is the
list that stops you losing points while you work out the rest.

> **Everything here needs an elevated PowerShell.** Start → type `powershell` →
> **Ctrl+Shift+Enter**. If you forget this, Windows often gives you a shorter
> answer instead of an error. For example, you may see no Security-log events
> or miss another user's scheduled task and think the box is clean.

---

## Windows at a glance

The whole flow on one screen, in the order rehearsed on the lab box. The runner
does it for you and asks before every change; the commands under **By hand** are
the same steps if the runner breaks. The detail for each step is further down.

### Start — by hand, once

**1. A 64-bit elevated PowerShell.** Start → **Windows PowerShell** (NOT the
"(x86)" one) → **Ctrl+Shift+Enter**. `[Environment]::Is64BitProcess` must say `True`.

**2. Get the kit** (the box needs internet; see *Minute 0* if it has none)
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $ProgressPreference = 'SilentlyContinue'
iwr -UseBasicParsing https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.zip -OutFile C:\kit.zip
Expand-Archive C:\kit.zip C:\ -Force; cd C:\ccdc-training-main
```

**3. Let this window run the kit**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

### Phase 1 — lock the doors (every box, before Phase 2 on any)

```powershell
.\windows\first15.ps1 -Phase 1
```
**It runs:** config and the Quotient questions → passwords → recon → triage → harden → alex check.
**You do:** paste block 1 · type the Administrator password · submit the PCR ·
copy the recon zip off · read the REDs · say `y` to harden after reading its list.

**By hand:**

1. **The config** — for the tryout it is already written from the packet
   ```powershell
   mkdir C:\ProgramData\CCDC -Force | Out-Null
   copy config\tryout-windows.env C:\ProgramData\CCDC\ccdc.env
   ```
   If Quotient scores HTTP or FTP on this box, add `W3SVC`/`FTPSVC` to
   `CCDC_WINDOWS_SERVICES` and `80`/`21` to `CCDC_ALLOWED_TCP_PORTS` in notepad.
   (Any other event: copy `config\example.env` instead and fill `CCDC_ALLOWED_USERS` ·
   `CCDC_WINDOWS_SERVICES` · `CCDC_ALLOWED_TCP_PORTS` · `CCDC_TCP_CHECKS`.)

2. **Every default password** — the red team has the packet
   ```powershell
   .\windows\passwords.ps1 -Apply
   net user Administrator *
   ```
   Paste block 1 of the password sheet, then Enter on an empty line. On the domain
   controller it changes the DOMAIN accounts and proves each with an LDAP login.
   The Administrator password is sheet section 4. Then block 1 into Quotient's
   Password Change Request.

3. **The "before" picture** (read-only)
   ```powershell
   .\windows\recon.ps1
   ```
   Run the two zip lines it prints (the runner zips it for you), then right-click
   the zip in `C:\` in File Explorer → **Copy**, and paste it on your laptop.

4. **What is wrong right now** (read-only) — fix `scoreduser` / `scoredservice` first
   ```powershell
   .\windows\triage.ps1
   ```

5. **The hardening checklist** — read the dry run, then apply. Firewall default-deny only ever through here.
   ```powershell
   .\windows\harden.ps1
   .\windows\harden.ps1 -Apply
   ```

6. **Your backup admin is alex**
   ```powershell
   net user alex
   net group "Domain Admins" /domain
   ```
   alex is a packet administrator whose password block 1 already changed. The
   packet says the box should have *only* its listed users, so do not create a new
   one. Check alex is active and in Domain Admins (`net localgroup Administrators`
   off a DC).

### Phase 2 — go deep (one box at a time)

```powershell
.\windows\first15.ps1 -Phase 2
```
**It runs:** down to 0 RED → arm → bless → opens the lookout window.
**You do:** approve held items by number, only after reading them · bless only at 0 RED.

**By hand:**

1. **Down to 0 RED**
   ```powershell
   .\windows\triage.ps1
   .\windows\sentry.ps1 -Status
   .\windows\sentry.ps1 -Approve all -Apply
   ```
   Then each held item you have read: `.\windows\sentry.ps1 -Approve N -Apply` (N from `-Status`).

2. **Canaries and the self-repairing tasks**
   ```powershell
   .\windows\arm.ps1 -Apply
   ```

3. **Freeze the clean box** — after arm, so the baseline includes its tasks
   ```powershell
   .\windows\baseline.ps1 -Bless -StableForSeconds 20 -Apply
   ```

4. **In a SECOND elevated window — the lookout**
   ```powershell
   cd C:\ccdc-training-main; Set-ExecutionPolicy -Scope Process Bypass -Force
   .\windows\sentry.ps1 -Watch
   ```

### When the popup fires — the loop

**1. Everything that changed, numbered**
```powershell
.\windows\baseline.ps1 -Status
```

**2. For each number** — run its "if this is NOT yours" lines, or allow it:
```powershell
.\windows\baseline.ps1 -Explain N
.\windows\baseline.ps1 -Allow 'SECTION:KEY' -Reason 'why this is mine' -Apply
```
`-Explain` prints the exact `-Allow` line for that item.

**3. Anything dangerous left, with its fix**
```powershell
.\windows\triage.ps1
.\windows\sentry.ps1 -Status
```

**4. Until it says "Nothing has changed"**
```powershell
.\windows\baseline.ps1 -Status
```

### Traps that cost time on the lab box

- A tool looks stuck: the title bar says **Select** — press **Esc**. Do not click inside a running window.
- A Defender popup is a red-team sighting: **Windows Security → Protection history**, or `Get-MpThreatDetection`.
- **64-bit PowerShell only.** Check `[Environment]::Is64BitProcess` is `True` before running anything. In 32-bit PowerShell, Defender, Get-LocalUser and Get-WindowsFeature show as "not recognized", and some of harden's registry writes land where Windows never reads them. On the lab box this looked like Defender had been removed.
- On a domain controller every account is a domain account. Disabling one disables it everywhere in the domain.
- Never paste a `Block 3389` or a default-deny line by hand; RDP may be how you and the scorer get in.
- Passwords go on paper, never into chat or a file you keep.

---

## Minute 0 — get the kit onto the box

You have GitHub access. That is the fastest path and it survives you breaking
something:

```powershell
cd C:\
git clone https://github.com/lbanner18/ccdc-training.git
cd ccdc-training
```

No git (the usual case on Windows)? Download the ZIP and expand it. Three
short lines, short enough to type on a console that will not paste:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $ProgressPreference = 'SilentlyContinue'
iwr -UseBasicParsing https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.zip -OutFile C:\kit.zip
Expand-Archive C:\kit.zip C:\ -Force; cd C:\ccdc-training-main
```

Each part of line 1 is there for a reason. PowerShell 5.1 on Server
2016/2012 R2 offers TLS 1.0, which GitHub refuses ("Could not create SSL/TLS
secure channel"). The progress bar slows 5.1's download many times over.
`-UseBasicParsing` stops iwr failing on a box where Internet Explorer never ran.

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
mkdir C:\ProgramData\CCDC -Force | Out-Null
copy config\example.env C:\ProgramData\CCDC\ccdc.env
notepad C:\ProgramData\CCDC\ccdc.env
```

The `mkdir` line matters on a fresh box: the folder does not exist yet, and
without it the copy fails with "Could not find a part of the path".

Start with these five lines. Replace the examples with values from the packet:

```ini
CCDC_ALLOWED_USERS="Administrator youraccount svc_whatever"   # accounts that must keep working
CCDC_WINDOWS_SERVICES="W3SVC MSSQLSERVER"                     # services you are scored on
CCDC_ALLOWED_TCP_PORTS="80 443 3389"                          # ports the packet says are open
CCDC_TCP_CHECKS="127.0.0.1:80"                                # how to tell a service is alive
CCDC_HTTP_CHECKS="http://127.0.0.1/"
```

The tools will not make changes while `CCDC_ALLOWED_USERS` and
`CCDC_WINDOWS_SERVICES` are empty. That prevents a common mistake: disabling
the account or service that the scorer needs. If you see a message saying the
packet lists are empty, stop and fill in those two lines.

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
.\windows\triage.ps1
```

> **Tip**: All Windows tools auto-detect `C:\ProgramData\CCDC\ccdc.env`. You do not need to type `-Config` unless using a custom path.

Read **RED** first. Fix these two before spending time on cleanup:

- `scoreduser` — **an account the packet says must work has been disabled.**
- `scoredservice` — **a service you are graded on is stopped.**

Fix those two before you read another line:

```powershell
net user NAME /active:yes
Start-Service NAME
```

Every other finding prints the command that fixes it, and a card reference.
The cards are in [`windows-cards.md`](windows-cards.md).

**When there are more than about five findings, stop pasting and use the
queue.** Thirty findings is a lot of copying at a moment when you also have an
inject open, and copying is where the wrong hostname gets into the right
command.

```powershell
.\windows\sentry.ps1 -Status
```

It numbers everything it can act on and marks each one:

| | |
|---|---|
| **SWEEP** | The tool can handle this safely. `-Approve all -Apply` includes it. |
| **LOOK** | This could affect a login, service, or port. Read it, then approve that number only. |

```powershell
# every SWEEP item; every LOOK item is handed back to you with its number
.\windows\sentry.ps1 -Approve all -Apply

# then the LOOK items, one at a time, once you have looked
.\windows\sentry.ps1 -Approve 7 -Apply
```

Leave `-Apply` off and it tells you what it would do and changes nothing.

Before using the queue, know what these messages mean:

- **Numbers come from `-Status`.** They do not change until you run `-Status`
  again. A new finding cannot quietly become item 7 after you read item 7.
- **The tool checks again before changing anything.** If the item disappeared,
  it skips it instead of guessing.
- **It saves the old state first.** `-Undo` does not automatically reverse a
  change; it shows what changed and where the saved "before" files are.

If something is yours and you are tired of seeing it:

```powershell
.\windows\sentry.ps1 -Mute 'listener|tcp/8080'
```

It stays in `triage.ps1`. It just stops asking you to decide.

---

## Minutes 6–10 — credentials

The training's own words: *"Generally the #1 priority is to change passwords.
The red team knows the default passwords."*

```powershell
.\windows\users.ps1
```

Read the table. The column that matters is the last one — `** NO **` means
enabled and not named in your packet list.

**Make sure you have a second administrator first.** If they take your account
out of Administrators, this is the difference between a bad ten minutes and a
lost box. For the tryout that is **alex**: it is in the packet, and the packet
says the box should have only its listed users, so do not create a new one.
Check it is active and still an admin:

```powershell
net user alex
net group "Domain Admins" /domain       # off a DC: net localgroup Administrators
```

(`users.ps1 -CreateAdmin NAME -Apply` exists for events whose packet allows
extra accounts.)

Then rotate everything that is not scored:

```powershell
.\windows\users.ps1 -RotateAll -Apply
```

> **It skips scored accounts on purpose.** On many setups the scoring engine
> logs in as those accounts using a password from the packet. Changing it takes
> the check down. If the packet says to change them — it often does, with a form
> to submit the new password on — use `passwords.ps1` with your PCR block:

```powershell
.\windows\passwords.ps1 -Apply
```
Paste the same `user,password` block you submitted to Quotient, then press Enter on an empty line. On a Domain Controller (like `lapis`), this resets AD passwords and tests each via LDAP. Add `-Kick` to terminate stale logon sessions.

**Write the passwords on paper.** The tool saves them to
`C:\ProgramData\CCDC\state\passwords-*.txt`, which is a file on the box
somebody is attacking.

---

## Minutes 10–14 — the checklist, one command

```powershell
.\windows\harden.ps1
```

That is a **dry run**. It prints every change it would make and does nothing.
Read it. Then:

```powershell
.\windows\harden.ps1 -Apply
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

Before writing a network or unnecessary-software response, produce the table
that says what owns each reachable thing. `REVIEW` is an unanswered packet
question, not permission to remove it:

```powershell
.\windows\surface.ps1 -Table
```

```powershell
.\windows\arm.ps1 -Apply
```

This is the one-command setup for the things that are safe to set up together:
it lays the four canaries, turns on their read-audit policy, installs the
scored-service/canary Watchdog, installs the Guardian task that repairs it,
and installs Continuity-Audit to report a missing Guardian. It verifies all of
that before it says `armed`.

It does **not** change passwords, firewall policy, accounts, or scored-service
settings. It also does not choose where to send off-box evidence. Those are
packet and team decisions, so the tool leaves them with you. The next section
freezes this deliberately installed chain into the baseline.

The Watchdog runs `canary.ps1 -Check` each pass and records a trip in
`watchdog.log`. Check `guardian.ps1 -Status` whenever you come up for air. The
integrity checker writes changed status to `integrity.log`. An Administrator
can still remove all three tasks; this is redundancy, not tamper-proofing.

```powershell
.\windows\integrity.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
```

`OK` means the Guardian task exists, is running, and its task action names the
expected private Guardian script. `MISSING`, `STOPPED`, `REDIRECTED`, or
`PAYLOAD-MISSING` means preserve the log and investigate before reinstalling.

The task labels and the private running script names come from
`CCDC_WINDOWS_*` deployment keys in `ccdc.env`; the template uses
`Operations-Monitor`, `Maintenance-Check`, `service-monitor.ps1`, and
`health-check.ps1` (plus `integrity-check.ps1` for the canary child and
`continuity-audit.ps1` for the Guardian check). They are neutral operational
labels, not fake Windows components. If you change any of
them on an already-armed box, remove the old pair with the old config first,
then install the new pair:

```powershell
.\windows\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Uninstall -Apply -TaskName CCDC-Guardian -WatchdogTaskName CCDC-Watchdog
.\windows\arm.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Apply
```

Guardian keeps a separate `.repair` authority with a SHA-256 manifest beside
those private copies. On each pass it verifies that authority before restoring
an altered or missing private guardian, watchdog, canary, or common payload.
If the authority itself does not match its manifest it records an integrity gap
and refuses to “repair” from it. An Administrator can alter both; use this to
recover from ordinary file/task tampering, not as a claim of tamper-proofing.

### Prove the chain once on the disposable VM

Do this only on a snapshot you can revert. It tests the behavior that a source
review cannot prove. This exact sequence was proven on `ccdc-win` on
2026-09-21, then Guardian was reinstalled and all three tasks were checked as
running. Run it again after changing any of these scripts; the old result does
not prove a new version.

```powershell
# First record the three task states and the private directory.
.\windows\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status

# Delete ONE private watchdog file. Guardian should restore it on the next pass.
Remove-Item C:\ProgramData\CCDC\maintenance\service-monitor.ps1
Start-Sleep -Seconds 75
.\windows\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
Get-Content C:\ProgramData\CCDC\guardian.log -Tail 20

# Alter the live watchdog file. It should also be replaced from .repair.
Add-Content C:\ProgramData\CCDC\maintenance\service-monitor.ps1 '# lab alteration'
Start-Sleep -Seconds 75
Get-Content C:\ProgramData\CCDC\guardian.log -Tail 20

# Remove the watchdog TASK. Guardian should recreate it.
Stop-ScheduledTask -TaskName Operations-Monitor
Unregister-ScheduledTask -TaskName Operations-Monitor -Confirm:$false
Start-Sleep -Seconds 75
.\windows\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status

# Remove the Guardian TASK. Continuity-Audit should report MISSING; it does not
# pretend it can restart a Guardian that is no longer running.
Stop-ScheduledTask -TaskName Maintenance-Check
Unregister-ScheduledTask -TaskName Maintenance-Check -Confirm:$false
Start-Sleep -Seconds 75
.\windows\integrity.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
Get-Content C:\ProgramData\CCDC\integrity.log -Tail 20

# Reinstall Guardian before the final test. Then alter ONE repair copy. This
# must NOT be copied back. Look for INTEGRITY-GAP in guardian.log instead.
.\windows\guardian.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Install -Apply
Add-Content C:\ProgramData\CCDC\maintenance\.repair\service-monitor.ps1 '# lab alteration'
Start-Sleep -Seconds 75
Get-Content C:\ProgramData\CCDC\guardian.log -Tail 20
```

Use the actual configured private directory and filenames if you changed them.
The first three tests should produce `INTEGRITY-REPAIRED` or a task-repair log.
The removed Guardian should produce `INTEGRITY-GAP` in `integrity.log`. The
final test should produce `INTEGRITY-GAP`, not a repair. Revert the snapshot or
reinstall Guardian after recording the results.

### Repeat the recovery proof without typing each failure by hand

On a disposable snapshot, the lab-only drill performs the same four checks,
waits for the actual task/file/log result, and finishes by reinstalling the
healthy three-task chain. It deliberately interrupts monitoring, so it needs
both confirmations below. Do not run it on the competition host.

```powershell
$env:CCDC_WIN_LAB = 1
.\redteam\windows-recovery-self-test.ps1 -Config C:\ProgramData\CCDC\ccdc.env -IAcceptThisBoxIsDisposable
```

It is a repeatable proof of ordinary recovery, not a promise that an
Administrator cannot remove every task and both copies.

---

## Once you believe the box — freeze it

Do this **after** hardening, not on arrival. Blessing a box you have not
cleaned makes whatever they left behind the definition of normal, and every
drift report after that will agree the backdoor belongs there.

```powershell
.\windows\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Bless -StableForSeconds 20 -Apply
```

The 20-second quiet window is intentional. The tool takes one picture, waits,
then takes another. If a service, task, startup entry, account, listener,
firewall rule, share, WMI subscription, Defender exclusion, or executable that
Windows is set to run changes in between, it refuses to bless either picture.
It saves a short list of the changed rows under `C:\ProgramData\CCDC\state` so
you can inspect the race instead of accidentally teaching the baseline that a
new backdoor is normal. If the box is busy because of an update or a service
restart you understand, wait for it to settle and run the same command again.

Expect roughly 40 seconds: one inventory, the 20-second wait, then a second
inventory. Then, any time you want to know what has happened since:

```powershell
.\windows\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
.\windows\baseline.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Explain 4
```

**A CHANGED line is worth more of your attention than an ADDED one.** Adding
is what installers do. Changing a service's binary path, or a file that was
already there, is what somebody does to keep access.

When a change is yours, say so once and stop seeing it:

```powershell
.\windows\baseline.ps1 -Config CONFIG -Allow 'services:MyApp' -Reason 'our web app, minute 40' -Apply
```

It insists on the reason. An allowlist entry with no reason is
indistinguishable, an hour later, from something nobody ever looked at.

**Copy `C:\ProgramData\CCDC\state\baseline.json` off the box.** A baseline that
lives only where the attacker is, is a baseline the attacker can edit.

Use the evidence exporter after Guardian and baseline have written their first
records. Replace the share with a workstation or team evidence share you are
allowed to use. The ZIP includes the config, Guardian manifests, Guardian /
watchdog / integrity logs, baseline state, and the newest built-in recon and
timeline evidence cases (up to 50 MB each); the tool verifies the copied ZIP
hash before it says success.

If you have already run `recovery.ps1 -Create -Apply`, the exporter includes
that whole-kit archive and its hash files too (also capped at 50 MB). That is
the copy that still helps if both the checkout and `C:\ProgramData\CCDC` vanish.

```powershell
.\windows\evidence.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Destination \\workstation\evidence -Bundle -Apply
```

It never picks a destination or stores credentials. The share must already be
reachable, and it may contain sensitive config values, so use a team-controlled
location rather than a public or personal service. Run this exporter manually
from your elevated operator PowerShell, not as a SYSTEM task: your allowed UNC
share may use your account's network access.

Make a recovery copy of the whole kit once it is on the box. This is separate
from Guardian: Guardian repairs the small private scripts it runs, while this
recovers the checkout if its folder is deleted. It restores only into a brand
new folder, so the damaged folder remains evidence instead of being overwritten.

```powershell
.\windows\recovery.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Create -Apply
```

At any point after hardening, this one check answers whether the logs and audit
settings you need for an incident report are still usable:

```powershell
.\windows\audit.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Check
```

---

## Leave a lookout running — so you can work another box

Nothing above tells you when something NEW appears: the Guardian tasks keep the
kit and the scored service alive, and that is all. Once the box is frozen, open
a **second** elevated PowerShell on it and leave this running:

```powershell
cd C:\ccdc-training-main; Set-ExecutionPolicy -Scope Process Bypass -Force
.\windows\sentry.ps1 -Watch
```

Every two minutes it re-runs triage, the baseline comparison, the canary check
and Defender's detection list, and shouts only about what is **new** since the
last pass: a red banner, two beeps, and a popup in every session on the box —
including your RDP window while you are typing in another one.

- First pass lists what is already open, without a popup. Those are yours to
  work through with `sentry.ps1 -Status`.
- A grey `quiet` line each pass means it is alive and nothing changed.
- Green `resolved` lines appear as you fix things.
- It changes nothing. Fixing is still `sentry.ps1 -Status` / `-Approve`.
- **Do not click inside that window.** A click starts a selection and freezes
  the loop until you press Esc; the title bar then begins with "Select".

`-IntervalSeconds 60` checks more often; `-NoPopup` keeps it to the window.

## The tripwires are already laid

`arm.ps1` laid them before it installed Watchdog, so Watchdog can check them
immediately. If `arm.ps1` printed a problem, use this read-only command to see
whether the files and their audit policy are present before you re-run arm:

```powershell
.\windows\canary.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Status
```

This puts four decoy files where somebody rummaging would find them — a
`backup-credentials.txt`, a `domain admin.txt`, a `web.config.bak`, a network
diagram — and asks Windows to log every read of them.

**It detects reads, not just changes.** That is the whole point: an attacker
who opens a file called "domain admin" has already got what they came for and
has changed nothing, so a hash check would call the box clean. Windows records
the read as Security event 4663, and that event carries the **account name and
the process**.

Check the canaries whenever you have finished a change or inject:

```powershell
.\windows\canary.ps1 -Config C:\ProgramData\CCDC\ccdc.env -Check
```

Read-only, safe in a loop, exits 2 when something tripped. The installed
watchdog runs it automatically after the tripwires are laid; use this command
when you want the account and process on screen. A trip looks like this:

```
  TRIPPED  C:\Users\Public\Documents\domain admin.txt
           at 2026-09-18 08:42:56Z by Administrator
           process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Nothing legitimate reads these files.** They are not referenced by any
service and not on any path. A trip is not a maybe — take the account name and
go find out what else it did, then write the incident report while it is fresh.

Each decoy says it is a decoy on its first line, so when you find one at hour
four you will not waste a minute wondering whether it is a real credential file
you forgot about.

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
| fix it by number | `.\windows\sentry.ps1 -Config CONFIG -Status` |
| freeze a box you believe | `.\windows\baseline.ps1 -Config CONFIG -Bless -StableForSeconds 20 -Apply` |
| what changed since | `.\windows\baseline.ps1 -Config CONFIG -Status` |
| lay tripwires | `.\windows\canary.ps1 -Config CONFIG -Deploy -Apply` |
| has anything been touched | `.\windows\canary.ps1 -Config CONFIG -Check` |
| tell me when something new appears | `.\windows\sentry.ps1 -Watch` (second window) |
| record the box, read-only | `.\windows\recon.ps1 -Config CONFIG` |
| accounts and passwords | `.\windows\users.ps1 -Config CONFIG` |
| the whole hardening checklist | `.\windows\harden.ps1 -Config CONFIG` |
| just the firewall | `.\windows\harden.ps1 -Config CONFIG -Only Firewall -Apply` |
| arm canaries and the recovery chain | `.\windows\arm.ps1 -Config CONFIG -Apply` |
| basic Splunk and firewall help | [`splunk-and-firewalls.md`](splunk-and-firewalls.md) |
| know what a finding means | [`windows-cards.md`](windows-cards.md) |
| the Linux box | [`linux-first-15-minutes.md`](linux-first-15-minutes.md) |

---

## What this kit does NOT do on Windows

Said plainly, because a tool that overstates its coverage is worse than one
that does less.

- **No domain hardening.** On a domain controller `users.ps1` refuses to run and
  tells you the AD commands instead. GPO, delegation and AD ACLs are by hand.
- **The baseline is configuration, not the filesystem.** `baseline.ps1` freezes
  services, tasks, autostarts, accounts, ports, firewall rules, shares, WMI
  subscriptions and Defender exclusions, plus every executable those wire to
  run — about 250 files, nine seconds. It does **not** hash the System32 tree:
  measured, that is ~14,000 files and five minutes a pass, and Authenticode
  already answers "is this file explained?" without a baseline. A file nothing
  wires to run is not covered.
- **No tamper-proof watchdog.** Windows has a three-task chain: Watchdog keeps
  scored services running, Guardian restores Watchdog, and Continuity-Audit
  reports a missing or redirected Guardian. That catches ordinary file or task
  tampering while you are busy. An Administrator can still remove all three
  tasks and both private copies, so this is recovery and evidence—not magic.
- **Autostart coverage is deliberately bounded, not “Autoruns.”** The fallback
  covers scheduled tasks; Run/RunOnce, 32-bit, and policy Run keys; all local
  Startup folders; Winlogon; AppInit DLLs; IFEO debuggers; Active Setup; and
  permanent WMI consumers. `baseline.ps1` also freezes those rows. It does not
  cover browser or shell extensions, print monitors, LSA providers, drivers,
  or vendor-specific hooks. The optional wider inventory requires an explicitly
  configured absolute `CCDC_AUTORUNSC_PATH` to a validly Microsoft-signed
  `autorunsc.exe`; it never searches `PATH` or downloads a tool. By default it
  also will not accept the Sysinternals EULA for you. Set
  `CCDC_AUTORUNSC_ACCEPT_EULA=1` only as an intentional operator choice.
- **The approval queue applies a subset.** `sentry.ps1` acts on 21 of the 58
  checks. The rest print a command because their fix needs a judgement no
  table can hold — see the list in its `-?` help.
- **Detection is a list, not a proof.** "Nothing found" means "none of the
  things this tool looks for", never "clean".
