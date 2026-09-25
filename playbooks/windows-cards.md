# Windows remediation cards

One card per thing `windows\triage.ps1` can tell you. Each says what the
finding means, how to confirm it yourself, exactly what to run, and what to do
next — because the next thing is usually more important than the fix.

These cards are for use during the event. You can paste every command as shown
except words in `CAPITALS`; replace those first. For example, replace `NAME`
with the actual username that `triage.ps1` printed.

Run everything from an **elevated** PowerShell. Without elevation, Windows may
return an incomplete result instead of an error. For example, another user's
scheduled task may be missing from the list.

> Where a card says `CONFIG`, it means your config file — the same file the
> Linux box uses. Default: `C:\ProgramData\CCDC\ccdc.env`

---

## CARD W1 — accounts: who can log in, and who is administrator

`RED rogueadmin` · `RED newuser` · `RED nopassword` · `RED guest` · `RED scoreduser`

Start with accounts because known or default passwords give an attacker direct
access. This card helps you find accounts that can log in or administer the
box.

### The five findings, and what each one means

| finding | what it means |
|---|---|
| `rogueadmin` | an account has administrator rights and the packet does not name it |
| `newuser` | an enabled account whose password was set *after* the box was built |
| `nopassword` | an enabled account that can log on with no password at all |
| `guest` | the Guest account is enabled; it is disabled on every stock image |
| `scoreduser` | **an account the packet says must work has been disabled — that is lost points right now** |

`scoreduser` is the one to do first. It is not hardening, it is uptime.

### Find it yourself

```powershell
net localgroup Administrators
net user
Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon | Format-Table -AutoSize
```

On a **domain controller** none of the above is the whole story — there are no
local accounts there at all. Use:

```powershell
net group "Domain Admins" /domain
Get-ADUser -Filter * -Properties Enabled,PasswordLastSet,whenCreated |
    Sort-Object whenCreated -Descending | Select-Object -First 20 Name,Enabled,whenCreated
```

### Fix it

**A scored account was disabled — do this first:**
```powershell
net user NAME /active:yes
```

**An administrator that should not be one.** Take the rights, do not delete the
account: deleting it destroys the evidence of what it did, and a deleted SID
cannot be put back.
```powershell
net localgroup Administrators NAME /delete
net user NAME                                # what is it? when was it made?
```

**An account that is not supposed to exist at all:**
```powershell
net user NAME /active:no          # disable first - reversible, and it stops the login now
# only once you are sure, and never for a scored account:
net user NAME /delete
```

**Change the passwords.** This is the highest-value thing on the whole box.
Never type the password on the command line — it lands in your history and on
anyone's screen:
```powershell
net user NAME *                   # prompts, and does not echo
```

Do all of them, including service accounts, including `Administrator`. Write
them down on paper. The kit will drive this for you and keep a list of what it
changed:
```powershell
.\windows\users.ps1 -Config CONFIG                 # read the plan
.\windows\users.ps1 -Config CONFIG -RotateAll -Apply
```

### Make a second way in, before you need it

The training said this outright: *"Create a backup admin user and give them
sudo access with a different password."* The Windows version:

```powershell
.\windows\users.ps1 -Config CONFIG -CreateAdmin ops2 -Apply
```

If the red team takes your account out of Administrators, that second account
is the difference between a bad ten minutes and a lost box.

### What to do next

An account did not appear on its own. Something created it, and that something
is still there — work **CARD W2** (services), **CARD W3** (scheduled tasks) and
**CARD W4** (autostart) before you call this closed.

---

## CARD W2 — services: what you are scored on, and where they hide

`RED scoredservice` · `RED svcpath` · `AMBER svcunquoted` · `AMBER svcaccount`

A service is the most durable foothold on Windows: it survives reboot, it runs
as SYSTEM by default, and it lives in a list four hundred entries long that
nobody reads. So do not read the list — ask the three questions a legitimate
service always answers the same way.

### `scoredservice` — do this first, diagnose second

A service the packet says you are graded on is not running. **Start it, then
find out why.** Scoring is per-check; every minute spent diagnosing first is a
minute of zeros.

```powershell
Start-Service NAME
Get-Service NAME | Select-Object Name,Status,StartType

# now: why did it stop?
sc.exe qc NAME                                     # did the binary path change?
Get-WinEvent -LogName System -MaxEvents 40 | Where-Object Message -match 'NAME'
```

If it will not stay started, the binary or its config was changed. Check
**CARD W9** (backups) for a known-good copy.

### `svcpath` — running from somewhere a service never runs from

No shipped service runs out of `Temp`, `AppData`, `Downloads`, `Public` or a
user profile. A directory a normal user can write to is a directory where the
binary can be swapped for another one.

```powershell
sc.exe qc NAME
Get-Item 'PATH' | Select-Object FullName,CreationTime,Length
Get-AuthenticodeSignature 'PATH' | Select-Object Status,SignerCertificate

# evidence BEFORE you touch it
Copy-Item 'PATH' C:\ProgramData\CCDC\evidence\ -Force
Stop-Service NAME
Set-Service NAME -StartupType Disabled
```

### `svcunquoted` — the space in the path

`C:\Program Files\App\svc.exe` with no quotes: Windows tries `C:\Program.exe`
first. Anyone who can write `C:\` gets SYSTEM on the next reboot. Usually a
vendor bug rather than an attacker, which is why it is amber — and still worth
fixing, because the red team looks for it too.

```powershell
sc.exe config NAME binPath= "\"C:\Program Files\App\svc.exe\" -args"
```

### `svcaccount` — logging on as a user

A service that logs on as a named user account supplies that user's
credentials on every boot without anyone typing them. Legitimate for some
applications; also a tidy way to keep access.

```powershell
sc.exe qc NAME
net user THEACCOUNT
```

### Removing a service that is not yours

`baseline.ps1 -Status` lists it as `ADDED services NAME`; `-Explain N` prints
these same lines. Record it, stop it, delete it. The program it ran stays on
disk as evidence: hash it, and remove whatever else starts it (a Run key, a
task) before you decide what to do with the file.

```powershell
sc.exe qc NAME                  # what it runs and as whom - for the report
Stop-Service -Name NAME -Force
sc.exe delete NAME
Get-FileHash -LiteralPath 'C:\PATH\FROM\qc.exe'
```

`sentry.ps1` only restores a service's *permissions*; it never deletes one,
because a service it cannot identify might be scored.

### What to do next

If you removed a service, check that whatever installed it is gone too —
**CARD W3** and **CARD W4**. A service that comes back after you delete it
means you removed the payload and left the mechanism.

---

## CARD W3 — scheduled tasks

`RED taskcmd` · `AMBER newtask`

Persistence that needs no service and no logged-on user. Task *names* are
chosen to blend in (`GoogleUpdateTaskMachineUA`, `OneDriveSync`), so do not
read names. Read actions.

### What makes an action a payload

Any of these in a task's action, regardless of what the task is called:

- `-enc` / `-EncodedCommand` — a base64 command, which exists to be unreadable
- `DownloadString`, `DownloadFile`, `IEX`, `Invoke-Expression`
- `-w hidden` / `-WindowStyle Hidden`
- anything executing out of `\Temp\`, `\AppData\`, `\Public\`
- `mshta`, `certutil -urlcache`, `rundll32 ... javascript:`

### Find it yourself

```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    Select-Object TaskPath,TaskName,State | Format-Table -AutoSize

# the whole definition, which is where the action is
Export-ScheduledTask -TaskName 'NAME' -TaskPath '\'
```

Without the ScheduledTasks module:
```cmd
schtasks /query /fo LIST /v | more
```

### Decode what it actually runs

If you find `-enc`, decode it before you delete it — the decoded text is the
evidence, and it usually names an address:

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PASTE_THE_BASE64'))
```

### Fix it

```powershell
Export-ScheduledTask -TaskName 'NAME' -TaskPath '\PATH\' |
    Out-File C:\ProgramData\CCDC\evidence\task-NAME.xml     # evidence first
Disable-ScheduledTask -TaskName 'NAME' -TaskPath '\PATH\'
Unregister-ScheduledTask -TaskName 'NAME' -TaskPath '\PATH\' -Confirm:$false
```

### What to do next

The task ran something. Find that file, preserve it, remove it — and find what
*created the task*, which is the part that brings it back.

### `webshell` — web root backdoors (IIS / W3SVC)

When IIS is running, an attacker can drop an `.aspx`, `.ashx`, or `.php` file in `C:\inetpub\wwwroot` that executes system commands over HTTP without authentication. A filename or one suspicious-looking line is a lead, not permission to delete a real application handler: preserve and read it first.

Find and remove:
```powershell
# List executable scripts placed in web root
Get-ChildItem -Path C:\inetpub\wwwroot -Recurse -File |
    Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize

# Search for execution patterns (cmd.exe, powershell, eval, ProcessStartInfo)
Select-String -Path C:\inetpub\wwwroot\* -Pattern 'eval\(|ProcessStartInfo|cmd\.exe|powershell'

# Preserve the suspected file before making a removal decision
$suspect = 'C:\inetpub\wwwroot\cmd.aspx'
Get-FileHash -Algorithm SHA256 -LiteralPath $suspect
Copy-Item -LiteralPath $suspect -Destination C:\ProgramData\CCDC\evidence\ -Force
Get-Content -LiteralPath $suspect -TotalCount 80

# Only after the packet/application owner confirms it is not needed:
# Remove-Item -LiteralPath $suspect -Force
```

---

## CARD W4 — autostart, registry, and the login-screen backdoors

`RED runkey` · `RED ifeo` · `RED winlogon` · `RED startupfile`

Everything on this card runs without anyone logging in, or the instant somebody
does.

### `ifeo` — the one to know by heart

"Image File Execution Options" lets you attach a debugger to a program. The
debugger runs **instead of** the program, as whoever launched it. Attach
`cmd.exe` to `sethc.exe` and five presses of Shift at the lock screen is a
SYSTEM shell with no password.

There is no legitimate reason for one of these on a competition box.

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
    ForEach-Object {
        $d = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($d) { "{0} -> {1}" -f $_.PSChildName, $d }
    }

Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger
```

The other half of the same trick is replacing the binary outright. Check:
```powershell
Get-FileHash C:\Windows\System32\sethc.exe,C:\Windows\System32\utilman.exe,C:\Windows\System32\osk.exe
Get-AuthenticodeSignature C:\Windows\System32\sethc.exe | Select-Object Status
```
A `NotSigned` or `HashMismatch` status on a System32 binary is conclusive.

### `winlogon` — one appended comma

Stock `Userinit` is exactly `C:\Windows\system32\userinit.exe,`. Anything after
that comma runs at every interactive logon. Stock `Shell` is exactly
`explorer.exe`.

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
    Select-Object Userinit,Shell

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
    -Name Userinit -Value 'C:\Windows\system32\userinit.exe,'
```

### `runkey` — the ordinary autostart

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'NAME'
```

Also worth one look each, because they are autostart too and nobody checks them:

```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User
Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

### What to do next

Autostart entries come in pairs with something else. Work **CARD W3** and
**CARD W2**, then re-run triage — if the entry is back, you removed the payload
and left what writes it.

---

## CARD W5 — processes and listening ports

`RED netproc` · `RED tmpproc` · `AMBER listener`

From the training: *"If a process is listening on a port, people can reach it
from outside your computer."*

### `netproc` — an interpreter holding a port

`powershell.exe`, `cmd.exe`, `python.exe`, `wscript`, `mshta` listening on a
port is a bind shell until proven otherwise. A real service is a real service
binary.

**Read the command line before you kill it. The command line is the evidence.**

```powershell
Get-CimInstance Win32_Process -Filter 'ProcessId=PID' |
    Select-Object ProcessId,ParentProcessId,CommandLine | Format-List

Get-NetTCPConnection -OwningProcess PID | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State

Stop-Process -Id PID -Force
```

Then find the **parent**. The parent is how it comes back.

### `tmpproc` — running from a temporary directory

Installers do this for a few seconds. Nothing legitimate does it for long.

```powershell
Get-CimInstance Win32_Process -Filter 'ProcessId=PID' | Format-List ProcessId,ParentProcessId,CommandLine,CreationDate
Copy-Item 'THE_EXE' C:\ProgramData\CCDC\evidence\ -Force      # evidence FIRST
Stop-Process -Id PID -Force
Remove-Item 'THE_EXE' -Force
```

### `listener` — a port the packet does not name

You cannot remove a port; you act on whatever holds it. **Block it at the
firewall before you kill anything** — a firewall rule is reversible in one
command and a killed process is not.

```powershell
Get-Process -Id PID | Select-Object Name,Path,StartTime
New-NetFirewallRule -DisplayName 'CCDC block PORT' -Direction Inbound -LocalPort PORT -Protocol TCP -Action Block
```

If it turns out to be a service you are scored on, put the port in
`CCDC_ALLOWED_TCP_PORTS` in your config and remove the block rule.

### Find it yourself

```powershell
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress,LocalPort,OwningProcess,
        @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object LocalPort | Format-Table -AutoSize
```
Or, on any Windows ever made:
```cmd
netstat -ano -p TCP | findstr LISTENING
```

---

## CARD W6 — Defender

`RED defenderoff` · `RED defenderexcl` · `AMBER defendersig`

From the training: *"Red Team likes to mess with this, such as setting
exclusion paths."*

**An exclusion is better than turning Defender off, from their point of view,
because the icon stays green.** A directory quietly stops being scanned and
nothing on the desktop looks wrong.

On a competition box the correct number of exclusions is almost always zero.

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,AntivirusSignatureAge
Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension

# turn it back on
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false

# remove an exclusion
Remove-MpPreference -ExclusionPath 'C:\THE\PATH'

# look at what was parked in it before you forget
Get-ChildItem -Recurse 'C:\THE\PATH' -ErrorAction SilentlyContinue |
    Select-Object FullName,CreationTime,Length | Sort-Object CreationTime -Descending

# then scan
Update-MpSignature
# error 0x8024402c / 0x80072ee7: no route to the update server. No internet -
# nothing to do. Internet up but a domain policy points at WSUS - go direct:
Update-MpSignature -UpdateSource MicrosoftUpdateServer
# "completed with errors" on an old Server 2016 image (2016-era definitions):
# straight from the Malware Protection Center, which worked where both failed
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate -MMPC
Start-MpScan -ScanType QuickScan
```

The GUI tells you the same thing and is faster to read under pressure:
**Start → Windows Security → Virus & threat protection → Manage settings →
Exclusions.**

If the Defender module is missing entirely, that is itself worth a look: either
a third-party AV displaced it, or somebody removed it.

```powershell
Get-Service WinDefend | Select-Object Status,StartType
```

---

## CARD W7 — firewall

`RED fwoff` · `RED fwinbound` · `AMBER fwlog` · `AMBER fwallow`

From the training: *"If attackers can communicate with your box at all, they're
going to get in. A firewall is the most effective thing we're going to do to
stop them."*

### The three things that have to be true

1. **All three profiles on.** Domain, Private, Public. A box moves between them
   without telling you, and the one that is off is the one that matters.
2. **Default inbound = Block.** Otherwise every rule you write is a patch over
   a hole rather than an exception to a wall.
3. **Logging on.** Without it you cannot answer *"what did they try"* in the
   incident report, and incident reports are worth points.

```powershell
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked

Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -LogBlocked True -LogMaxSizeKilobytes 16384
```

Or, where PowerShell has no NetSecurity module:
```cmd
netsh advfirewall show allprofiles
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

### Back it up FIRST, and back it up again after

The training said to export before changing. Do it — a bad rule set is a
five-second restore instead of a rebuild:

```powershell
netsh advfirewall export C:\ProgramData\CCDC\backup\firewall-before.wfw
# ... make changes ...
netsh advfirewall export C:\ProgramData\CCDC\backup\firewall-after.wfw
# and to undo:
netsh advfirewall import C:\ProgramData\CCDC\backup\firewall-before.wfw
```

### `fwallow` — an inbound allow rule for a port nobody asked for

```powershell
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    ForEach-Object {
        $p = ($_ | Get-NetFirewallPortFilter).LocalPort
        if ($p -and $p -ne 'Any') { "{0}  {1}  {2}" -f $_.DisplayName, $p, $_.Profile }
    }

Disable-NetFirewallRule -DisplayName 'THE RULE'
```

### The trap that costs a scored service

**Outbound rules break things you did not expect.** Windows allows most
outbound by default; a deny-all-outbound policy will stop a scored service
talking to its database and you will spend twenty minutes finding out why.
Change outbound last, and only with a scored check running.

### Order matters when you cannot see the box

If you are working over RDP or SSH, **make sure your own access rule exists
before you set default-inbound to Block.** This is the single most common way
to lock yourself out:

```powershell
New-NetFirewallRule -DisplayName 'CCDC allow RDP' -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName 'CCDC allow SSH' -Direction Inbound -LocalPort 22   -Protocol TCP -Action Allow
```

---

## CARD W8 — logging

`RED logcleared` · `AMBER psloggingoff`

Half your points are injects, and **incident reports earn points**. You cannot
write one from logs that were cleared or never turned on.

### `logcleared` — the Security log was cleared

Event ID **1102**. Nothing legitimate clears the Security log during an event.
Everything before that timestamp is gone.

**A cleared log is itself a reportable incident.** Put the timestamp in the
report — "at 11:42 the Security log was cleared, so the record before that time
does not exist" is a finding, not an apology.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 | Format-List TimeCreated,Message
Get-WinEvent -LogName Security -MaxEvents 5 | Select-Object TimeCreated,Id   # is it logging NOW?
```

### `psloggingoff` — script block logging

The highest-value log on Windows, and off by default. With it on, **every**
PowerShell command run on the box lands in
`Microsoft-Windows-PowerShell/Operational` as event **4104** — including theirs,
including decoded `-enc` payloads.

```powershell
.\windows\harden.ps1 -Config CONFIG -Only Logging -Apply   # this and the rest of the logging setup
```

By hand:
```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1
```

### The event IDs worth knowing

| ID | what it is |
|---|---|
| 4624 / 4625 | logon succeeded / failed — `LogonType 3` is network, `10` is RDP |
| 4720 | a user account was created |
| 4728 / 4732 | account added to a global / local group — **this is privilege escalation** |
| 4672 | special privileges assigned at logon — an admin logon |
| 7045 | **a service was installed** — one of the highest-signal events on Windows |
| 4698 | a scheduled task was created |
| 1102 | the Security log was cleared |
| 4104 | PowerShell script block executed |

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4728,4732,4672} -MaxEvents 50 |
    Select-Object TimeCreated,Id,Message | Format-List

Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 |
    Select-Object TimeCreated,Message | Format-List
```

### Turn the auditing on that is off by default

```powershell
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
# and include the command line with process creation - this is the good one:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## CARD W9 — backups, and getting a service back

Not a triage finding — the thing you wish you had done an hour ago.

```powershell
.\windows\harden.ps1 -Config CONFIG -Only Backup -Apply  # config, firewall, users, service definitions
```

There is no separate `backup.ps1`: the `Backup` step inside `harden.ps1` is
the kit command that makes these local restore copies.

The training warned that backups get attacked too. So:

- keep one copy **off the box** (your laptop, another VM)
- keep a **hash** of what you backed up, so you can tell whether the copy changed
- a revert **costs points** — restoring one file does not. Prefer the file.

```powershell
netsh advfirewall export C:\ProgramData\CCDC\backup\firewall.wfw
reg export HKLM\SYSTEM\CurrentControlSet\Services C:\ProgramData\CCDC\backup\services.reg /y
Get-LocalUser | Export-Csv C:\ProgramData\CCDC\backup\users.csv -NoTypeInformation
secedit /export /cfg C:\ProgramData\CCDC\backup\secpol.inf
```

---

## CARD W10 — RDP, SSH, and broadcast poisoning (LLMNR / NetBIOS)

`RED rdpnla` · `AMBER llmnr` · `AMBER netbios`

The remote access controls that keep attackers out of your console, and the
broadcast protocols that leak credentials across the local subnet.

```powershell
# is RDP on, and does it require Network Level Authentication?
Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication

# require NLA - this alone stops a large class of unauthenticated RDP exploits
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1

# enable RDP Restricted Admin mode (prevents credentials being harvested from memory if RDP is compromised)
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -Value 0 -Type DWord

# who is allowed to use RDP?
net localgroup "Remote Desktop Users"

# who is connected RIGHT NOW - the Windows version of `who`
query user
quser
```

**Kicking somebody off.** The Linux training covered `pkill -t pts/X`; this is
the same move:
```powershell
query user                       # note the ID column
logoff ID
```

If RDP is **not** scored and not how you are working, turn it off:
```powershell
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
```

### Broadcast poisoning (Responder / Inveigh hash theft)

When Windows fails to resolve a hostname over DNS, it broadcasts to the local subnet
via LLMNR (UDP 5355) and NetBIOS (UDP 137). An attacker running Responder answers these
broadcasts instantly and captures your NTLMv2 challenge-response hashes.

```powershell
# Disable LLMNR multicast resolution:
$dnsKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (-not (Test-Path -LiteralPath $dnsKey)) { New-Item -Path $dnsKey -Force | Out-Null }
Set-ItemProperty -Path $dnsKey -Name EnableMulticast -Value 0 -Type DWord

# Disable NetBIOS over TCP/IP across active adapters:
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
    ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } }
```

---

## CARD W11 — service permissions, and WMI persistence

These are the two that pass every other card. A service here can have the right
path, be properly quoted, run as a stock account, and still be a one-command
takeover. A WMI subscription is not a file, a service, a task or a run key, so
W2, W3, W4 and W5 all miss it.

### `svcacl` — a service ordinary users may reconfigure

A service's permissions say who may **change** it, which is a different question
from who it runs as.

```powershell
# what the kit found, in full
sc.exe sdshow SERVICE

# every service, so you can see the shape of a normal one
Get-Service | ForEach-Object { "$($_.Name): $(sc.exe sdshow $_.Name)" }
```

Read the SDDL by field, not by eye. Each `(...)` is one ACE:

```
(A ; ; CCDCLCSWRPWPDTLOCRSDRCWDWO ; ; ; AU)
 ^     ^                                ^
 allow rights                           who
```

The rights that matter, and the reason:

| Code | Means | Why it is a takeover |
|---|---|---|
| `DC` | change config | point it at your binary, restart it |
| `WD` | write DAC | grant yourself `DC`, then do the above |
| `WO` | write owner | take ownership, then rewrite the DAC |
| `SD` | delete | remove a scored service outright |

**`WD` is two different things depending on which field it is in.** In the
rights field it is WRITE_DAC. In the *who* field it is Everyone. Reading the
ACE as one string gets this wrong.

Principals to worry about: `AU` Authenticated Users, `BU` Users, `IU`
Interactive, `WD` Everyone, `AN` Anonymous.

**Fix — put back the stock DACL:**
```powershell
sc.exe sdset SERVICE "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
```
That is: SYSTEM may run it, Administrators may do anything, Interactive and
Service may look. Verify with `sc.exe sdshow SERVICE`.

### `svcdiracl` — the same takeover, without touching the service

If you can write into the directory a service binary lives in, you replace the
`.exe` and wait for a restart. **No service configuration changes**, so
anything watching service config sees nothing.

```powershell
icacls "C:\path\to\dir"
icacls "C:\path\to\dir" /remove:g "BUILTIN\Users"
icacls "C:\path\to\dir" /remove:g "Everyone"
```

`(OI)(CI)M` means Modify, inherited by files and folders. On a directory that
service binaries run from, for a group like Users, that is the finding.

### `wmisub` — persistence nothing else on this page finds

Three objects in `root\subscription`: a **filter** (the trigger), a **consumer**
(the payload) and a **binding** joining them.

```powershell
# the payload
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer |
    Format-List Name, CommandLineTemplate
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer |
    Format-List Name, ScriptText

# the trigger - READ THIS BEFORE DELETING, it is incident-report material
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
    Format-List Name, Query

# what is wired to what
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
    Format-List Filter, Consumer
```

**Remove all three, or it comes back.** A binding whose consumer is gone is
harmless, but a filter and consumer left behind can be re-bound in one command.

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
    Where-Object { $_.Consumer -match 'NAME' } | Remove-CimInstance
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer |
    Where-Object { $_.Name -eq 'NAME' } | Remove-CimInstance
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
    Where-Object { $_.Name -eq 'NAME' } | Remove-CimInstance
```

The query in the filter tells you **what they were waiting for** — a logon, a
process starting, a time of day. Write that down before you delete it.

---

## CARD W12 — SMB: shares, signing, and SMBv1

On Linux, file sharing is a daemon you can uninstall. Here it is the operating
system, and it is listening whether you think about it or not.

```powershell
Get-SmbServerConfiguration | Format-List EnableSMB1Protocol, RequireSecuritySignature, EnableSecuritySignature
Get-SmbShare
Get-SmbSession          # who is connected right now
Get-SmbOpenFile         # what they have open
```

### `smbv1`

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```
Nothing made this decade needs it. If a finding says it is on, somebody either
turned it on or left it on.

### `smbsign`

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```
Without signing, an attacker who can make any machine authenticate to them
**relays** that authentication here and acts as that account. Nothing is
cracked, and no password is ever learned. This is the single highest-value SMB
setting on the box.

### `share` — a share anyone can write to

```powershell
Get-SmbShareAccess -Name NAME
Revoke-SmbShareAccess -Name NAME -AccountName 'Everyone' -Force
Remove-SmbShare -Name NAME -Force           # if nothing needs it
```

Shares ending in `$` (`C$`, `ADMIN$`, `IPC$`) are administrative and normal —
the kit skips them. A **named** share granting `Everyone` or `Authenticated
Users` Full or Change is the finding. If anything on that path is ever
executed, that is remote code execution with no credential at all.

**Kicking somebody off a share:**
```powershell
Get-SmbSession | Format-Table SessionId, ClientComputerName, ClientUserName
Close-SmbSession -SessionId ID -Force
```

---

## CARD W13 — credentials sitting in memory

**This card has no Linux equivalent.** On Linux a password is a hash in
`/etc/shadow` and an attacker has to crack it. Here it is also material in LSASS
that a local administrator can read and **replay on another machine** without
ever learning the password.

That is why one compromised Windows box becomes all of them, and why these
three settings are worth more than their size suggests.

### `wdigest` — cleartext passwords in memory

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0
```

**Nothing legitimate needs this.** It has been off by default since 2012 R2, so
finding it on means somebody turned it on, and the only reason to is to read
plaintext passwords out of memory.

If you find it on: **every password used on this box since then is theirs.**
Rotate, and say so in the incident report.
```powershell
.\windows\users.ps1 -Config CONFIG -RotateAll -Apply
```

### `lsappl` — LSA not running protected

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
```

Makes the ordinary ways of reading LSASS fail, and logs the attempt.

**Needs a reboot.** Decide in the first fifteen minutes or not at all — do not
reboot a scored box at minute 50 for a hardening nicety.

### `nullsession` — anonymous account enumeration

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1 -Type DWord
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous    -Value 1 -Type DWord
```

This is how an unauthenticated host on your segment gets the user list it is
about to spray passwords against.

### What you cannot fix from here

Pass-the-hash works even with all three set correctly — the hash is a valid
credential by design. What actually limits it is not reusing the local
Administrator password across machines. If you have time and more than one
Windows box, make them different:

```powershell
.\windows\users.ps1 -Config CONFIG -Rotate Administrator -Apply
```

---

## The order to work these in

1. **W1 `scoreduser`** and **W2 `scoredservice`** — anything scored that is down. Points, right now.
2. **W1** — passwords, rogue admins, backup admin.
3. **W7** — firewall on, default deny inbound, and *your own access rule first*.
4. **W6** — Defender back on, exclusions gone.
5. **W8** — logging on, before you need it.
6. **W4, W3, W2** — the persistence hunt: autostart, tasks, services.
7. **W11** — service permissions and WMI. These pass every check above, so they
   are the ones still standing after a hunt that looked successful.
8. **W13** — WDigest off. One registry write, and it decides whether a
   compromise here becomes a compromise everywhere.
9. **W12** — SMB signing and any share granting Everyone.
10. **W5** — processes and ports.
11. **W9** — back up what you now have.

W13's `RunAsPPL` is the one item with a reboot attached. Do it in the first
fifteen minutes or leave it — a reboot late in the round costs uptime, and
uptime is half the score.

Then re-run triage. Anything that came back is a mechanism you have not found
yet, and that is the most important sentence on this page.
