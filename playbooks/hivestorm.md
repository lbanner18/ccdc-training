# HIVESTORM — Tuesday 2026-11-17, 7–9 PM, CTB 365

Two images, one Windows, one Linux. **No red team.** A scoring engine on each
image awards points for fixes and forensic answers, and **takes points away**
for breaking what the README requires. Two hours, so work in score order.

## What changes from the CCDC kit

| CCDC tryout | HIVESTORM |
|---|---|
| packet's scored accounts | **README on the Desktop**: authorized admins, users, critical services |
| Quotient checks services | the engine checks the README's critical services |
| red team | none: sentry, guardian, canaries, watchdog, bless/arm are **not needed** |
| alex as backup admin | **never add an account.** An unlisted user costs points |
| policy.sh "print, don't apply PAM" | **apply it by hand.** Password, lockout and aging policy are points |
| — | **forensic questions** on the Desktop, worth points, answered in their file |
| — | **the scoring engine** runs on the box. Never kill it, block it or remove it |

## 0. First five minutes, per image (no tools yet)

1. Open the **README**. On paper: admins / standard users / critical services /
   anything it says not to touch.
2. Open the **Score Report** shortcut and note what it is (process / service /
   scheduled task). That one is off-limits to every "kill / remove / disable" fix.
3. Read the **Forensic Questions**. Answer the easy ones NOW. Any question about a
   file, user, process or package must be answered **before** you remove it.
   Leave the question text intact; fill in only the ANSWER line.

## 1. Linux image

```bash
cd ~ && git clone https://github.com/lbanner18/ccdc-training && cd ccdc-training   # or the tar.gz line from tryout-day.md
chmod +x linux/*.sh
CFG=/tmp/ccdc-linux.env; sudo cp config/hivestorm-linux.env "$CFG" && sudo chmod 600 "$CFG"
sudo nano "$CFG"     # CCDC_ALLOWED_USERS / CCDC_ALLOWED_ADMINS / CCDC_INTERACTIVE_USERS from the README
sudo ./linux/first15.sh --phase 1
```

Phase 1 answers:
- **passwords:** `y`. Weak passwords score. Write the sheet down, and **do not
  rotate your own login** unless you have its new password on paper.
- **harden (cut list):** read it. Cutting a README critical service costs points.
- **backup admin alex: `n`.** No new accounts tonight.

Then `sudo ./linux/first15.sh --phase 2`:
- **firewall, sshd:** `y` (both score). On the image console there's no second
  tab to confirm from: confirm from a second TTY (Ctrl-Alt-F2) or `ssh localhost`.
- **0 RED, fix by number:** `a` is fine. The admin and unknown-user REDs are the points.
- **bless / arm: `n`.** That's red-team machinery.

By hand, after (each one is a usual HIVESTORM point):
```bash
sudo ./linux/policy.sh --config "$CFG"          # paste the printed edits: login.defs, pwquality, faillock
sudo apt update && sudo apt -y upgrade           # takes a while, start it in a 2nd TTY early
sudo ufw enable; sudo ufw status                 # if fw.sh refused ufw
find /home -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.ogg'    # banned media (forensics first!)
dpkg -l | grep -Ei 'john|hydra|nmap|wireshark|netcat|ophcrack|aircrack|nikto'   # hacking tools
sudo passwd -l root; grep -E '^[^:]*:[^:]*:0:' /etc/passwd   # only root has UID 0
```

## 2. Windows image

Elevated PowerShell:
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $ProgressPreference = 'SilentlyContinue'
iwr -UseBasicParsing https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.zip -OutFile C:\kit.zip
Expand-Archive C:\kit.zip C:\ -Force; cd C:\ccdc-training-main
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
mkdir C:\ProgramData\CCDC -Force | Out-Null; copy config\hivestorm-windows.env C:\ProgramData\CCDC\ccdc.env
notepad C:\ProgramData\CCDC\ccdc.env     # ALLOWED_USERS / ALLOWED_ADMINS / services from the README
.\windows\first15.ps1 -Phase 1
```

Phase 1 answers:
- **"what Quotient says is scored":** answer from the README's critical services.
- **passwords:** `y`. Write the sheet. Skip your own login.
- **hardening checklist:** read the dry run. In **Services** and **Persistence**,
  anything that is the scoring engine stays. Cut the rest.
- **backup admin alex: `n`.**

Then `.\windows\first15.ps1 -Phase 2`: fix REDs by number, then **`n`** to
canaries / self-repairing tasks / freeze / lookout.

By hand, after:
- `net user Guest /active:no`; rename/disable Administrator only if the README allows it
- Windows Update; Defender real-time protection on; firewall on for all three profiles
- `secpol.msc` → Audit Policy: success+failure on logon, account mgmt, policy change
- UAC on (`secpol` → Security Options); SMBv1 off; remove banned software from Apps
- Shares: `net share`, remove any the README doesn't need

## When stuck

Ask the hint people. That's what they're there for. The kit's cards
(`remediation-cards.md`, `windows-cards.md`) still explain every finding.
