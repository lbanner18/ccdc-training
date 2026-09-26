# Tryout day — the Mojank packet, Saturday 2026-09-26

One page, in order. Every command was run on a replica of the packet's boxes
(Ubuntu 18.04, Rocky 9 + Splunk 10.0.2, a Server 2016 domain controller).
`x` is your team number; `200+x` is its third octet (team 12 → `192.168.212.x`).

| box | public / inside | OS | log in as |
|---|---|---|---|
| bedrock | `192.168.200+x.2` / `172.16.1.1` | VyOS 2025.11 (router, 1:1 NAT) | `vyos` |
| iron | `.10` / `172.16.1.10` | Ubuntu 18.04 | `steve` |
| lapis | `.11` / `172.16.1.11` | Server 2016, domain controller | `steve` (RDP) |
| redstone | `.12` / `172.16.1.12` | Rocky 9.6 + Splunk (not scored) | `steve`; Splunk `admin` |

Scored: **HTTP, SSH, FTP, AD/DNS, POP3** — which box has which is on Quotient.

## Tonight, on your laptop

```bash
cd ~/ccdc-training && git pull
./linux/passwords.sh --generate --out ~/tryout-passwords.txt \
  --users "steve alex enderman creeper villager zombie enderdragon irongolem chickenjockey ghast"
```

Print or copy it by hand. **It never goes in the repo** (the tool refuses to
write it there). One list for every box: the same block goes into Quotient.

## 9:00 — before scoring starts

1. `auth.byuccdc.org` → note your **team number**. Connect NetBird. Open Quotient
   and **write down which service is scored on which box** — that decides
   everything below. Open Proxmox (console only; it cannot paste).
2. Never reveal your team number; inject PDFs are `teamXX_injectYY.pdf`, no real name.

## 10:00 — the first ten minutes: every default password, every box

The red team has the same packet and tries its default password everywhere first.

**iron and redstone** (`ssh steve@192.168.200+x.10`, then `.12`):
```bash
git clone https://github.com/lbanner18/ccdc-training ~/ccdc-training      # iron
cd ~ && curl -L https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.tar.gz | tar xz && mv ccdc-training-main ccdc-training   # redstone: no git there
cd ~/ccdc-training && chmod +x linux/*.sh
CFG=/tmp/ccdc-linux.env; cp config/tryout-linux.env "$CFG" && chmod 600 "$CFG"
sudo ./linux/passwords.sh --config "$CFG" --apply
```
Paste **block 1** of your sheet, press **Ctrl-D**. It sets all ten (an account a
box doesn't have is skipped and named), then logs in
to FTP and POP3 as each one to prove the services took them. Sessions still
open under the OLD password are listed; end them with the printed command, or
re-run with `--kick`. Also `sudo passwd root` (sheet section 4).

**redstone only — Splunk's admin** (the web UI is `:8000`; admin on the default
password is a remote shell for anyone). `PACKET-DEFAULT` is the packet's password:
```bash
sudo /opt/splunk/bin/splunk edit user admin -password 'NEW-FROM-SHEET' -auth 'admin:PACKET-DEFAULT'
```

**lapis** (RDP as `steve`, elevated PowerShell):
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $ProgressPreference = 'SilentlyContinue'
iwr -UseBasicParsing https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.zip -OutFile C:\kit.zip
Expand-Archive C:\kit.zip C:\ -Force; cd C:\ccdc-training-main
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
mkdir C:\ProgramData\CCDC -Force | Out-Null; copy config\tryout-windows.env C:\ProgramData\CCDC\ccdc.env
.\windows\passwords.ps1 -Apply
```
Paste **block 1**, then press Enter on an empty line. On the DC it changes the
DOMAIN accounts and proves each with an LDAP login — the way AD is scored.
Then `net user Administrator *` (sheet section 4).

**bedrock** (`ssh vyos@192.168.200+x.2`):
```
configure
set system login user vyos authentication plaintext-password 'NEW-FROM-SHEET'
commit
save
exit
```

**Quotient → Password Change Request:** paste block 1 (`user,password`, no
spaces). If it asks per box, the same block for each. **Until Quotient has
them, the scorer uses the old passwords and fails.**

## Then each box: its own flow

**Order: Phase 1 on lapis → iron → redstone, then Phase 2 on each.** Every box gets
new passwords and hardening before any box gets the deep work. Phase 1 includes
the password step; if you already did it above, answer `n` there.

**Linux** — `sudo ./linux/first15.sh --phase 1` on each box, then `--phase 2`. It
walks `playbooks/linux-first-15-minutes.md`, "Linux at a glance", and asks before
every change. By hand, the short version:
```bash
sudo ./linux/discover.sh --config "$CFG" --apply     # services, ports, checks from what runs
sudo ./linux/triage.sh --config "$CFG"
sudo ./linux/harden.sh --config "$CFG"                       # READ the list: --cut only acts on a list you have seen
sudo ./linux/harden.sh --config "$CFG" --cut all-safe --apply
id alex; sudo passwd -S alex     # backup admin = alex (packet: only listed users) - in sudo/wheel, not locked
sudo ./linux/fw.sh --config "$CFG" --apply     # then --confirm from a NEW ssh session
sudo ./linux/sshd.sh --config "$CFG" --apply   # then --confirm from a NEW ssh session
sudo ./linux/baseline.sh --config "$CFG" --bless --stable-for 20 --apply
sudo ./linux/arm.sh --config "$CFG" --apply
```

**Windows (lapis)** — `.\windows\first15.ps1 -Phase 1`, then Phase 1 on the other
boxes, then `-Phase 2`. It walks `playbooks/windows-first-15-minutes.md`, "Windows
at a glance", and asks before every change. By hand: `triage.ps1` → `harden.ps1`
then `-Apply` → check **alex** is an active Domain Admin (the packet allows only
its listed users, so no new account) → `arm.ps1 -Apply` → `baseline.ps1 -Bless
-StableForSeconds 20 -Apply` → second window: `sentry.ps1 -Watch`.

**Bedrock (VyOS router) — look, do not filter.** It does the 1:1 NAT that makes
every scored service reachable and carries Splunk forwarding to the Black Team.
One wrong filter here takes everything off the scoreboard at once; the host
firewalls already close what is not scored. Detail: `firewall-appliance.md`.

1. Password — in the 10:00 block above.
2. Save what is there, off the box: `show configuration commands` → copy to your laptop.
3. All day: `show system commit` lists every change, who and when. **A commit you
   did not make is the red team on your router.** `show system commit diff N` shows it.
4. Must change something? `commit-confirm 5` instead of `commit` - it reverts on its
   own. Check the scored services from off the box, then `confirm` and `save`.

Do NOT: a default-drop filter · `set service ssh listen-address` (lockout; the
Proxmox console cannot paste) · block any IP (rule 4).

**Splunk (redstone, not scored).** Phase 1 on redstone changes Splunk's admin
password, checks forwarding and writes one test event, then prints the search.

- Run that search in the web UI, `http://192.168.200+x.12:8000`. Found = logs arrive.
- **Never disable forwarding or block outbound** — the rules forbid it.
- For an incident report: one host, a short fixed time range, then the starter
  searches in `splunk-and-firewalls.md` (failed logins, new users, one IP).
- Re-check forwarding any time:
  `sudo ~/ccdc-training/linux/splunk.sh --config /tmp/ccdc-linux.env --test-event --apply`

## All day — the loop

- **Quotient graphs first.** Everything down at once is a firewall — yours or theirs.
- **A popup, or you come back to a box: ONE command.** It lists what is wrong, numbered, and fixes what you pick.
  - Linux: `sudo ~/ccdc-training/linux/fix.sh`
  - Windows (elevated): `powershell -ExecutionPolicy Bypass -File C:\ccdc-training-main\windows\fix.ps1`
- After fixing anything scored: check it from **off the box** (your laptop over NetBird).

## Rules that cost points if forgotten

- **No IP blocking, no scorer-only rules** (rule 4). The configs leave source filtering empty.
- **Never disable Splunk forwarding** to the Black Team indexer. Outbound stays open.
- **Never require LDAP signing on lapis** — it refuses the scorer's LDAP login.
  Triage shows it RED (`dcldapsign`) if anyone turns it on.
- A **revert** costs 100, then 200, then 400. Most breakage here has an undo:
  `fw.sh --rollback`, `sshd.sh --rollback`, `harden.sh --undo --apply`.
- **Injects are yours to write** — no AI for any part of the response. PDF, memo
  format, submit something even if incomplete; you can resubmit.

## Incident reports — where the evidence already is

- Linux: `/var/tmp/ccdc-evidence/` — `sentry.log` (what was removed, when),
  `removed/` (each item kept as evidence), `auth-log-from-journal.*` (a wiped
  auth log, rebuilt), `baseline/` (what changed since the freeze).
- Windows: `C:\ProgramData\CCDC\` — `state\findings.txt`, `backup\`, the Watch
  window's alerts. `.\windows\timeline.ps1` for a timeline.
- Write what you saw, when, how they got in, what you removed, what stops it
  next time. Screenshots of the commands above are the evidence.
