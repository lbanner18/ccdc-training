# Tryout day — the Mojank packet, Saturday 2026-09-26

One page, in order. The Linux and Windows flows were rehearsed on replicas of
the packet's boxes (Ubuntu 18.04, Rocky 9 + Splunk, a Server 2016 domain
controller). The VyOS commands were NOT - the lab has no router; they are
standard commands, check each against the box in front of you.
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

1. `auth.byuccdc.org` → note your **team number**. Connect NetBird. Open Proxmox
   (console only; it cannot paste).
2. Open Quotient and **write this on paper** — the runners ask you about it:
   ```
   iron:     ____________      (of HTTP SSH FTP POP3)
   lapis:    AD/DNS  ______    (HTTP? FTP?)
   redstone: ____________
   ```
   Where it is used: lapis Phase 1 asks "Is HTTP / FTP scored on this box?";
   iron and redstone Phase 1 print what is running - anything on your paper that
   is missing, or listed "INSTALLED BUT NOT RUNNING", start with the printed command.
3. Never reveal your team number; inject PDFs are `teamXX_injectYY.pdf`, no real name.

## 10:00 — the first ten minutes: every default password, every box

The red team has the same packet and tries its default password everywhere first.

**iron and redstone** (`ssh steve@192.168.200+x.10`, then `.12`):
```bash
git clone https://github.com/lbanner18/ccdc-training ~/ccdc-training      # iron
cd ~ && curl -L https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.tar.gz | tar xz && mv ccdc-training-main ccdc-training   # redstone: no git there
cd ~/ccdc-training && chmod +x linux/*.sh
CFG=/tmp/ccdc-linux.env; sudo cp config/tryout-linux.env "$CFG" && sudo chmod 600 "$CFG"
sudo ./linux/passwords.sh --config "$CFG" --apply
```
Paste **block 1** of your sheet, press **Ctrl-D**. It sets all ten (an account a
box doesn't have is skipped and named), then logs in
to FTP and POP3 as each one to prove the services took them. Sessions still
open under the OLD password are listed; end them with the printed command, or
re-run with `--kick`. Also `sudo passwd root` (sheet section 4).
**From here, `sudo` on these boxes wants steve's NEW password** (his block 1 line).

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
hardening before any box gets the deep work. The runner asks before every change,
and the **green box at the end of each phase says exactly what to run next.**

| | Phase 1 | Phase 2 |
|---|---|---|
| iron, redstone | `sudo ~/ccdc-training/linux/first15.sh --phase 1` | `sudo ~/ccdc-training/linux/first15.sh --phase 2` |
| lapis | `.\windows\first15.ps1 -Phase 1` | `.\windows\first15.ps1 -Phase 2` |

What the runners ask of you:

- **Password step:** you already did it at 10:00 - answer `n`.
- **Quotient questions / the service table:** answer from your paper.
- **Linux Phase 2, firewall and SSH:** have a SECOND tab at a prompt first. When it
  says "applied", ssh in from that tab and paste the one line it prints - 2 minutes.
  Then press Enter in the runner; it tells you "kept" or "rolled back".
- **The fix list:** `a` = fix every RED, a number = that one item, Enter = done.
- **Bless:** only at 0 RED - and **read every AMBER first.** Whatever is on the box
  when you bless counts as normal from then on.

If a runner breaks, the by-hand steps are in `linux-first-15-minutes.md` and
`windows-first-15-minutes.md` ("at a glance").

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

**Splunk (redstone, not scored).** Its admin password is in the 10:00 block. Phase
1 on redstone then checks forwarding, writes one test event and prints the search.

- Run that search in the web UI, `http://192.168.200+x.12:8000`. Found = logs arrive.
- **Never disable forwarding or block outbound** — the rules forbid it.
- For an incident report: one host, a short fixed time range, then the starter
  searches in `splunk-and-firewalls.md` (failed logins, new users, one IP).
- Re-check forwarding any time:
  `sudo ~/ccdc-training/linux/splunk.sh --config /tmp/ccdc-linux.env --test-event --apply`

## All day — the loop

- **A popup, or you come back to a box: ONE command.** It lists what is wrong, numbered, and fixes what you pick.
  - Linux: `sudo ~/ccdc-training/linux/fix.sh`
  - Windows (elevated): `powershell -ExecutionPolicy Bypass -File C:\ccdc-training-main\windows\fix.ps1`
- **Quotient first.** One service red → that box: run `fix`. Everything red at once →
  a firewall: yours (a change that did not roll back) or the router's.
- **Bedrock, every so often:** `show system commit` - a commit you did not make is the red team.
- After fixing anything scored: check it from **off the box** (your laptop over NetBird).
- Locked out after a firewall/SSH change? Do nothing for 2 minutes - it rolls itself back.

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
