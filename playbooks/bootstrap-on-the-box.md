# Bootstrap: from "I just logged in" to "recon is running"

Printable. This is the first three minutes, before
[`competition-day-playbook.md`](competition-day-playbook.md) §1 takes over.
Read it top to bottom and type as you go; every branch is decided by one probe.

Repo: `https://github.com/lbanner18/ccdc-training`

---

## STEP 0 — orient (30 seconds, read-only)

```bash
hostname; id; date -u
systemctl is-active <SCORED_SERVICE> 2>/dev/null || service --status-all 2>/dev/null | head
ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null
```

You want three facts: which box you are on, that you are root or can `sudo`, and
that the scored service is currently up. If the scored service is **already
down** at minute zero, fix that before anything else on this page — uptime is
scored from the first poll.

---

## STEP 1 — the probe that decides everything

One line. Its output picks your branch:

```bash
command -v git curl wget tar; timeout 5 curl -sI https://github.com >/dev/null 2>&1 && echo "EGRESS-YES" || echo "EGRESS-NO"
```

| Probe says | Go to |
|---|---|
| `EGRESS-YES` and `git` present | **1A — clone** |
| `EGRESS-YES`, no `git`, has `curl` or `wget` | **1B — tarball** |
| `EGRESS-NO` | **1C — push it from your workstation** |
| nothing works | **1D — the fallback that needs no kit** |

**Do not `apt install git`.** If apt works you already have egress, so 1A or 1B
is faster and changes nothing on the box. Installing packages at minute one is a
change you cannot tell apart from the red team's later.

### 1A — clone (preferred; CONFIRMED as the expected path for the BYU tryout)

```bash
cd ~ && git clone https://github.com/lbanner18/ccdc-training.git
cd ccdc-training && chmod +x linux/*.sh redteam/*.sh
```

If the repo is frozen under a tag for the event, clone that tag instead, so you
run exactly what was declared:

```bash
git clone --branch <FROZEN_TAG> --depth 1 https://github.com/lbanner18/ccdc-training.git
```

### 1B — tarball, no git needed

```bash
cd ~ && curl -L https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.tar.gz | tar xz
mv ccdc-training-main ccdc-training && cd ccdc-training && chmod +x linux/*.sh redteam/*.sh
```

`wget -qO- <url> | tar xz` if there is no curl.

### 1C — no egress: push it from the machine you are sitting at

**On your workstation** (the repo is already cloned there — do this before you
arrive):

```bash
cd ~/ccdc-training
tar czf - --exclude=.git . | ssh <USER>@<BOX> 'mkdir -p ~/ccdc-training && tar xzf - -C ~/ccdc-training && chmod +x ~/ccdc-training/linux/*.sh ~/ccdc-training/redteam/*.sh'
```

This is the path practised in the lab, and it needs nothing on the box but SSH.
No removable media — NCCDC rule 8.1 bans USB drives in the room.

### 1D — nothing works: the five commands that matter most

If you cannot get the kit on at all, you are not helpless — you are just slower.
These are the highest-value actions the kit automates, by hand:

```bash
# 1. see who is in and what listens
who; w; last -n 20; ss -ltnp
# 2. unauthorised accounts and UID-0
awk -F: '$3==0{print}' /etc/passwd; getent passwd | awk -F: '$7!~/(nologin|false)/{print $1,$7}'
# 3. scheduled footholds
ls -la /etc/cron.d /etc/cron.*/ 2>/dev/null; crontab -l; for u in $(cut -d: -f1 /etc/passwd); do crontab -u "$u" -l 2>/dev/null | sed "s/^/[$u] /"; done
# 4. every authorized_keys on the box
find / -name authorized_keys -not -path '*/proc/*' 2>/dev/null -exec ls -l {} \; -exec cat {} \;
# 5. SUID and recently-changed binaries
find / -perm -4000 -type f 2>/dev/null; find /usr/local/bin /usr/bin -mtime -7 -type f 2>/dev/null
```

Then rotate credentials and get the firewall right, by hand, in that order.

---

## STEP 2 — config (60 seconds)

```bash
cp config/example.env /tmp/ccdc-linux.env
vi /tmp/ccdc-linux.env
```

Fill only what you actually know from the packet. Four fields earn their keep
immediately; the rest can wait:

```
CCDC_BOX_NAME="<box>"
CCDC_SYSTEMD_SERVICES="<scored unit>"
CCDC_HTTP_CHECKS="scored|http://<scorer-visible-addr>:<port>/|<scored unit>"
CCDC_ALLOWED_TCP_PORTS="22 <scored ports>"
```

**Point the HTTP check at the address the scorer uses, not `127.0.0.1`.** A
check against localhost cannot see you firewalling off your own service, which
is the most common way to lose uptime while hardening well.

Never commit the filled copy. `*.env` is gitignored for exactly this reason.

---

## STEP 3 — prove the kit runs before you trust it (20 seconds)

```bash
./linux/recon.sh --help >/dev/null && echo "kit OK"
bash -n linux/*.sh && echo "syntax OK"
```

---

## STEP 4 — go

```bash
./linux/recon.sh --config /tmp/ccdc-linux.env      # baseline, read-only
./linux/hunt.sh  --config /tmp/ccdc-linux.env      # persistence sweep, read-only
```

Write down both evidence paths. That is your before-picture, and it is what the
incident-report inject is built from.

Now hand over to
[`competition-day-playbook.md`](competition-day-playbook.md) §1.

---

## The rules behind the branches

- **Rule 5.1** — free, public internet resources are valid for competition use.
- **Rule 5.2** — no *private* staging area; everything you pull must be
  "freely available to all other teams." A public repo satisfies this; a
  private one would not. This is why the repo is public.
- **Rule 5.6** — team-written tools must be public 3 months in advance,
  declared, and frozen. Its "no resources outside the competition environment"
  clause governs what the tools **do when they run** (no callbacks — this kit
  makes none), not how you obtain them.
- **Rule 8.1** — no USB or removable media in the room without prior
  authorisation. Hence 1C rather than a thumb drive.

Local tryouts may differ from national rules. Confirm before the event.

**BYU tryout, confirmed 2026-09-13:** GitHub scripts are fair game and the boxes
are expected to have internet to pull them. Anonymous clone and the curl
fallback were both verified against this repo the same day. The other branches
stay in this card because "should have internet" is intent, not a guarantee.
