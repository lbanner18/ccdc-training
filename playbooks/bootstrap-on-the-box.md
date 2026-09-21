# Bootstrap: from "I just logged in" to "recon is running"

Printable. Use this for the first three minutes after logging in. Read it from
top to bottom. The command in Step 1 tells you which download method to use.

Repo: `https://github.com/lbanner18/ccdc-training`

---

## STEP 0 — orient (30 seconds, read-only)

```bash
hostname; id; date -u
systemctl is-active <SCORED_SERVICE> 2>/dev/null || service --status-all 2>/dev/null | head
ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null
```

You need three facts: which box this is, whether you can use `sudo`, and whether
the scored service is up. Replace `<SCORED_SERVICE>` with the service from the
packet. If it is already down, restore it before doing the download steps.

---

## STEP 1 — the probe that decides everything

Run this one command. Its last line tells you which section to use next:

```bash
command -v git curl wget tar; timeout 5 curl -sI https://github.com >/dev/null 2>&1 && echo "EGRESS-YES" || echo "EGRESS-NO"
```

| Probe says | Go to |
|---|---|
| `EGRESS-YES` and `git` present | **1A — clone**. You can reach GitHub and have Git. |
| `EGRESS-YES`, no `git`, has `curl` or `wget` | **1B — tarball** |
| `EGRESS-NO` | **1C — push it from your workstation**. The box cannot reach GitHub. |
| nothing useful | **1D — the fallback that needs no kit** |

**Prefer 1B over installing git.** If a package manager works you already have
egress, so the `curl | tar` path gets the same files in one command, installs
nothing, and leaves no change on the box you would later have to tell apart from
the red team's.

But if you do want git — it is genuinely useful for pulling an update mid-event,
and `curl`/`wget` may both be missing — this is the exact line for each family:

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y git
# RHEL / Rocky / CentOS / Fedora
sudo dnf install -y git   ||  sudo yum install -y git
# Alpine
sudo apk add --no-cache git
# SUSE
sudo zypper --non-interactive install git
```

Check first — it is usually already there:

```bash
command -v git || echo "no git"
```

### 1A — clone   `RUN ON: the box`   (CONFIRMED as the expected path for the BYU tryout)

```bash
cd ~ && git clone https://github.com/lbanner18/ccdc-training.git
cd ccdc-training && chmod +x linux/*.sh redteam/*.sh
```

If the repo is frozen under a tag for the event, clone that tag instead, so you
run exactly what was declared:

```bash
git clone --branch <FROZEN_TAG> --depth 1 https://github.com/lbanner18/ccdc-training.git
```

### 1B — tarball, no git needed   `RUN ON: the box`

```bash
cd ~ && curl -L https://github.com/lbanner18/ccdc-training/archive/refs/heads/main.tar.gz | tar xz
mv ccdc-training-main ccdc-training && cd ccdc-training && chmod +x linux/*.sh redteam/*.sh
```

`wget -qO- <url> | tar xz` if there is no curl.

### 1C — no egress: push from your workstation   `RUN ON: your workstation, NOT the box`

**On your workstation** (the repo is already cloned there — do this before you
arrive):

```bash
cd ~/ccdc-training
tar czf - --exclude=.git . | ssh <USER>@<BOX> 'mkdir -p ~/ccdc-training && tar xzf - -C ~/ccdc-training && chmod +x ~/ccdc-training/linux/*.sh ~/ccdc-training/redteam/*.sh'
```

**The mistake everyone makes once:** running this inside your SSH session, on
the box. The box usually has an `authorized_keys` (that is how you got in) but
no private key, so it cannot SSH out to anything — including itself — and you
get `Permission denied (publickey)`. If you see that error, you are on the wrong
machine. Open a SECOND terminal on your workstation and run it there; leave the
SSH session alone.

Substitute the placeholders before you run it. `<USER>@<BOX>` typed literally
fails differently and more confusingly.

This is the path practised in the lab, and it needs nothing on the box but SSH.
No removable media — NCCDC rule 8.1 bans USB drives in the room.

### 1D — nothing works: the five commands that matter most   `RUN ON: the box`

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

## How you reach the box changes which branches exist

Two very different things get called "web access to the instance":

**(a) A portal that hands you an address and credentials**, and you SSH to the
box yourself from your own machine. Everything on this card works. 1C is
available as a fallback because there is a real network path from your machine
to the box.

**(b) A browser console** (noVNC, Guacamole, a web terminal) where the browser
is the *only* way in. Then there is **no network path from your laptop to the
box at all**, so 1C is impossible no matter what you type — `scp`, `tar | ssh`
and `rsync` all need that path. On a browser console:

- Box egress + `git clone` (1A) is not the convenient option, it is the only
  practical one.
- With no egress you are down to 1D and the clipboard. Browser consoles usually
  paste, often badly; a whole repo is not realistically pasteable, one script
  is.
- So find out whether the box has egress **before** the clock starts, because
  under (b) the answer determines whether you have tooling at all.

Confirm which one you have. It is a thirty-second question with a large blast
radius.

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
