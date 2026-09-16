# Packet → config, two days early

You get the packet before the event. That is the whole ballgame: every
judgement this kit makes comes out of one file, and if that file is filled in
before the clock starts, competition day stops being a series of decisions and
becomes a series of executions.

This is the worksheet for filling it. Work down it once, at a desk, with the
packet open. It takes about twenty minutes.

```bash
cp config/example.env ~/ccdc-real.env     # OUTSIDE the repo. Never commit it.
```

> **Why this file matters more than any script here.** `sentry.sh` refuses to
> act at all while `CCDC_ALLOWED_USERS` and `CCDC_SYSTEMD_SERVICES` are empty.
> That is deliberate: an empty protect list does not mean "nothing is
> protected", it means nobody has told the tool what is scored. Every "is this
> port expected", "is this account protected", "is this interpreter a scored
> service or a bind shell" traces back to a line you write here.

---

## 1. Who and what is scored

| The packet says | Fill in | If you get it wrong |
|---|---|---|
| Accounts that must keep working (incl. yours and any the scorer uses) | `CCDC_ALLOWED_USERS` | The kit offers to disable a scored account, or refuses to touch a rogue one |
| Services that are scored for uptime | `CCDC_SYSTEMD_SERVICES` | The watchdog holds up nothing; `arm.sh` preflight warns |
| Ports the scorer connects to | `CCDC_ALLOWED_TCP_PORTS`, `CCDC_ALLOWED_UDP_PORTS` | Every scored port is reported as an unexpected listener, forever |

```bash
CCDC_ALLOWED_USERS="root youradmin websvc"
CCDC_SYSTEMD_SERVICES="nginx mysql"
CCDC_ALLOWED_TCP_PORTS="22 80 443"
CCDC_ALLOWED_UDP_PORTS=""
```

**The UDP list is usually empty and that is fine** — triage allows the handful
of ports a stock install binds, plus the kernel's ephemeral range.

---

## 2. How the scorer reaches you

This is the single most common way to lose uptime while hardening well.

| The packet says | Fill in |
|---|---|
| The scoring engine's address / the URL it checks | `CCDC_HTTP_CHECKS`, `CCDC_TCP_CHECKS` |

```bash
CCDC_HTTP_CHECKS="
web|http://10.0.0.25:80/|nginx
"
CCDC_TCP_CHECKS="
ssh|10.0.0.25|22
db|10.0.0.25|3306|mysql
"
```

> **Use the address the scorer uses, never `127.0.0.1`.** A localhost probe
> cannot see you firewalling off your own service. `arm.sh --dry-run` warns
> about this, because it has happened.

Format is `name|host|port|unit` (TCP) and `name|url|unit` (HTTP). The unit
field is what gets restarted when the probe fails; leave it empty to log only.

---

## 3. The number that decides your downtime

```bash
CCDC_WATCHDOG_INTERVAL="5"
```

Your mean outage is roughly half this. Measured on the lab box against an
external scorer: the same killed service cost **57 seconds at 60, and 6 seconds
at 5**. A pass is a curl and two systemctl calls. Set it to 5.

---

## 4. SSH policy

Every value is optional and empty means "leave what the box already does
alone". Decide these now; on the day you only execute them.

```bash
CCDC_SSH_PERMIT_ROOT_LOGIN="no"
CCDC_SSH_PERMIT_EMPTY_PASSWORDS="no"
CCDC_SSH_MAX_AUTH_TRIES="4"
CCDC_SSH_LOGIN_GRACE="30"
CCDC_SSH_X11_FORWARDING="no"
CCDC_SSH_ROLLBACK_SECONDS="120"
CCDC_SSH_PASSWORD_AUTH=""        # <- READ THE NEXT PARAGRAPH
CCDC_SSH_ALLOW_USERS=""          # <- AND THIS ONE
```

**Leave `CCDC_SSH_PASSWORD_AUTH` empty** unless the packet explicitly says
key-only. If the scoring engine logs in with a password, turning password auth
off is downtime you caused. `sshd.sh` refuses to set it to `no` when no allowed
account has a working `authorized_keys`, but it cannot know what the scorer
does.

**`CCDC_SSH_ALLOW_USERS` is powerful and easy to get wrong.** It must include
every account that logs in, *including any the scorer uses*. `sshd.sh` refuses
an `AllowUsers` that omits the account you are running as, but it cannot refuse
one that omits the scorer. Leave it empty unless the packet makes the full list
unambiguous.

---

## 5. Logging

| The packet says | Fill in |
|---|---|
| The Splunk indexer's address | `CCDC_SPLUNK_INDEXERS` |
| Where the forwarder is installed, if unusual | `CCDC_SPLUNK_HOME` (empty = auto-detect) |

```bash
CCDC_SPLUNK_INDEXERS="10.0.0.10:9997"
CCDC_SPLUNK_REQUIRED_PATHS=""      # empty = auth/secure, audit.log, syslog/messages
```

These are checked *in addition* to whatever `outputs.conf` says, so a forwarder
that has quietly lost its output group is still measured against the packet.

---

## 6. What you would hate to lose

```bash
CCDC_BACKUP_PATHS="
/etc/ssh/sshd_config
/etc/passwd
/etc/group
/etc/sudoers
/var/www/html
"
```

Add the scored service's content and config. `arm.sh` takes this restore point
before anything else happens.

---

## 7. Firewall

```bash
CCDC_FIREWALL_ROLLBACK_SECONDS="60"
CCDC_ALLOW_OUTBOUND="1"
CCDC_ALLOWED_SOURCES=""            # scorer / Splunk / admin, if the packet names them
```

`CCDC_ALLOW_OUTBOUND="0"` kills most C2 callbacks and is the single most
effective anti-persistence setting here — but it can break DNS, package
updates, or a scored service that calls out. **Test it in the lab, do not
assume it.** If you have not tested it, ship `1`.

---

## 8. The one thing you cannot fill in advance

```bash
CCDC_DISABLE_SERVICES=""
```

It depends on what is actually installed, which you find out on the box. If the
packet names the image you can pre-stage a candidate list, but confirm it:

```bash
sudo ./linux/services.sh --config ~/ccdc-real.env --review
```

Two minutes on the day. Everything above this line is already decided.

---

## 9. Validate it before the day

Run this on the lab VM, against the **real** config, and fix what it says:

```bash
sudo ./linux/arm.sh --config ~/ccdc-real.env --dry-run
```

It checks that the evidence directory is writable, that every unit in
`CCDC_SYSTEMD_SERVICES` actually exists and is up, and warns if your HTTP check
points at localhost. Nothing is changed.

Then do a full rehearsal on a snapshot you can revert:

```
[ ] sudo ./linux/arm.sh --config ~/ccdc-real.env --apply
[ ] sudo ./linux/sentry.sh --config ~/ccdc-real.env --status
[ ] sudo ./linux/fw.sh --config ~/ccdc-real.env --apply   ... --confirm
[ ] sudo ./linux/sshd.sh --config ~/ccdc-real.env --apply ... --confirm
[ ] revert the snapshot
```

If the rehearsal is boring, the config is right.

---

## The finished checklist

```
[ ] CCDC_ALLOWED_USERS         every account that must keep working
[ ] CCDC_SYSTEMD_SERVICES      every scored service
[ ] CCDC_ALLOWED_TCP_PORTS     every scored port
[ ] CCDC_HTTP_CHECKS/TCP       the SCORER's address, not localhost
[ ] CCDC_WATCHDOG_INTERVAL=5
[ ] CCDC_SSH_*                 policy decided; PASSWORD_AUTH left empty unless sure
[ ] CCDC_SPLUNK_INDEXERS       the indexer
[ ] CCDC_BACKUP_PATHS          the scored content
[ ] CCDC_ALLOW_OUTBOUND        1 unless you tested 0
[ ] arm.sh --dry-run clean on the lab VM
[ ] full rehearsal done and snapshot reverted
[ ] the filled config is OUTSIDE the repo and not committed
```

Carry it on the day as a file you copy, not a thing you write.
