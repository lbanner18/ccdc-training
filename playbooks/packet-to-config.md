# Packet → config, two days early

Use the packet to fill in this file before the event. The scripts use these
values to decide what to protect and what to flag. If a value is missing, the
scripts should stop and ask instead of guessing.

This is the worksheet for filling it. Work down it once, at a desk, with the
packet open. It takes about twenty minutes.

```bash
cp config/example.env ~/ccdc-real.env     # OUTSIDE the repo. Never commit it.
```

> `sentry.sh` will not act while `CCDC_ALLOWED_USERS` and
> `CCDC_SYSTEMD_SERVICES` are empty. That is a safety stop. For example, if you
> leave the service list blank, the script cannot know whether `nginx` is a
> scored web service or something safe to stop.

---

## 1. Who and what is scored

| The packet says | Fill in | If you get it wrong |
|---|---|---|
| Accounts the packet permits to exist, including yours and service identities | `CCDC_ALLOWED_USERS` | The kit will not offer to remove them. Example: `websvc` belongs here even if it cannot log in. |
| Accounts that must accept an interactive login, only if the packet says so | `CCDC_INTERACTIVE_USERS` | The kit warns if that account is locked, expired, or set to nologin. |
| Services that are scored for uptime | `CCDC_SYSTEMD_SERVICES` | The watchdog checks and restarts these services. |
| Ports the scorer connects to | `CCDC_ALLOWED_TCP_PORTS`, `CCDC_ALLOWED_UDP_PORTS` | The kit knows these ports are expected listeners. |

```bash
CCDC_ALLOWED_USERS="root youradmin websvc"
CCDC_INTERACTIVE_USERS="youradmin"   # omit websvc unless the packet says it logs in
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

> **Use the scorer's address, not `127.0.0.1`.** `127.0.0.1` means "this same
> computer." It can still reach a web service after a firewall blocks everyone
> else. Example: use `http://10.0.0.25:80/` when that is the scoring engine.

TCP uses `name|host|port|unit`; HTTP uses `name|url|unit`. `name` is a label for
the report, and `unit` is the Linux service name to restart if the check fails.
Leave `unit` empty when you want an alert only. For example,
`web|http://10.0.0.25:80/|nginx` checks the URL and can restart `nginx`.

---

## 3. The number that decides your downtime

```bash
CCDC_WATCHDOG_INTERVAL="5"
```

This is how many seconds the watchdog waits between checks. With `60`, a service
can be down for nearly a minute before the next check. In the lab, the same
stopped service cost 57 seconds at `60` and 6 seconds at `5`. Use `5` unless
the packet gives a reason not to.

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

## 6a. Recovery copy of the kit

```bash
# Leave empty to store it beside the ordinary backup.
CCDC_RECOVERY_DIR=""
```

`backup.sh` saves the machine files you name above. `recovery.sh` saves a
checksummed copy of this toolkit, its playbooks, and the config file you used.
`arm.sh --apply` creates that copy automatically. This helps if somebody
deletes or replaces the checkout itself. It never restores over the live
checkout: recovery always creates a new directory first.

The same step leaves a root-owned restore helper beside the bundle. If the
checkout is gone, the default command is:

```bash
sudo /var/backups/ccdc/ccdc-kit-recover.sh --restore /root/ccdc-recovered --apply
```

If you set `CCDC_RECOVERY_DIR`, replace `/var/backups/ccdc` with that path.
The command verifies the newest archive before extracting it to
`/root/ccdc-recovered/kit`; it refuses if that destination already exists.

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
[ ] Apply the firewall, verify a new SSH connection and the scored service,
    then run `sudo ./linux/fw.sh --config ~/ccdc-real.env --confirm`.
[ ] Apply SSH policy, test a new login, then run
    `sudo ./linux/sshd.sh --config ~/ccdc-real.env --confirm`.
[ ] revert the snapshot
```

If the rehearsal is boring, the config is right.

---

## The finished checklist

```
[ ] CCDC_ALLOWED_USERS         every account the packet permits to exist
[ ] CCDC_INTERACTIVE_USERS     only accounts the scorer/admin must log into
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

---

# Changing the config once the event has started

Everything above assumes a desk, two days early, nothing running. Mid-event is
different, and it has a trap in it that costs you ten minutes and your trust in
the tool if you meet it cold.

## The trap, measured

The supervised sentry **does not read the file you edit.** `--install` copies
your config to `/usr/local/lib/ccdc-sentry/sentry.env` and the systemd unit's
`ExecStart` names that copy. This is deliberate — an attacker who can write to
your home directory must not be able to steer a loop running as root — but it
means editing `~/ccdc-real.env` changes nothing, and says nothing.

The obvious second attempt is worse. Edit the installed copy directly and it
looks like it worked:

```
15:CCDC_SYSTEMD_SERVICES="scored-web ssh"            # before
15:CCDC_SYSTEMD_SERVICES="scored-web ssh inventory-api"   # after the edit
```

Seventy-five seconds later, on the lab box, with nothing printed anywhere:

```
15:CCDC_SYSTEMD_SERVICES="scored-web ssh"
```

Guardian holds `sentry.env` in its repair tree and put it back, exactly as it
would if an attacker had edited it. Guardian cannot tell your legitimate change
from tampering — that ambiguity is the entire point of guardian — so it wins,
quietly, every minute.

## The one command

```bash
# 1. edit YOUR config, the one in your home directory
nano ~/ccdc-real.env

# 2. make the running tools use it
sudo ./linux/sentry.sh --config ~/ccdc-real.env --reload-config --apply
```

Step 2 takes guardian down, reinstalls sentry (which re-copies both the tool
tree and the config), and puts guardian back so it re-takes its copy including
your change — in that order, because any other order is undone. It refuses to
start if the config has a syntax error, and it prints back the three lists that
decide everything so you can see the change landed:

```
Done. The running sentry is using /home/banneluk/ccdc-real.env as of now.

  CCDC_SYSTEMD_SERVICES=scored-web ssh inventory-api
  CCDC_ALLOWED_TCP_PORTS=22 8080
  CCDC_ALLOWED_USERS=root banneluk www-lab
  CCDC_INTERACTIVE_USERS=banneluk
```

`--reload-config` with no `--apply` prints the three steps it would take and
changes nothing.

## Which knob for which finding

A finding is being reported because nothing on this box explains it. There are
two different ways to explain one, and they are not interchangeable.

| finding | the knob | what it means |
|---|---|---|
| `port` / `udpport` / `listener` on a port you serve | `CCDC_ALLOWED_TCP_PORTS`, `CCDC_ALLOWED_UDP_PORTS` | the packet says this port is open |
| `netprocsvc` — an interpreter holding an accounted-for port | `CCDC_SYSTEMD_SERVICES` | name the **unit**, and the process under it stops being a question at all |
| `uid0` / `svcshell` / `admingroup` for an account the packet names | `CCDC_ALLOWED_USERS` | this account is supposed to exist |
| `unit` / `rogueunit` for a service you were told to run | `CCDC_SYSTEMD_SERVICES` or `CCDC_PROTECT_SERVICES` | never remove this unit |

**Prefer the config over a standing exception.** A declared service is
*explained* — the check stops firing because the box now makes sense — where a
muted finding is *silenced*, still true, and still there. Use `--mute` for the
things the config has no word for:

```bash
sudo ./linux/sentry.sh --config ~/ccdc-real.env \
     --mute netprocsvc '/usr/bin/python3.12 tcp/4448' \
     --reason "inject 4: the API they asked for, no unit yet" --apply

sudo ./linux/sentry.sh --config ~/ccdc-real.env --muted      # everything silenced, with reasons
sudo ./linux/sentry.sh --config ~/ccdc-real.env --unmute netprocsvc '/usr/bin/python3.12 tcp/4448' --apply
```

The count of silenced findings prints at the top of every report whether or not
anything else is wrong, so this quiets the list without hiding anything from
you.

## Baseline is separate, and that is on purpose

`baseline.sh` answers "what changed since I froze this box", against its own
blessed inventory. Its exceptions live there, not in the config:

```bash
sudo ./linux/baseline.sh --config ~/ccdc-real.env \
     --allow /etc/profile.d/company-motd.sh \
     --reason "inject 3: the banner they asked for" --apply
```

No reload is needed for that one — `baseline.sh` runs from your tree, reads the
exceptions file directly, and is not supervised.

## If something goes wrong halfway

`--reload-config` takes guardian down before it touches anything. If the
reinstall fails, it says so and prints the command to put guardian back. Run it.
A box with no guardian has no keep-alive, and nothing else is watching for that
gap:

```bash
sudo ./linux/guardian.sh --config ~/ccdc-real.env --install --apply
```
