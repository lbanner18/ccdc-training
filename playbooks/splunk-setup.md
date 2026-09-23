# Splunk from nothing: indexer + both forwarders, solo

The tryout is four devices, and one of them is a Splunk indexer. The team
training has you build the pipeline yourself: indexer listening on 9997, a
`linux` and a `windows` index, a forwarder on each scored host. This is that,
in order, with every trap it hit in the lab.

**Proven 2026-09-22** with Splunk 10.4.0 (build `f798d4d49089`): indexer on
Ubuntu 24.04, forwarders on the same Ubuntu box and on Windows Server 2022.
Test events from both hosts were found on the indexer in the right index.
Lines marked *(not run in the lab)* are standard commands that were not
executed there.

Budget: about 15 minutes if the packages are already on the boxes.

| step | measured |
|---|---|
| indexer `dpkg -i` | 69 s |
| indexer first start | 17 s |
| Windows forwarder MSI, silent | 23 s |

## 0. Before you start (2 minutes that save 20)

1. **Is Splunk already installed?** On the indexer: `systemctl status Splunkd`
   and `ls /opt/splunk`. If the organisers built it, skip to step 1d, and
   **change the admin password in the web UI first** (Settings → Users →
   admin). A pre-built Splunk has a password the red team may already know.
2. **Check the clock on all three boxes.** `date -u` on Linux,
   `(Get-Date).ToUniversalTime()` on Windows. In the lab the indexer was six
   days behind: every event had arrived, and `earliest=-30m` still found
   nothing, because "the last 30 minutes" was measured on the indexer's clock.
   If they disagree, search with `earliest=0` until it is fixed.
3. Write down the indexer IP. Everything below uses it:

```bash
IDX=192.168.100.152        # the indexer, from the packet
```

## 1. Indexer (Linux)

**a. Install** (skip if it is already installed)

```bash
sudo dpkg -i splunk-10.4.0-f798d4d49089-linux-amd64.deb
```

**b. Seed the admin password without typing it on a command line.** Splunk
reads this file once on first start and then deletes it.

```bash
sudo tee /opt/splunk/etc/system/local/user-seed.conf >/dev/null <<'SEED'
[user_info]
USERNAME = admin
PASSWORD = choose-a-real-one-here
SEED
sudo chown splunk:splunk /opt/splunk/etc/system/local/user-seed.conf
```

**c. First start.** This runs as `splunk`, never as root. The same rule applies
to every Splunk command below.

```bash
sudo -u splunk /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt
```

**d. Log in once, then configure.** `login` prompts for the password, so it
stays out of your shell history. *(The interactive prompt was not run in the
lab; the commands after it were, with `-auth`.)*

```bash
sudo -u splunk /opt/splunk/bin/splunk login
sudo -u splunk /opt/splunk/bin/splunk enable listen 9997
sudo -u splunk /opt/splunk/bin/splunk add index linux
sudo -u splunk /opt/splunk/bin/splunk add index windows
sudo -u splunk /opt/splunk/bin/splunk display listen      # "Receiving is enabled on port 9997."
```

**e. Start at boot**

```bash
sudo -u splunk /opt/splunk/bin/splunk stop
sudo /opt/splunk/bin/splunk enable boot-start -user splunk -systemd-managed 1
sudo systemctl start Splunkd
systemctl is-enabled Splunkd; ss -ltn | grep -E ':(8000|8089|9997) '
```

**f. The indexer is a target too.** It listens on 8000 (web), 8089
(management) and 9997 (data). Someone who has the admin password and can reach
8000 or 8089 can install an app that runs a script: that is code execution as
the `splunk` user. So:

- allow **9997** from the two scored hosts only;
- allow **8000** from your own workstation only;
- do not expose **8089** at all. Forwarders do not need it unless you run a
  deployment server, and at a tryout you will not.

*(Firewall rules for the indexer were not run in the lab. It had no firewall.
Use `linux/fw.sh` if the indexer is a box you manage the same way.)*

Afterwards, check what is installed. Anything you did not add is a finding:

```bash
ls /opt/splunk/etc/apps
sudo -u splunk /opt/splunk/bin/splunk btool inputs list script | grep '^\[script'
```

## 2. Linux forwarder

```bash
sudo dpkg -i splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
```

**The trap that silently ships nothing:** the forwarder runs as `splunkfwd`,
and `/var/log/auth.log` and `/var/log/syslog` are `0640` owned by group `adm`.
`splunk add monitor /var/log/auth.log` still prints *"Added monitor"*, and
nothing ever arrives. The only record is a line in the forwarder's own
`splunkd.log`. Fix it before the first start, so no restart is needed:

```bash
sudo usermod -aG adm splunkfwd
```

Then seed an admin account (the CLI needs one), start it **as splunkfwd**, and
configure it:

```bash
sudo tee /opt/splunkforwarder/etc/system/local/user-seed.conf >/dev/null <<'SEED'
[user_info]
USERNAME = admin
PASSWORD = choose-a-real-one-here
SEED
sudo chown -R splunkfwd:splunkfwd /opt/splunkforwarder/etc/system/local
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk login
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk add forward-server "$IDX:9997"
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index linux
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog -index linux
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk add monitor /var/log/audit/audit.log -index linux
```

**Start at boot.** The training's steps skip this, and a reboot silences the
forwarder. `systemctl enable SplunkForwarder` does **not** work yet: there is
no unit until you create one.

```bash
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk stop
sudo /opt/splunkforwarder/bin/splunk enable boot-start -user splunkfwd -systemd-managed 1
sudo systemctl start SplunkForwarder
```

**Never run a bare `sudo splunk start` or `sudo splunk restart`.** On an
install without a unit it brings the forwarder back **as root**. That hides
every permission problem and runs a log parser as root. Worse, a later
`enable boot-start` then writes root into the config permanently. It happened
in the lab. Use `sudo systemctl restart SplunkForwarder` once the unit exists,
or `sudo -u splunkfwd ... restart` before. `linux/splunk.sh` reports a root
forwarder and prints the repair.

## 3. Windows forwarder

One line, run from an elevated PowerShell. `GENRANDOMPASSWORD=1` means no
password is typed anywhere: the forwarder's own admin account is never needed.

```powershell
$IDX = '192.168.100.152'
$msi = (Resolve-Path .\splunkforwarder-10.4.0-f798d4d49089-windows-x64.msi).Path   # msiexec wants a full path
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" AGREETOLICENSE=Yes RECEIVING_INDEXER=${IDX}:9997 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 WINEVENTLOG_APP_ENABLE=1 GENRANDOMPASSWORD=1 /quiet /L*v C:\Windows\Temp\uf-install.log"
```

That collects Security, System and Application into **`main`**, and skips
PowerShell/Operational, the log that script-block logging writes to. This adds
it and routes all four into `windows`:

```powershell
$f = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'
Add-Content -LiteralPath $f -Value '', '[WinEventLog://Microsoft-Windows-PowerShell/Operational]', 'disabled = 0'
Add-Content -LiteralPath $f -Value '', '[WinEventLog://Security]', 'index = windows', '', '[WinEventLog://System]', 'index = windows', '', '[WinEventLog://Application]', 'index = windows', '', '[WinEventLog://Microsoft-Windows-PowerShell/Operational]', 'index = windows'
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' restart
```

The service runs as `NT SERVICE\SplunkForwarder`, and it **can** read the
Security log. That was verified: 25,754 Security events arrived.

## 4. Prove it: the only step that counts

```bash
sudo ./linux/splunk.sh --config "$CFG"                    # clean?
sudo ./linux/splunk.sh --config "$CFG" --test-event --apply
```

```powershell
.\windows\splunk.ps1 -Config C:\ProgramData\CCDC\ccdc.env
.\windows\splunk.ps1 -Config C:\ProgramData\CCDC\ccdc.env -TestEvent -Apply
```

Each prints a token and the search that finds it: `index=* "ccdc-e2e-..."`.
**Find both tokens in Splunk.** A running service, a green check and an open
connection are all claims. A found token is proof. Write the token and the
time in your notes. That line is your inject evidence.

For the "logs received from hosts" screenshot the training asks for:

```spl
index=linux OR index=windows earliest=0 | stats count by host, index, source
```

And for the inject table: `./linux/splunk.sh --config "$CFG" --inventory` and
`.\windows\splunk.ps1 -Config ... -Inventory` each print one.

## When a token does not show up

Work down this list. It is ordered by how often each one was the answer:

| symptom | cause | check |
|---|---|---|
| nothing from a Linux file | `splunkfwd` cannot read it | `sudo ./linux/splunk.sh` names the file and prints the `usermod` |
| nothing recent, old data fine | indexer clock skew | `date -u` on both; search `earliest=0` |
| nothing at all from a host | 9997 blocked, or listen not enabled | `nc -vz $IDX 9997` / `Test-NetConnection $IDX -Port 9997`; `splunk display listen` |
| events vanish | input names an index the indexer lacks | Settings → Indexes on the indexer |
| connected, still nothing | inputs disabled, or not the log you wrote to | `splunk.sh` / `splunk.ps1` list every input and its index |
