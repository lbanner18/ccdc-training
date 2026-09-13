# Simulation runbook — practice the whole loop against the lab VM

A scripted Sunday drill: arm the defenses, let the red team land, detect it,
eradicate it, and (once it exists) prove the watchdog survives. Run it as a
checklist against the disposable lab VM — real root, real auditd, real systemd,
which is where the mutating paths that could not be tested on a workstation
actually get proven.

**Lab only.** Everything here plants real footholds and changes real config.
Never run `redteam/plant.sh` anywhere but a VM you own and can revert. Take the
`clean-baseline` snapshot before you start and revert to it at the end.

Time budget: ~60–90 min for the full loop the first time; ~30 once it is muscle
memory. Do it under a timer — the tryout clock is the real adversary.

---

## Prerequisites

```
[ ] Kit copied to the lab VM (tar the repo over, exclude .git and *.env).
[ ] Config filled: cp config/example.env /tmp/ccdc-linux.env and edit for the
    box (scored user/service/ports, evidence dir).
[ ] auditd installed on the VM (canary read-detection needs it). If it is not
    installed and the network is offline, note that and expect canary to fall
    back to hash/atime only.
[ ] clean-baseline snapshot taken.
```

---

## Phase 0 — arm the defenses (the first 15 minutes, timed)

```
[ ] ./linux/recon.sh --config /tmp/ccdc-linux.env      # baseline BEFORE plant
[ ] Note the evidence path. This is your known-good picture.
[ ] ./linux/canary.sh --config /tmp/ccdc-linux.env --deploy --dry-run
[ ] sudo ./linux/canary.sh --config /tmp/ccdc-linux.env --deploy --apply
[ ] ./linux/canary.sh --config /tmp/ccdc-linux.env --status   # decoys + audit rules laid
[ ] sudo ./linux/watchdog.sh --config /tmp/ccdc-linux.env --apply &   # keep services up
[ ] (optional) sudo ./linux/fw.sh --config /tmp/ccdc-linux.env --apply then --confirm
```

**Pass:** `canary.sh --status` lists the decoys and, if auditd is present, the
`ccdc-canary` / `ccdc-sensitive` rules. The watchdog is logging health checks.

---

## Phase 1 — the red team lands

```
[ ] sudo ./redteam/plant.sh
[ ] Read the printed GROUND TRUTH list (11 artifacts, all tagged RT_LAB_PLANT).
    That list is your answer key. Do not peek at it again until you score.
```

`plant.sh` drops: a rogue user (`rtsvc`), a sudoers NOPASSWD backdoor, an extra
root SSH key, a `cron.d` entry, a root crontab entry, a disguised systemd timer
("System Logging Helper"), the implant binary, a `profile.d` hook, a `.bashrc`
hook, a SUID root shell (`rootbash`), and a `/dev/shm` payload.

---

## Phase 2 — detect it (this is the graded skill)

```
[ ] ./linux/hunt.sh --config /tmp/ccdc-linux.env       # persistence sweep
[ ] ./linux/canary.sh --config /tmp/ccdc-linux.env --check   # did they touch a decoy?
[ ] ./redteam/score.sh /var/tmp/ccdc-evidence          # score hunt vs ground truth
```

**Pass:** `score.sh` prints `[CAUGHT ]` for all ten of its checks. A `[MISSED ]`
is a real gap — note which artifact and which hunt section should have caught
it, then fix `hunt.sh` (that is how the detection holes were closed before).

Cross-check by eye, because `score.sh` is a grep and can score a false CAUGHT:

```
[ ] hunt.sh extra-persistence.txt   -> .bashrc hook, profile.d, kernel modules
[ ] hunt.sh persistence.txt         -> rt-cron, root crontab, rt-backdoor timer
[ ] hunt.sh suid-capabilities.txt   -> rootbash (SUID)
[ ] hunt.sh process-anomalies.txt   -> /dev/shm/.rt
[ ] recon.sh accounts.txt/ssh.txt   -> rtsvc, sudoers NOPASSWD, extra SSH key
```

Note: the `.bashrc` hook is caught by the extended `hunt.sh` sweep but is NOT one
of `score.sh`'s checks — verify it by eye so you learn to catch what the grep
misses. If a decoy trip fired in `canary.sh --check`, treat that as the first
alarm you would have seen live, before you ever ran a sweep.

---

## Phase 3 — eradicate it (the SANS loop, by hand)

Do this manually the first time — the muscle memory is the point. `plant.sh
--clean` is the authoritative reset, but if you lead with it you have practiced
nothing.

```
[ ] CONTAIN: lock the rogue user, remove its sudo:
    sudo passwd -l rtsvc ; sudo sed -i '/rtsvc/d' /etc/sudoers   (visudo-check!)
[ ] Snapshot / copy evidence BEFORE deleting (forensics + the IR-memo inject).
[ ] ERADICATE each foothold AND the way back in:
    - userdel -r rtsvc
    - remove the extra key line from /root/.ssh/authorized_keys
    - rm /etc/cron.d/rt-cron ; crontab -e (drop the rt-implant line)
    - systemctl disable --now rt-backdoor.timer ; rm the unit files ; daemon-reload
    - rm /usr/local/bin/rt-implant /usr/local/bin/rootbash /dev/shm/.rt
    - remove the /etc/profile.d/rt-profile.sh and /root/.bashrc hooks
[ ] RE-HUNT: ./linux/hunt.sh --config ... then ./redteam/score.sh
    -> now every check should read MISSED (nothing left to catch = clean box)
[ ] RECOVER: confirm the scored service still answers FROM THE NETWORK.
```

**Pass:** a second `score.sh` reports everything MISSED (i.e. gone), the scored
service is up, and you wrote a timeline as you went (that timeline is the
incident-report inject, half-done).

---

## Phase 4 — watchdog survival

`guardian.sh` is built. This is the drill that proves resilience against a
root-level attacker — and it is also the **first time its mutating paths run as
root**: everything tested so far ran against a sandbox with `/etc` redirected
and `systemctl` stubbed, so the file reconciliation is proven and the unit
handling is not. Expect to find something here.

```
[ ] sudo ./linux/guardian.sh --config /tmp/ccdc-linux.env --install --apply
[ ] sudo ./linux/guardian.sh --config /tmp/ccdc-linux.env --status  # 3 layers live
[ ] ATTACK 1 — kill the watchdog process:   sudo pkill -f watchdog.sh
    -> within one interval it is running again. Confirm with --status.
[ ] ATTACK 2 — stop the service:            sudo systemctl stop <name>
    -> a tick (timer or cron) restarts it within the interval.
[ ] ATTACK 3 — delete one layer's unit file, then delete a second:
    -> the surviving layer rebuilds the deleted ones. Confirm all three back.
[ ] ATTACK 4 — BACKDOOR a layer instead of deleting it: append
    ExecStartPost=/bin/sh -c 'id > /tmp/pwned' to <name>.service
    -> next tick quarantines a copy under $CCDC_EVIDENCE_DIR/guardian.tampered/
       and rewrites the unit from source. Confirm the line is gone, the copy
       kept, and --status stopped reporting MODIFIED.
[ ] ATTACK 5 — DROP-IN OVERRIDE, leaving the unit file untouched:
    mkdir -p /etc/systemd/system/<name>.service.d
    printf '[Service]\nExecStartPost=/bin/sh -c "id > /tmp/pwned"\n' \
      > /etc/systemd/system/<name>.service.d/override.conf ; systemctl daemon-reload
    -> next tick quarantines the whole .d directory and restarts the unit.
       The unit file's hash never changed, so this is the attack a
       fragment-only check cannot see. Confirm /tmp/pwned was never created.
[ ] ATTACK 6 — remove ALL THREE layers in the same interval:
    -> only now does it stay down. This is the documented limit, not a bug.
[ ] CLEAN: sudo ./linux/guardian.sh --config ... --uninstall --apply
    -> the disarm sentinel stops the rebuild; --status shows nothing left.
    -> confirm removal is exact against the manifest (no stray footholds).
```

**Pass:** attacks 1–5 self-heal within the interval; attack 6 stays down;
`--uninstall` leaves zero artifacts (verify against the manifest — your own
footholds must be as removable as the red team's should have been).

One thing to watch while you do this: run `./linux/hunt.sh` with the guardian
armed and confirm you can tell its four artifacts apart from a red-team plant
using nothing but the manifest. If you cannot do that under time pressure, the
guardian is a liability rather than a defense — that is the actual test.

---

## Phase 5 — firewall dead man's switch (optional refresher)

Already proven with two real lockout tests, but worth one rep so it is reflex:

```
[ ] From a SECOND ssh session as backup, in the first session:
    sudo ./linux/fw.sh --config ... --apply     # arms auto-rollback
[ ] Deliberately break access (e.g. drop your own port) and do nothing.
    -> the rollback fires on its own; the second session proves you are back.
[ ] On a good apply: --confirm within the window to keep the rules.
```

---

## Reset

```
[ ] sudo ./redteam/plant.sh --clean       # authoritative removal of any plants
[ ] sudo ./linux/canary.sh --config ... --remove --apply
[ ] Revert the VM to clean-baseline.
```

---

## Self-scoring — are you tryout-ready?

You are ready when, under a timer and without notes:

- Phase 0 (arm defenses) done in **under 15 minutes**.
- Phase 2 catches **all 11** planted footholds, including the `.bashrc` hook
  that `score.sh` does not check.
- Phase 3 eradication leaves a clean box **and** the scored service stays up
  throughout — you never took down your own service to remove a foothold.
- You produced a timestamped timeline good enough to drop into the
  incident-report inject.
- (After guardian) attacks 1–3 self-heal and `--uninstall` is exact.

Then do it again while also answering a pre-written inject from
`injects/responses/` on the clock — because on the day, both halves of the score
are happening at once.
