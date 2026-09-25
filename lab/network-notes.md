# Practice-lab reachability: laptop can't reach the replica VMs

Not part of the kit — notes for whoever's debugging the laptop's connection to
iron-test / redstone-test / lapis-test. Delete this file once it's sorted; it
has nothing to do with the actual tryout (that goes over NetBird tomorrow, to
completely different infrastructure, and is unaffected by any of this).

## Symptom

From Luke's Windows laptop: both `ssh` (port 22) and RDP (port 3389) to the
practice VMs **time out** - no response, not a refusal. Confirmed against
`iron-test` (192.168.122.23) and `lapis-test` (192.168.122.188).

Earlier "successful" SSH sessions to iron/redstone in this conversation were
run from the homelab host itself (the Claude Code session's own shell), not
from the laptop - so they never actually proved laptop reachability. That's
now been separated out and confirmed: **the laptop has never successfully
reached any of the three practice VMs, on any port.**

## Where the VMs actually live

The three practice replicas (`iron-test`, `redstone-test`, `lapis-test`) run
under libvirt on **luke-banner-homelab**, a separate physical machine from
the laptop:

- Host's own LAN address: `192.168.86.206/24` on `wlo1` (home wifi)
- VMs sit on libvirt's `default` network: `192.168.122.0/24`, NAT'd through
  `virbr0` (gateway `192.168.122.1`), **only reachable from the host itself**
- No DNAT/port-forward rules exist on the host for that subnet (checked
  `iptables -t nat -S`, nothing matches `192.168.122.*`)
- No router-level route exists either, as far as this session can tell

A libvirt NAT network being unreachable from other LAN devices, with no
forwarding set up, is the *expected* default - not a misconfiguration to keep
hunting for. Both ports timing out uniformly (rather than one working, one
refused) is exactly what "no route to 192.168.122.0/24" looks like from the
laptop's side.

## Already ruled out (checked directly on the VMs, from the host)

- `lapis-test`'s RDP: enabled (`fDenyTSConnections=0`), NLA off, firewall
  rule `Remote Desktop - User Mode (TCP-In)` is `Enabled=True Profile=Any
  Action=Allow`, listener up on `0.0.0.0:3389`.
- No per-VM libvirt network filtering: `virsh dumpxml` shows no `<filterref>`
  on any of the three VMs' interfaces - `lapis-test` and `iron-test` (which
  *did* work, from the host) are wired identically.
- The host's own `sshd` listens on `0.0.0.0:22`, so nothing there blocks the
  host itself from being reached.

So this isn't a VM problem. It's the laptop-to-host network path.

## First thing to check

Does the laptop even reach the **host** (192.168.86.206), never mind the VMs?

```powershell
Test-NetConnection 192.168.86.206 -Port 22
ping 192.168.86.206
```

- **If that connects:** laptop and host share a LAN/segment fine; the VMs'
  private `192.168.122.0/24` is just unrouted from there. Go to Fix A or B
  below.
- **If that also times out:** the laptop isn't even on the same network as
  the homelab host right now (different wifi, VPN capturing the route, campus/
  guest network, etc.) - that's the actual thing to chase, before anything
  about the VMs matters.

## Fix A (recommended) - SSH jump/tunnel through the host, no router changes

Only needs the laptop to reach `192.168.86.206:22`, which the check above
confirms.

```powershell
# SSH to a VM, via the host as a jump box
ssh -J banneluk@192.168.86.206 steve@192.168.122.23

# RDP: forward the port locally, then point mstsc at localhost
ssh -L 3389:192.168.122.188:3389 banneluk@192.168.86.206
# ...then Remote Desktop Connection -> localhost
```

## Fix B - port-forward (DNAT) on the host

More setup, but the laptop then talks to `192.168.86.206:<port>` directly
with no SSH client needed for RDP. On the host (needs root, which this
session doesn't have passwordless):

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 2223 -j DNAT --to 192.168.122.23:22
sudo iptables -t nat -A PREROUTING -p tcp --dport 23389 -j DNAT --to 192.168.122.188:3389
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
```
(pick free host-side ports per VM/service; enable IP forwarding if it isn't
already: `sudo sysctl -w net.ipv4.ip_forward=1`)

## Fix C - static route on the home router

Route `192.168.122.0/24` -> `192.168.86.206` on the router itself. Most
"native" feeling once done, but needs router admin access and affects the
whole home network, not just this laptop - probably overkill for one night
of practice.
