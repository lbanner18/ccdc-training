# Draft: Install & Validate End-Point Protection (SOFT04A)

**Deliverable beyond the memo:** status screenshots *and* a findings report per
server. Two artifacts per box, not one.

**Check the network first.** This inject assumes you can download signatures.
On an isolated competition network you often cannot — see the notes.

---

```text
INTEROFFICE MEMORANDUM

To:      <ROLE THE INJECT CAME FROM>
From:    Team <XX>
Date:    <DATE>
Subject: Install & Validate End-Point Protection

Summary: We were asked to select and deploy endpoint protection on each of our
         servers, run a full scan, and report the results. Protection is now
         active on all <N> systems; scans have completed and the findings are
         summarized below, with per-system screenshots and reports attached.

1. What we selected, and why

   | System type | Product selected | Why |
   |-------------|------------------|-----|
   | Windows servers and workstations | Microsoft Defender Antivirus | Built into the operating system, supported by the vendor, no additional licensing, and already present on every Windows system we own |
   | Linux servers | ClamAV | Open source, actively maintained by Cisco Talos, packaged for every distribution we run |

   We chose software already included with the operating system wherever one
   existed. It is supported, it introduces no new vendor, and it costs
   nothing. Both products are documented publicly - Microsoft Defender at
   https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows
   and ClamAV at https://docs.clamav.net/.

2. What was done on each system

   Windows:
   - Confirmed Defender Antivirus is enabled and that real-time protection is
     on, rather than assuming it.
   - Updated definitions.
   - Ran a full scan of all drives.
   - Captured the resulting status and scan report.

   Linux:
   - Installed ClamAV and its signature updater.
   - Updated signatures.
   - Ran a full filesystem scan, excluding only the virtual filesystems that
     represent kernel state rather than stored files.
   - Captured the scan summary and the list of detections.

3. Status by system

   | # | System | OS | Product | Real-time protection | Definitions dated | Full scan completed | Detections |
   |---|--------|----|---------|--------------------|------------------|--------------------|-----------|
   | 1 | <HOST> | <OS> | <PRODUCT> | <on/n-a> | <DATE> | <yes> | <N> |

   Screenshots of the protection status and of the completed scan are attached
   for every system in the table.

4. Findings

   <IF CLEAN: All scans completed with no detections. This does not mean the
   systems are known clean - signature-based scanning only finds known
   malicious files, and it will not find an attacker who is using legitimate
   administrative tools or valid credentials. We treat a clean scan as one
   input, not as an all-clear.>

   <IF DETECTIONS: The following items were detected and handled.>

   | System | Path | Detection name | Action taken | Verified removed |
   |--------|------|----------------|--------------|------------------|
   | <HOST> | <PATH> | <NAME> | <quarantined / deleted> | <yes> |

   For each detection we also checked whether the attacker had left a way back
   in - added accounts, scheduled jobs, service entries, startup items, or
   authorized keys - because removing the file alone does not remove the
   access.

5. Limitations and recommendation

   Antivirus is a floor, not a ceiling. It detects known malicious files and
   does not detect misuse of legitimate credentials or built-in system tools,
   which is how most intrusions actually progress. We recommend it be paired
   with central log collection and alerting, which is where that activity
   becomes visible.

   <IF APPLICABLE: Signature updates require outbound internet access, which
   <SYSTEM> does not have. Signatures for that system were transferred
   manually and are dated <DATE>. We recommend a supported update path be
   established.>

If there are any concerns, questions, or clarifications, please do not
hesitate to reach out.

With Regards,
Team <XX>
```

---

## Notes before you send this

- **No internet means no signatures.** `freshclam` fails closed, and `clamscan`
  will not run at all without a signature database present. If the competition
  network is isolated, download `main.cvd`, `daily.cvd`, and `bytecode.cvd`
  onto a reachable host first and copy them to `/var/lib/clamav/`. Discover
  this at minute 5, not minute 50.
- **A full `clamscan /` will eat the box.** It is single-threaded and memory
  hungry, and on a small VM it can starve the scored service — losing you more
  points than the inject is worth. Use `--exclude-dir` for `/proc`, `/sys`,
  `/dev`, and run it with `nice`. Scan and verify the scored service at the
  same time.
- **Defender is often disabled on competition images**, sometimes by policy
  rather than by the service. `Get-MpComputerStatus` tells you the truth;
  `Set-MpPreference -DisableRealtimeMonitoring $false` re-enables it, but if a
  GPO turned it off, fix the GPO.
- **Useful commands** (for you, not for the memo): `Update-MpSignature`,
  `Start-MpScan -ScanType FullScan`, `Get-MpThreatDetection`; and
  `freshclam`, `clamscan -r -i --exclude-dir='^/(proc|sys|dev)' /`.
- **Alpine** has ClamAV in the community repository, which may not be enabled.
  If it is not, say so in section 5 rather than silently skipping the box — a
  named exception scores, a missing row does not.
- **"Validate" is in the inject name.** A screenshot of an installer is not
  validation. A screenshot of a *completed scan with a result* is.
