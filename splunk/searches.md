# Starter Splunk searches

Replace `index=main` and the host names with the values from the team packet.
These are intentionally small searches you can paste during a timed inject.

## Linux

```spl
index=main sourcetype=linux_secure ("Failed password" OR "authentication failure")
| stats count min(_time) as first max(_time) as last values(src) as sources by user
```

```spl
index=main sourcetype=linux_secure ("Accepted password" OR "Accepted publickey")
| table _time host user src method
| sort - _time
```

```spl
index=main sourcetype=linux_secure ("new user" OR "useradd" OR "adduser")
| table _time host _raw
```

```spl
index=main sourcetype=linux_secure ("sudo:" OR "COMMAND=")
| table _time host user command _raw
| sort - _time
```

```spl
index=main ("Stopped" OR "Failed" OR "Started") (sshd OR nginx OR apache OR named OR mysql)
| table _time host _raw
```

## Windows Security log

```spl
index=main sourcetype=WinEventLog:Security EventCode IN (4624,4625)
| stats count values(src_ip) as source_ips by EventCode Account_Name Logon_Type
```

```spl
index=main sourcetype=WinEventLog:Security EventCode=4720
| table _time Computer Account_Name SubjectUserName
```

```spl
index=main sourcetype=WinEventLog:Security EventCode=4732
| table _time Computer MemberName TargetUserName SubjectUserName
```

```spl
index=main sourcetype=WinEventLog:System EventCode=7045
| table _time Computer Service_Name ImagePath Service_File_Name Account_Name
```

```spl
index=main sourcetype=WinEventLog:Security EventCode IN (4698,1102)
| table _time Computer EventCode SubjectUserName Task_Name _raw
```

## Canary and audit trips (this kit's own signal)

The highest-confidence intrusion signal on the box. `canary.sh` writes trips to
`$CCDC_EVIDENCE_DIR/canary.alerts.log`; forward that file, and forward auditd.

Forward the alert log — add to `inputs.conf` on the Linux host:

```ini
[monitor:///var/tmp/ccdc-evidence/canary.alerts.log]
index = main
sourcetype = ccdc:canary
```

A canary decoy was touched, modified, or deleted (start incident response now):

```spl
index=main sourcetype=ccdc:canary ("TRIP" OR "AUDIT")
| rex "kind=(?<kind>\S+)"
| rex "path=(?<path>\S+)"
| table _time host kind path _raw
| sort - _time
```

auditd caught access to a decoy or a real sensitive file (needs the auditd
add-on or a monitor of `/var/log/audit/audit.log`). Our rules are tagged with
the keys `ccdc-canary` and `ccdc-sensitive`:

```spl
index=main (sourcetype=linux_audit OR source="/var/log/audit/audit.log")
  ("key=\"ccdc-canary\"" OR "key=\"ccdc-sensitive\"")
| rex "key=\"(?<canary_key>ccdc-[a-z]+)\""
| rex "\buid=(?<uid>\d+)"
| rex "\bexe=\"(?<exe>[^\"]+)\""
| table _time host canary_key uid exe _raw
| sort - _time
```

Read of /etc/shadow by anything other than the expected auth stack — one of the
clearest "someone is looting credentials" signals:

```spl
index=main (sourcetype=linux_audit OR source="/var/log/audit/audit.log")
  "name=\"/etc/shadow\""
| rex "\bexe=\"(?<exe>[^\"]+)\""
| search NOT exe IN ("/usr/sbin/sshd","/usr/bin/login","/usr/sbin/unix_chkpwd","/usr/bin/passwd","/usr/bin/sudo")
| table _time host exe _raw
```

